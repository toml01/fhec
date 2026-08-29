//! The per-function pass: statement walking, legality (spec §7), definite
//! assignment (spec §6), and rewrite-site/ACL-fact collection — one
//! source-ordered walk. Expression typing lives in [`crate::exprs`].

use fhec_bind::{BoundUnit, Builtin, ContractId, FileId, FunctionId, Resolution, VarOwner};
use fhec_ir::EType;
use fhec_targets::TargetProfile;
use solar_ast as ast;
use solar_data_structures::map::FxHashMap;
use solar_interface::{source_map::SourceMap, Span};

use crate::decl::declared_ty;
use crate::diag::{codes, Diagnostic};
use crate::sites::{CheckedUnit, EncryptedIfSite, EncryptedReturn};
use crate::trust::Trust;
use crate::ty::{PlainTy, Ty};

/// Definite-assignment state of an encrypted local (spec §6).
///
/// Two states suffice: "maybe assigned" and "definitely unassigned" trigger
/// the same conservative rejection, so both map to `Unassigned`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AState {
    /// Not assigned on every path.
    Unassigned,
    /// Assigned on every path.
    Assigned,
}

impl AState {
    fn join(a: AState, b: AState) -> AState {
        a.min(b)
    }
}

/// One tracked local/parameter/named-return of the current function.
pub(crate) struct LocalSlot {
    /// The declared encrypted type, when encrypted (only those participate
    /// in definite assignment).
    pub(crate) encrypted: Option<EType>,
    /// Current definite-assignment state.
    pub(crate) state: AState,
    /// The encrypted-branch depth at declaration (0 = outside branches).
    pub(crate) decl_depth: u32,
}

/// Whether `inner` lies within `outer`.
pub(crate) fn span_within(inner: Span, outer: Span) -> bool {
    inner.lo() >= outer.lo() && inner.hi() <= outer.hi()
}

pub(crate) struct FnChecker<'a, 'ast> {
    pub(crate) unit: &'a BoundUnit<'ast>,
    pub(crate) trust: &'a Trust,
    pub(crate) profile: &'a dyn TargetProfile,
    pub(crate) sm: &'a SourceMap,
    pub(crate) out: &'a mut CheckedUnit,
    pub(crate) safe_cache: &'a mut FxHashMap<FunctionId, bool>,

    pub(crate) fid: FunctionId,
    pub(crate) file: FileId,
    pub(crate) contract: Option<ContractId>,
    pub(crate) is_view_or_pure: bool,
    pub(crate) is_public_or_external: bool,
    /// Whether this function is declared inside a `library`. A library's
    /// state-changing `public`/`external` members are delegatecall-linked:
    /// they share the host's `msg.sender` and storage, so R3's "grant the
    /// external caller" premise does not apply there — but a library's
    /// `view`/`pure` member IS directly, independently callable (Solidity's
    /// library-call protection only reverts a direct `CALL` for
    /// state-changing members), so the `view`/`pure` exception still applies
    /// to it first (spec §8.3, §8.4).
    pub(crate) in_library: bool,
    /// Whether the `returns` list carries a §2.8 shared-boundary marker. Such
    /// a function states no R3 fact: a legal shared return grants through
    /// `FHE.shareT(..., msg.sender)` instead of `allowTransient`, and an
    /// illegal one refuses the unit, so R3 must never fire either way.
    pub(crate) has_shared_return: bool,

    /// Slot arena for this function.
    pub(crate) slots: Vec<LocalSlot>,
    /// Lexical scopes: name → slot index.
    pub(crate) scopes: Vec<FxHashMap<String, usize>>,
    /// Unassigned/maybe reads seen in the current statement:
    /// (slot, read span).
    pub(crate) pending: Vec<(usize, Span)>,
    /// Already-reported §6 violations, to avoid duplicates.
    pub(crate) flagged: Vec<(usize, Span)>,
    /// Encrypted-branch nesting depth (0 = straight-line code).
    pub(crate) branch_depth: u32,
    /// Per open encrypted branch: encrypted slots written (first write span).
    pub(crate) branch_writes: Vec<FxHashMap<usize, Span>>,
    /// Per open encrypted branch: encrypted slots read before definite
    /// assignment (first read span). Such a read makes the branch merge need
    /// the target's incoming value even if the branch later assigns it.
    pub(crate) branch_unassigned_reads: Vec<FxHashMap<usize, Span>>,
    /// The span of the statement currently being walked (facts anchor on it).
    pub(crate) current_stmt_span: Span,
    /// The span of the `precondition` block currently being walked, if any.
    /// A local whose declaration lies inside it does not escape the block, so
    /// it is the one thing §2.7 lets the block write (see
    /// [`FnChecker::check_precondition_block`]).
    pub(crate) pre_span: Option<Span>,
    /// Encrypted named-return slots for this function: (slot index,
    /// declaration span). Populated once in [`FnChecker::run`]; consulted at
    /// every function exit point (spec §6).
    pub(crate) named_returns: Vec<(usize, Span)>,
    /// Whether the straight-line path currently being walked has already
    /// diverted away — `return`/`revert`/a builtin halt end the function;
    /// `break`/`continue` end the current loop iteration. Either way, code
    /// walked after this point in the same block is unreachable. Loop
    /// exits (`break`/`continue`) feed their state back into the enclosing
    /// loop via [`loop_breaks`](Self::loop_breaks) /
    /// [`loop_continues`](Self::loop_continues) instead of being lost, so
    /// only `return`/`revert`/a halt ever escape a loop's own handling
    /// still set. Conservative elsewhere: loops and `try` reset this back
    /// to the pre-statement value rather than proving termination, so it
    /// never claims a path terminates unless a `return`/`revert`/halt sits
    /// directly on it.
    pub(crate) terminated: bool,
    /// Stack of open loops; each frame holds the definite-assignment
    /// snapshot captured at every `break` reached inside that loop (spec
    /// §6: a `break` exits the loop with whatever was assigned up to that
    /// point, not with the state at the end of the loop body).
    pub(crate) loop_breaks: Vec<Vec<Vec<AState>>>,
    /// Stack of open loops; each frame holds the definite-assignment
    /// snapshot captured at every `continue` reached inside that loop.
    /// Unlike `break`, `continue` does not exit the loop — but the
    /// condition (`while`/`for`) or the trailing condition (`do`/`while`)
    /// is re-checked right after it and may end the loop there, so a
    /// `continue` point is just as much a loop-exit candidate as a
    /// `break` point or the body's own normal fallthrough (spec §6).
    pub(crate) loop_continues: Vec<Vec<Vec<AState>>>,
}

impl<'a, 'ast> FnChecker<'a, 'ast> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        unit: &'a BoundUnit<'ast>,
        trust: &'a Trust,
        profile: &'a dyn TargetProfile,
        sm: &'a SourceMap,
        out: &'a mut CheckedUnit,
        safe_cache: &'a mut FxHashMap<FunctionId, bool>,
        fid: FunctionId,
    ) -> Self {
        let f = unit.function(fid);
        let mutability = f.ast.header.state_mutability();
        let visibility = f.ast.header.visibility();
        FnChecker {
            unit,
            trust,
            profile,
            sm,
            out,
            safe_cache,
            fid,
            file: f.file,
            contract: f.contract,
            is_view_or_pure: matches!(
                mutability,
                ast::StateMutability::View | ast::StateMutability::Pure
            ),
            is_public_or_external: matches!(
                visibility,
                Some(ast::Visibility::Public) | Some(ast::Visibility::External)
            ),
            in_library: f
                .contract
                .is_some_and(|c| unit.contract(c).kind == ast::ContractKind::Library),
            has_shared_return: crate::shared::declares_shared_return(f.ast),
            slots: Vec::new(),
            scopes: vec![FxHashMap::default()],
            pending: Vec::new(),
            flagged: Vec::new(),
            branch_depth: 0,
            branch_writes: Vec::new(),
            branch_unassigned_reads: Vec::new(),
            current_stmt_span: Span::DUMMY,
            pre_span: None,
            named_returns: Vec::new(),
            terminated: false,
            loop_breaks: Vec::new(),
            loop_continues: Vec::new(),
        }
    }

    pub(crate) fn run(mut self) {
        let f = self.unit.function(self.fid);
        // Parameters: tracked as assigned (encrypted params are always
        // initialized by the caller / the sugar expansion).
        for &p in &f.params {
            let v = self.unit.var(p);
            let ty = declared_ty(self.unit, self.trust, &v.decl.ty);
            if let Some(name) = v.name {
                self.declare_slot(name.as_str().to_string(), ty.etype(), AState::Assigned);
            }
        }
        // Named returns behave as locals that start unassigned (spec §6).
        //
        // Known gap, pre-existing and not specific to named returns:
        // `declared_ty` (crates/fhec-check/src/decl.rs) types every
        // qualified path (`Lib.Type`, any `segments.len() != 1`) as
        // `Unknown`, by deliberate design across the whole checker (spec
        // §3.2: `Unknown` is silent everywhere, not conservatively
        // flagged). A named return declared via a qualified path to an
        // encrypted type (e.g. `returns (Fhe.euint64 r)`) therefore never
        // reaches `named_returns` at all — this exit-point check silently
        // does not apply to it, exactly like every other checker pass that
        // reads a qualified type. Fixing this only for named-return
        // registration would leave the rest of the checker (operators,
        // ACL, assignment tracking on that same variable) still blind to
        // it, which is inconsistent; a real fix belongs in `declared_ty`
        // itself and is out of scope here. Unqualified encrypted-type names
        // (`euint64`, `ebool`, ...) are how every real CoFHE Solidity
        // program spells these types, so this is expected to be rare.
        for &r in &f.returns {
            let v = self.unit.var(r);
            let ty = declared_ty(self.unit, self.trust, &v.decl.ty);
            if let Some(name) = v.name {
                let etype = ty.etype();
                let idx = self.declare_slot(name.as_str().to_string(), etype, AState::Unassigned);
                if etype.is_some() {
                    self.named_returns.push((idx, v.decl.span));
                }
            }
        }
        if !self.named_returns.is_empty() {
            // A modifier attached to this function that can `return;`
            // before its `_;` placeholder skips the function body entirely
            // on that path: whatever the body would have assigned never
            // runs. Detected conservatively and unconditionally (regardless
            // of what the body itself does below) — issue #82's hazard
            // class again, just crossing a modifier boundary instead of a
            // callee boundary.
            if self.has_risky_modifier() {
                self.flag_all_named_returns(
                    "a modifier attached to this function may skip its `_;` \
                     placeholder on some path — by returning before it, or by \
                     falling off the end without ever reaching it — which skips \
                     the function body on that path; this encrypted named \
                     return would then cross the call boundary unassigned, the \
                     same CoFHE default-ciphertext hazard as an unassigned \
                     encrypted variable",
                );
            }
            // This analysis does not parse Yul: an inline-assembly block
            // may `return`/`stop`/`revert` and exit the function right
            // there, which would make code textually after it (that would
            // otherwise assign a named return) unreachable — but nothing
            // here can tell. Rather than modeling Yul control flow,
            // conservatively fail closed whenever the body contains
            // inline assembly anywhere (spec §1.3).
            if f.ast.body.as_ref().is_some_and(contains_assembly) {
                self.flag_all_named_returns(
                    "this function contains inline assembly, whose control flow this \
                     checker does not analyze; an assembly `return`/`stop`/`revert` \
                     could exit before code that would otherwise assign this \
                     encrypted named return runs, so it is conservatively flagged \
                     rather than trusted",
                );
            }
        }
        let Some(body) = &f.ast.body else { return };
        self.walk_block(body);
        // Implicit return at the closing brace: unreachable only if the
        // body's last straight-line statement was itself a terminator.
        if !self.terminated {
            self.check_named_returns_unassigned();
        }
    }

    /// Unconditionally flags every encrypted named return of this function
    /// with `message`, for a hazard this analysis cannot rule out just by
    /// examining the body's own control flow (an unanalyzable modifier or
    /// inline assembly). Idempotent: already-flagged slots are skipped.
    fn flag_all_named_returns(&mut self, message: &str) {
        for &(slot, decl_span) in &self.named_returns.clone() {
            if !self.flagged.contains(&(slot, decl_span)) {
                self.flagged.push((slot, decl_span));
                self.out.diagnostics.push(
                    Diagnostic::error(
                        codes::POSSIBLY_UNINITIALIZED,
                        decl_span,
                        message.to_string(),
                    )
                    .with_rule("§6"),
                );
            }
        }
    }

    /// Whether any modifier invoked by this function may skip its `_;`
    /// placeholder on some path (see [`modifier_may_skip_body`]).
    ///
    /// Fails closed: a modifier name this analysis cannot resolve to a
    /// walkable, in-unit modifier body — unresolved, a qualified/external
    /// name, an overload candidate that turns out not to be a modifier, or
    /// one with no body to walk — is treated as risky too, exactly like an
    /// analyzed modifier that turns out to be risky. An existentially risky
    /// (or unanalyzable) candidate is enough to flag (spec §1.3: when in
    /// doubt, reject) — this is deliberately the same conservative
    /// direction as every other "cannot prove it's safe" case in this
    /// analysis, even though it means an external modifier (e.g. an
    /// imported `nonReentrant`) makes this fire unconditionally.
    fn has_risky_modifier(&self) -> bool {
        let f = self.unit.function(self.fid);
        f.ast.header.modifiers.iter().any(|m| {
            let Some(seg) = m.name.segments().first() else {
                // A malformed path has nothing to resolve either — fail
                // closed rather than assume it's safe.
                return true;
            };
            let Some(Resolution::Function(fids)) = self.unit.resolve_span(seg.span) else {
                // Anything this binder resolution cannot hand back as an
                // in-unit function/modifier candidate set — unresolved, a
                // qualified/external name, a base contract outside the
                // unit, or any other resolution kind — is not analyzable.
                return true;
            };
            fids.iter().any(|&fid| {
                let mf = self.unit.function(fid);
                // A resolved candidate that isn't a modifier at all, or has
                // no body in this unit to walk (e.g. an abstract/virtual
                // declaration without an implementation here), is equally
                // unanalyzable — fail closed rather than trust it.
                mf.ast.kind != ast::FunctionKind::Modifier
                    || match &mf.ast.body {
                        Some(body) => modifier_may_skip_body(body),
                        None => true,
                    }
            })
        })
    }

    // ---- slot machinery ------------------------------------------------

    pub(crate) fn declare_slot(
        &mut self,
        name: String,
        encrypted: Option<EType>,
        state: AState,
    ) -> usize {
        let idx = self.slots.len();
        self.slots.push(LocalSlot {
            encrypted,
            state,
            decl_depth: self.branch_depth,
        });
        self.scopes
            .last_mut()
            .expect("scope stack is never empty")
            .insert(name, idx);
        idx
    }

    /// Innermost slot for `name`, if any.
    pub(crate) fn slot_of(&self, name: &str) -> Option<usize> {
        self.scopes.iter().rev().find_map(|s| s.get(name).copied())
    }

    pub(crate) fn snapshot(&self) -> Vec<AState> {
        self.slots.iter().map(|s| s.state).collect()
    }

    pub(crate) fn restore(&mut self, snap: &[AState]) {
        for (i, st) in snap.iter().enumerate() {
            self.slots[i].state = *st;
        }
    }

    pub(crate) fn join_into(&mut self, snap: &[AState]) {
        for (i, st) in snap.iter().enumerate() {
            self.slots[i].state = AState::join(self.slots[i].state, *st);
        }
    }

    /// Restores `self.slots` to the join (meet) of every given exit-state
    /// candidate — the states definite-assignment sees at a point every
    /// candidate can reach. An arm/clause/loop-exit that cannot actually
    /// reach the join point (it terminates via `return`/`revert`, or a loop
    /// never runs zero times) must be excluded from `candidates` by the
    /// caller; its state must not pollute the join. Empty `candidates` means
    /// nothing reaches this point — state is moot, and the caller is
    /// expected to also mark `self.terminated`.
    pub(crate) fn join_all(&mut self, candidates: &[&[AState]]) {
        let mut iter = candidates.iter();
        if let Some(first) = iter.next() {
            self.restore(first);
            for c in iter {
                self.join_into(c);
            }
        }
    }

    /// Records an unassigned/maybe read of a tracked encrypted slot.
    pub(crate) fn note_read(&mut self, name: &str, span: Span) {
        if let Some(idx) = self.slot_of(name) {
            let slot = &self.slots[idx];
            if slot.encrypted.is_some() && slot.state != AState::Assigned {
                self.pending.push((idx, span));
                if self.branch_depth > 0 && slot.decl_depth < self.branch_depth {
                    if let Some(log) = self.branch_unassigned_reads.last_mut() {
                        log.entry(idx).or_insert(span);
                    }
                }
            }
        }
    }

    /// Marks a direct assignment to a named slot; returns the slot index.
    pub(crate) fn note_assign(&mut self, name: &str, span: Span) -> Option<usize> {
        let idx = self.slot_of(name)?;
        if self.slots[idx].encrypted.is_some() {
            if self.branch_depth > 0 && self.slots[idx].decl_depth < self.branch_depth {
                // A merge write of the enclosing encrypted if (spec §5.2):
                // logged; the pre-value check happens when the branch closes.
                if let Some(log) = self.branch_writes.last_mut() {
                    log.entry(idx).or_insert(span);
                }
            }
            self.slots[idx].state = AState::Assigned;
        }
        Some(idx)
    }

    /// Emits FHE2007 for pending unassigned reads inside `within`.
    pub(crate) fn flag_uninit_in(&mut self, within: Span, context: &str) {
        let mut i = 0;
        while i < self.pending.len() {
            let (slot, span) = self.pending[i];
            if span_within(span, within) {
                self.pending.remove(i);
                if !self.flagged.contains(&(slot, span)) {
                    self.flagged.push((slot, span));
                    self.out.diagnostics.push(
                        Diagnostic::error(
                            codes::POSSIBLY_UNINITIALIZED,
                            span,
                            format!(
                                "possibly uninitialized encrypted variable used {context}; \
                                 CoFHE silently substitutes a default ciphertext for \
                                 uninitialized handles"
                            ),
                        )
                        .with_rule("§6"),
                    );
                }
            } else {
                i += 1;
            }
        }
    }

    /// Emits FHE2007 for every encrypted named return not definitely
    /// assigned at the current point: a bare `return;` or the function's
    /// implicit exit at the closing brace both hand the caller whatever is
    /// currently in the named-return slots (spec §6). An explicit
    /// `return expr;` supplies the returned values directly instead and is
    /// checked at its own use site (see the `Return(Some(e))` handling),
    /// so it does not call this.
    pub(crate) fn check_named_returns_unassigned(&mut self) {
        for &(slot, decl_span) in &self.named_returns {
            if self.slots[slot].state != AState::Assigned
                && !self.flagged.contains(&(slot, decl_span))
            {
                self.flagged.push((slot, decl_span));
                self.out.diagnostics.push(
                    Diagnostic::error(
                        codes::POSSIBLY_UNINITIALIZED,
                        decl_span,
                        "this encrypted named return is not assigned on every path \
                         reaching `return` or the end of the function; CoFHE silently \
                         substitutes a default ciphertext for uninitialized handles, and \
                         that handle crosses the call boundary to the caller",
                    )
                    .with_rule("§6"),
                );
            }
        }
    }

    /// Whether typing `rhs` left a not-yet-flagged "possibly uninitialized
    /// encrypted read" marker anywhere within its span in [`Self::pending`]
    /// — a bare reference to an unassigned tracked local/parameter/named-
    /// return, or an unassigned arm reachable through a ternary/short-
    /// circuit join. Used, by both assignment (`r = x;`, `(r, y) = (x,
    /// z);`) and declaration-initializer handling, to propagate an
    /// uninitialized handle through a copy instead of unconditionally
    /// marking the copy's target assigned (spec §6; issue #82's hazard
    /// class, one function-local hop earlier).
    ///
    /// A read-only peek: unlike [`Self::flag_uninit_in`], this never
    /// consumes the marker or emits a diagnostic on its own — whatever
    /// later actually uses the copy (a return, an operand, the function's
    /// exit check) is where the real diagnostic belongs, correctly
    /// targeted. Callers MUST evaluate this before performing the copy's
    /// own write: the write does not touch `pending`, but if the RHS is a
    /// self-copy (`r = r;`) sharing the target's own slot, reading current
    /// slot *state* after the write would just see the write's own fresh
    /// value — checking `pending` (populated once, at type time, before
    /// any write) instead of slot state sidesteps that ordering hazard.
    pub(crate) fn rhs_is_unassigned(&self, rhs: &'ast ast::Expr<'ast>) -> bool {
        self.pending
            .iter()
            .any(|&(_, span)| span_within(span, rhs.span))
    }

    pub(crate) fn error(&mut self, code: &'static str, span: Span, msg: impl Into<String>) {
        self.out
            .diagnostics
            .push(Diagnostic::error(code, span, msg));
    }

    /// A rewrite site was created here: reject in `view`/`pure` (spec §3.4).
    pub(crate) fn note_site(&mut self, span: Span) {
        if self.is_view_or_pure {
            self.out.diagnostics.push(
                Diagnostic::error(
                    codes::FHE_IN_VIEW_OR_PURE,
                    span,
                    "this expression lowers to an FHE library operation, which cannot \
                     execute in a `view`/`pure` function",
                )
                .with_rule("§3.4"),
            );
        }
    }

    // ---- statements ----------------------------------------------------

    pub(crate) fn walk_block(&mut self, block: &'ast ast::Block<'ast>) {
        self.scopes.push(FxHashMap::default());
        for s in block.stmts.iter() {
            // Once a statement in this block has unconditionally terminated
            // (`return`/`revert`/`break`/`continue`), everything after it is
            // unreachable dead code and must not be walked as if it runs.
            if self.terminated {
                break;
            }
            self.walk_stmt(s);
        }
        self.scopes.pop();
    }

    fn in_branch(&self) -> bool {
        self.branch_depth > 0
    }

    /// Whether `e` is a call to the builtin `revert(...)`/`revert()` or
    /// `selfdestruct(...)` — both unconditionally halt execution, unlike
    /// `require`/`assert`, which only halt when their condition is false.
    /// The `revert Error(...);` *statement* form (spec-distinct from this
    /// call form) is handled separately, in the `Revert` statement arm.
    /// Mirrors the callee resolution in `exprs::call`, but only needs the
    /// name, not a type.
    fn expr_is_unconditional_halt(&self, e: &'ast ast::Expr<'ast>) -> bool {
        let ast::ExprKind::Call(c, _) = &e.peel_parens().kind else {
            return false;
        };
        let mut callee = c.peel_parens();
        while let ast::ExprKind::CallOptions(inner, _) = &callee.kind {
            callee = inner.peel_parens();
        }
        let ast::ExprKind::Ident(id) = &callee.kind else {
            return false;
        };
        matches!(
            self.unit.resolve(*id),
            Some(Resolution::Builtin(Builtin("revert" | "selfdestruct")))
        )
    }

    pub(crate) fn walk_stmt(&mut self, s: &'ast ast::Stmt<'ast>) {
        use ast::StmtKind::*;
        self.pending.clear();
        self.current_stmt_span = s.span;
        match &s.kind {
            DeclSingle(v) => self.decl_single(v),
            DeclMulti(vars, rhs) => {
                self.type_expr(rhs);
                // When `rhs` is itself an explicit tuple literal of the
                // same shape (`(euint64 y, euint64 z) = (x, b);`), pair
                // each declared component with its RHS element so an
                // unassigned one propagates instead of unconditionally
                // becoming Assigned (spec §6) — same technique as
                // `assign_tuple_lvalues`. A call-returning-tuple RHS (`(y,
                // z) = f();`) has no per-component identity to inspect
                // here; that hazard is caught at the callee's own exit
                // points instead.
                let rels = match &rhs.peel_parens().kind {
                    ast::ExprKind::Tuple(rels) if rels.len() == vars.len() => Some(rels),
                    _ => None,
                };
                for (i, v) in vars.iter().enumerate() {
                    if let Some(v) = v.as_ref().unspan() {
                        let rel = rels
                            .and_then(|rels| rels[i].as_ref().unspan())
                            .map(|e| &**e);
                        let decl = declared_ty(self.unit, self.trust, &v.ty);
                        let assigned = !(matches!(decl, Ty::Encrypted(_))
                            && rel.is_some_and(|r| self.rhs_is_unassigned(r)));
                        self.decl_var(v, assigned);
                    }
                }
            }
            Block(b) | UncheckedBlock(b) => self.walk_block(b),
            // A `precondition` block is a plaintext guard with its own,
            // stricter rules (spec §2.7); its scope does not escape.
            Precondition(b) => self.check_precondition_block(b),
            Break => {
                if self.in_branch() {
                    self.error(
                        codes::BREAK_CONTINUE_IN_BRANCH,
                        s.span,
                        "`break`/`continue` cannot appear inside an encrypted branch: \
                         both branches always execute (restructure the loop body)",
                    );
                } else {
                    // Exits the loop right here, with whatever is assigned
                    // up to this point — not with the state at the end of
                    // the loop body (spec §6).
                    let snap = self.snapshot();
                    if let Some(top) = self.loop_breaks.last_mut() {
                        top.push(snap);
                    }
                }
                self.terminated = true;
            }
            Continue => {
                if self.in_branch() {
                    self.error(
                        codes::BREAK_CONTINUE_IN_BRANCH,
                        s.span,
                        "`break`/`continue` cannot appear inside an encrypted branch: \
                         both branches always execute (restructure the loop body)",
                    );
                } else {
                    // Jumps back to the loop's own condition re-check,
                    // which may end the loop right there: a `continue`
                    // point is a loop-exit candidate too, just like a
                    // `break` point (spec §6).
                    let snap = self.snapshot();
                    if let Some(top) = self.loop_continues.last_mut() {
                        top.push(snap);
                    }
                }
                // Nothing after it in this block runs this iteration.
                self.terminated = true;
            }
            Placeholder => {}
            Expr(e) => {
                self.type_root_expr(e);
                // `revert(...)`/`selfdestruct(...)` as a builtin *call*
                // (spec-distinct from the `revert Error(...);` statement
                // form below) unconditionally halts execution too.
                if self.expr_is_unconditional_halt(e) {
                    self.terminated = true;
                }
            }
            If(cond, then, els) => self.if_stmt(s, cond, then, els.as_deref()),
            While(cond, body) => {
                if self.in_branch() {
                    self.error(
                        codes::PLAINTEXT_FLOW_IN_BRANCH,
                        s.span,
                        "plaintext control flow inside an encrypted branch is not \
                         supported in v1 (hoist or flatten)",
                    );
                }
                let ty = self.type_expr(cond);
                self.reject_encrypted_loop(&ty, cond.span);
                // Zero-trip candidate: the condition can be false on entry,
                // so the body (and any `break`/`continue` inside it) may
                // never run.
                let snap = self.snapshot();
                let pre_terminated = self.terminated;
                self.loop_breaks.push(Vec::new());
                self.loop_continues.push(Vec::new());
                self.walk_stmt(body);
                let body_terminated = self.terminated;
                let body_states = self.snapshot();
                let breaks = self.loop_breaks.pop().unwrap_or_default();
                let continues = self.loop_continues.pop().unwrap_or_default();
                let mut candidates: Vec<&[AState]> = vec![&snap];
                // A body that always terminates (return/revert/break/
                // continue on every path) never falls through to re-check
                // the condition, so its end state does not reach after the
                // loop; each `break`/`continue` point is its own, separate
                // candidate (a `continue` re-checks the condition right
                // there, which may end the loop with exactly that state).
                if !body_terminated {
                    candidates.push(&body_states);
                }
                for b in breaks.iter().chain(continues.iter()) {
                    candidates.push(b);
                }
                self.join_all(&candidates);
                // The zero-trip candidate is always present, so the loop's
                // own control flow never terminates the function on its own
                // (§1.3: when in doubt, keep checking code after the loop).
                self.terminated = pre_terminated;
            }
            DoWhile(body, cond) => {
                if self.in_branch() {
                    self.error(
                        codes::PLAINTEXT_FLOW_IN_BRANCH,
                        s.span,
                        "plaintext control flow inside an encrypted branch is not \
                         supported in v1 (hoist or flatten)",
                    );
                }
                let pre_terminated = self.terminated;
                self.loop_breaks.push(Vec::new());
                self.loop_continues.push(Vec::new());
                self.walk_stmt(body);
                let body_terminated = self.terminated;
                let body_states = self.snapshot();
                let breaks = self.loop_breaks.pop().unwrap_or_default();
                let continues = self.loop_continues.pop().unwrap_or_default();
                self.pending.clear();
                self.current_stmt_span = s.span;
                let ty = self.type_expr(cond);
                self.reject_encrypted_loop(&ty, cond.span);

                // Unlike `while`/`for`, a `do` body always runs at least
                // once: there is no zero-trip candidate. The only ways out
                // are falling through the body normally (if it doesn't
                // always terminate first), each `break` point, and each
                // `continue` point (its re-check of `cond` may end the
                // loop with exactly that state — a `continue` here is just
                // as much an exit candidate as a `break`).
                let mut candidates: Vec<&[AState]> = Vec::new();
                if !body_terminated {
                    candidates.push(&body_states);
                }
                for b in breaks.iter().chain(continues.iter()) {
                    candidates.push(b);
                }
                // If nothing reaches the loop's own exit (every avenue
                // through the body terminates, with no `break`/`continue`
                // escaping it), the `do`/`while` itself always terminates
                // the function.
                self.terminated = pre_terminated || candidates.is_empty();
                self.join_all(&candidates);
            }
            For {
                init,
                cond,
                next,
                body,
            } => {
                if self.in_branch() {
                    self.error(
                        codes::PLAINTEXT_FLOW_IN_BRANCH,
                        s.span,
                        "plaintext control flow inside an encrypted branch is not \
                         supported in v1 (hoist or flatten)",
                    );
                }
                self.scopes.push(FxHashMap::default());
                if let Some(init) = init {
                    self.walk_stmt(init);
                }
                self.pending.clear();
                if let Some(cond) = cond {
                    let ty = self.type_expr(cond);
                    self.reject_encrypted_loop(&ty, cond.span);
                }
                // Zero-trip candidate: `init` and one (possibly failing)
                // `cond` check ran, but neither the body nor `next` did.
                // Captured before typing `next`, which — in real Solidity
                // semantics — only ever runs after a body iteration, never
                // on a `cond` check that fails immediately.
                let snap = self.snapshot();
                let pre_terminated = self.terminated;
                self.loop_breaks.push(Vec::new());
                self.loop_continues.push(Vec::new());
                self.walk_stmt(body);
                let body_terminated = self.terminated;
                // `next` runs after a body iteration that falls through to
                // it; a `break`/`return` inside the body skips it. A
                // `continue` also runs `next` before `cond` is re-checked in
                // real Solidity semantics — this typing (and its assignment
                // effects) is not separately re-applied to each individual
                // `continue` candidate captured below, only ever computed
                // once, here: a narrow, safe-direction precision gap for
                // THOSE candidates' own values (spec §1.3). This is over-
                // strict, not a miss, ONLY when `!body_terminated` (the
                // plain-fallthrough state typed below already includes
                // whatever `next` assigns, and every `continue` candidate
                // stays a subset of that): once `body_terminated` forces the
                // join-of-continues fallback below, the direction is no
                // longer guaranteed one-sided — see that fallback's own
                // comment for the case it exists to fix.
                //
                // But `next` must still be visited at least once whenever a
                // `continue` can reach it — i.e. whenever this loop's
                // `continue` list (captured while walking `body` above) is
                // non-empty — even when `body_terminated` (every body path
                // takes `continue`/`break`/`return`, so the plain-
                // fallthrough branch below never runs). Otherwise `next`'s
                // own diagnostics (an uninitialized encrypted read inside
                // it, or an encrypted loop-control expression) go
                // completely unchecked on every path through this loop, a
                // real miss rather than merely the over-strict gap above
                // (issue #90, gap 2). Peeked from the still-open frame
                // before it's popped below; typed exactly once, in a single
                // `if`, so `next`'s own diagnostics never fire twice even
                // when both conditions hold at once.
                let next_reachable = !body_terminated
                    || self
                        .loop_continues
                        .last()
                        .is_some_and(|frame| !frame.is_empty());
                if next_reachable {
                    if let Some(next) = next {
                        // When `body_terminated`, `self.slots` right now
                        // holds whatever the LAST body path walked left
                        // behind (e.g. one arm of an `if`/`else` where every
                        // arm terminates) — not a state any path that
                        // actually reaches `next` produces. The only paths
                        // that reach `next` here are the `continue` points
                        // captured while walking `body` above (a plain
                        // fallthrough is impossible when `body_terminated`,
                        // and `break` never runs `next`), so restore to
                        // their join before typing `next`, then restore
                        // back so `body_states`/`breaks`/`continues` below
                        // are unaffected. Round-2 review of issue #90: typing
                        // `next` against the wrong leftover state produced
                        // both a false positive (a slot the reached-via-
                        // `continue` path actually assigned, but the
                        // untaken arm left unassigned) and a mirror miss
                        // (the reverse — assigned in the untaken arm,
                        // unassigned on the actual `continue` path).
                        let restore_after = if body_terminated {
                            let pre_next = self.snapshot();
                            // Cloned (not borrowed) so `join_all`'s `&mut
                            // self` below doesn't conflict with a borrow of
                            // `self.loop_continues`.
                            let frame = self.loop_continues.last().cloned().unwrap_or_default();
                            let refs: Vec<&[AState]> = frame.iter().map(Vec::as_slice).collect();
                            self.join_all(&refs);
                            Some(pre_next)
                        } else {
                            None
                        };
                        let ty = self.type_expr(next);
                        self.reject_encrypted_loop(&ty, next.span);
                        if let Some(pre_next) = restore_after {
                            self.restore(&pre_next);
                        }
                    }
                }
                // `body_states` is snapshotted AFTER the `next_reachable`
                // typing above, so when `!body_terminated` it correctly
                // includes whatever `next` just assigned — unchanged from
                // before. When `body_terminated` is true, `body_states` is
                // still excluded from `candidates` below exactly as before:
                // the newly-added `next_reachable` typing above runs purely
                // for `next`'s own diagnostics and `pending`-marker side
                // effects in that case, not to manufacture a fallthrough
                // candidate that cannot really occur (every body path
                // terminated, so control never reaches a plain "ran the
                // body, now falls through to `next`" point at all — only
                // each individual `continue`/`break` candidate below does,
                // and those keep their own pre-`next` snapshot per the
                // precision-gap note above).
                let body_states = self.snapshot();
                let breaks = self.loop_breaks.pop().unwrap_or_default();
                let continues = self.loop_continues.pop().unwrap_or_default();
                let mut candidates: Vec<&[AState]> = vec![&snap];
                if !body_terminated {
                    candidates.push(&body_states);
                }
                for b in breaks.iter().chain(continues.iter()) {
                    candidates.push(b);
                }
                self.join_all(&candidates);
                // Same rationale as `while` above.
                self.terminated = pre_terminated;
                self.scopes.pop();
            }
            Return(e) => {
                if self.in_branch() {
                    self.error(
                        codes::RETURN_IN_BRANCH,
                        s.span,
                        "`return` cannot appear inside an encrypted branch: both \
                         branches always execute (assign to a local and return after \
                         the `if`)",
                    );
                }
                if let Some(e) = e {
                    let ty = self.type_expr(e);
                    self.flag_uninit_in(e.span, "as a return value");
                    if let Ty::Encrypted(t) = ty {
                        if !self.in_branch() && !self.has_shared_return {
                            let fact = EncryptedReturn {
                                stmt_span: s.span,
                                expr_span: e.span,
                                value_ty: t,
                                is_public_or_external: self.is_public_or_external,
                                is_view_or_pure: self.is_view_or_pure,
                                in_library: self.in_library,
                                function: self.fid,
                                file: self.file,
                            };
                            self.out.acl.returns.push(fact);
                        }
                    }
                } else if !self.in_branch() {
                    // A bare `return;` hands the caller whatever is
                    // currently in the named-return slots.
                    self.check_named_returns_unassigned();
                }
                self.terminated = true;
            }
            Revert(_path, args) => {
                if self.in_branch() {
                    self.error(
                        codes::REVERT_IN_BRANCH,
                        s.span,
                        "`revert` cannot appear inside an encrypted branch: encrypted \
                         conditions cannot revert (guard with a plaintext condition \
                         before the `if`, or encode failure in state)",
                    );
                }
                for a in args.exprs() {
                    self.type_expr(a);
                }
                self.terminated = true;
            }
            Emit(_path, args) => {
                if self.in_branch() {
                    self.error(
                        codes::EMIT_IN_BRANCH,
                        s.span,
                        "`emit` cannot appear inside an encrypted branch: events are \
                         public and emitting per-branch leaks the condition",
                    );
                }
                for a in args.exprs() {
                    self.type_expr(a);
                }
            }
            Assembly(_) => {
                if self.in_branch() {
                    self.error(
                        codes::ASSEMBLY_IN_BRANCH,
                        s.span,
                        "inline assembly cannot appear inside an encrypted branch",
                    );
                }
                // The Yul block itself is not walked, so an assignment to a
                // named return inside inline assembly is invisible to this
                // analysis: the slot stays (possibly wrongly) `Unassigned`.
                // Safe-direction (over-strict, not a miss) — documented
                // limitation, not a soundness gap.
            }
            Try(t) => {
                if self.in_branch() {
                    self.error(
                        codes::PLAINTEXT_FLOW_IN_BRANCH,
                        s.span,
                        "`try` inside an encrypted branch is not supported \
                         (it is plaintext control flow and an external call)",
                    );
                }
                self.type_expr(&*t.expr);
                let snap = self.snapshot();
                let pre_terminated = self.terminated;
                let mut outs: Vec<Vec<AState>> = Vec::new();
                for clause in t.clauses.iter() {
                    self.restore(&snap);
                    self.terminated = pre_terminated;
                    self.scopes.push(FxHashMap::default());
                    for v in clause.args.vars.iter() {
                        self.decl_var(v, true);
                    }
                    self.walk_block(&clause.block);
                    self.scopes.pop();
                    // A clause that always returns/reverts never reaches the
                    // point after the `try`; its (possibly unassigned) state
                    // must not pollute the join for the clauses that do.
                    if !self.terminated {
                        outs.push(self.snapshot());
                    }
                }
                // Join only the clauses that can actually reach here — not
                // the pre-`try` state: an uncaught revert from the call
                // itself doesn't return named values at all, so that state
                // is never a valid join candidate either.
                self.join_all(&outs.iter().map(Vec::as_slice).collect::<Vec<_>>());
                // If every clause terminates, the `try` as a whole does too.
                self.terminated = pre_terminated || outs.is_empty();
            }
        }
        self.pending.clear();
    }

    fn reject_encrypted_loop(&mut self, ty: &Ty, span: Span) {
        if ty.is_encrypted() {
            self.error(
                codes::ENCRYPTED_LOOP,
                span,
                "loops with encrypted conditions or loop-control expressions are not \
                 expressible: the trip count would leak the ciphertext (spec §5.6)",
            );
        }
    }

    fn decl_single(&mut self, v: &'ast ast::VariableDefinition<'ast>) {
        if v.in_sugar.is_some() {
            self.error(
                codes::IN_SUGAR_BAD_POSITION,
                v.span,
                "the `in` encrypted-input sugar is only permitted in function and \
                 constructor parameter lists",
            );
        }
        // Typed before decl_var: an initializer executes before the
        // variable exists, and shadowing within it via the same name is
        // illegal Solidity anyway — but typing it first also lets a copy
        // from an unassigned encrypted expression (`euint64 y = x;`)
        // propagate that status to `y`, instead of unconditionally
        // becoming Assigned (spec §6; issue #82's hazard class).
        let decl = declared_ty(self.unit, self.trust, &v.ty);
        let init_ty = v.initializer.as_ref().map(|init| self.type_expr(init));
        let assigned = match (&v.initializer, &init_ty) {
            (Some(init), Some(_)) => {
                !(matches!(decl, Ty::Encrypted(_)) && self.rhs_is_unassigned(init))
            }
            _ => false,
        };
        self.decl_var(v, assigned);
        if let (Some(init), Some(init_ty)) = (&v.initializer, &init_ty) {
            if decl == Ty::Plain(PlainTy::Bool) && *init_ty == Ty::Encrypted(EType::Ebool) {
                self.error(
                    codes::EBOOL_AS_BOOL,
                    init.span,
                    "`ebool` cannot initialize a plaintext `bool`; decryption is an \
                     explicit asynchronous operation",
                );
            }
        }
    }

    pub(crate) fn decl_var(&mut self, v: &'ast ast::VariableDefinition<'ast>, assigned: bool) {
        let ty = declared_ty(self.unit, self.trust, &v.ty);
        if let Some(name) = v.name {
            self.out.types.record(name.span, ty.clone());
            self.declare_slot(
                name.as_str().to_string(),
                ty.etype(),
                if assigned {
                    AState::Assigned
                } else {
                    AState::Unassigned
                },
            );
        }
    }

    fn if_stmt(
        &mut self,
        s: &'ast ast::Stmt<'ast>,
        cond: &'ast ast::Expr<'ast>,
        then: &'ast ast::Stmt<'ast>,
        els: Option<&'ast ast::Stmt<'ast>>,
    ) {
        let cond_ty = self.type_expr(cond);
        match cond_ty {
            Ty::Encrypted(EType::Ebool) => {
                self.flag_uninit_in(cond.span, "as an encrypted `if` condition");
                let site = EncryptedIfSite {
                    span: s.span,
                    cond_span: cond.span,
                    then_span: then.span,
                    else_span: els.map(|e| e.span),
                    depth: self.branch_depth,
                    function: self.fid,
                    file: self.file,
                };
                self.note_site(s.span);
                self.out.if_sites.push(site);

                let snap = self.snapshot();
                let pre_terminated = self.terminated;
                self.branch_depth += 1;
                self.branch_writes.push(FxHashMap::default());
                self.branch_unassigned_reads.push(FxHashMap::default());

                self.walk_stmt(then);
                let then_states = self.snapshot();
                let then_writes = self.branch_writes.pop().unwrap_or_default();
                let then_unassigned_reads = self.branch_unassigned_reads.pop().unwrap_or_default();
                self.restore(&snap);
                self.branch_writes.push(FxHashMap::default());
                self.branch_unassigned_reads.push(FxHashMap::default());
                if let Some(els) = els {
                    self.walk_stmt(els);
                }
                let else_states = self.snapshot();
                let else_writes = self.branch_writes.pop().unwrap_or_default();
                let else_unassigned_reads = self.branch_unassigned_reads.pop().unwrap_or_default();

                self.branch_depth -= 1;

                // A merge needs a pre-value unless both branch environments
                // independently produce the location without first reading its
                // unassigned incoming value. Keep one deterministic write
                // span per slot for diagnostics and outer-branch propagation.
                // Iterated (not moved/consumed): `then_writes`/`else_writes`
                // are also used below to tell "both arms wrote this slot"
                // apart from "only one did" when computing the merge's
                // final state.
                let mut writes: FxHashMap<usize, Span> = FxHashMap::default();
                for (&slot, &span) in then_writes.iter() {
                    writes.entry(slot).or_insert(span);
                }
                for (&slot, &span) in else_writes.iter() {
                    writes.entry(slot).or_insert(span);
                }
                let mut writes: Vec<(usize, Span)> = writes.into_iter().collect();
                writes.sort_by_key(|(_, sp)| (sp.lo(), sp.hi()));
                for (slot, wspan) in &writes {
                    let needs_pre = els.is_none()
                        || then_states[*slot] != AState::Assigned
                        || else_states[*slot] != AState::Assigned
                        || then_unassigned_reads.contains_key(slot)
                        || else_unassigned_reads.contains_key(slot);
                    if snap[*slot] != AState::Assigned
                        && needs_pre
                        && !self.flagged.contains(&(*slot, *wspan))
                    {
                        self.flagged.push((*slot, *wspan));
                        self.out.diagnostics.push(
                            Diagnostic::error(
                                codes::POSSIBLY_UNINITIALIZED,
                                *wspan,
                                "this write inside an encrypted branch merges with the \
                                 variable's previous value, which is possibly \
                                 uninitialized; assign the variable before the `if`",
                            )
                            .with_rule("§6"),
                        );
                    }
                }

                // Post-merge: everything not written by either branch joins
                // the two branch environments (which, for an untouched slot,
                // both equal the pre-if state anyway, so this is exactly
                // that pre-if state).
                self.restore(&snap);
                self.join_into(&then_states);
                self.join_into(&else_states);
                for (slot, wspan) in writes {
                    // A written slot's PRE-if value is never part of the
                    // merged result — the lowered `L = FHE.select(...)`
                    // always overwrites it, on both arms — unlike the
                    // three-way join above (restore-to-snap, then join in
                    // both arms), which would otherwise drag the pre-if
                    // state back in for every slot, written or not. So a
                    // written slot's final state is recomputed here as the
                    // join of *only* what each arm's own write actually
                    // produced: `Assigned` only if every arm's contribution
                    // was itself definitely-assigned. A missing `else` arm
                    // contributes the pre-if value by construction
                    // (`else_states` was snapshotted right after restoring
                    // to `snap`, before any `els` walk), so this still
                    // correctly falls back to the pre-if value exactly when
                    // only one arm writes.
                    //
                    // This is NOT the same thing as forcing `Assigned`
                    // unconditionally (the previous, incorrect assumption):
                    // round 5's copy-propagation can leave an arm's own
                    // write as `Unassigned` when that arm merely copied an
                    // unassigned value (`then { r = u; }` where `u` is
                    // itself unassigned) — `FHE.select` still runs and
                    // still produces a ciphertext, but mixing in a default
                    // handle from the unassigned side makes that ciphertext
                    // meaningless depending on which arm actually ran at
                    // runtime. Whatever later reads/returns the merged slot
                    // is where the ordinary FHE2007 machinery now correctly
                    // fires (spec §6) — no separate diagnostic is needed
                    // here, and the merge's own "needs a pre-value" check
                    // above (which this loop does not touch) still covers
                    // its own, different hazard.
                    //
                    // When only ONE arm writes this slot AND the pre-if
                    // value was itself unassigned, the other arm's
                    // contribution really is that pre-if value (already
                    // reflected in the three-way join above, via
                    // `then_states`/`else_states` both equalling `snap` on
                    // the side that never wrote it) — that shape is the
                    // merge's own "needs a pre-value" hazard above, which
                    // already owns it; forcing `Assigned` here avoids
                    // re-flagging the same root cause a second time through
                    // the function's exit check, preserving existing,
                    // deliberate behavior for that shape (fixtures/typing/
                    // fhe2007-encrypted-if-one-arm expects exactly one
                    // diagnostic, not two, for exactly this reason).
                    //
                    // But when the pre-if value WAS already `Assigned`, the
                    // "needs a pre-value" check above stays silent for this
                    // slot (its own premise — the pre-value might be
                    // uninitialized — does not hold), so nothing else catches
                    // a one-arm write that copies an unassigned value on top
                    // of an already-assigned target (`r = a; if (eb) { r = u;
                    // }`). Joining unconditionally once the pre-if value is
                    // `Assigned` closes that gap: the untouched arm's own
                    // contribution is still `Assigned` (unchanged from
                    // `snap`), so the join reduces to the writing arm's own
                    // state exactly as intended, with no new false positive.
                    if (then_writes.contains_key(&slot) && else_writes.contains_key(&slot))
                        || snap[slot] == AState::Assigned
                    {
                        self.slots[slot].state = AState::join(then_states[slot], else_states[slot]);
                    } else {
                        self.slots[slot].state = AState::Assigned;
                    }
                    // Nested encrypted ifs: the merge write is itself a write
                    // of the enclosing branch.
                    if self.branch_depth > 0 && self.slots[slot].decl_depth < self.branch_depth {
                        if let Some(log) = self.branch_writes.last_mut() {
                            log.entry(slot).or_insert(wspan);
                        }
                    }
                }
                // Both branches always execute in the lowered code (a
                // `return`/`revert` directly inside either is illegal and
                // separately rejected), so this construct never terminates
                // the function on its own.
                self.terminated = pre_terminated;
            }
            Ty::Encrypted(other) => {
                let mut d = Diagnostic::error(
                    codes::CONDITION_NOT_EBOOL,
                    cond.span,
                    format!(
                        "`if` condition has type `{}`; encrypted conditions must be \
                         `ebool`",
                        other.solidity_name()
                    ),
                )
                .with_rule("§3.3");
                if let (EType::Euint(_), Ok(snippet)) = (other, self.sm.span_to_snippet(cond.span))
                {
                    d = d.with_fixit(crate::diag::FixIt {
                        span: cond.span,
                        replacement: format!("FHE.ne({snippet}, FHE.as{}(0))", other.suffix()),
                        safe: false,
                    });
                }
                self.out.diagnostics.push(d);
                self.walk_stmt(then);
                if let Some(els) = els {
                    self.walk_stmt(els);
                }
            }
            _ => {
                // Plaintext (or unknown) condition: ordinary control flow.
                if self.in_branch() {
                    self.error(
                        codes::PLAINTEXT_FLOW_IN_BRANCH,
                        s.span,
                        "plaintext control flow inside an encrypted branch is not \
                         supported in v1 (hoist or flatten)",
                    );
                }
                let snap = self.snapshot();
                let pre_terminated = self.terminated;
                self.walk_stmt(then);
                let then_states = self.snapshot();
                let then_terminated = self.terminated;
                self.restore(&snap);
                self.terminated = pre_terminated;
                let mut else_terminated = false;
                if let Some(els) = els {
                    self.walk_stmt(els);
                    else_terminated = self.terminated;
                }
                let else_states = self.snapshot();
                // Only an arm that can actually reach the join point
                // contributes its assignment state there; a terminated arm's
                // state (possibly unassigned) must not pollute the join past
                // its own `return`/`revert`. A missing `else` behaves like an
                // empty, non-terminating arm (falls through unchanged).
                let mut candidates: Vec<&[AState]> = Vec::new();
                if !then_terminated {
                    candidates.push(&then_states);
                }
                if !else_terminated {
                    candidates.push(&else_states);
                }
                self.join_all(&candidates);
                // The merge point is reachable unless it was already
                // unreachable coming in, or both branches terminate (a
                // missing `else` counts as a branch that falls through).
                self.terminated = pre_terminated || (then_terminated && else_terminated);
            }
        }
    }

    // ---- helpers used by exprs.rs ---------------------------------------

    /// Reports a plaintext (or unprovable) write inside an encrypted branch
    /// (FHE3006), unless the location was declared inside the branch.
    pub(crate) fn branch_plain_write(&mut self, span: Span, decl_depth: u32) {
        if self.in_branch() && decl_depth < self.branch_depth {
            self.error(
                codes::PLAINTEXT_WRITE_IN_BRANCH,
                span,
                "write to a plaintext location inside an encrypted branch leaks the \
                 condition: both branches always execute (write an encrypted value, \
                 or hoist the write out of the `if`)",
            );
        }
    }

    /// The declared encrypted type and owner of a variable, by resolution.
    pub(crate) fn var_decl_ty(&self, res: &Resolution) -> Option<(Ty, VarOwner)> {
        let vid = match res {
            Resolution::Local(v)
            | Resolution::Param(v)
            | Resolution::StateVar(v)
            | Resolution::FileConst(v) => *v,
            _ => return None,
        };
        let v = self.unit.var(vid);
        Some((declared_ty(self.unit, self.trust, &v.decl.ty), v.owner))
    }
}

/// Conservatively determines whether a modifier's body might, on some path,
/// either hit a bare `return;` before its `_;` placeholder runs, or simply
/// fall off the end of the body without ever reaching the placeholder at
/// all (Solidity treats that identically to an early `return`: the guarded
/// function's body never runs, and the call returns default values). Either
/// way, an encrypted named return the function body would otherwise assign
/// is left untouched and crosses the call boundary unassigned (issue #82's
/// hazard class again).
///
/// Also risky, unconditionally, if the body contains inline assembly
/// anywhere: an assembly `return`/`stop`/`revert` could exit before `_;`
/// ever runs, and this analysis does not parse Yul to rule that out (see
/// [`contains_assembly`]).
///
/// This is a standalone, deliberately simple reachability scan — not the
/// full [`AState`] definite-assignment machinery — since a modifier body
/// only needs one bit of information per statement: does the placeholder
/// definitely run on every path through it, and is there a `return` before
/// it does. Loops and `try` are treated pessimistically (a `return` anywhere
/// inside is risky; the placeholder is never counted as *definite* from
/// inside one, since they may run zero times or not reach every clause),
/// which only ever widens what gets flagged, never narrows it (spec §1.3).
pub(crate) fn modifier_may_skip_body(block: &ast::Block<'_>) -> bool {
    /// Returns `(definitely_reaches_placeholder, may_return_before_it)` for
    /// one statement, given whether the placeholder is already guaranteed to
    /// have run on entry (`definite_in`).
    fn scan_stmt(s: &ast::Stmt<'_>, definite_in: bool) -> (bool, bool) {
        use ast::StmtKind::*;
        match &s.kind {
            Placeholder => (true, false),
            Return(_) => (definite_in, !definite_in),
            Block(b) | UncheckedBlock(b) => scan_block(b, definite_in),
            If(_, then, els) => {
                let (dt, rt) = scan_stmt(then, definite_in);
                let (de, re) = match els {
                    Some(e) => scan_stmt(e, definite_in),
                    None => (false, false),
                };
                (dt && de, rt || re)
            }
            While(_, body) | DoWhile(body, _) => {
                let (_, risky) = scan_stmt(body, definite_in);
                (false, risky)
            }
            For { body, .. } => {
                let (_, risky) = scan_stmt(body, definite_in);
                (false, risky)
            }
            Try(t) => {
                let risky = t
                    .clauses
                    .iter()
                    .any(|c| scan_block(&c.block, definite_in).1);
                (false, risky)
            }
            _ => (false, false),
        }
    }

    fn scan_block(block: &ast::Block<'_>, definite_in: bool) -> (bool, bool) {
        let mut definite = definite_in;
        let mut risky = false;
        for s in block.stmts.iter() {
            let (d, r) = scan_stmt(s, definite);
            risky |= r;
            definite |= d;
        }
        (definite, risky)
    }

    // Risky if a `return` can happen before the placeholder is definite, OR
    // if the placeholder is not *definitely* reached by the end of the
    // block at all (falling off the end without ever running `_;` is the
    // same hazard as an explicit early `return`), OR if the body contains
    // inline assembly anywhere (its control flow is opaque to this scan).
    let (definitely_reaches_placeholder, may_return_before_it) = scan_block(block, false);
    may_return_before_it || !definitely_reaches_placeholder || contains_assembly(block)
}

/// Whether `block` contains an inline-assembly statement anywhere,
/// including nested inside `if`/`else`, loops, `try`/`catch`, and nested
/// blocks. This checker does not parse Yul, so it cannot tell whether an
/// assembly block unconditionally exits via `return`/`stop`/`revert` —
/// which would make code textually after it look reachable when it is not.
/// Used to fail closed (flag rather than trust) a function or modifier
/// whose body contains one anywhere, instead of modeling Yul control flow.
pub(crate) fn contains_assembly(block: &ast::Block<'_>) -> bool {
    fn stmt_has(s: &ast::Stmt<'_>) -> bool {
        use ast::StmtKind::*;
        match &s.kind {
            Assembly(_) => true,
            Block(b) | UncheckedBlock(b) | Precondition(b) => block_has(b),
            If(_, then, els) => stmt_has(then) || els.as_ref().is_some_and(|e| stmt_has(e)),
            While(_, body) | DoWhile(body, _) => stmt_has(body),
            For { init, body, .. } => init.as_ref().is_some_and(|i| stmt_has(i)) || stmt_has(body),
            Try(t) => t.clauses.iter().any(|c| block_has(&c.block)),
            _ => false,
        }
    }

    fn block_has(block: &ast::Block<'_>) -> bool {
        block.stmts.iter().any(stmt_has)
    }

    block_has(block)
}
