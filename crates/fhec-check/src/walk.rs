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
    pub(crate) is_view: bool,
    pub(crate) is_public_or_external: bool,
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
    /// hit an unconditional terminator (`return`/`revert`): code walked
    /// after this point is unreachable. Conservative: loops and `try` reset
    /// it back to the pre-statement value rather than proving termination,
    /// so it never claims a path terminates unless a `return`/`revert` sits
    /// directly on it.
    pub(crate) terminated: bool,
    /// Stack of open loops; each frame holds the definite-assignment
    /// snapshot captured at every `break` reached inside that loop (spec
    /// §6: a `break` exits the loop with whatever was assigned up to that
    /// point, not with the state at the end of the loop body).
    pub(crate) loop_breaks: Vec<Vec<Vec<AState>>>,
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
            is_view: mutability == ast::StateMutability::View,
            is_public_or_external: matches!(
                visibility,
                Some(ast::Visibility::Public) | Some(ast::Visibility::External)
            ),
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
        // A modifier attached to this function that can `return;` before its
        // `_;` placeholder skips the function body entirely on that path:
        // whatever the body would have assigned never runs. Detected
        // conservatively and unconditionally (regardless of what the body
        // itself does below) — issue #82's hazard class again, just crossing
        // a modifier boundary instead of a callee boundary.
        if !self.named_returns.is_empty() && self.has_risky_modifier() {
            for &(slot, decl_span) in &self.named_returns.clone() {
                if !self.flagged.contains(&(slot, decl_span)) {
                    self.flagged.push((slot, decl_span));
                    self.out.diagnostics.push(
                        Diagnostic::error(
                            codes::POSSIBLY_UNINITIALIZED,
                            decl_span,
                            "a modifier attached to this function may `return` before \
                             its `_;` placeholder, skipping the function body on that \
                             path; this encrypted named return would then cross the call \
                             boundary unassigned, the same CoFHE default-ciphertext \
                             hazard as an unassigned encrypted variable",
                        )
                        .with_rule("§6"),
                    );
                }
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

    /// Whether any modifier invoked by this function may `return;` before
    /// its `_;` placeholder runs, on some path (see [`modifier_may_skip_body`]).
    /// An unresolved or overloaded modifier name is checked for every
    /// candidate — existentially risky is enough to flag (spec §1.3: when in
    /// doubt, reject).
    fn has_risky_modifier(&self) -> bool {
        let f = self.unit.function(self.fid);
        f.ast.header.modifiers.iter().any(|m| {
            let Some(seg) = m.name.segments().first() else {
                return false;
            };
            let Some(Resolution::Function(fids)) = self.unit.resolve_span(seg.span) else {
                return false;
            };
            fids.iter().any(|&fid| {
                let mf = self.unit.function(fid);
                mf.ast.kind == ast::FunctionKind::Modifier
                    && mf.ast.body.as_ref().is_some_and(modifier_may_skip_body)
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

    fn snapshot(&self) -> Vec<AState> {
        self.slots.iter().map(|s| s.state).collect()
    }

    fn restore(&mut self, snap: &[AState]) {
        for (i, st) in snap.iter().enumerate() {
            self.slots[i].state = *st;
        }
    }

    fn join_into(&mut self, snap: &[AState]) {
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
    fn join_all(&mut self, candidates: &[&[AState]]) {
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
                for v in vars.iter() {
                    if let Some(v) = v.as_ref().unspan() {
                        self.decl_var(v, true);
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
                }
                // Jumps back to the loop's condition check: nothing after it
                // in this block runs this iteration. It is not itself a
                // loop-exit (see `Break`), so it contributes no candidate.
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
                // so the body (and any `break` inside it) may never run.
                let snap = self.snapshot();
                let pre_terminated = self.terminated;
                self.loop_breaks.push(Vec::new());
                self.walk_stmt(body);
                let body_terminated = self.terminated;
                let body_states = self.snapshot();
                let breaks = self.loop_breaks.pop().unwrap_or_default();
                let mut candidates: Vec<&[AState]> = vec![&snap];
                // A body that always terminates (return/revert/break/
                // continue on every path) never falls through to re-check
                // the condition, so its end state does not reach after the
                // loop; each `break` point is its own, separate candidate.
                if !body_terminated {
                    candidates.push(&body_states);
                }
                for b in &breaks {
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
                self.walk_stmt(body);
                let body_terminated = self.terminated;
                let body_states = self.snapshot();
                let breaks = self.loop_breaks.pop().unwrap_or_default();
                self.pending.clear();
                self.current_stmt_span = s.span;
                let ty = self.type_expr(cond);
                self.reject_encrypted_loop(&ty, cond.span);

                // Unlike `while`/`for`, a `do` body always runs at least
                // once: there is no zero-trip candidate. The only ways out
                // are falling through the body normally (if it doesn't
                // always terminate first) and each `break` point.
                let mut candidates: Vec<&[AState]> = Vec::new();
                if !body_terminated {
                    candidates.push(&body_states);
                }
                for b in &breaks {
                    candidates.push(b);
                }
                // If nothing reaches the loop's own exit (every avenue
                // through the body terminates, and no `break` escaped it),
                // the `do`/`while` itself always terminates the function.
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
                self.walk_stmt(body);
                let body_terminated = self.terminated;
                // `next` runs after a body iteration that falls through to
                // it; a `break`/`return`/`continue` inside the body skips it.
                if !body_terminated {
                    if let Some(next) = next {
                        let ty = self.type_expr(next);
                        self.reject_encrypted_loop(&ty, next.span);
                    }
                }
                let body_states = self.snapshot();
                let breaks = self.loop_breaks.pop().unwrap_or_default();
                let mut candidates: Vec<&[AState]> = vec![&snap];
                if !body_terminated {
                    candidates.push(&body_states);
                }
                for b in &breaks {
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
                                is_view: self.is_view,
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
        self.decl_var(v, v.initializer.is_some());
        if let Some(init) = &v.initializer {
            // Typed before decl_var? Order: initializer executes before the
            // variable exists; but decl_var only registers the slot, and
            // shadowing within the initializer of the same name is illegal
            // Solidity anyway. Type it now for sites/facts.
            let init_ty = self.type_expr(init);
            let decl = declared_ty(self.unit, self.trust, &v.ty);
            if decl == Ty::Plain(PlainTy::Bool) && init_ty == Ty::Encrypted(EType::Ebool) {
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
                let mut writes = then_writes;
                for (slot, span) in else_writes {
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

                // Post-merge: written slots are assigned on every path (the
                // merge `L = FHE.select(...)` runs unconditionally); everything
                // else joins the two branch environments.
                self.restore(&snap);
                self.join_into(&then_states);
                self.join_into(&else_states);
                for (slot, wspan) in writes {
                    self.slots[slot].state = AState::Assigned;
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

/// Conservatively determines whether a modifier's body might reach a bare
/// `return;` on some path before its `_;` placeholder runs. Such a path
/// skips the guarded function's body entirely (issue #82's hazard class
/// again: an encrypted named return the body would otherwise assign is left
/// untouched, and crosses the call boundary unassigned).
///
/// This is a standalone, deliberately simple reachability scan — not the
/// full [`AState`] definite-assignment machinery — since a modifier body
/// only needs one bit of information: can a `return` happen before the
/// placeholder is guaranteed to have run. Loops and `try` are treated
/// pessimistically (a `return` anywhere inside is risky; the placeholder is
/// never counted as *definite* from inside one, since they may run zero
/// times or not reach every clause), which only ever widens what gets
/// flagged, never narrows it (spec §1.3).
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

    scan_block(block, false).1
}
