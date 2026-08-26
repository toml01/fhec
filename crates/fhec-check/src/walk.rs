//! The per-function pass: statement walking, legality (spec §7), definite
//! assignment (spec §6), and rewrite-site/ACL-fact collection — one
//! source-ordered walk. Expression typing lives in [`crate::exprs`].

use fhec_bind::{BoundUnit, ContractId, FileId, FunctionId, Resolution, VarOwner};
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
    /// The span of the statement currently being walked (facts anchor on it).
    pub(crate) current_stmt_span: Span,
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
            slots: Vec::new(),
            scopes: vec![FxHashMap::default()],
            pending: Vec::new(),
            flagged: Vec::new(),
            branch_depth: 0,
            branch_writes: Vec::new(),
            current_stmt_span: Span::DUMMY,
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
                self.declare_slot(name.as_str().to_string(), ty.etype(), AState::Unassigned);
            }
        }
        let Some(body) = &f.ast.body else { return };
        self.walk_block(body);
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

    /// Records an unassigned/maybe read of a tracked encrypted slot.
    pub(crate) fn note_read(&mut self, name: &str, span: Span) {
        if let Some(idx) = self.slot_of(name) {
            let slot = &self.slots[idx];
            if slot.encrypted.is_some() && slot.state != AState::Assigned {
                self.pending.push((idx, span));
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
            self.walk_stmt(s);
        }
        self.scopes.pop();
    }

    fn in_branch(&self) -> bool {
        self.branch_depth > 0
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
            Break | Continue => {
                if self.in_branch() {
                    self.error(
                        codes::BREAK_CONTINUE_IN_BRANCH,
                        s.span,
                        "`break`/`continue` cannot appear inside an encrypted branch: \
                         both branches always execute (restructure the loop body)",
                    );
                }
            }
            Placeholder => {}
            Expr(e) => {
                self.type_root_expr(e);
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
                let snap = self.snapshot();
                self.walk_stmt(body);
                self.join_into(&snap);
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
                self.walk_stmt(body);
                self.pending.clear();
                self.current_stmt_span = s.span;
                let ty = self.type_expr(cond);
                self.reject_encrypted_loop(&ty, cond.span);
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
                if let Some(next) = next {
                    let ty = self.type_expr(next);
                    self.reject_encrypted_loop(&ty, next.span);
                }
                let snap = self.snapshot();
                self.walk_stmt(body);
                self.join_into(&snap);
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
                        if !self.in_branch() {
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
                }
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
                let mut outs: Vec<Vec<AState>> = Vec::new();
                for clause in t.clauses.iter() {
                    self.restore(&snap);
                    self.scopes.push(FxHashMap::default());
                    for v in clause.args.vars.iter() {
                        self.decl_var(v, true);
                    }
                    self.walk_block(&clause.block);
                    self.scopes.pop();
                    outs.push(self.snapshot());
                }
                // After a try: conservative join over every clause.
                self.restore(&snap);
                for o in &outs {
                    self.join_into(o);
                }
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
                self.branch_depth += 1;
                self.branch_writes.push(FxHashMap::default());

                self.walk_stmt(then);
                let then_states = self.snapshot();
                self.restore(&snap);
                if let Some(els) = els {
                    self.walk_stmt(els);
                }
                let else_states = self.snapshot();

                let writes = self.branch_writes.pop().unwrap_or_default();
                self.branch_depth -= 1;

                // §5.2 step 4: every written pre-existing location is read as
                // a pre-value; a possibly-uninitialized pre-value is FHE2007.
                let mut writes: Vec<(usize, Span)> = writes.into_iter().collect();
                writes.sort_by_key(|(_, sp)| (sp.lo(), sp.hi()));
                for (slot, wspan) in &writes {
                    if snap[*slot] != AState::Assigned && !self.flagged.contains(&(*slot, *wspan)) {
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
                self.walk_stmt(then);
                let then_states = self.snapshot();
                self.restore(&snap);
                if let Some(els) = els {
                    self.walk_stmt(els);
                }
                let else_states = self.snapshot();
                self.restore(&then_states);
                self.join_into(&else_states);
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
