//! The `precondition { ... }` block checks (spec §2.7).
//!
//! A `precondition` block moves the generated encrypted-input materializers
//! *after* a plaintext guard, so an unauthorized caller reverts with the
//! contract's own error instead of with proof verification. The transpiler
//! never moves author statements: only the materializers move, and only when
//! the author wrote the marker.
//!
//! Two independent checks live here.
//!
//! 1. **Position** ([`scan`]) — solar parses `precondition` in every statement
//!    position (allow-and-flag). At most one block is legal per function or
//!    constructor body: the first statement, and only when the parameter list
//!    declares at least one dialect-managed encrypted input. Everything else
//!    is FHE1017. Only legal blocks become a [`PreconditionSite`], so the
//!    lowerer can act on a site unconditionally.
//!
//! 2. **Body** ([`FnChecker::check_precondition_block`]) — the block is a
//!    *plaintext guard*. It runs before the materializers, so it cannot name
//!    a dialect-managed input (FHE3014), and it is restricted to an explicit
//!    whitelist of effect-free plaintext forms (FHE3015). The list is a
//!    whitelist on purpose: an unrecognized form is refused, never assumed
//!    harmless (spec §1.3).

use fhec_bind::{BoundUnit, Resolution, TypeDeclKind, UnresolvedReason};
use solar_ast as ast;
use solar_data_structures::map::FxHashMap;
use solar_interface::Span;

use crate::decl::{declared_ty, nesting, Nesting};
use crate::diag::{codes, Diagnostic};
use crate::sites::{CheckedUnit, PreconditionSite};
use crate::ty::Ty;
use crate::walk::FnChecker;

/// The spec section every diagnostic in this module cites.
const RULE: &str = "§2.7";

/// The refusal for a value whose declared type the positive fragment (§3.1)
/// does not cover. `Ty::Unknown` means "the checker does not know", so it is
/// refused exactly like an encrypted type would be (§1.3).
const UNRESOLVED_TYPE: &str = "this value has a type the checker cannot prove is plaintext; a \
                               `precondition` block is a plaintext guard and may only use values \
                               it can prove are plaintext";

/// Whether a function's parameter list declares at least one encrypted input
/// the dialect materializes inside the body.
///
/// Today that is exactly the §2.3 `in eT` sugar. The later `in(proof) eT` and
/// `in shared eT` forms extend this predicate; the legality rule above is
/// phrased in terms of it, not of one spelling.
fn has_managed_encrypted_input<'ast>(
    unit: &BoundUnit<'ast>,
    f: &fhec_bind::FunctionInfo<'ast>,
) -> bool {
    f.params
        .iter()
        .any(|&p| unit.var(p).decl.in_sugar.is_some())
}

/// Collects every `precondition` statement of a body, in source order,
/// together with whether it is the body's first statement.
fn collect<'ast>(
    body: &'ast ast::Block<'ast>,
) -> Vec<(bool, &'ast ast::Stmt<'ast>, &'ast ast::Block<'ast>)> {
    let mut out = Vec::new();
    for (i, stmt) in body.stmts.iter().enumerate() {
        walk(stmt, i == 0, &mut out);
    }
    out
}

fn walk<'ast>(
    stmt: &'ast ast::Stmt<'ast>,
    top_first: bool,
    out: &mut Vec<(bool, &'ast ast::Stmt<'ast>, &'ast ast::Block<'ast>)>,
) {
    use ast::StmtKind::*;
    if let Precondition(block) = &stmt.kind {
        out.push((top_first, stmt, block));
        // Nested occurrences are duplicates; keep reporting them.
        for s in block.stmts.iter() {
            walk(s, false, out);
        }
        return;
    }
    match &stmt.kind {
        Block(b) | UncheckedBlock(b) => {
            for s in b.stmts.iter() {
                walk(s, false, out);
            }
        }
        If(_, t, e) => {
            walk(t, false, out);
            if let Some(e) = e {
                walk(e, false, out);
            }
        }
        While(_, b) | DoWhile(b, _) => walk(b, false, out),
        For { init, body, .. } => {
            if let Some(init) = init {
                walk(init, false, out);
            }
            walk(body, false, out);
        }
        Try(t) => {
            for clause in t.clauses.iter() {
                for s in clause.block.stmts.iter() {
                    walk(s, false, out);
                }
            }
        }
        _ => {}
    }
}

/// Checks `precondition` positions across the unit and states the legal sites.
pub(crate) fn scan<'ast>(unit: &BoundUnit<'ast>, out: &mut CheckedUnit) {
    for (fid, f) in unit.functions() {
        let Some(body) = &f.ast.body else { continue };
        let found = collect(body);
        if found.is_empty() {
            continue;
        }
        let legal_kind = matches!(
            f.ast.kind,
            ast::FunctionKind::Function | ast::FunctionKind::Constructor
        );
        let managed = legal_kind && has_managed_encrypted_input(unit, f);
        let mut claimed = false;
        // A site is stated only when *every* occurrence in this function is
        // legal, so the lowerer never sees a site next to a refused block.
        let mut refused = false;
        let mut site = None;
        for (top_first, stmt, block) in found {
            let keyword = keyword_span(stmt.span);
            // "Duplicate" is checked first: every occurrence after a claimed
            // one is also not the body's first statement, and naming the
            // duplication is the more useful of the two facts.
            if claimed {
                refused = true;
                bad_position(
                    out,
                    keyword,
                    "a function may declare at most one `precondition` block",
                );
                continue;
            }
            if !top_first {
                refused = true;
                bad_position(
                    out,
                    keyword,
                    "a `precondition` block must be the first statement of a function or \
                     constructor body: it guards the generated encrypted-input conversions, \
                     which are inserted directly after it",
                );
                continue;
            }
            claimed = true;
            if !managed {
                refused = true;
                bad_position(
                    out,
                    keyword,
                    "a `precondition` block is only permitted on a function or constructor \
                     that declares at least one dialect-managed encrypted input (`in eT`); \
                     without one there is nothing for it to guard — use a plain block or a \
                     modifier",
                );
                continue;
            }
            site = Some(PreconditionSite {
                stmt_span: stmt.span,
                marker_span: stmt.span.with_hi(block.span.lo()),
                block_span: block.span,
                function: fid,
                file: f.file,
            });
        }
        if let (false, Some(site)) = (refused, site) {
            out.precondition_sites.push(site);
        }
    }
}

/// The `precondition` keyword alone: `stmt.span` starts at the contextual
/// keyword, which is a fixed ASCII word.
fn keyword_span(stmt_span: Span) -> Span {
    stmt_span.with_hi(stmt_span.lo() + solar_interface::BytePos(KEYWORD.len() as u32))
}

const KEYWORD: &str = "precondition";

fn bad_position(out: &mut CheckedUnit, span: Span, message: &str) {
    out.diagnostics
        .push(Diagnostic::error(codes::PRECONDITION_BAD_POSITION, span, message).with_rule(RULE));
}

// ---------------------------------------------------------------------------
// Body rules
// ---------------------------------------------------------------------------

impl<'ast> FnChecker<'_, 'ast> {
    /// Walks a `precondition` block under the §2.7 whitelist.
    ///
    /// Applies to *every* occurrence, legal or not: a badly positioned block
    /// is still a `precondition` block, and reporting its contents helps more
    /// than hiding them. Ordinary typing runs too (so encryptedness is known
    /// exactly); the whitelist then decides what may stay.
    pub(crate) fn check_precondition_block(&mut self, block: &'ast ast::Block<'ast>) {
        // The outermost block's span decides which locals are the block's own
        // (a nested `precondition` is inside it, so it needs no update).
        let outer = self.pre_span.replace(block.span);
        self.pre_block(block);
        self.pre_span = outer;
    }

    /// Whether `v` is declared *inside* the `precondition` block being walked.
    ///
    /// The binder resolves both block locals and the function's named returns
    /// to [`Resolution::Local`] (a named return "behaves as a local"), but a
    /// named return is part of the signature and outlives the block. Only the
    /// declaration position separates them.
    fn declared_in_precondition(&self, v: fhec_bind::VarId) -> bool {
        let decl = self.unit.var(v).decl.span;
        self.pre_span
            .is_some_and(|pre| pre.lo() <= decl.lo() && decl.hi() <= pre.hi())
    }

    fn pre_block(&mut self, block: &'ast ast::Block<'ast>) {
        self.scopes.push(FxHashMap::default());
        for s in block.stmts.iter() {
            self.pre_stmt(s);
        }
        self.scopes.pop();
    }

    fn pre_reject(&mut self, span: Span, message: impl Into<String>) {
        self.out.diagnostics.push(
            Diagnostic::error(codes::PRECONDITION_FORBIDDEN_EFFECT, span, message).with_rule(RULE),
        );
    }

    fn pre_stmt(&mut self, s: &'ast ast::Stmt<'ast>) {
        use ast::StmtKind::*;
        self.pending.clear();
        self.current_stmt_span = s.span;
        match &s.kind {
            // Nested blocks stay blocks. A nested `precondition` is reported
            // by the position scan; its contents obey the same rules.
            Block(b) | UncheckedBlock(b) | Precondition(b) => self.pre_block(b),
            DeclSingle(v) => {
                // A refused declaration swallows its initializer: one mistake,
                // one diagnostic.
                if self.pre_decl(v) {
                    if let Some(init) = &v.initializer {
                        self.pre_expr(init);
                    }
                }
            }
            DeclMulti(vars, rhs) => {
                let mut ok = true;
                for v in vars.iter() {
                    if let Some(v) = v.as_ref().unspan() {
                        ok &= self.pre_decl(v);
                    }
                }
                if ok {
                    self.pre_expr(rhs);
                }
            }
            If(cond, then, els) => {
                let ty = self.pre_expr(cond);
                if ty.is_encrypted() {
                    // Already reported by `pre_expr`; do not walk the arms as
                    // if the condition were plaintext.
                    return;
                }
                self.pre_stmt(then);
                if let Some(els) = els {
                    self.pre_stmt(els);
                }
            }
            Expr(e) => {
                self.pre_expr(e);
            }
            Revert(_path, args) => {
                for a in args.exprs() {
                    self.pre_expr(a);
                }
            }
            Return(_) => self.pre_reject(
                s.span,
                "`return` is not permitted in a `precondition` block: the generated \
                 encrypted-input conversions run after the block and would be skipped \
                 (revert instead, or move the code into the body)",
            ),
            Break | Continue => self.pre_reject(
                s.span,
                "`break`/`continue` is not permitted in a `precondition` block",
            ),
            While(..) | DoWhile(..) | For { .. } => self.pre_reject(
                s.span,
                "loops are not permitted in a `precondition` block: it is a straight-line \
                 plaintext guard",
            ),
            Try(_) => self.pre_reject(
                s.span,
                "`try` is not permitted in a `precondition` block: it is an external call, \
                 whose effects the checker cannot verify",
            ),
            Assembly(_) => self.pre_reject(
                s.span,
                "inline assembly is not permitted in a `precondition` block: its effects \
                 are opaque to the checker",
            ),
            Emit(..) => self.pre_reject(
                s.span,
                "`emit` is not permitted in a `precondition` block: the block runs before \
                 the encrypted inputs are verified, so the event would be observable for \
                 calls that later revert",
            ),
            Placeholder => {
                self.pre_reject(s.span, "`_;` is not permitted in a `precondition` block")
            }
        }
        self.pending.clear();
    }

    /// A local declaration inside the block. Its scope does not escape.
    /// Returns whether the declaration is permitted.
    fn pre_decl(&mut self, v: &'ast ast::VariableDefinition<'ast>) -> bool {
        if v.in_sugar.is_some() {
            self.error(
                codes::IN_SUGAR_BAD_POSITION,
                v.span,
                "the `in` encrypted-input sugar is only permitted in function and \
                 constructor parameter lists",
            );
            return false;
        }
        let ty = declared_ty(self.unit, self.trust, &v.ty);
        match nesting(self.unit, self.trust, &ty) {
            Nesting::Encrypted(t) => {
                self.pre_reject(
                    v.span,
                    format!(
                        "a local holding `{}` cannot be declared in a `precondition` block: \
                         the block is a plaintext guard that runs before the encrypted \
                         inputs exist",
                        t.solidity_name()
                    ),
                );
                return false;
            }
            // `Unknown` is "the checker does not know", never "plaintext": a
            // qualified type name (`NS.euint32`) leaves the positive fragment
            // and could name an encrypted type (§1.3).
            Nesting::Unknown => {
                self.pre_reject(v.span, UNRESOLVED_TYPE);
                return false;
            }
            Nesting::Plain => {}
        }
        self.decl_var(v, v.initializer.is_some());
        true
    }

    /// Types `e`, then walks it under the whitelist. Returns the root type.
    fn pre_expr(&mut self, e: &'ast ast::Expr<'ast>) -> Ty {
        let ty = self.type_expr(e);
        self.pre_walk_expr(e);
        ty
    }

    /// The §2.7 expression whitelist. Rejects at the outermost offending node
    /// and does not descend into it, so one mistake yields one diagnostic.
    fn pre_walk_expr(&mut self, e: &'ast ast::Expr<'ast>) {
        use ast::ExprKind::*;

        // A dialect-managed input is not materialized yet: naming it here is
        // FHE3014, which is more specific than "encrypted expression".
        if let Ident(id) = &e.kind {
            if self.is_managed_input(*id) {
                self.reject_managed_input(*id, e.span);
                return;
            }
        }

        if self.out.types.get(e.span).is_some_and(|t| t.is_encrypted()) {
            // The whole expression is encrypted, so the walk stops here. If a
            // managed input hides inside it (`amount == enc`), name *that*:
            // FHE3014 says what to do, FHE3015 only says "not here".
            if let Some(id) = managed_input_in(e, &|id| self.is_managed_input(id)) {
                self.reject_managed_input(id, id.span);
                return;
            }
            self.pre_reject(
                e.span,
                "an encrypted value cannot appear in a `precondition` block: the block is a \
                 plaintext guard that runs before any FHE operation of this function",
            );
            return;
        }

        match &e.kind {
            Lit(..) | Type(_) | TypeCall(_) | Err(_) => {}
            Ident(id) => self.pre_ident(*id, e.span),
            Member(obj, _) => self.pre_walk_expr(obj),
            Index(base, kind) => {
                self.pre_walk_expr(base);
                match kind {
                    ast::IndexKind::Index(i) => {
                        if let Some(i) = i {
                            self.pre_walk_expr(i);
                        }
                    }
                    ast::IndexKind::Range(a, b) => {
                        if let Some(a) = a {
                            self.pre_walk_expr(a);
                        }
                        if let Some(b) = b {
                            self.pre_walk_expr(b);
                        }
                    }
                }
            }
            Binary(l, _, r) => {
                self.pre_walk_expr(l);
                self.pre_walk_expr(r);
            }
            Unary(op, x) => {
                if op.kind.has_side_effects() {
                    self.pre_write(x, e.span);
                } else {
                    self.pre_walk_expr(x);
                }
            }
            Ternary(c, a, b) => {
                self.pre_walk_expr(c);
                self.pre_walk_expr(a);
                self.pre_walk_expr(b);
            }
            Assign(lhs, _, rhs) => {
                self.pre_write(lhs, e.span);
                self.pre_walk_expr(rhs);
            }
            Tuple(els) => {
                for el in els.iter() {
                    if let Some(el) = el.as_ref().unspan() {
                        self.pre_walk_expr(el);
                    }
                }
            }
            Array(els) => {
                for el in els.iter() {
                    self.pre_walk_expr(el);
                }
            }
            Call(callee, args) => self.pre_call(e, callee, args),
            Delete(_) => self.pre_reject(
                e.span,
                "`delete` is not permitted in a `precondition` block: it is a state write",
            ),
            // `payable(x)` is a built-in conversion to `address payable`, not
            // a call: it reads its operand and produces a plaintext address.
            Payable(args) => {
                for a in args.exprs() {
                    self.pre_walk_expr(a);
                }
            }
            CallOptions(..) | New(_) => self.pre_reject(
                e.span,
                "this expression is not permitted in a `precondition` block: only \
                 effect-free plaintext code the checker can verify may appear here",
            ),
        }
    }

    /// Reports FHE3014 for a dialect-managed input named inside the block.
    fn reject_managed_input(&mut self, id: solar_interface::Ident, span: Span) {
        self.out.diagnostics.push(
            Diagnostic::error(
                codes::ENCRYPTED_INPUT_IN_PRECONDITION,
                span,
                format!(
                    "`{}` is a dialect-managed encrypted input; it does not exist yet \
                     inside a `precondition` block, because the block runs before the \
                     generated conversion",
                    id.as_str()
                ),
            )
            .with_rule(RULE),
        );
    }

    /// Whether `id` names a parameter carrying a dialect input marker.
    fn is_managed_input(&self, id: solar_interface::Ident) -> bool {
        matches!(
            self.unit.resolve(id),
            Some(Resolution::Param(v)) if self.unit.var(*v).decl.in_sugar.is_some()
        )
    }

    fn pre_ident(&mut self, id: solar_interface::Ident, span: Span) {
        self.pre_ident_resolution(self.unit.resolve(id).cloned(), id, span);
    }

    /// The body of [`Self::pre_ident`], factored out so the file-scope miss
    /// carried by [`UnresolvedReason::IncompleteInheritance`] can be judged
    /// by the same rule as a direct unresolved result.
    fn pre_ident_resolution(
        &mut self,
        res: Option<Resolution>,
        id: solar_interface::Ident,
        span: Span,
    ) {
        use Resolution::*;
        match res {
            // A value read. The recorded type of the expression is not
            // enough: a declared type the positive fragment does not cover
            // (`NS.euint32`, a qualified custom type) types as `Unknown`,
            // which that check cannot tell from plaintext, and a *plain*
            // container may still hold encrypted data (`euint32[]`). Judge
            // the declared type all the way down (§1.3).
            Some(res @ (Local(_) | Param(_) | StateVar(_) | FileConst(_))) => {
                match self
                    .var_decl_ty(&res)
                    .map(|(t, _)| nesting(self.unit, self.trust, &t))
                {
                    Some(Nesting::Encrypted(t)) => self.pre_reject(
                        span,
                        format!(
                            "`{}` holds `{}`; a `precondition` block is a plaintext guard \
                             that runs before any FHE operation of this function",
                            id.as_str(),
                            t.solidity_name()
                        ),
                    ),
                    Some(Nesting::Unknown) => self.pre_reject(span, UNRESOLVED_TYPE),
                    _ => {}
                }
            }
            // The names used as call/cast callees, and event/error paths.
            Some(Function(_) | Contract(_) | TypeName(_) | Builtin(_) | Event(_) | Error(_)) => {}
            // Judge the name by what file scope would have said, rather than
            // by the generic inheritance failure. This is an explicit policy:
            // the binder deliberately does not resolve that fallback, because
            // an unseen base can shadow the name.
            Some(Unresolved(UnresolvedReason::IncompleteInheritance { fallback, .. })) => {
                self.pre_ident_resolution(Some(*fallback), id, span);
            }
            _ => self.pre_reject(
                span,
                format!(
                    "`{}` comes from outside this compilation unit, or cannot be resolved; \
                     a `precondition` block may only read names the checker can prove are \
                     plaintext",
                    id.as_str()
                ),
            ),
        }
    }

    /// A write target. Only a *whole* local declared inside the block may be
    /// written: `a = ...` rebinds a name the block owns and nothing outside it
    /// can observe that.
    ///
    /// A write *through* a block-local (`a[i] = ...`, `a.f = ...`) is always
    /// refused. In Solidity a reference-typed local binds to existing data
    /// instead of copying it, so such a write can mutate data the block does
    /// not own — through the declaration (`uint256[] memory a = param;`),
    /// through a later rebind (`a = param;`), through a tuple declaration, or
    /// through a reference stored inside a container the block did allocate.
    /// The checker does not guess an aliasing lattice (§1.3), so it refuses
    /// every through-write instead of proving freshness case by case.
    /// Everything else escapes, and is reported by *why* it escapes.
    fn pre_write(&mut self, lhs: &'ast ast::Expr<'ast>, span: Span) {
        // A tuple lvalue is a list of write targets; judge each on its own.
        if let ast::ExprKind::Tuple(els) = &lhs.peel_parens().kind {
            for el in els.iter() {
                if let Some(el) = el.as_ref().unspan() {
                    self.pre_write(el, span);
                }
            }
            return;
        }
        match self.write_target(lhs) {
            WriteTarget::BlockLocal => {
                // Legal. The name itself still obeys the whitelist (its
                // declared type must be provably plaintext).
                self.pre_walk_expr(lhs);
            }
            WriteTarget::Escaping(name) => self.pre_reject(
                span,
                format!(
                    "a `precondition` block must not write to `{name}`: it is declared \
                     outside the block, so the effect would escape a guard that is \
                     plaintext only"
                ),
            ),
            WriteTarget::ThroughLocal(name) => self.pre_reject(
                span,
                format!(
                    "a `precondition` block must not write through `{name}`: an element or \
                     member write reaches the data the local refers to, which the checker \
                     cannot prove lives inside the block, so the effect could escape a \
                     guard that is plaintext only (assign the local itself instead)"
                ),
            ),
            WriteTarget::State => self.pre_reject(
                span,
                "a state write is not permitted in a `precondition` block: the block runs \
                 before the encrypted inputs are verified, so the write would persist for \
                 calls that later revert (only locals declared inside the block may be \
                 assigned)",
            ),
        }
    }

    /// Classifies the base of an lvalue path (`x`, `x[i]`, `x.f`, and nestings).
    fn write_target(&self, lhs: &'ast ast::Expr<'ast>) -> WriteTarget {
        let Some(root) = lvalue_root(lhs) else {
            return WriteTarget::State;
        };
        // A write *through* the root (`x[i] = ...`, `x.f = ...`) reaches the
        // data the root refers to; a write *to* the root only rebinds it.
        let through_root = !matches!(lhs.peel_parens().kind, ast::ExprKind::Ident(_));
        match self.unit.resolve(root) {
            Some(Resolution::Local(v)) if self.declared_in_precondition(*v) => {
                if through_root {
                    WriteTarget::ThroughLocal(root.as_str().to_string())
                } else {
                    WriteTarget::BlockLocal
                }
            }
            // A parameter, or a named return — both are part of the signature
            // and outlive the block, even though the binder calls the latter
            // a local.
            Some(Resolution::Local(_) | Resolution::Param(_)) => {
                WriteTarget::Escaping(root.as_str().to_string())
            }
            _ => WriteTarget::State,
        }
    }

    /// Whether `obj.name` in callee position is an in-unit type conversion
    /// (`Lib.Money(x)`) or a UDVT `wrap`/`unwrap` (`Money.wrap(x)`,
    /// `Lib.Money.unwrap(x)`), rather than a member *call*.
    fn plaintext_type_member(
        &self,
        obj: &'ast ast::Expr<'ast>,
        name: solar_interface::Ident,
    ) -> bool {
        // `Lib.Money(x)`: the whole callee is a qualified type name.
        if let Some(td) = self.qualified_type(obj, name) {
            return self.plaintext_type_decl(td);
        }
        // `Money.wrap(x)`: the object is the UDVT, the member is the
        // primitive.
        if !matches!(name.as_str(), "wrap" | "unwrap") {
            return false;
        }
        let td = match &obj.peel_parens().kind {
            ast::ExprKind::Ident(id) => match self.unit.resolve(*id) {
                Some(Resolution::TypeName(td)) => *td,
                _ => return false,
            },
            ast::ExprKind::Member(inner, member) => match self.qualified_type(inner, *member) {
                Some(td) => td,
                None => return false,
            },
            _ => return false,
        };
        matches!(self.unit.type_decl(td).kind, TypeDeclKind::Udvt(_))
            && self.plaintext_type_decl(td)
    }

    /// Whether an in-unit type declaration is one the block may convert
    /// through.
    ///
    /// An encrypted type or an external-input handle is refused however it is
    /// spelled: bare (`euint32.wrap(x)`) or qualified (`Lib.euint32.wrap(x)`).
    /// Both are profile types, so `wrap`/`unwrap` on them produces a value the
    /// block must not hold — the same trust rule that types `euint32` decides,
    /// so a plaintext UDVT that merely shares the name is unaffected.
    fn plaintext_type_decl(&self, td: fhec_bind::TypeDeclId) -> bool {
        let name = self.unit.type_decl(td).name;
        !matches!(
            crate::decl::custom_ty(
                self.unit,
                self.trust,
                name.as_str(),
                &Resolution::TypeName(td),
            ),
            Ty::Encrypted(_) | Ty::Plain(crate::ty::PlainTy::ExternalInput(_))
        )
    }

    /// The in-unit type declaration a `Contract.Name` path names, if any.
    fn qualified_type(
        &self,
        obj: &'ast ast::Expr<'ast>,
        name: solar_interface::Ident,
    ) -> Option<fhec_bind::TypeDeclId> {
        let ast::ExprKind::Ident(id) = &obj.peel_parens().kind else {
            return None;
        };
        let Some(Resolution::Contract(cid)) = self.unit.resolve(*id) else {
            return None;
        };
        let cid = *cid;
        self.unit
            .type_decls()
            .find(|(_, t)| t.contract == Some(cid) && t.name.as_str() == name.as_str())
            .map(|(id, _)| id)
    }

    fn pre_call(
        &mut self,
        e: &'ast ast::Expr<'ast>,
        callee: &'ast ast::Expr<'ast>,
        args: &'ast ast::CallArgs<'ast>,
    ) {
        let callee = callee.peel_parens();
        let ok = match &callee.kind {
            // Elementary casts: `uint256(x)`, `address(0)`.
            ast::ExprKind::Type(_) => true,
            // `new uint256[](n)`, `new bytes(n)`: allocating memory is a pure
            // plaintext operation. A `new` on any other type deploys a
            // contract and stays refused.
            ast::ExprKind::New(ty) => is_memory_allocation(ty),
            ast::ExprKind::Ident(id) => match self.callee_resolution(*id) {
                Some(Resolution::Function(fids)) => {
                    let fids = fids.clone();
                    if let Some(message) = self.incomplete_overload_set(id.as_str(), &fids) {
                        self.pre_reject(e.span, message);
                        return;
                    }
                    if !self.all_view_or_pure(&fids) {
                        false
                    } else if let Some(message) = self.unusable_return(&fids) {
                        self.pre_reject(e.span, message);
                        return;
                    } else if let Some(message) = self.mutable_memory_param(&fids) {
                        self.pre_reject(e.span, message);
                        return;
                    } else {
                        true
                    }
                }
                Some(Resolution::Builtin(b)) => matches!(
                    b.0,
                    "require"
                        | "assert"
                        | "revert"
                        | "keccak256"
                        | "sha256"
                        | "ripemd160"
                        | "ecrecover"
                        | "addmod"
                        | "mulmod"
                ),
                // Contract/UDVT/struct/enum conversions and constructions.
                Some(Resolution::Contract(_) | Resolution::TypeName(_)) => true,
                _ => false,
            },
            // A member callee is a call — except when it names an in-unit
            // *type*: `Lib.Money(x)` converts, and `Money.wrap(x)` is the
            // UDVT primitive. Neither runs user code.
            ast::ExprKind::Member(obj, name) => self.plaintext_type_member(obj, *name),
            _ => false,
        };
        if !ok {
            self.pre_reject(
                e.span,
                "only `require`/`assert`/`revert`, plaintext conversions, and calls to \
                 statically resolved `view`/`pure` functions of this compilation unit may \
                 appear in a `precondition` block; imported, unresolved, member, and \
                 state-changing calls are refused",
            );
            return;
        }
        // The callee itself needs no further walking: it is a name the arm
        // above already accepted.
        for a in args.exprs() {
            self.pre_walk_expr(a);
        }
    }

    /// Whether every candidate of an overload group is declared `view`/`pure`.
    ///
    /// Solidity only lets an override tighten mutability, so a `view`
    /// declaration is a sound upper bound even for a `virtual` callee.
    /// Why a callee's declared return list disqualifies it, if it does.
    ///
    /// The declared list is checked directly instead of the call's inferred
    /// type so tuple returns and every nested declared type are classified
    /// independently. A return the checker cannot prove plaintext is refused
    /// either way (spec §1.3).
    fn unusable_return(&self, fids: &[fhec_bind::FunctionId]) -> Option<String> {
        let mut unknown = false;
        for &f in fids {
            for r in self.unit.function(f).ast.header.returns() {
                let ty = declared_ty(self.unit, self.trust, &r.ty);
                match nesting(self.unit, self.trust, &ty) {
                    Nesting::Encrypted(t) => {
                        return Some(format!(
                            "this call returns `{}`; a `precondition` block is a plaintext \
                             guard and runs before any encrypted value of this function \
                             exists",
                            t.solidity_name()
                        ))
                    }
                    Nesting::Plain => {}
                    Nesting::Unknown => unknown = true,
                }
            }
        }
        unknown.then(|| {
            "this call has a return type the checker cannot prove is plaintext; a \
             `precondition` block may only use values it can prove are plaintext"
                .to_string()
        })
    }

    /// Whether any candidate of an overload group takes a `memory` reference
    /// parameter.
    ///
    /// `view`/`pure` only forbid state access, not memory mutation: a `pure`
    /// callee may still write through a `memory` array/struct/`bytes`/
    /// `string` argument, letting an effect escape the block by proxy
    /// instead of through a direct write. `calldata` is read-only and
    /// `storage`/`transient` writes are already state changes `view`/`pure`
    /// forbid outright, so only `memory` needs this guard.
    fn mutable_memory_param(&self, fids: &[fhec_bind::FunctionId]) -> Option<String> {
        fids.iter().find_map(|&f| {
            self.unit
                .function(f)
                .ast
                .header
                .parameters
                .iter()
                .find_map(|p| {
                    (p.data_location == Some(ast::DataLocation::Memory)).then(|| {
                        "this call takes a `memory` reference parameter; a `precondition` block \
                     may not call anything that could write through it, since that write \
                     would escape the block the same way a direct write would"
                            .to_string()
                    })
                })
        })
    }

    /// The resolution to judge a `precondition` callee by.
    ///
    /// Under an incomplete linearization every name that is not the
    /// contract's own member degrades, `require` included, which would make
    /// a `precondition` block unusable in any contract that inherits from a
    /// package. The builtin answer file scope would have given is restored
    /// here, and only that: a `Function` fallback stays degraded, because an
    /// unseen base can shadow a file-scope function and this module must not
    /// license a call on a guess (§1.3). A base declaring `require` itself
    /// would defeat this, which is the general hazard tracked separately.
    fn callee_resolution(&self, id: solar_interface::Ident) -> Option<Resolution> {
        match self.unit.resolve(id)? {
            Resolution::Unresolved(UnresolvedReason::IncompleteInheritance {
                fallback, ..
            }) => match fallback.as_ref() {
                b @ Resolution::Builtin(_) => Some(b.clone()),
                other => Some(Resolution::Unresolved(
                    UnresolvedReason::IncompleteInheritance {
                        contract: self.contract?,
                        fallback: Box::new(other.clone()),
                    },
                )),
            },
            other => Some(other.clone()),
        }
    }

    /// Refuses a call whose overload set this unit cannot see in full.
    ///
    /// Under an incomplete linearization the binder answers with the members
    /// of the known prefix only, and that answer is a *lower bound*: Solidity
    /// unions overloads across the whole linearization, so an unseen base may
    /// add a signature that solc prefers. Judging the call by the prefix
    /// alone would license a state-changing overload on the strength of a
    /// `view` one (§1.3). The §7 branch rules are already safe here, because
    /// their gate reads `linearization.order`, which an incomplete
    /// linearization leaves as just the contract itself.
    fn incomplete_overload_set(
        &self,
        name: &str,
        fids: &[fhec_bind::FunctionId],
    ) -> Option<String> {
        let contract = self.contract?;
        if self.unit.linearization(contract).complete {
            return None;
        }
        let inherited = fids
            .iter()
            .any(|&f| self.unit.function(f).contract != Some(contract));
        inherited.then(|| {
            format!(
                "`{name}` is declared by a base of `{}`, which also inherits a base outside \
                 the compilation unit, so the transpiler cannot see every overload solc will \
                 choose from; call it outside the `precondition` block",
                self.unit.contract(contract).name_str
            )
        })
    }

    fn all_view_or_pure(&self, fids: &[fhec_bind::FunctionId]) -> bool {
        !fids.is_empty()
            && fids.iter().all(|&f| {
                matches!(
                    self.unit.function(f).ast.header.state_mutability(),
                    ast::StateMutability::View | ast::StateMutability::Pure
                )
            })
    }
}

/// What an lvalue path ultimately writes to.
enum WriteTarget {
    /// The whole of a local declared inside the `precondition` block: the
    /// write only rebinds a name the block owns, so it is legal.
    BlockLocal,
    /// A parameter or named return: the write would outlive the block.
    Escaping(String),
    /// An element or member *of* a local declared inside the block: the local
    /// may refer to data that lives outside it.
    ThroughLocal(String),
    /// A state variable, or a target the checker cannot pin down.
    State,
}

/// Whether `new T(...)` allocates memory rather than deploying a contract.
fn is_memory_allocation(ty: &ast::Type<'_>) -> bool {
    match &ty.kind {
        ast::TypeKind::Array(_) => true,
        ast::TypeKind::Elementary(e) => {
            matches!(e, ast::ElementaryType::Bytes | ast::ElementaryType::String)
        }
        _ => false,
    }
}

/// The first identifier anywhere in `e` for which `is_managed` holds.
///
/// The walk is a plain pre-order over every sub-expression: the point is to
/// find the input wherever the author put it, not to model the expression.
fn managed_input_in(
    e: &ast::Expr<'_>,
    is_managed: &dyn Fn(solar_interface::Ident) -> bool,
) -> Option<solar_interface::Ident> {
    use ast::ExprKind::*;
    let find = |x: &ast::Expr<'_>| managed_input_in(x, is_managed);
    match &e.kind {
        Ident(id) => is_managed(*id).then_some(*id),
        Lit(..) | Type(_) | TypeCall(_) | New(_) | Err(_) => None,
        Member(obj, _) | Delete(obj) | Unary(_, obj) => find(obj),
        Index(base, kind) => find(base).or_else(|| match kind {
            ast::IndexKind::Index(i) => i.as_deref().and_then(find),
            ast::IndexKind::Range(a, b) => a
                .as_deref()
                .and_then(find)
                .or_else(|| b.as_deref().and_then(find)),
        }),
        Binary(l, _, r) | Assign(l, _, r) => find(l).or_else(|| find(r)),
        Ternary(c, a, b) => find(c).or_else(|| find(a)).or_else(|| find(b)),
        Tuple(els) => els
            .iter()
            .filter_map(|el| el.as_ref().unspan())
            .find_map(|el| find(el)),
        Array(els) => els.iter().find_map(|el| find(el)),
        Payable(args) => args.exprs().find_map(find),
        Call(callee, args) => find(callee).or_else(|| args.exprs().find_map(find)),
        CallOptions(inner, opts) => find(inner).or_else(|| opts.iter().find_map(|o| find(o.value))),
    }
}

/// The root identifier of an lvalue, when it has one.
fn lvalue_root<'ast>(e: &'ast ast::Expr<'ast>) -> Option<solar_interface::Ident> {
    match &e.peel_parens().kind {
        ast::ExprKind::Ident(id) => Some(*id),
        ast::ExprKind::Index(base, _) | ast::ExprKind::Member(base, _) => lvalue_root(base),
        _ => None,
    }
}
