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

use fhec_bind::{BoundUnit, Resolution};
use solar_ast as ast;
use solar_data_structures::map::FxHashMap;
use solar_interface::Span;

use crate::decl::declared_ty;
use crate::diag::{codes, Diagnostic};
use crate::sites::{CheckedUnit, PreconditionSite};
use crate::ty::Ty;
use crate::walk::FnChecker;

/// The spec section every diagnostic in this module cites.
const RULE: &str = "§2.7";

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
        self.pre_block(block);
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
        if declared_ty(self.unit, self.trust, &v.ty).is_encrypted() {
            self.pre_reject(
                v.span,
                "an encrypted local cannot be declared in a `precondition` block: the block \
                 is a plaintext guard that runs before the encrypted inputs exist",
            );
            return false;
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
                self.out.diagnostics.push(
                    Diagnostic::error(
                        codes::ENCRYPTED_INPUT_IN_PRECONDITION,
                        e.span,
                        format!(
                            "`{}` is a dialect-managed encrypted input; it does not exist \
                             yet inside a `precondition` block, because the block runs \
                             before the generated conversion",
                            id.as_str()
                        ),
                    )
                    .with_rule(RULE),
                );
                return;
            }
        }

        if self.out.types.get(e.span).is_some_and(|t| t.is_encrypted()) {
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
            CallOptions(..) | New(_) | Payable(_) => self.pre_reject(
                e.span,
                "this expression is not permitted in a `precondition` block: only \
                 effect-free plaintext code the checker can verify may appear here",
            ),
        }
    }

    /// Whether `id` names a parameter carrying a dialect input marker.
    fn is_managed_input(&self, id: solar_interface::Ident) -> bool {
        matches!(
            self.unit.resolve(id),
            Some(Resolution::Param(v)) if self.unit.var(*v).decl.in_sugar.is_some()
        )
    }

    fn pre_ident(&mut self, id: solar_interface::Ident, span: Span) {
        use Resolution::*;
        match self.unit.resolve(id) {
            // Plaintext parameters, block locals, state reads, constants, and
            // the names used as call/cast callees.
            Some(
                Local(_) | Param(_) | StateVar(_) | FileConst(_) | Function(_) | Contract(_)
                | TypeName(_) | Builtin(_) | Event(_) | Error(_),
            ) => {}
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

    /// A write target. Only locals declared inside the block may be written:
    /// the block's scope does not escape, so such a write cannot be observed
    /// after it. Everything else is reported as a state write.
    fn pre_write(&mut self, lhs: &'ast ast::Expr<'ast>, span: Span) {
        let root = lvalue_root(lhs);
        let local =
            root.is_some_and(|id| matches!(self.unit.resolve(id), Some(Resolution::Local(_))));
        if local && matches!(lhs.peel_parens().kind, ast::ExprKind::Ident(_)) {
            // `x = ...` / `x += ...` / `x++` on a block-local: legal.
            return;
        }
        if root.is_some_and(|id| matches!(self.unit.resolve(id), Some(Resolution::Param(_)))) {
            self.pre_reject(
                span,
                "a `precondition` block must not write to a parameter: its effect would \
                 escape the block, which is a plaintext guard only",
            );
            return;
        }
        self.pre_reject(
            span,
            "a state write is not permitted in a `precondition` block: the block runs \
             before the encrypted inputs are verified, so the write would persist for \
             calls that later revert (only locals declared inside the block may be \
             assigned)",
        );
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
            ast::ExprKind::Ident(id) => match self.unit.resolve(*id) {
                Some(Resolution::Function(fids)) => {
                    let fids = fids.clone();
                    if !self.all_view_or_pure(&fids) {
                        false
                    } else if let Some(message) = self.unusable_return(&fids) {
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
    /// type: an *unnamed* encrypted return (`returns (euint64)`, the shape
    /// every confidential getter uses) resolves to no variable, so the
    /// inferred type would be `Unknown` and would slip through. A return the
    /// checker cannot prove plaintext is refused either way (spec §1.3).
    fn unusable_return(&self, fids: &[fhec_bind::FunctionId]) -> Option<String> {
        let mut unknown = false;
        for &f in fids {
            for r in self.unit.function(f).ast.header.returns() {
                match declared_ty(self.unit, self.trust, &r.ty) {
                    Ty::Encrypted(t) => {
                        return Some(format!(
                            "this call returns `{}`; a `precondition` block is a plaintext \
                             guard and runs before any encrypted value of this function \
                             exists",
                            t.solidity_name()
                        ))
                    }
                    Ty::Plain(_) => {}
                    Ty::Unknown => unknown = true,
                }
            }
        }
        unknown.then(|| {
            "this call has a return type the checker cannot prove is plaintext; a \
             `precondition` block may only use values it can prove are plaintext"
                .to_string()
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

/// The root identifier of an lvalue, when it has one.
fn lvalue_root<'ast>(e: &'ast ast::Expr<'ast>) -> Option<solar_interface::Ident> {
    match &e.peel_parens().kind {
        ast::ExprKind::Ident(id) => Some(*id),
        ast::ExprKind::Index(base, _) | ast::ExprKind::Member(base, _) => lvalue_root(base),
        _ => None,
    }
}
