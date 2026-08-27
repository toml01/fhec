//! The shared-boundary checks (spec §2.8).
//!
//! Two independent constructs share this module because they share one
//! diagnostic family and one profile capability:
//!
//! - **shared input** — `in shared eT name`. The wire parameter becomes
//!   `sharedT name_shared` and the body opens with
//!   `eT name = FHE.receiveTParam(name_shared);` at the materialization point
//!   (§2.7). Its parameter list must not also carry an external `in` /
//!   `in(proof)` input: the two have different verification models, and this
//!   MVP refuses to pick an ordering between them.
//! - **shared return** — `returns (shared(msg.sender) eT)`. The ABI result
//!   type becomes `sharedT` and every `return expr;` becomes
//!   `return FHE.shareT(expr, msg.sender);`.
//!
//! Solar parses both markers wherever they can be written unambiguously
//! (allow-and-flag); every position and shape this module does not accept is
//! FHE1015, so a misplaced marker yields a dialect diagnostic rather than a
//! parse error. Only *legal* occurrences become sites, so the lowerer can act
//! on a site unconditionally.
//!
//! # Three conservative MVP restrictions on shared returns
//!
//! Each draws a boundary around a known, tracked defect in the ACL pass's
//! statement composition rather than risk a silent miscompile (§1.3).
//!
//! 1. **No assignment in the returned expression.** An encrypted assignment
//!    inside a `return` states an R1 storage-write fact anchored on the
//!    `return` statement, and R1 inserts its grant *after* that statement —
//!    i.e. after control has already left the function, silently dropping the
//!    grant. Refusing the shape keeps the two rules from ever meeting.
//! 2. **`return` must sit inside a braced block.** R2 inserts grant
//!    statements *before* the statement it serves. When that statement is the
//!    braceless body of an `if`/`for`/`while`, only the first inserted
//!    statement stays under the conditional and the rest — including the
//!    `return` — escape it. Requiring braces keeps a shared return out of that
//!    shape entirely.
//! 3. **No rewrite site in a returned expression an R2 grant owns.** See
//!    [`r2_owned_stmts`]. The first two rules are purely syntactic; this one
//!    reads the R2 facts, so it must run after the per-function walk — which
//!    it does, because [`scan`] is the last stage of [`crate::check`].
//!
//! The shared-return rewrite itself never inserts a statement: it wraps the
//! returned expression in place with two zero-width insertions at the
//! expression's own boundaries, so it composes with R2's grants and with
//! ordinary operator lowering inside the expression without owning anything.

use fhec_bind::{BoundUnit, FunctionInfo, SourceFile};
use fhec_ir::EType;
use fhec_targets::TargetProfile;
use solar_ast as ast;
use solar_interface::Span;

use crate::decl::declared_ty;
use crate::diag::{codes, Diagnostic};
use crate::sites::{CheckedUnit, SharedInputSite, SharedReturnSite};
use crate::sugar::ident_occurs;
use crate::trust::Trust;
use crate::ty::Ty;
use crate::walk::span_within;

/// The spec section every diagnostic in this module cites.
const RULE: &str = "§2.8";

/// The fixed generated wire-parameter suffix of a shared input.
const WIRE_SUFFIX: &str = "_shared";

/// The one recipient expression this MVP accepts.
const RECIPIENT: &str = "msg.sender";

/// Checks every shared-boundary marker of the unit and states the legal sites.
///
/// Runs *after* the per-function walk: the shared-return type rule (FHE2012)
/// compares each returned expression's recorded type against the declared one.
pub(crate) fn scan<'ast>(
    files: &[SourceFile<'ast>],
    unit: &BoundUnit<'ast>,
    trust: &Trust,
    profile: &dyn TargetProfile,
    out: &mut CheckedUnit,
) {
    for (fid, f) in unit.functions() {
        scan_params(unit, trust, profile, out, fid, f);
        scan_returns(unit, trust, profile, out, fid, f);
    }
    // Event/error parameter lists and state variables: never legal, and not
    // reachable through `BoundUnit`, so walk the file item trees.
    for file in files {
        for item in file.ast.items.iter() {
            scan_item(out, item);
        }
    }
}

/// Whether a function's `returns` list carries any shared-boundary marker.
///
/// The ACL pass's R3 rule (§8.3) MUST NOT fire for such a function: a legal
/// shared return grants through `FHE.shareT(..., msg.sender)` instead, and an
/// illegal one refuses the unit. The predicate is deliberately broader than
/// "legal shared return" — a marker in the list is enough to suppress R3,
/// whatever else is wrong with it.
pub(crate) fn declares_shared_return(f: &ast::ItemFunction<'_>) -> bool {
    f.header.returns().iter().any(|r| r.shared.is_some())
}

// ---------------------------------------------------------------------------
// Shared inputs — `in shared eT name`
// ---------------------------------------------------------------------------

fn scan_params<'ast>(
    unit: &BoundUnit<'ast>,
    trust: &Trust,
    profile: &dyn TargetProfile,
    out: &mut CheckedUnit,
    fid: fhec_bind::FunctionId,
    f: &FunctionInfo<'ast>,
) {
    let decls: Vec<&ast::VariableDefinition<'ast>> =
        f.params.iter().map(|&p| unit.var(p).decl).collect();
    if decls.iter().all(|d| d.shared.is_none()) {
        return;
    }

    // Whole-list rules first, each refusing the function outright: no site is
    // stated even for a parameter that is fine on its own (§1.3). The first
    // failure ends the scan, so one wrong signature yields one diagnostic.
    let anchor = decls
        .iter()
        .find_map(|d| d.shared.as_ref())
        .expect("at least one shared marker")
        .span;

    if f.ast.kind != ast::FunctionKind::Function {
        return bad_position(
            out,
            anchor,
            format!(
                "`in shared` is only permitted in a `function` parameter list, not in a \
                 `{}` parameter list",
                f.ast.kind.to_str()
            ),
        );
    }
    if !matches!(
        f.ast.header.visibility(),
        Some(ast::Visibility::Public) | Some(ast::Visibility::External)
    ) {
        return bad_position(
            out,
            anchor,
            "`in shared` is only permitted on a `public` or `external` function: a shared \
             handle is an ABI wire type, so an internal caller has nothing to pass"
                .to_string(),
        );
    }
    if matches!(
        f.ast.header.state_mutability(),
        ast::StateMutability::View | ast::StateMutability::Pure
    ) {
        return bad_position(
            out,
            anchor,
            "`in shared` is not permitted on a `view` or `pure` function: receiving a shared \
             handle changes the access-control state"
                .to_string(),
        );
    }
    // MVP: one parameter list carries either shared inputs or external ones,
    // never both. Several external inputs verify as one atomic proof batch,
    // and this draft fixes no ordering between that batch and the receives.
    if decls
        .iter()
        .any(|d| d.in_sugar.is_some() && d.shared.is_none())
    {
        return bad_position(
            out,
            f.ast.header.parameters.span,
            "this parameter list mixes `in shared` inputs with external `in` inputs; \
             a function may declare either kind, not both (split it into two functions)"
                .to_string(),
        );
    }

    let mut refused = false;
    let mut sites: Vec<SharedInputSite> = Vec::new();
    for decl in &decls {
        let Some(shared) = decl.shared.as_ref() else {
            continue;
        };
        if shared.has_recipient() {
            refused = true;
            bad_position(
                out,
                shared.span,
                "a recipient belongs on a shared *return* type; an input is written \
                 `in shared eT name` with no recipient"
                    .to_string(),
            );
            continue;
        }
        let Some(in_sugar) = decl.in_sugar else {
            // Unreachable through the grammar (the bare marker is only read
            // after `in`), but refuse rather than assume (§1.3).
            refused = true;
            bad_position(
                out,
                shared.span,
                "a shared input is written `in shared eT name`; the `in` keyword is required"
                    .to_string(),
            );
            continue;
        };
        if in_sugar.proof.is_some() {
            refused = true;
            bad_position(
                out,
                shared.span,
                "`in shared` takes no proof binder: a shared handle is received from its \
                 sharer, not verified against an input proof"
                    .to_string(),
            );
            continue;
        }
        let ty = declared_ty(unit, trust, &decl.ty);
        let Ty::Encrypted(ety) = ty else {
            refused = true;
            bad_position(
                out,
                decl.ty.span,
                "`in shared` must be followed by an encrypted type \
                 (ebool, euint8..euint128, eaddress)"
                    .to_string(),
            );
            continue;
        };
        let Some(name) = decl.name else {
            refused = true;
            bad_position(
                out,
                shared.span,
                "an `in shared` parameter must be named: the expansion declares \
                 `<name>_shared` and receives it into `<name>`"
                    .to_string(),
            );
            continue;
        };
        if !supports_shared(profile, out, ety, shared.span) {
            refused = true;
            continue;
        }
        let generated = format!("{}{WIRE_SUFFIX}", name.as_str());
        if ident_occurs(f.ast, &generated) {
            refused = true;
            out.diagnostics.push(
                Diagnostic::error(
                    codes::SHARED_BOUNDARY_NAME_COLLISION,
                    decl.span,
                    format!(
                        "the expansion needs the identifier `{generated}`, which is already \
                         used in this function; rename one of them (the transpiler never \
                         renames silently)"
                    ),
                )
                .with_rule(RULE),
            );
            continue;
        }
        sites.push(SharedInputSite {
            param_span: decl.span,
            ty: ety,
            name: name.as_str().to_string(),
            has_body: f.ast.body.is_some(),
            body_span: f.ast.body.as_ref().map(|b| b.span),
            function: fid,
            file: f.file,
        });
    }

    if !refused {
        out.shared_input_sites.extend(sites);
    }
}

// ---------------------------------------------------------------------------
// Shared returns — `returns (shared(msg.sender) eT)`
// ---------------------------------------------------------------------------

fn scan_returns<'ast>(
    unit: &BoundUnit<'ast>,
    trust: &Trust,
    profile: &dyn TargetProfile,
    out: &mut CheckedUnit,
    fid: fhec_bind::FunctionId,
    f: &FunctionInfo<'ast>,
) {
    let returns: Vec<&ast::VariableDefinition<'ast>> = f.ast.header.returns().iter().collect();
    if returns.iter().all(|r| r.shared.is_none()) {
        return;
    }
    let anchor = returns
        .iter()
        .find_map(|r| r.shared.as_ref())
        .expect("at least one shared marker")
        .span;

    // Signature rules first, each refusing the function outright. The first
    // failure ends the scan: a return list of the wrong shape makes every
    // statement-level judgement about it misleading.
    if f.ast.kind != ast::FunctionKind::Function {
        return bad_position(
            out,
            anchor,
            format!(
                "a shared return is only permitted on a `function`, not on a `{}`",
                f.ast.kind.to_str()
            ),
        );
    }
    if !matches!(
        f.ast.header.visibility(),
        Some(ast::Visibility::Public) | Some(ast::Visibility::External)
    ) {
        return bad_position(
            out,
            anchor,
            "a shared return is only permitted on a `public` or `external` function: a shared \
             handle is an ABI wire type, so an internal caller has nothing to receive"
                .to_string(),
        );
    }
    if matches!(
        f.ast.header.state_mutability(),
        ast::StateMutability::View | ast::StateMutability::Pure
    ) {
        return bad_position(
            out,
            anchor,
            "a shared return is not permitted on a `view` or `pure` function: sharing a \
             handle changes the access-control state"
                .to_string(),
        );
    }
    // MVP: exactly one unnamed shared return, alone in its list. A tuple, a
    // named fallthrough return, or a list that mixes a shared return with a
    // plain or encrypted one are all refused rather than resolved.
    if returns.len() != 1 {
        return bad_position(
            out,
            anchor,
            "a shared return must be the only return of its function: this list declares \
             more than one return value"
                .to_string(),
        );
    }
    let decl = returns[0];
    let shared = decl.shared.as_ref().expect("the only return carries it");
    match shared.recipient.as_ref() {
        None => {
            return bad_position(
                out,
                shared.span,
                format!("a shared return must name its recipient: `shared({RECIPIENT}) eT`"),
            );
        }
        Some(e) if !fhec_syntax::is_msg_sender(e) => {
            return bad_position(
                out,
                e.span,
                format!(
                    "the only recipient this version accepts is `{RECIPIENT}`; the transpiler \
                     cannot prove another expression names the caller"
                ),
            );
        }
        Some(_) => {}
    }
    if decl.in_sugar.is_some() {
        return bad_position(
            out,
            shared.span,
            "`in` marks an input parameter and has no meaning on a return type".to_string(),
        );
    }
    if decl.name.is_some() {
        return bad_position(
            out,
            decl.span,
            "a shared return must be unnamed: the value is wrapped where it is returned, so \
             a named fallthrough return has nothing to wrap"
                .to_string(),
        );
    }
    let ty = declared_ty(unit, trust, &decl.ty);
    let Ty::Encrypted(ety) = ty else {
        return bad_position(
            out,
            decl.ty.span,
            "`shared(...)` must be followed by an encrypted type \
             (ebool, euint8..euint128, eaddress)"
                .to_string(),
        );
    };
    if !supports_shared(profile, out, ety, shared.span) {
        return;
    }

    let mut refused = false;
    let mut return_exprs: Vec<Span> = Vec::new();
    let r2_owned = r2_owned_stmts(out, fid);
    if let Some(body) = &f.ast.body {
        let mut found: Vec<(&ast::Stmt<'ast>, bool)> = Vec::new();
        for s in body.stmts.iter() {
            collect_returns(s, true, &mut found);
        }
        for (stmt, braced) in found {
            let ast::StmtKind::Return(e) = &stmt.kind else {
                unreachable!("collect_returns only yields return statements");
            };
            let Some(e) = e else {
                refused = true;
                bad_position(
                    out,
                    stmt.span,
                    "a function with a shared return must return a value explicitly: \
                     `return <expr>;`"
                        .to_string(),
                );
                continue;
            };
            if !braced {
                refused = true;
                bad_position(
                    out,
                    stmt.span,
                    "a `return` of a shared value must sit inside a braced block: wrap the \
                     branch body in `{ }`"
                        .to_string(),
                );
                continue;
            }
            if let Some(span) = assignment_in(e) {
                refused = true;
                bad_position(
                    out,
                    span,
                    "the returned expression of a shared return must not assign: assign in \
                     its own statement and return the variable"
                        .to_string(),
                );
                continue;
            }
            if r2_owned.iter().any(|owned| span_within(stmt.span, *owned)) {
                if let Some(site) = rewrite_site_in(out, fid, e.span) {
                    refused = true;
                    bad_position(
                        out,
                        site,
                        "this `return` sits in a statement the §8.2 R2 rule owns (an external \
                         call there takes an encrypted argument), and the returned expression \
                         still needs lowering; R2 renders only its own call site, and a shared \
                         return replaces the R3 re-render that used to cover the rest. \
                         Compute the value in its own statement and return the variable"
                            .to_string(),
                    );
                    continue;
                }
            }
            match out.types.get(e.span) {
                Some(Ty::Encrypted(t)) if *t == ety => return_exprs.push(e.span),
                other => {
                    refused = true;
                    out.diagnostics.push(
                        Diagnostic::error(
                            codes::SHARED_BOUNDARY_TYPE_MISMATCH,
                            e.span,
                            format!(
                                "this function shares `{}`, but the returned expression is {}",
                                ety.solidity_name(),
                                describe(other)
                            ),
                        )
                        .with_rule(RULE),
                    );
                }
            }
        }
    }

    if !refused {
        out.shared_return_sites.push(SharedReturnSite {
            decl_span: decl.span,
            ty: ety,
            recipient: RECIPIENT.to_string(),
            return_exprs,
            function: fid,
            file: f.file,
        });
    }
}

/// The statement spans one function's R2 facts (§8.2) anchor on.
///
/// A statement that triggers R2 becomes the ACL pass's property: R2 inserts its
/// `allowTransient` grants before the statement and renders the call site
/// itself, and pass 1 then skips **every** statement inside that span, not only
/// the one R2 rendered. Anything else in that span that needs lowering is
/// therefore dropped without a word. That is a tracked defect of the ACL/ops
/// composition (issue #38), older and wider than the shared boundary; this
/// rule fences the shared boundary off from it, it does not repair it.
///
/// A shared return newly exposes it through `return`. While R3 (§8.3) applied,
/// its whole-statement re-render happened to lower the returned expression as
/// well; a shared return suppresses R3 and wraps in place with two zero-width
/// insertions, so nothing covers the expression any more. Rather than emit a
/// silently wrong ciphertext (§1.3), refuse the shape.
///
/// The judgement is deliberately conservative: the checker knows neither the
/// ACL mode nor whether R2 will dedupe against a grant the source already
/// carries, and either would make R2 leave the statement alone. A stated fact
/// is enough to refuse.
fn r2_owned_stmts(out: &CheckedUnit, fid: fhec_bind::FunctionId) -> Vec<Span> {
    out.acl
        .external_args
        .iter()
        .filter(|c| c.function == fid)
        .map(|c| c.stmt_span)
        .collect()
}

/// The span of the first rewrite site lowering would have to render inside
/// `expr`, if any.
///
/// Only expression-level sites can occur in a returned expression. Assignment
/// sites (compound assignment, `++`/`--`) cannot: restriction 1 above refuses
/// those first.
fn rewrite_site_in(out: &CheckedUnit, fid: fhec_bind::FunctionId, expr: Span) -> Option<Span> {
    let operators = out
        .operator_sites
        .iter()
        .filter(|s| s.function == fid)
        .map(|s| s.span);
    let ternaries = out
        .ternary_sites
        .iter()
        .filter(|s| s.function == fid)
        .map(|s| s.span);
    operators
        .chain(ternaries)
        .find(|span| span_within(*span, expr))
}

/// Every `return` statement of a body, paired with whether it sits inside a
/// braced block rather than being the bare body of a conditional or a loop.
fn collect_returns<'ast>(
    stmt: &'ast ast::Stmt<'ast>,
    braced: bool,
    out: &mut Vec<(&'ast ast::Stmt<'ast>, bool)>,
) {
    use ast::StmtKind::*;
    match &stmt.kind {
        Return(_) => out.push((stmt, braced)),
        Block(b) | UncheckedBlock(b) | Precondition(b) => {
            for s in b.stmts.iter() {
                collect_returns(s, true, out);
            }
        }
        If(_, t, e) => {
            collect_returns(t, false, out);
            if let Some(e) = e {
                collect_returns(e, false, out);
            }
        }
        While(_, b) | DoWhile(b, _) => collect_returns(b, false, out),
        For { init, body, .. } => {
            if let Some(init) = init {
                collect_returns(init, false, out);
            }
            collect_returns(body, false, out);
        }
        Try(t) => {
            for clause in t.clauses.iter() {
                for s in clause.block.stmts.iter() {
                    collect_returns(s, true, out);
                }
            }
        }
        _ => {}
    }
}

/// The span of the first assignment, `++`, or `--` inside an expression.
fn assignment_in<'ast>(e: &'ast ast::Expr<'ast>) -> Option<Span> {
    use ast::visit::Visit;
    use std::ops::ControlFlow;

    struct Search {
        found: Option<Span>,
    }
    impl<'ast> Visit<'ast> for Search {
        type BreakValue = ();
        fn visit_expr(&mut self, e: &'ast ast::Expr<'ast>) -> ControlFlow<()> {
            let hit = match &e.kind {
                ast::ExprKind::Assign(..) => true,
                ast::ExprKind::Unary(op, _) => matches!(
                    op.kind,
                    ast::UnOpKind::PreInc
                        | ast::UnOpKind::PreDec
                        | ast::UnOpKind::PostInc
                        | ast::UnOpKind::PostDec
                ),
                _ => false,
            };
            if hit {
                self.found = Some(e.span);
                return ControlFlow::Break(());
            }
            self.walk_expr(e)
        }
    }
    let mut s = Search { found: None };
    let _ = s.visit_expr(e);
    s.found
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Illegal item-level positions: event/error parameters and state variables.
fn scan_item(out: &mut CheckedUnit, item: &ast::Item<'_>) {
    match &item.kind {
        ast::ItemKind::Contract(c) => {
            for inner in c.body.iter() {
                scan_item(out, inner);
            }
        }
        ast::ItemKind::Event(ev) => {
            for p in ev.parameters.vars.iter() {
                if let Some(s) = p.shared.as_ref() {
                    wrong_place(out, s.span, "an event parameter list");
                }
            }
        }
        ast::ItemKind::Error(err) => {
            for p in err.parameters.vars.iter() {
                if let Some(s) = p.shared.as_ref() {
                    wrong_place(out, s.span, "an error parameter list");
                }
            }
        }
        ast::ItemKind::Variable(v) => {
            if let Some(s) = v.shared.as_ref() {
                wrong_place(out, s.span, "a variable declaration");
            }
        }
        _ => {}
    }
}

fn wrong_place(out: &mut CheckedUnit, span: Span, place: &str) {
    bad_position(
        out,
        span,
        format!(
            "a shared-boundary marker is only permitted on a function parameter \
             (`in shared eT name`) or on a function return type (`shared(msg.sender) eT`), \
             not in {place}"
        ),
    );
}

/// Reports the profile gap behind a missing shared boundary as FHE5001 and
/// returns whether the boundary exists.
fn supports_shared(
    profile: &dyn TargetProfile,
    out: &mut CheckedUnit,
    ty: EType,
    span: Span,
) -> bool {
    match profile.shared_wire_type(ty) {
        Ok(_) => true,
        Err(e) => {
            out.diagnostics.push(
                Diagnostic::error(
                    codes::OP_NOT_IN_PROFILE,
                    span,
                    format!("the shared boundary cannot be lowered here: {e}"),
                )
                .with_rule("§1.5"),
            );
            false
        }
    }
}

fn describe(ty: Option<&Ty>) -> String {
    match ty {
        Some(Ty::Encrypted(t)) => format!("`{}`", t.solidity_name()),
        Some(Ty::Plain(_)) => "a plaintext value".to_string(),
        _ => "of a type the checker cannot prove is that encrypted type".to_string(),
    }
}

fn bad_position(out: &mut CheckedUnit, span: Span, message: String) {
    out.diagnostics.push(
        Diagnostic::error(codes::SHARED_BOUNDARY_BAD_POSITION, span, message).with_rule(RULE),
    );
}
