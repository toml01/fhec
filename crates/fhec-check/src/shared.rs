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

use fhec_bind::{
    BaseRef, BoundUnit, ContractId, FunctionInfo, Resolution, SourceFile, UnresolvedReason,
};
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

/// Whether an expression is `msg.sender` where `msg` *resolves* to the
/// Solidity builtin, not merely an expression spelled that way.
///
/// Structural spelling is not enough: a parameter, local, or struct field
/// literally named `msg` shadows the builtin, and the checker must not
/// accept a shadowed `msg.sender` as the recipient. Doing so would let the
/// lowerer's fixed `msg.sender` re-emission (spec §2.8) resolve, in the
/// generated Solidity, to whatever the shadowing declaration is — a
/// caller-controlled value in the worst case (issue #61). Requiring the
/// resolution, not the text, is the only way to keep the transpiler's proof
/// that no other expression evaluates to the real caller (restriction 2).
///
/// Under an incomplete linearization (an unseen base), `msg` degrades to
/// [`UnresolvedReason::IncompleteInheritance`] like any other name that is
/// not the contract's own member — an unseen base could in principle also
/// declare a member named `msg`. Requiring `Resolution::Builtin` outright
/// would then refuse `shared(msg.sender)` in every contract that inherits
/// from a package, which is the dominant real-world shape (spec §2.8 already
/// has fixture/test coverage for it). This module follows the same narrow,
/// established policy as `precondition.rs`'s `callee_resolution` for
/// `require`: trust the `fallback` — what file scope alone would have
/// answered — exactly when it says `Builtin`, and only then. A base that
/// truly shadows `msg` defeats this, the same general hazard already
/// documented there.
fn resolves_to_msg_sender(unit: &BoundUnit<'_>, e: &ast::Expr<'_>) -> bool {
    let ast::ExprKind::Member(base, member) = &e.peel_parens().kind else {
        return false;
    };
    if member.as_str() != "sender" {
        return false;
    }
    let ast::ExprKind::Ident(id) = &base.peel_parens().kind else {
        return false;
    };
    let is_msg_builtin = |r: &Resolution| matches!(r, Resolution::Builtin(b) if b.0 == "msg");
    match unit.resolve(*id) {
        Some(r) if is_msg_builtin(r) => true,
        Some(Resolution::Unresolved(UnresolvedReason::IncompleteInheritance {
            fallback, ..
        })) => is_msg_builtin(fallback),
        _ => false,
    }
}

/// The span of the first local declaration named `msg` anywhere in `body`,
/// if any — a plain local, a tuple-declaration component, a `for`-init
/// declaration, or a `try`/`catch` binder. Any of these is a *declaration*
/// that shadows the `msg` builtin (Solidity scoping); a plain *use* of the
/// name (an ordinary identifier expression) does not, and must not trip
/// this, or a legitimate `shared(msg.sender)` return would refuse itself by
/// finding its own header recipient.
///
/// Deliberately does not track which declarations are actually in scope at
/// which `return`: see the call site in [`scan_returns`] for why the
/// over-approximation (refuse on any declaration in the body, not just one
/// that provably reaches a `return`) is the conservative and simple choice.
fn body_shadows_msg<'ast>(body: &'ast ast::Block<'ast>) -> Option<Span> {
    use ast::visit::Visit;
    use std::ops::ControlFlow;

    struct Search;
    impl<'ast> Visit<'ast> for Search {
        type BreakValue = Span;

        fn visit_variable_definition(
            &mut self,
            var: &'ast ast::VariableDefinition<'ast>,
        ) -> ControlFlow<Self::BreakValue> {
            if let Some(name) = var.name {
                if name.as_str() == "msg" {
                    return ControlFlow::Break(name.span);
                }
            }
            ControlFlow::Continue(())
        }
    }

    match Search.visit_block(body) {
        ControlFlow::Break(span) => Some(span),
        ControlFlow::Continue(()) => None,
    }
}

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
        scan_params(files, unit, trust, profile, out, fid, f);
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

#[allow(clippy::too_many_arguments)]
fn scan_params<'ast>(
    files: &[SourceFile<'ast>],
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
    let profile_import = crate::imports::selective_profile_import(files[f.file.index()].ast, trust);

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
    // `external` only, not `public`. Lowering rewrites the declaration alone;
    // an internal call site keeps passing the source `eT`, which no longer
    // matches the generated `sharedT` parameter. A `public` function is
    // callable internally (self-calls, recursion), so allowing it would emit
    // Solidity that does not type-check. `external` has no internal call
    // sites, so the rewrite is complete by construction.
    if f.ast.header.visibility() != Some(ast::Visibility::External) {
        return bad_position(
            out,
            anchor,
            "`in shared` is only permitted on an `external` function: a shared handle is an \
             ABI wire type, and an internal call site is not rewritten, so a `public` \
             function's own internal callers could not pass one"
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
        if let Some(loc) = decl.data_location {
            refused = true;
            bad_data_location(out, decl.span, loc);
            continue;
        }
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
            // The dominant cause is a selective import that names only the
            // `shared*` wire types — exactly the files that reach for this
            // marker first. Say that instead of listing the type the author
            // already wrote (spec §2.8).
            if let Some(import) = &profile_import {
                if let Some(name) = crate::sugar::unimported_encrypted_type(&decl.ty, import) {
                    crate::sugar::refuse_symbol_not_imported(
                        out,
                        decl.ty.span,
                        import,
                        &name,
                        "it names a profile encrypted type",
                        RULE,
                    );
                    continue;
                }
            }
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
        // The expansion declares the parameter with the shared wire type,
        // which a selective import must also name (spec §2.8).
        if let Some(import) = &profile_import {
            if let Ok(wire) = profile.shared_wire_type(ety) {
                if !import.has(&wire) {
                    refused = true;
                    crate::sugar::refuse_symbol_not_imported(
                        out,
                        decl.ty.span,
                        import,
                        &wire,
                        "the expansion declares the parameter with it",
                        RULE,
                    );
                    continue;
                }
            }
        }
        // A bodiless declaration generates no local and keeps the author's
        // parameter name, so no name is introduced to collide.
        let generated = format!("{}{WIRE_SUFFIX}", name.as_str());
        if f.ast.body.is_some() && ident_occurs(f.ast, &generated) {
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
        if let Some(span) = crate::sugar::modifier_reference(f.ast, name.as_str()) {
            refused = true;
            crate::sugar::refuse_modifier_reference(out, span, name.as_str(), &generated, RULE);
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
    if let Some(loc) = decl.data_location {
        return bad_data_location(out, decl.span, loc);
    }
    match shared.recipient.as_ref() {
        None => {
            return bad_position(
                out,
                shared.span,
                format!("a shared return must name its recipient: `shared({RECIPIENT}) eT`"),
            );
        }
        Some(e) if !resolves_to_msg_sender(unit, e) => {
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
    // The header recipient resolves to the builtin at the point it is
    // checked (params and named returns in scope, nothing declared in the
    // body yet). But the lowerer does not carry that resolution forward: it
    // re-emits the literal text `msg.sender` fresh at every `return`
    // (spec §2.8's rewrite). A local, a `for`-init declaration, or a
    // `try`/`catch` binder named `msg` anywhere in the body shadows the
    // builtin in Solidity from its declaration point onward, which would
    // flip a later re-emitted `msg.sender` to read the shadowing
    // declaration instead of the real transaction sender (issue #61 follow
    // up). Working out exactly which `return`s a given declaration reaches
    // needs the same per-statement reachability analysis this module
    // elsewhere avoids, so this refuses the whole function instead of
    // guessing (§1.3) — a function legitimately declaring something named
    // `msg` is not a real-world shape worth the extra precision for.
    if let Some(body) = &f.ast.body {
        if let Some(shadow_span) = body_shadows_msg(body) {
            return bad_position(
                out,
                shadow_span,
                "this function declares a local named `msg`, which shadows the builtin from \
                 here onward; the shared return's recipient, `msg.sender`, is re-emitted at \
                 every `return` and would then read this declaration instead of the real \
                 transaction sender — rename it"
                    .to_string(),
            );
        }
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
            let recorded = out.types.get(e.span);
            match recorded {
                Some(Ty::Encrypted(t)) if *t == ety => return_exprs.push(e.span),
                // An unreadable base is the one cause fhec cannot rule out by
                // reading harder, and it is also the one cause the output
                // checks for itself: the rewrite takes the encrypted type
                // from the *declared* return, so a wrong assumption reaches
                // solc as a type error on `FHE.shareT(...)`, never as a
                // silent ciphertext. Warn and proceed rather than refuse
                // every contract that inherits from a package.
                None | Some(Ty::Unknown)
                    if incomplete_inheritance_call(unit, trust, e).is_some() =>
                {
                    return_exprs.push(e.span);
                    out.diagnostics.push(
                        Diagnostic::warning(
                            codes::SHARED_BOUNDARY_TYPE_MISMATCH,
                            e.span,
                            format!(
                                "this function shares `{}`, but {}; the rewrite assumes the \
                                 declared type, and solc rejects the output if that is wrong",
                                ety.solidity_name(),
                                describe_mismatch(unit, trust, e, recorded)
                            ),
                        )
                        .with_rule(RULE),
                    );
                }
                other => {
                    refused = true;
                    out.diagnostics.push(
                        Diagnostic::error(
                            codes::SHARED_BOUNDARY_TYPE_MISMATCH,
                            e.span,
                            format!(
                                "this function shares `{}`, but {}",
                                ety.solidity_name(),
                                describe_mismatch(unit, trust, e, other)
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

/// Illegal item-level positions: event/error parameters, state variables, and
/// the in-body declaration lists of a `try` statement.
fn scan_item<'ast>(out: &mut CheckedUnit, item: &'ast ast::Item<'ast>) {
    match &item.kind {
        ast::ItemKind::Contract(c) => {
            for inner in c.body.iter() {
                scan_item(out, inner);
            }
        }
        ast::ItemKind::Function(f) => {
            if let Some(body) = &f.body {
                scan_body(out, body);
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

/// Refuses a shared marker in a `try` statement's declaration lists.
///
/// Solar parses the success clause's `returns (...)` list and every `catch`
/// clause's argument list with the ordinary function-parameter grammar, so a
/// marker can be written in either (allow-and-flag). Neither is a legal
/// position (§2.8), and neither is reachable through `BoundUnit`'s function
/// headers, so the body is walked here. Without this the marker reaches the
/// emitter unlowered and leaks raw `shared(...)` / `in shared` text into the
/// generated Solidity, where only the solc gate rejects it — far from the
/// construct that caused it.
fn scan_body<'ast>(out: &mut CheckedUnit, body: &'ast ast::Block<'ast>) {
    use ast::visit::Visit;
    use std::ops::ControlFlow;

    struct Search<'a> {
        out: &'a mut CheckedUnit,
    }
    impl<'ast> Visit<'ast> for Search<'_> {
        type BreakValue = std::convert::Infallible;

        fn visit_stmt(&mut self, stmt: &'ast ast::Stmt<'ast>) -> ControlFlow<Self::BreakValue> {
            if let ast::StmtKind::Try(t) = &stmt.kind {
                // Solar always pushes the success clause first, whether or not
                // the source wrote a `returns (...)` list for it.
                for (i, clause) in t.clauses.iter().enumerate() {
                    let place = if i == 0 {
                        "a `try` return-parameter list"
                    } else {
                        "a `catch` clause parameter list"
                    };
                    for p in clause.args.vars.iter() {
                        if let Some(s) = p.shared.as_ref() {
                            wrong_place(self.out, s.span, place);
                        }
                    }
                }
            }
            self.walk_stmt(stmt)
        }
    }

    let mut search = Search { out };
    let _ = search.visit_block(body);
}

/// Refuses an explicit data location on a shared-marked declaration.
///
/// Encrypted types and their shared wire types are value types, so no location
/// applies; plain Solidity rejects `euint64 calldata v` outright. Whole-
/// declaration replacement in the lowerer would drop the keyword silently,
/// which is exactly the "guess instead of refuse" §1.3 forbids.
fn bad_data_location(out: &mut CheckedUnit, span: Span, loc: ast::DataLocation) {
    bad_position(
        out,
        span,
        format!(
            "a shared-boundary declaration takes no data location: `{loc}` has no meaning on \
             an encrypted value type (remove it)"
        ),
    );
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

fn describe_mismatch(
    unit: &BoundUnit<'_>,
    trust: &Trust,
    expr: &ast::Expr<'_>,
    ty: Option<&Ty>,
) -> String {
    match ty {
        Some(Ty::Encrypted(t)) => {
            format!("the returned expression is `{}`", t.solidity_name())
        }
        Some(Ty::Plain(_)) => "the returned expression is a plaintext value".to_string(),
        _ => incomplete_inheritance_call(unit, trust, expr).unwrap_or_else(|| {
            "the returned expression is of a type the checker cannot prove is that encrypted type"
                .to_string()
        }),
    }
}

/// The FHE2012 explanation for a call whose callee this unit cannot see past
/// an incomplete inheritance surface.
///
/// `trust` is consulted so a call the checker types *through the profile
/// library* never qualifies: an `Unknown` there means the profile does not
/// model that operation, which the unreadable surface did not cause and which
/// solc will not catch. Only a callee the unit genuinely cannot resolve does.
fn incomplete_inheritance_call(
    unit: &BoundUnit<'_>,
    trust: &Trust,
    expr: &ast::Expr<'_>,
) -> Option<String> {
    let ast::ExprKind::Call(callee, _) = &expr.peel_parens().kind else {
        return None;
    };
    let (name, root) = callee_path(callee)?;
    let res = unit.resolve(root)?;
    if trust.is_fhe_library(unit, root.as_str(), res) {
        return None;
    }
    let Resolution::Unresolved(UnresolvedReason::IncompleteInheritance { contract, .. }) = res
    else {
        return None;
    };
    let contract_name = &unit.contract(*contract).name_str;
    let cause = opaque_base(unit, *contract, &mut Vec::new()).map_or_else(
        || "has an inherited surface the binder cannot establish completely".to_string(),
        |base| match base {
            OpaqueBase::External(base) => {
                format!("inherits `{base}`, which is outside the compilation unit")
            }
            OpaqueBase::Unknown(base) => {
                format!("inherits `{base}`, which cannot be resolved inside the compilation unit")
            }
        },
    );
    Some(format!(
        "`{name}` resolves to `Unknown` because contract `{contract_name}` {cause}"
    ))
}

fn callee_path(expr: &ast::Expr<'_>) -> Option<(String, solar_interface::Ident)> {
    match &expr.peel_parens().kind {
        ast::ExprKind::Ident(id) => Some((id.as_str().to_string(), *id)),
        ast::ExprKind::Member(object, member) => {
            let (prefix, root) = callee_path(object)?;
            Some((format!("{prefix}.{}", member.as_str()), root))
        }
        ast::ExprKind::CallOptions(inner, _) => callee_path(inner),
        _ => None,
    }
}

enum OpaqueBase {
    External(String),
    Unknown(String),
}

fn opaque_base(
    unit: &BoundUnit<'_>,
    contract: ContractId,
    seen: &mut Vec<ContractId>,
) -> Option<OpaqueBase> {
    if seen.contains(&contract) {
        return None;
    }
    seen.push(contract);
    for base in &unit.contract(contract).bases {
        match base {
            BaseRef::External { name, .. } => return Some(OpaqueBase::External(name.clone())),
            BaseRef::Unknown { name } => return Some(OpaqueBase::Unknown(name.clone())),
            BaseRef::InUnit(base) => {
                if let Some(cause) = opaque_base(unit, *base, seen) {
                    return Some(cause);
                }
            }
        }
    }
    None
}

fn bad_position(out: &mut CheckedUnit, span: Span, message: String) {
    out.diagnostics.push(
        Diagnostic::error(codes::SHARED_BOUNDARY_BAD_POSITION, span, message).with_rule(RULE),
    );
}
