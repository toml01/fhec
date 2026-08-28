//! The emit-time twin of `trust.rs` (spec §1.3): every function the lowerer
//! will splice a generated `FHE.<op>(...)` call into must have `FHE` still
//! resolve to the trusted profile library at that function's scope. A state
//! variable, local, parameter, inherited member, or member of a base the
//! unit cannot see can all shadow `FHE` and silently retarget every
//! generated call and ACL grant in the function — the checker's trust rule
//! only ever asked this question for *reads* of `FHE` written by the author;
//! this asks it for the *writes* the lowerer is about to make.
//!
//! A collision with a name the transpiler must write is the same class of
//! problem as the FHE1011/FHE1016 generated-name collisions: refuse rather
//! than silently rename around it.

use std::collections::HashSet;

use fhec_bind::{BoundUnit, FunctionId, Resolution};
use solar_interface::{Span, Symbol};

use crate::diag::{codes, Diagnostic};
use crate::sites::CheckedUnit;
use crate::trust::Trust;

/// Scans every function that at least one collected rewrite site or ACL fact
/// says will need a generated `FHE.` call, and refuses with FHE1022 when
/// `FHE` does not resolve to the profile library at that function's scope.
///
/// Must run after every pass that populates `out`'s site/fact vectors
/// (`sugar`, the main `walk`, and `shared` — the shared-boundary sites are
/// the last ones stated).
pub(crate) fn scan(unit: &BoundUnit<'_>, trust: &Trust, out: &mut CheckedUnit) {
    let fhe = Symbol::intern("FHE");
    let mut seen: HashSet<FunctionId> = HashSet::new();
    let mut diags = Vec::new();
    for function in functions_writing_fhe(out) {
        if !seen.insert(function) {
            continue;
        }
        let info = unit.function(function);
        let res = unit.resolve_name_in_scope(Some(function), info.contract, info.file, fhe, "FHE");
        if trust.is_fhe_library(unit, "FHE", &res) {
            continue;
        }
        // `Unresolved` carries no competing declaration to blame — `FHE`
        // simply has no binding here at all, in or out of the unit. Writing
        // the generated call would then fail loudly at solc as an undefined
        // identifier, which is not the silent-miscompile risk this rule
        // guards against, and is also the same residual uncertainty the
        // read-side trust rule already accepts for an incomplete
        // inheritance surface (`trust.rs` rule 3) rather than reject every
        // inheriting contract.
        if matches!(res, Resolution::Unresolved(_)) {
            continue;
        }
        let span = shadow_span(unit, &res).unwrap_or(info.span);
        diags.push(
            Diagnostic::error(
                codes::FHE_LIBRARY_IDENTIFIER_SHADOWED,
                span,
                "this declaration shadows `FHE`, the identifier a generated call in this \
                 function must use; the call would silently bind to it instead of the \
                 profile library (the transpiler never renames a generated call around a \
                 collision) — rename this declaration",
            )
            .with_rule("§1.3"),
        );
    }
    out.diagnostics.extend(diags);
}

/// Every function id that at least one collected site or ACL fact will need
/// to write a generated `FHE.` call in. `precondition_sites` is the only
/// site kind that never does (it only locates the materialization point for
/// the others), so it is intentionally excluded.
fn functions_writing_fhe(out: &CheckedUnit) -> impl Iterator<Item = FunctionId> + '_ {
    out.operator_sites
        .iter()
        .map(|s| s.function)
        .chain(out.ternary_sites.iter().map(|s| s.function))
        .chain(out.if_sites.iter().map(|s| s.function))
        .chain(out.compound_sites.iter().map(|s| s.function))
        .chain(out.incdec_sites.iter().map(|s| s.function))
        .chain(out.cast_sugar_sites.iter().map(|s| s.function))
        .chain(out.sugar_sites.iter().map(|s| s.function))
        .chain(out.shared_input_sites.iter().map(|s| s.function))
        .chain(out.shared_return_sites.iter().map(|s| s.function))
        .chain(out.acl.storage_writes.iter().map(|s| s.function))
        .chain(out.acl.external_args.iter().map(|s| s.function))
        .chain(out.acl.returns.iter().map(|s| s.function))
}

/// The most useful span to point the diagnostic at: the offending
/// declaration itself, when the untrusted resolution carries one.
fn shadow_span(unit: &BoundUnit<'_>, res: &Resolution) -> Option<Span> {
    match res {
        Resolution::Local(v)
        | Resolution::Param(v)
        | Resolution::StateVar(v)
        | Resolution::FileConst(v) => {
            let info = unit.var(*v);
            Some(info.name.map(|n| n.span).unwrap_or(info.decl.span))
        }
        Resolution::Contract(id) => Some(unit.contract(*id).name.span),
        Resolution::TypeName(id) => Some(unit.type_decl(*id).name.span),
        Resolution::Function(fs) => fs
            .first()
            .and_then(|f| unit.function(*f).name)
            .map(|n| n.span),
        _ => None,
    }
}
