//! The emit-time twin of `trust.rs` (spec §1.3): every function the lowerer
//! will splice a generated call into must have the identifiers that call
//! uses still resolve to the trusted profile module at that function's
//! scope. A state variable, local, parameter, inherited member, or member
//! of a base the unit cannot see can all shadow one of those identifiers
//! and silently retarget the generated call (or ACL grant) it belongs to —
//! `trust.rs` only ever asked this question for *reads* written by the
//! author; this asks it for the *writes* the lowerer is about to make.
//!
//! Two identifier families are checked, at the same function granularity:
//!
//! - **`FHE`** (spec §1.5), used by every operator/select/cast/ACL/shared-
//!   boundary call the lowerer writes. Trust reuses `trust::is_fhe_library`
//!   verbatim, including its rule 4 (in-unit library declaration).
//! - The *batched* `in`-sugar materializer (`TargetProfile::
//!   batch_input_statements`, cofhe-contracts#78), used when a function has
//!   more than one `in` parameter with a body: `Impl`, `Utils`,
//!   `UnsignedEncryptedInput`, plus the wire/encrypted type names the batch
//!   actually uses (`externalT.unwrap(...)`, `eT.wrap(...)` for each `T` the
//!   function's `in` parameters name). None of these have a rule-4-style
//!   structural signature of their own to recognize; trust instead follows
//!   `Trust::is_trusted_profile_declaration` (the generic exposure paths,
//!   plus being declared in-unit in the same file as the recognized
//!   `library FHE`) or, for the type names, `Trust::encrypted_type` /
//!   `Trust::external_input_type`.
//!
//! A collision with a name the transpiler must write is the same class of
//! problem as the FHE1011/FHE1016 generated-name collisions: refuse rather
//! than silently rename around it (FHE1022).

use std::collections::{HashMap, HashSet};

use fhec_bind::{BoundUnit, FunctionId, Resolution, UnresolvedReason};
use fhec_ir::EType;
use solar_interface::{Span, Symbol};

use crate::diag::{codes, Diagnostic};
use crate::sites::CheckedUnit;
use crate::trust::Trust;

/// The batch `in`-sugar materializer's fixed identifiers (spec §2.3),
/// besides `FHE` itself.
const BATCH_MATERIALIZER_NAMES: [&str; 3] = ["Impl", "Utils", "UnsignedEncryptedInput"];

/// Scans every function that at least one collected rewrite site or ACL fact
/// says will need a generated call, and refuses with FHE1022 when the
/// identifier that call must use does not resolve to the profile module at
/// that function's scope.
///
/// Must run after every pass that populates `out`'s site/fact vectors
/// (`sugar`, the main `walk`, and `shared` — the shared-boundary sites are
/// the last ones stated).
pub(crate) fn scan(unit: &BoundUnit<'_>, trust: &Trust, out: &mut CheckedUnit) {
    let mut diags = Vec::new();
    let mut seen: HashSet<(String, FunctionId)> = HashSet::new();

    for function in functions_writing_fhe(out) {
        check_one(unit, function, "FHE", &mut seen, &mut diags, |res| {
            trust.is_fhe_library(unit, "FHE", res)
        });
    }
    for (function, types) in functions_writing_batch_materializer(out) {
        for name in BATCH_MATERIALIZER_NAMES {
            check_one(unit, function, name, &mut seen, &mut diags, |res| {
                trust.is_trusted_profile_declaration(unit, res)
            });
        }
        for ty in types {
            let external = ty.external_name();
            check_one(unit, function, external, &mut seen, &mut diags, |res| {
                trust.external_input_type(unit, external, res).is_some()
            });
            let plain = ty.solidity_name();
            check_one(unit, function, plain, &mut seen, &mut diags, |res| {
                trust.encrypted_type(unit, plain, res).is_some()
            });
        }
    }
    out.diagnostics.extend(diags);
}

/// Checks one (identifier, function) pair once, pushing FHE1022 when the
/// identifier is shadowed rather than trusted.
fn check_one(
    unit: &BoundUnit<'_>,
    function: FunctionId,
    name: &str,
    seen: &mut HashSet<(String, FunctionId)>,
    diags: &mut Vec<Diagnostic>,
    is_trusted: impl Fn(&Resolution) -> bool,
) {
    if !seen.insert((name.to_string(), function)) {
        return;
    }
    let info = unit.function(function);
    let symbol = Symbol::intern(name);
    let res = unit.resolve_name_in_scope(Some(function), info.contract, info.file, symbol, name);

    // A known (in-unit) ancestor's own declaration always beats the
    // incomplete-inheritance fallback's benefit of the doubt: it is
    // concrete proof of a real, visible shadow, not mere uncertainty about
    // an unseen base. `resolve_name_in_scope` cannot always surface it
    // itself — a *trailing* opaque base in the linearization can block the
    // "provably first" prefix it computes even when an earlier, in-unit
    // base already declares `name` — so recheck explicitly whenever the
    // resolution took the incomplete-inheritance path.
    if let Resolution::Unresolved(UnresolvedReason::IncompleteInheritance { contract, .. }) = &res {
        if let Some(shadow) = unit.known_ancestor_member(*contract, symbol) {
            let span = shadow_span(unit, &shadow).unwrap_or(info.span);
            diags.push(diagnostic_for(name, &shadow, span));
            return;
        }
    }

    if is_trusted(&res) {
        return;
    }
    // Only a provably total absence of any binding (`NotFound`) is safe to
    // let through unflagged: nothing anywhere — in the unit or out of it —
    // can define `name`, so writing the generated call fails loudly at solc
    // as an undefined identifier, which is not the silent-miscompile risk
    // this rule guards against.
    //
    // Every other `Unresolved` reason means *something* unconfirmed could
    // still define `name`, silently:
    // - `MaybeExternal`: some plain-imported file the binder cannot see
    //   into might export it.
    // - `IncompleteInheritance`: an unseen base might declare it — the
    //   binder's own fallback already gives the explicit-profile-import
    //   case the benefit of the doubt (`is_trusted` would have returned
    //   `true` above, via `Trust::resolution_trusted`'s recursive fallback
    //   check, and the known-ancestor check above already ruled out a
    //   visible shadow); reaching this point means even that fallback did
    //   not prove it, so the unseen base is the only remaining explanation
    //   and must be refused, not waved through.
    // - `Ambiguous` / `ImportFailed` / `MaybeReExport`: likewise unconfirmed.
    //
    // This is the exact shape of the original issue's "member of a base
    // outside the compilation unit" repro variant, just reached without an
    // explicit competing declaration in scope.
    if matches!(res, Resolution::Unresolved(UnresolvedReason::NotFound)) {
        return;
    }
    let span = shadow_span(unit, &res).unwrap_or(info.span);
    diags.push(diagnostic_for(name, &res, span));
}

/// The FHE1022 diagnostic for one untrusted resolution of `name`.
fn diagnostic_for(name: &str, res: &Resolution, span: Span) -> Diagnostic {
    let message = if matches!(res, Resolution::Unresolved(_)) {
        format!(
            "`{name}` does not provably resolve to the profile module in this function \
             (an unconfirmed plain import or an unseen base could still bind it to \
             something else); a generated call here would guess — import the profile \
             module directly so `{name}` resolves without depending on inheritance or \
             an unconfirmed import"
        )
    } else {
        format!(
            "this declaration shadows `{name}`, an identifier a generated call in this \
             function must use; the call would silently bind to it instead of the \
             profile module (the transpiler never renames a generated call around a \
             collision) — rename this declaration"
        )
    };
    Diagnostic::error(codes::FHE_LIBRARY_IDENTIFIER_SHADOWED, span, message).with_rule("§1.3")
}

/// Every function id that at least one collected site or ACL fact will need
/// to write a generated `FHE.` call in. `precondition_sites` is the only
/// *whole* site kind that never does (it only locates the materialization
/// point for the others), so it is intentionally excluded.
///
/// The three boundary-sugar kinds (`sugar_sites`, `shared_input_sites`,
/// `shared_return_sites`) additionally rewrite a *bodiless* declaration's
/// signature only — an interface method or abstract function with no body
/// (spec §2.3 restriction 3, §2.8): `crates/fhec-lower/src/pass_ops.rs`
/// returns before writing any generated call once `!has_body`
/// (`expand_function_sugar`, `expand_shared_inputs`) or when
/// `return_exprs` is empty (`expand_shared_returns`, which has no
/// `has_body` field of its own — an empty `return_exprs` is how a bodiless
/// `SharedReturnSite` is spelled). Counting those bodiless sites here would
/// refuse FHE1022 on a shadow that can never actually retarget a generated
/// call (#84). Every other site kind here is only ever collected while
/// walking a function body (operators, ternaries, `if`, compound/incdec,
/// cast sugar, ACL facts), so a bodiless declaration structurally cannot
/// produce one and no filter is needed for them.
fn functions_writing_fhe(out: &CheckedUnit) -> impl Iterator<Item = FunctionId> + '_ {
    out.operator_sites
        .iter()
        .map(|s| s.function)
        .chain(out.ternary_sites.iter().map(|s| s.function))
        .chain(out.if_sites.iter().map(|s| s.function))
        .chain(out.compound_sites.iter().map(|s| s.function))
        .chain(out.incdec_sites.iter().map(|s| s.function))
        .chain(out.cast_sugar_sites.iter().map(|s| s.function))
        .chain(
            out.sugar_sites
                .iter()
                .filter(|s| s.has_body)
                .map(|s| s.function),
        )
        .chain(
            out.shared_input_sites
                .iter()
                .filter(|s| s.has_body)
                .map(|s| s.function),
        )
        .chain(
            out.shared_return_sites
                .iter()
                .filter(|s| !s.return_exprs.is_empty())
                .map(|s| s.function),
        )
        .chain(out.acl.storage_writes.iter().map(|s| s.function))
        .chain(out.acl.external_args.iter().map(|s| s.function))
        .chain(out.acl.returns.iter().map(|s| s.function))
}

/// Every function id whose `in`-sugar sites will lower through the *batched*
/// materializer (more than one `in` parameter sharing the function, all with
/// a body, spec §2.3 — a bodiless declaration only rewrites the signature
/// and never reaches `batch_input_statements`), paired with the distinct
/// encrypted types its parameters name (what `externalT`/`eT` the
/// materializer will write `.unwrap`/`.wrap` calls on).
fn functions_writing_batch_materializer(out: &CheckedUnit) -> Vec<(FunctionId, Vec<EType>)> {
    let mut by_fn: HashMap<FunctionId, Vec<EType>> = HashMap::new();
    for s in out.sugar_sites.iter().filter(|s| s.has_body) {
        by_fn.entry(s.function).or_default().push(s.ty);
    }
    by_fn
        .into_iter()
        .filter(|(_, types)| types.len() > 1)
        .map(|(f, mut types)| {
            types.sort_by_key(|t| t.solidity_name());
            types.dedup();
            (f, types)
        })
        .collect()
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
