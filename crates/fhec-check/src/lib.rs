//! FHE type checker, definite assignment, legality — pipeline stages 4–5.
//!
//! [`check`] consumes a bound compilation unit (fhec-bind) and the pinned
//! target profile (fhec-targets) and produces a [`CheckedUnit`]:
//!
//! - a span-keyed [`TypeTable`] over the *positive fragment* (spec §3.1);
//! - typed **rewrite sites** — the lowering pass's entire worklist. The site
//!   types make the spec §3.2 discipline structural: an `Unknown` type cannot
//!   reach lowering because [`sites::OperandKind`] cannot express it;
//! - **ACL facts** (spec §8) — inputs to the ACL pass's R1/R2/R3 policy;
//! - **diagnostics** with stable spec §9 codes. Any error diagnostic MUST
//!   abort lowering for the affected contract (spec §1.3: never guess).
//!
//! # Prime-directive posture
//!
//! Everything the checker cannot type is `Unknown`, silently. `Unknown` only
//! becomes an error where a rewrite would need certainty (an encrypted
//! operand meets it, spec §3.2). Existing FHE library calls the profile does
//! not know are left to solc — the checker refuses to guess but also refuses
//! to reject what it does not need to understand. Pure plain-Solidity input
//! produces zero sites and zero diagnostics (the §1.4 no-op guarantee at
//! check level; ACL *facts* may still be stated — the ACL pass's dedupe rule
//! §8.6 makes them no-ops on already-annotated code).
//!
//! # Nesting note for the lowerer
//!
//! Operator/ternary sites are emitted for every nested occurrence (`a + b +
//! c` yields two sites, the inner one covered by the outer one's operand
//! span). The lowerer must render nested sites recursively instead of
//! splicing overlapping patches: an operand whose (paren-peeled) span equals
//! a site's span is rendered from that site, not from source text.
//!
//! # Dialect note
//!
//! The checker is dialect-agnostic: it states sites/facts for every file of
//! the unit. Only `.fsol` files may be patched (spec §2.1); the caller
//! filters by dialect when driving the lowering pass.

mod decl;
mod diag;
mod emit_trust;
mod exprs;
mod imports;
mod ops;
mod precondition;
mod shared;
mod sites;
mod sugar;
mod trust;
mod ty;
mod walk;

pub use diag::{codes, Diagnostic, FixIt, Severity};
pub use ops::is_msg_sender;
pub use sites::{
    AclFacts, CastSugarSite, CheckedUnit, CompoundAssignSite, EncryptedArgCall, EncryptedIfSite,
    EncryptedReturn, EncryptedStorageWrite, InSugarSite, IncDecSite, OperandKind, OperandPlan,
    OperatorSite, PreconditionSite, SharedInputSite, SharedReturnSite, SlotKind, TernarySite,
    TypeTable,
};
pub use trust::is_profile_library_function;
pub use ty::{PlainTy, Ty};

use fhec_bind::{BoundUnit, SourceFile};
use fhec_targets::TargetProfile;
use solar_data_structures::map::FxHashMap;
use solar_interface::source_map::SourceMap;

/// Runs stages 4–5 over a bound unit.
///
/// Must run inside the same solar session scope that parsed and bound the
/// files (spans and identifier texts resolve against the live session).
/// `files` are the same parsed sources handed to [`fhec_bind::bind`].
pub fn check<'ast>(
    files: &[SourceFile<'ast>],
    unit: &BoundUnit<'ast>,
    profile: &dyn TargetProfile,
    sm: &SourceMap,
) -> CheckedUnit {
    let trust = trust::Trust::new(profile);
    let mut out = CheckedUnit::default();

    sugar::scan(files, unit, &trust, profile, &mut out);
    precondition::scan(unit, &mut out);

    let mut safe_cache: FxHashMap<fhec_bind::FunctionId, bool> = FxHashMap::default();
    let fids: Vec<fhec_bind::FunctionId> = unit.functions().map(|(id, _)| id).collect();
    for fid in fids {
        walk::FnChecker::new(unit, &trust, profile, sm, &mut out, &mut safe_cache, fid).run();
    }
    // Last: the shared-return type rule (FHE2012) reads the types the walk
    // recorded for each returned expression.
    shared::scan(files, unit, &trust, profile, &mut out);
    // Emit-time trust (FHE1022): needs every site/fact vector above final.
    emit_trust::scan(unit, &trust, &mut out);
    out
}
