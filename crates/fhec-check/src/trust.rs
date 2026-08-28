//! The FHE-library trust rule: when a name is *the* profile FHE library.
//!
//! The checker types `FHE.add(...)`, method bindings, and encrypted type
//! names via the pinned target profile. Doing so is a semantic claim, so it
//! is gated by an explicit, conservative trust rule (spec §1.3):
//!
//! 1. **External import match.** The name resolves to
//!    [`Resolution::External`] whose import specifier is one of the profile's
//!    own import specifiers (module directory + known file), e.g.
//!    `@fhenixprotocol/cofhe-contracts/FHE.sol`.
//! 2. **Plain-import exposure.** The name is unresolved with
//!    [`UnresolvedReason::MaybeExternal`] and at least one of the candidate
//!    specifiers matches rule 1. This is the dominant real-world pattern
//!    (`import "@fhenixprotocol/cofhe-contracts/FHE.sol";`): the binder
//!    cannot see the file's exports, but the author explicitly imported the
//!    profile library, and both solc and the verify gate re-check actual
//!    name resolution downstream.
//! 3. **Incomplete inheritance.** [`UnresolvedReason::IncompleteInheritance`]
//!    defers to its `fallback` — what file scope would have said — so rule 2
//!    can still recognize exposure from an explicit profile plain import.
//!    This is a deliberate, narrow policy: the binder does not resolve that
//!    fallback itself, because an unseen base can shadow the name. (A base
//!    shadowing `FHE`/`euint32` cannot be ruled out either, but treating that
//!    as possible would reject every inheriting contract; the explicit
//!    profile import wins.)
//! 4. **In-unit library.** The name resolves to an in-unit `library FHE`
//!    declared in a file that also declares a user-defined value type
//!    `euintN is bytes32` (the CoFHE library file itself, when it is part of
//!    the compilation unit — the conformance-corpus case).
//!
//! Encrypted *type* names (`euint32`, `ebool`, ...) and external-input
//! handle names (`externalEuint32`, ...) trust the same paths; additionally
//! an in-unit user-defined value type named like one of them counts when its
//! underlying type is `bytes32` (matching CoFHE's declarations).
//!
//! Anything not covered types as `Unknown` — never a guess.

use fhec_bind::{BoundUnit, FileId, FunctionId, Resolution, TypeDeclKind, UnresolvedReason};
use fhec_ir::{EType, FheOp};
use fhec_targets::TargetProfile;
use solar_ast as ast;

/// Precomputed trust facts for one compilation unit + profile.
pub(crate) struct Trust {
    /// Import specifiers considered "the profile library", extracted from
    /// the profile's import lines plus the interface-file convention.
    specifiers: Vec<String>,
    /// The module directory prefix (e.g. `@fhenixprotocol/cofhe-contracts/`).
    module_prefix: Option<String>,
}

impl Trust {
    pub(crate) fn new(profile: &dyn TargetProfile) -> Self {
        let mut specifiers = Vec::new();
        let mut module_prefix = None;
        for line in profile.import_lines() {
            if let Some(spec) = extract_specifier(&line) {
                if let Some(dir) = spec.rfind('/') {
                    module_prefix = Some(spec[..=dir].to_string());
                }
                specifiers.push(spec);
            }
        }
        Trust {
            specifiers,
            module_prefix,
        }
    }

    /// Whether an import specifier denotes the profile library.
    pub(crate) fn specifier_trusted(&self, spec: &str) -> bool {
        if self.specifiers.iter().any(|s| s == spec) {
            return true;
        }
        // Any file under the profile's module directory (ICofhe.sol etc.).
        self.module_prefix
            .as_ref()
            .is_some_and(|p| spec.starts_with(p.as_str()))
    }

    /// Whether a resolution reaches a trusted profile-module import,
    /// independent of what name produced it (external-import-specifier
    /// match, exposure through a plain import of the profile, or an
    /// incomplete-inheritance fallback that itself resolves this way).
    /// `is_fhe_library`'s rule 4 (in-unit library declaration) is layered on
    /// top of this for `FHE` specifically; this alone is what `emit_trust`
    /// reuses for the other generated-only names (`Impl`, `Utils`,
    /// `UnsignedEncryptedInput`) that have no rule-4 equivalent.
    pub(crate) fn resolution_trusted(&self, res: &Resolution) -> bool {
        match res {
            Resolution::External { specifier, .. } => self.specifier_trusted(specifier),
            Resolution::Unresolved(UnresolvedReason::MaybeExternal { specifiers }) => {
                specifiers.iter().any(|s| self.specifier_trusted(s))
            }
            Resolution::Unresolved(UnresolvedReason::IncompleteInheritance {
                fallback, ..
            }) => self.resolution_trusted(fallback),
            _ => false,
        }
    }

    /// Unwraps a chain of `Unresolved(IncompleteInheritance)` fallbacks down
    /// to what they ultimately resolve to.
    ///
    /// `resolution_trusted` already sees past this wrapper on its own (it
    /// recurses into `fallback` itself) for the `External`/`MaybeExternal`
    /// paths. But every check here that pattern-matches a *specific*
    /// resolution variant instead — rule 4's `Contract`, the in-unit-corpus
    /// file check, the UDVT bypass — needs to see past it too, or it
    /// silently loses that check whenever an unseen base sits between the
    /// identifier and the profile import that would otherwise prove it
    /// trusted: an in-unit `import "./FHE.sol"` combined with an unrelated
    /// unseen base (spec §1.3) is an ordinary, common shape, not an edge
    /// case — the binder cannot resolve the fallback itself precisely
    /// because an unseen base *could* shadow it, so every caller that wants
    /// to recognize a specific trusted shape underneath must unwrap first.
    pub(crate) fn unwrap_fallback(res: &Resolution) -> &Resolution {
        match res {
            Resolution::Unresolved(UnresolvedReason::IncompleteInheritance {
                fallback, ..
            }) => Self::unwrap_fallback(fallback),
            _ => res,
        }
    }

    /// Whether `res` (for an identifier written `FHE`) is the profile FHE
    /// library.
    pub(crate) fn is_fhe_library(
        &self,
        unit: &BoundUnit<'_>,
        name: &str,
        res: &Resolution,
    ) -> bool {
        if name != "FHE" {
            return false;
        }
        if self.resolution_trusted(res) {
            return true;
        }
        // Rule 4: an in-unit `library FHE` whose member surface strongly
        // identifies it as the profile library (it declares both `select`
        // and `allowThis`) — the conformance-corpus case where FHE.sol is
        // part of the compilation unit. Unwrap first: an unseen base can
        // put this behind an incomplete-inheritance fallback even when the
        // in-unit import is unambiguous.
        if let Resolution::Contract(id) = Self::unwrap_fallback(res) {
            let c = unit.contract(*id);
            return Self::looks_like_fhe_library(unit, c);
        }
        false
    }

    /// Whether a contract declaration structurally looks like the profile's
    /// `library FHE` (rule 4): a library named `FHE` declaring both
    /// `select` and `allowThis`.
    fn looks_like_fhe_library(unit: &BoundUnit<'_>, c: &fhec_bind::ContractInfo<'_>) -> bool {
        if c.kind != ast::ContractKind::Library || c.name_str != "FHE" {
            return false;
        }
        let has = |n: &str| {
            c.functions
                .iter()
                .any(|f| unit.function(*f).name_str.as_deref() == Some(n))
        };
        has("select") && has("allowThis")
    }

    /// Whether `file` is the profile module file itself — an in-unit file
    /// that declares the rule-4 `library FHE`. Other generated-only names
    /// declared alongside it in that same file (`Impl`, `Utils`,
    /// `UnsignedEncryptedInput`, the batch `in`-sugar materializer's
    /// symbols, spec §2.3) are declared by the same trusted profile module,
    /// even though they have no distinctive member surface of their own to
    /// recognize structurally the way rule 4 recognizes `library FHE`.
    ///
    /// Known limitation: real cofhe-contracts actually splits `Utils` and
    /// `UnsignedEncryptedInput` into a separate `ICofhe.sol` file from
    /// `FHE.sol`. This same-file heuristic does not follow that split — an
    /// in-unit-vendored profile that mirrors the real package layout across
    /// two files could still see a spurious FHE1022 on those two names. Not
    /// confirmed as reachable through the discovery/import paths this
    /// codebase actually exercises (`specifier_trusted`'s module-prefix
    /// check already covers `ICofhe.sol` for the plain-import/external
    /// paths); documented here rather than hardened, pending a concrete
    /// repro.
    fn file_is_profile_module(&self, unit: &BoundUnit<'_>, file: FileId) -> bool {
        unit.contracts()
            .any(|(_, c)| c.file == file && Self::looks_like_fhe_library(unit, c))
    }

    /// Whether `res` is trusted to be a name the profile module declares —
    /// the generic exposure paths (`resolution_trusted`: a trusted import
    /// specifier, or exposure through a plain import of the profile), or,
    /// for a `Contract`/`TypeName` resolution, being declared in-unit in the
    /// same file as the recognized `library FHE` (see
    /// [`file_is_profile_module`](Self::file_is_profile_module)).
    ///
    /// Unlike [`is_fhe_library`](Self::is_fhe_library) this is not keyed to
    /// a specific name: it answers "does the profile module declare
    /// whatever this resolved to", which is exactly what `emit_trust` needs
    /// for `Impl`/`Utils`/`UnsignedEncryptedInput` — names with no
    /// rule-4-style structural signature of their own.
    pub(crate) fn is_trusted_profile_declaration(
        &self,
        unit: &BoundUnit<'_>,
        res: &Resolution,
    ) -> bool {
        match Self::unwrap_fallback(res) {
            Resolution::Contract(id) => self.file_is_profile_module(unit, unit.contract(*id).file),
            Resolution::TypeName(id) => self.file_is_profile_module(unit, unit.type_decl(*id).file),
            unwrapped => self.resolution_trusted(unwrapped),
        }
    }

    /// The encrypted type a *type name* resolution denotes, when trusted.
    pub(crate) fn encrypted_type(
        &self,
        unit: &BoundUnit<'_>,
        name: &str,
        res: &Resolution,
    ) -> Option<EType> {
        let ety = etype_by_name(name)?;
        match Self::unwrap_fallback(res) {
            Resolution::TypeName(id) => match &unit.type_decl(*id).kind {
                TypeDeclKind::Udvt(u) => udvt_is_bytes32(u).then_some(ety),
                _ => None,
            },
            unwrapped => self.resolution_trusted(unwrapped).then_some(ety),
        }
    }

    /// The encrypted value type of an external-input handle *type name*
    /// (`externalEuint32`), when trusted.
    pub(crate) fn external_input_type(
        &self,
        unit: &BoundUnit<'_>,
        name: &str,
        res: &Resolution,
    ) -> Option<EType> {
        let ety = EType::ALL.into_iter().find(|t| t.external_name() == name)?;
        match Self::unwrap_fallback(res) {
            // The corpus case: FHE.sol in unit declares the UDVTs.
            Resolution::TypeName(id) => match &unit.type_decl(*id).kind {
                TypeDeclKind::Udvt(u) => udvt_is_bytes32(u).then_some(ety),
                _ => None,
            },
            unwrapped => self.resolution_trusted(unwrapped).then_some(ety),
        }
    }
}

/// Whether `fid` is declared by the trusted profile library module (spec
/// §8.6): the recognized in-unit `library FHE` itself (rule 4), or a
/// library declared in the same file — CoFHE's per-type `BindingsEuintN`
/// method-syntax extensions live alongside `library FHE` in `FHE.sol` and
/// forward to it, so the same-file check already recognizes the file.
///
/// Used by the lowerer's ACL pass (spec §8.6) to gate a method-syntax
/// broad-grant match (`ptr.allowPublic()`) the same way library syntax
/// (`FHE.allowPublic(ptr)`) is gated on [`crate::PlainTy::FheLib`]: an
/// in-unit, non-profile `using` binding (e.g. a synthetic `using FakeAcl for
/// euint32;`) resolves to a candidate function outside the profile module
/// and this returns `false` for it (issue #87). A method call with **no**
/// in-unit candidate at all — the ordinary real-world case, since CoFHE's
/// `using BindingsEuintN for euintN global;` lives inside `FHE.sol`,
/// invisible to the binder unless that file is itself part of the
/// compilation unit — is not covered by this function; the caller treats
/// that absence as trusted by default.
pub fn is_profile_library_function(
    unit: &BoundUnit<'_>,
    profile: &dyn TargetProfile,
    fid: FunctionId,
) -> bool {
    let Some(cid) = unit.function(fid).contract else {
        return false;
    };
    let file = unit.contract(cid).file;
    Trust::new(profile).file_is_profile_module(unit, file)
}

/// `euint32` → `EType::Euint(W32)`, etc.
pub(crate) fn etype_by_name(name: &str) -> Option<EType> {
    EType::ALL.into_iter().find(|t| t.solidity_name() == name)
}

/// The profile operation a method/library-function name denotes, if any.
///
/// Cast functions (`asEuint32`, ...) are handled separately by the caller.
pub(crate) fn op_by_name(name: &str) -> Option<FheOp> {
    Some(match name {
        "add" => FheOp::Add,
        "sub" => FheOp::Sub,
        "mul" => FheOp::Mul,
        "div" => FheOp::Div,
        "rem" => FheOp::Rem,
        "and" => FheOp::And,
        "or" => FheOp::Or,
        "xor" => FheOp::Xor,
        "shl" => FheOp::Shl,
        "shr" => FheOp::Shr,
        "not" => FheOp::Not,
        "eq" => FheOp::Eq,
        "ne" => FheOp::Ne,
        "lt" => FheOp::Lt,
        "lte" => FheOp::Lte,
        "gt" => FheOp::Gt,
        "gte" => FheOp::Gte,
        "min" => FheOp::Min,
        "max" => FheOp::Max,
        "square" => FheOp::Square,
        "rol" => FheOp::Rol,
        "ror" => FheOp::Ror,
        "select" => FheOp::Select,
        "allowThis" => FheOp::AllowThis,
        "allowSender" => FheOp::AllowSender,
        "allowTransient" => FheOp::AllowTransient,
        "allowGlobal" => FheOp::AllowGlobal,
        _ => return None,
    })
}

/// The target type of a profile cast-function name (`asEuint32` → euint32).
pub(crate) fn cast_target_by_name(name: &str) -> Option<EType> {
    let stripped = name.strip_prefix("as")?;
    EType::ALL.into_iter().find(|t| t.suffix() == stripped)
}

/// Whether a UDVT's underlying type is `bytes32`.
fn udvt_is_bytes32(u: &ast::ItemUdvt<'_>) -> bool {
    matches!(
        u.ty.kind,
        ast::TypeKind::Elementary(ast::ElementaryType::FixedBytes(size)) if size.bytes() == 32
    )
}

/// Extracts the quoted specifier from an import line.
fn extract_specifier(line: &str) -> Option<String> {
    let start = line.find(['"', '\''])?;
    let quote = line.as_bytes()[start] as char;
    let rest = &line[start + 1..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_specifier() {
        assert_eq!(
            extract_specifier("import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";").as_deref(),
            Some("@fhenixprotocol/cofhe-contracts/FHE.sol")
        );
        assert_eq!(extract_specifier("pragma solidity ^0.8.25;"), None);
    }

    #[test]
    fn type_name_tables() {
        assert_eq!(
            etype_by_name("euint64"),
            Some(EType::Euint(fhec_ir::EWidth::W64))
        );
        assert_eq!(etype_by_name("uint64"), None);
        assert_eq!(cast_target_by_name("asEbool"), Some(EType::Ebool));
        assert_eq!(cast_target_by_name("asEuint256"), None);
        assert_eq!(op_by_name("lte"), Some(FheOp::Lte));
        assert_eq!(op_by_name("decrypt"), None);
    }
}
