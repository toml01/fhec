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
//! 3. **Incomplete inheritance.** A positive file-scope binding survives
//!    incomplete inheritance directly. For a file-scope miss,
//!    [`UnresolvedReason::IncompleteInheritance`] defers to its unresolved
//!    `fallback`, so rule 2 can still recognize exposure from an explicit
//!    profile plain import.
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

use fhec_bind::{BoundUnit, Resolution, TypeDeclKind, UnresolvedReason};
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

    /// Whether a resolution for a name written `text` reaches the profile
    /// library through the trust rule.
    fn resolution_trusted(&self, res: &Resolution) -> bool {
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
        // part of the compilation unit.
        if let Resolution::Contract(id) = res {
            let c = unit.contract(*id);
            if c.kind == ast::ContractKind::Library && c.name_str == "FHE" {
                let has = |n: &str| {
                    c.functions
                        .iter()
                        .any(|f| unit.function(*f).name_str.as_deref() == Some(n))
                };
                return has("select") && has("allowThis");
            }
        }
        false
    }

    /// The encrypted type a *type name* resolution denotes, when trusted.
    pub(crate) fn encrypted_type(
        &self,
        unit: &BoundUnit<'_>,
        name: &str,
        res: &Resolution,
    ) -> Option<EType> {
        let ety = etype_by_name(name)?;
        match res {
            Resolution::TypeName(id) => match &unit.type_decl(*id).kind {
                TypeDeclKind::Udvt(u) => udvt_is_bytes32(u).then_some(ety),
                _ => None,
            },
            _ => self.resolution_trusted(res).then_some(ety),
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
        match res {
            // The corpus case: FHE.sol in unit declares the UDVTs.
            Resolution::TypeName(id) => match &unit.type_decl(*id).kind {
                TypeDeclKind::Udvt(u) => udvt_is_bytes32(u).then_some(ety),
                _ => None,
            },
            _ => self.resolution_trusted(res).then_some(ety),
        }
    }
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
