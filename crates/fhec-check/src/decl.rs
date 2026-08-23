//! Declared-type resolution: an AST type node → the checker's [`Ty`].

use fhec_bind::{BoundUnit, Resolution, TypeDeclKind};
use solar_ast as ast;

use crate::trust::Trust;
use crate::ty::{PlainTy, Ty};

/// Resolves a declaration's type annotation to the checker's type language
/// (spec §3.1: declared variables/params/returns type precisely).
pub(crate) fn declared_ty<'ast>(unit: &BoundUnit<'ast>, trust: &Trust, ty: &ast::Type<'ast>) -> Ty {
    match &ty.kind {
        ast::TypeKind::Elementary(e) => Ty::Plain(elementary(*e)),
        ast::TypeKind::Mapping(m) => Ty::Plain(PlainTy::Mapping(
            Box::new(declared_ty(unit, trust, &m.key)),
            Box::new(declared_ty(unit, trust, &m.value)),
        )),
        ast::TypeKind::Array(a) => Ty::Plain(PlainTy::Array(Box::new(declared_ty(
            unit, trust, &a.element,
        )))),
        ast::TypeKind::Function(_) => Ty::Plain(PlainTy::Opaque),
        ast::TypeKind::Custom(path) => {
            let segments = path.segments();
            if segments.len() != 1 {
                // Qualified type names (`Lib.Struct`) are outside the
                // positive fragment for now.
                return Ty::Unknown;
            }
            let first = segments[0];
            let name = first.as_str();
            let Some(res) = unit.resolve_span(first.span) else {
                return Ty::Unknown;
            };
            custom_ty(unit, trust, name, res)
        }
    }
}

/// Types a resolved single-segment custom type name.
pub(crate) fn custom_ty(unit: &BoundUnit<'_>, trust: &Trust, name: &str, res: &Resolution) -> Ty {
    if let Some(ety) = trust.encrypted_type(unit, name, res) {
        return Ty::Encrypted(ety);
    }
    if let Some(ety) = trust.external_input_type(unit, name, res) {
        return Ty::Plain(PlainTy::ExternalInput(ety));
    }
    match res {
        Resolution::TypeName(id) => match &unit.type_decl(*id).kind {
            TypeDeclKind::Struct(_) => Ty::Plain(PlainTy::Struct(*id)),
            TypeDeclKind::Enum(_) => Ty::Plain(PlainTy::Enum(*id)),
            // An untrusted user-defined value type: a plaintext value the
            // checker does not model further.
            TypeDeclKind::Udvt(_) => Ty::Plain(PlainTy::Opaque),
        },
        Resolution::Contract(id) => Ty::Plain(PlainTy::ContractInstance(*id)),
        _ => Ty::Unknown,
    }
}

/// Maps an elementary Solidity type to [`PlainTy`].
pub(crate) fn elementary(e: ast::ElementaryType) -> PlainTy {
    match e {
        ast::ElementaryType::Bool => PlainTy::Bool,
        ast::ElementaryType::Address(_) => PlainTy::Address,
        ast::ElementaryType::UInt(size) => PlainTy::Uint(size.bits()),
        ast::ElementaryType::Int(size) => PlainTy::Int(size.bits()),
        ast::ElementaryType::FixedBytes(size) => PlainTy::FixedBytes(size.bytes()),
        ast::ElementaryType::Bytes => PlainTy::Bytes,
        ast::ElementaryType::String => PlainTy::String,
        ast::ElementaryType::Fixed(..) | ast::ElementaryType::UFixed(..) => PlainTy::Opaque,
    }
}
