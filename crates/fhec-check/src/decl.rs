//! Declared-type resolution: an AST type node → the checker's [`Ty`].

use fhec_bind::{BoundUnit, Resolution, TypeDeclId, TypeDeclKind};
use fhec_ir::EType;
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

/// What a declared type contributes to a plaintext-only rule (spec §2.7).
///
/// A container's *root* type says nothing about its contents: `euint32[]` is
/// a plain array whose elements are encrypted, and a plain struct may declare
/// an encrypted field. A caller that must prove "plaintext, all the way down"
/// therefore asks [`nesting`], not `Ty` alone.
pub(crate) enum Nesting {
    /// Nothing encrypted and nothing unresolved, at any depth.
    Plain,
    /// An encrypted type at the root or inside it.
    Encrypted(EType),
    /// Nothing encrypted, but a type the checker cannot resolve, at some
    /// depth.
    Unknown,
}

/// Classifies `ty` and everything inside it (array elements, mapping key and
/// value, struct fields). `Encrypted` wins over `Unknown`: it is the more
/// specific fact, and it names the type.
pub(crate) fn nesting(unit: &BoundUnit<'_>, trust: &Trust, ty: &Ty) -> Nesting {
    let mut seen = Vec::new();
    let mut unknown = false;
    match encrypted_inside(unit, trust, ty, &mut seen, &mut unknown) {
        Some(e) => Nesting::Encrypted(e),
        None if unknown => Nesting::Unknown,
        None => Nesting::Plain,
    }
}

/// The first encrypted type at or inside `ty`. Sets `unknown` when an
/// unresolved type is passed on the way.
///
/// `seen` breaks the cycle a self-referential struct would otherwise form; a
/// struct already on the path was judged by the outer call.
fn encrypted_inside(
    unit: &BoundUnit<'_>,
    trust: &Trust,
    ty: &Ty,
    seen: &mut Vec<TypeDeclId>,
    unknown: &mut bool,
) -> Option<EType> {
    let plain = match ty {
        Ty::Encrypted(e) => return Some(*e),
        Ty::Unknown => {
            *unknown = true;
            return None;
        }
        Ty::Plain(p) => p,
    };
    match plain {
        PlainTy::Array(el) => encrypted_inside(unit, trust, el, seen, unknown),
        PlainTy::Mapping(k, v) => encrypted_inside(unit, trust, k, seen, unknown)
            .or_else(|| encrypted_inside(unit, trust, v, seen, unknown)),
        PlainTy::Struct(id) => {
            if seen.contains(id) {
                return None;
            }
            seen.push(*id);
            let TypeDeclKind::Struct(s) = &unit.type_decl(*id).kind else {
                return None;
            };
            s.fields.iter().find_map(|f| {
                let fty = declared_ty(unit, trust, &f.ty);
                encrypted_inside(unit, trust, &fty, seen, unknown)
            })
        }
        _ => None,
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
