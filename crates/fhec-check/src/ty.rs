//! The checker's type language: the positive fragment plus `Unknown`.

use fhec_bind::{ContractId, TypeDeclId};
use fhec_ir::EType;

/// The encryptedness type of an expression (spec §3.1).
///
/// `Unknown` is a first-class, safe result: it means "the checker does not
/// know", never "assume plaintext". The interaction rules of spec §3.2 are the
/// only place `Unknown` becomes an error (when it meets an encrypted operand
/// at a rewrite site).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ty {
    /// A precisely-typed encrypted value.
    Encrypted(EType),
    /// A precisely-typed plaintext value.
    Plain(PlainTy),
    /// Anything the positive fragment does not cover.
    Unknown,
}

impl Ty {
    /// Whether this is an encrypted value type.
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Ty::Encrypted(_))
    }

    /// The encrypted type, when encrypted.
    pub fn etype(&self) -> Option<EType> {
        match self {
            Ty::Encrypted(t) => Some(*t),
            _ => None,
        }
    }
}

/// A plaintext type, structured exactly as far as the coercion rules
/// (spec §3.3) and the reject rules (spec §7) need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlainTy {
    /// `bool`.
    Bool,
    /// `uintN` (bits).
    Uint(u16),
    /// `intN` (bits).
    Int(u16),
    /// `address` / `address payable`.
    Address,
    /// `bytesN`.
    FixedBytes(u8),
    /// Dynamic `bytes`.
    Bytes,
    /// `string`.
    String,
    /// A number literal. `value` is `None` when the literal exceeds
    /// `u128::MAX` (then it fits no encrypted width; spec §3.3 rule 2).
    NumLit {
        /// The literal value, when it fits in `u128`.
        value: Option<u128>,
    },
    /// An encrypted-input struct (`InEuint32`, ...) of the given value type.
    InStruct(EType),
    /// A struct value of an in-unit struct declaration.
    Struct(TypeDeclId),
    /// An enum value of an in-unit enum declaration.
    Enum(TypeDeclId),
    /// A mapping (declared storage type; not a value type).
    Mapping(Box<Ty>, Box<Ty>),
    /// An array of the element type (declared type).
    Array(Box<Ty>),
    /// A reference to an in-unit contract/interface/library used as a value
    /// or namespace (`Lib`, `IThing`).
    ContractRef(ContractId),
    /// A value whose declared type is an in-unit contract/interface
    /// (`IERC20 token`) — calls on it are external calls.
    ContractInstance(ContractId),
    /// A type used in expression position (cast callee, struct constructor).
    TypeRef(TypeDeclId),
    /// A trusted encrypted type name used in expression position
    /// (`euint32.wrap(...)`).
    EncTypeRef(EType),
    /// The trusted FHE library identifier itself (`FHE`).
    FheLib,
    /// A member function of the trusted FHE library (`FHE.add`), by name.
    FheFn(String),
    /// A profile method on an encrypted receiver (`a.add`), by receiver type
    /// and name.
    MethodRef(EType, String),
    /// A Solidity builtin namespace or function (`msg`, `require`, ...).
    BuiltinRef(&'static str),
    /// A statement-like void result (ACL calls, `require(...)`).
    Unit,
    /// A plaintext type the checker recognizes but does not model further.
    Opaque,
}

impl PlainTy {
    /// Whether a value of this plaintext type implicitly converts to the
    /// plaintext analogue of `target` (spec §3.3 rule 1).
    ///
    /// Number literals are handled separately (range check, rule 2).
    pub fn converts_to(&self, target: EType) -> bool {
        match (self, target) {
            (PlainTy::Bool, EType::Ebool) => true,
            (PlainTy::Uint(bits), EType::Euint(w)) => *bits <= w.bits(),
            (PlainTy::Address, EType::Eaddress) => true,
            _ => false,
        }
    }
}
