//! Encrypted value types and their width ordering.

use std::fmt;

/// Bit width of an encrypted unsigned integer type.
///
/// The variants are declared narrowest-first so the derived [`Ord`] gives the
/// widening order of spec §3.3: `W8 < W16 < W32 < W64 < W128`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EWidth {
    /// 8 bits (`euint8`).
    W8,
    /// 16 bits (`euint16`).
    W16,
    /// 32 bits (`euint32`).
    W32,
    /// 64 bits (`euint64`).
    W64,
    /// 128 bits (`euint128`).
    W128,
}

impl EWidth {
    /// All widths, narrowest first.
    pub const ALL: [EWidth; 5] = [
        EWidth::W8,
        EWidth::W16,
        EWidth::W32,
        EWidth::W64,
        EWidth::W128,
    ];

    /// The number of bits.
    pub fn bits(self) -> u16 {
        match self {
            EWidth::W8 => 8,
            EWidth::W16 => 16,
            EWidth::W32 => 32,
            EWidth::W64 => 64,
            EWidth::W128 => 128,
        }
    }
}

impl fmt::Display for EWidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.bits())
    }
}

/// An encrypted value type of the CoFHE type family (spec §1.5).
///
/// There is no `euint256`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EType {
    /// Encrypted boolean (`ebool`).
    Ebool,
    /// Encrypted unsigned integer of the given width (`euint8`..`euint128`).
    Euint(EWidth),
    /// Encrypted address (`eaddress`).
    Eaddress,
}

impl EType {
    /// All encrypted types: `ebool`, the five `euintN` widths, `eaddress`.
    pub const ALL: [EType; 7] = [
        EType::Ebool,
        EType::Euint(EWidth::W8),
        EType::Euint(EWidth::W16),
        EType::Euint(EWidth::W32),
        EType::Euint(EWidth::W64),
        EType::Euint(EWidth::W128),
        EType::Eaddress,
    ];

    /// The Solidity spelling of the type (`"euint32"`).
    pub fn solidity_name(self) -> &'static str {
        match self {
            EType::Ebool => "ebool",
            EType::Euint(EWidth::W8) => "euint8",
            EType::Euint(EWidth::W16) => "euint16",
            EType::Euint(EWidth::W32) => "euint32",
            EType::Euint(EWidth::W64) => "euint64",
            EType::Euint(EWidth::W128) => "euint128",
            EType::Eaddress => "eaddress",
        }
    }

    /// The capitalized type name used in library identifiers (`"Euint32"`):
    /// the suffix of `asEuint32`, `externalEuint32`, `EUINT32_TFHE`.
    pub fn suffix(self) -> &'static str {
        match self {
            EType::Ebool => "Ebool",
            EType::Euint(EWidth::W8) => "Euint8",
            EType::Euint(EWidth::W16) => "Euint16",
            EType::Euint(EWidth::W32) => "Euint32",
            EType::Euint(EWidth::W64) => "Euint64",
            EType::Euint(EWidth::W128) => "Euint128",
            EType::Eaddress => "Eaddress",
        }
    }

    /// The matching external-input handle type name (`"externalEuint32"`,
    /// spec §1.5). Since cofhe-contracts 0.2.0 encrypted inputs arrive as
    /// these `bytes32` value types plus a proof, not as `InEuintX` structs.
    pub fn external_name(self) -> &'static str {
        match self {
            EType::Ebool => "externalEbool",
            EType::Euint(EWidth::W8) => "externalEuint8",
            EType::Euint(EWidth::W16) => "externalEuint16",
            EType::Euint(EWidth::W32) => "externalEuint32",
            EType::Euint(EWidth::W64) => "externalEuint64",
            EType::Euint(EWidth::W128) => "externalEuint128",
            EType::Eaddress => "externalEaddress",
        }
    }

    /// The plaintext Solidity counterpart (`"uint32"` for `euint32`), i.e.
    /// the type a trivial encrypt conceptually starts from (spec §3.3).
    pub fn plaintext_type(self) -> &'static str {
        match self {
            EType::Ebool => "bool",
            EType::Euint(EWidth::W8) => "uint8",
            EType::Euint(EWidth::W16) => "uint16",
            EType::Euint(EWidth::W32) => "uint32",
            EType::Euint(EWidth::W64) => "uint64",
            EType::Euint(EWidth::W128) => "uint128",
            EType::Eaddress => "address",
        }
    }

    /// The width when this is a `euintN`, otherwise `None`.
    pub fn width(self) -> Option<EWidth> {
        match self {
            EType::Euint(w) => Some(w),
            _ => None,
        }
    }

    /// Whether this is a `euintN` type.
    pub fn is_euint(self) -> bool {
        matches!(self, EType::Euint(_))
    }

    /// The narrowest `euintN` both operands widen to (spec §3.3 rule 3).
    ///
    /// Returns `None` unless both types are `euintN`; widening never crosses
    /// kinds (`ebool`/`eaddress` do not widen).
    pub fn common_euint(a: EType, b: EType) -> Option<EType> {
        match (a, b) {
            (EType::Euint(wa), EType::Euint(wb)) => Some(EType::Euint(wa.max(wb))),
            _ => None,
        }
    }
}

impl fmt::Display for EType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.solidity_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widening_order() {
        let mut prev = None;
        for w in EWidth::ALL {
            if let Some(p) = prev {
                assert!(p < w, "{p} must be narrower than {w}");
            }
            prev = Some(w);
        }
        assert!(EWidth::W8 < EWidth::W128);
        assert_eq!(EWidth::W64.max(EWidth::W16), EWidth::W64);
    }

    #[test]
    fn names() {
        assert_eq!(EType::Euint(EWidth::W32).solidity_name(), "euint32");
        assert_eq!(EType::Euint(EWidth::W32).suffix(), "Euint32");
        assert_eq!(EType::Euint(EWidth::W32).external_name(), "externalEuint32");
        assert_eq!(EType::Euint(EWidth::W32).plaintext_type(), "uint32");
        assert_eq!(EType::Ebool.suffix(), "Ebool");
        assert_eq!(EType::Ebool.external_name(), "externalEbool");
        assert_eq!(EType::Ebool.plaintext_type(), "bool");
        assert_eq!(EType::Eaddress.suffix(), "Eaddress");
        assert_eq!(EType::Eaddress.external_name(), "externalEaddress");
        assert_eq!(EType::Eaddress.plaintext_type(), "address");
        assert_eq!(EType::Eaddress.to_string(), "eaddress");
    }

    #[test]
    fn common_euint_widens_to_the_wider_operand() {
        let e8 = EType::Euint(EWidth::W8);
        let e128 = EType::Euint(EWidth::W128);
        assert_eq!(EType::common_euint(e8, e128), Some(e128));
        assert_eq!(EType::common_euint(e128, e8), Some(e128));
        assert_eq!(EType::common_euint(e8, e8), Some(e8));
        assert_eq!(EType::common_euint(EType::Ebool, e8), None);
        assert_eq!(EType::common_euint(e8, EType::Eaddress), None);
    }

    #[test]
    fn all_covers_the_seven_types() {
        assert_eq!(EType::ALL.len(), 7);
        assert_eq!(EWidth::ALL.len(), 5);
    }
}
