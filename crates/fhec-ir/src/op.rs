//! The abstract FHE operations lowering emits.

use std::fmt;

use crate::etype::{EType, EWidth};

/// An abstract FHE operation (spec §4, §8).
///
/// Lowering emits these; a target profile maps each to a concrete library
/// call or reports it unsupported (spec §1.5, error FHE5001). Operations
/// with payloads carry the type information their rendering depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FheOp {
    /// `+` — wrapping addition.
    Add,
    /// `-` — wrapping subtraction.
    Sub,
    /// `*` — multiplication.
    Mul,
    /// `/` — division (semantics of division by zero are backend-defined).
    Div,
    /// `%` — remainder (same caveat as [`FheOp::Div`]).
    Rem,
    /// `&` on `euintN`, `&&`/`&` on `ebool`.
    And,
    /// `|` on `euintN`, `||`/`|` on `ebool`.
    Or,
    /// `^`.
    Xor,
    /// `<<` — both operands the same encrypted width (spec §4.3).
    Shl,
    /// `>>` — both operands the same encrypted width (spec §4.3).
    Shr,
    /// `~` on `euintN`, `!` on `ebool` (unary).
    Not,
    /// `==` — result `ebool`.
    Eq,
    /// `!=` — result `ebool`.
    Ne,
    /// `<` — result `ebool`.
    Lt,
    /// `<=` — result `ebool`.
    Lte,
    /// `>` — result `ebool`.
    Gt,
    /// `>=` — result `ebool`.
    Gte,
    /// Minimum of two operands (no operator; used by lowering helpers).
    Min,
    /// Maximum of two operands (no operator; used by lowering helpers).
    Max,
    /// Squaring (no operator; `x.square()` method pass-through, spec §4.1).
    Square,
    /// Rotate left (no operator; `x.rol(n)` method pass-through, spec §4.1).
    Rol,
    /// Rotate right (no operator; `x.ror(n)` method pass-through, spec §4.1).
    Ror,
    /// Ternary multiplexer: `select(cond, ifTrue, ifFalse)` (spec §5).
    Select,
    /// Trivial encryption of a plaintext operand to `to` (spec §3.3 rule 1).
    TrivialEncrypt {
        /// The encrypted type produced.
        to: EType,
    },
    /// Widening cast along the `euintN` chain (spec §3.3 rule 3).
    ///
    /// Widths are structural: widening exists only between `euintN` types
    /// and only from narrower to wider.
    Widen {
        /// The operand's width.
        from: EWidth,
        /// The (strictly wider) result width.
        to: EWidth,
    },
    /// Verified conversion of an external-input handle (`externalEuintX`)
    /// plus its input proof into the value type (spec §2.3). Two rendered
    /// arguments: the handle and the proof bytes.
    FromExternal {
        /// The encrypted value type produced.
        ty: EType,
    },
    /// ACL: allow the current contract (spec §8.1). Rendering only; the
    /// insertion policy lives in the ACL pass.
    AllowThis,
    /// ACL: allow `msg.sender` (spec §8.1). Rendering only.
    AllowSender,
    /// ACL: transient allowance for an account (spec §8.2, §8.3).
    /// Two arguments: the handle and the account expression.
    AllowTransient,
    /// ACL: global allowance. Never auto-inserted (spec §8.5); present so
    /// existing calls can be typed and rendered.
    AllowGlobal,
    /// ACL: allow a named reader (spec §8.9 R4/R5, §8.10). Two arguments:
    /// the handle and the reader's address expression. Only ever inserted
    /// where an author-stated reader policy (§8.8) names that reader.
    Allow,
    /// ACL: allow everyone (spec §8.9 `public` reader). One argument: the
    /// handle. Only ever inserted from a `public` reader policy (§8.8).
    AllowPublic,
}

impl FheOp {
    /// The number of rendered call arguments.
    ///
    /// Note this counts *all* arguments, including plaintext ones: e.g.
    /// [`FheOp::AllowTransient`] takes the handle and an address.
    pub fn arity(self) -> usize {
        match self {
            FheOp::Not
            | FheOp::Square
            | FheOp::TrivialEncrypt { .. }
            | FheOp::Widen { .. }
            | FheOp::AllowThis
            | FheOp::AllowSender
            | FheOp::AllowGlobal
            | FheOp::AllowPublic => 1,
            FheOp::Add
            | FheOp::Sub
            | FheOp::Mul
            | FheOp::Div
            | FheOp::Rem
            | FheOp::And
            | FheOp::Or
            | FheOp::Xor
            | FheOp::Shl
            | FheOp::Shr
            | FheOp::Eq
            | FheOp::Ne
            | FheOp::Lt
            | FheOp::Lte
            | FheOp::Gt
            | FheOp::Gte
            | FheOp::Min
            | FheOp::Max
            | FheOp::Rol
            | FheOp::Ror
            | FheOp::FromExternal { .. }
            | FheOp::AllowTransient
            | FheOp::Allow => 2,
            FheOp::Select => 3,
        }
    }

    /// Whether this is an ACL operation (spec §8).
    pub fn is_acl(self) -> bool {
        matches!(
            self,
            FheOp::AllowThis
                | FheOp::AllowSender
                | FheOp::AllowTransient
                | FheOp::AllowGlobal
                | FheOp::Allow
                | FheOp::AllowPublic
        )
    }

    /// A stable lower-case mnemonic for diagnostics and debug printing.
    ///
    /// This is NOT the rendered library call name; target profiles own the
    /// concrete spelling.
    pub fn mnemonic(self) -> &'static str {
        match self {
            FheOp::Add => "add",
            FheOp::Sub => "sub",
            FheOp::Mul => "mul",
            FheOp::Div => "div",
            FheOp::Rem => "rem",
            FheOp::And => "and",
            FheOp::Or => "or",
            FheOp::Xor => "xor",
            FheOp::Shl => "shl",
            FheOp::Shr => "shr",
            FheOp::Not => "not",
            FheOp::Eq => "eq",
            FheOp::Ne => "ne",
            FheOp::Lt => "lt",
            FheOp::Lte => "lte",
            FheOp::Gt => "gt",
            FheOp::Gte => "gte",
            FheOp::Min => "min",
            FheOp::Max => "max",
            FheOp::Square => "square",
            FheOp::Rol => "rol",
            FheOp::Ror => "ror",
            FheOp::Select => "select",
            FheOp::TrivialEncrypt { .. } => "trivial-encrypt",
            FheOp::Widen { .. } => "widen",
            FheOp::FromExternal { .. } => "from-external",
            FheOp::AllowThis => "allow-this",
            FheOp::AllowSender => "allow-sender",
            FheOp::AllowTransient => "allow-transient",
            FheOp::AllowGlobal => "allow-global",
            FheOp::Allow => "allow",
            FheOp::AllowPublic => "allow-public",
        }
    }
}

impl fmt::Display for FheOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            FheOp::TrivialEncrypt { to } => write!(f, "trivial-encrypt→{to}"),
            FheOp::Widen { from, to } => write!(f, "widen(euint{from}→euint{to})"),
            FheOp::FromExternal { ty } => write!(f, "from-external({})", ty.external_name()),
            other => f.write_str(other.mnemonic()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arity() {
        assert_eq!(FheOp::Not.arity(), 1);
        assert_eq!(FheOp::AllowThis.arity(), 1);
        assert_eq!(FheOp::Add.arity(), 2);
        assert_eq!(FheOp::AllowTransient.arity(), 2);
        assert_eq!(FheOp::Select.arity(), 3);
        assert_eq!(FheOp::TrivialEncrypt { to: EType::Ebool }.arity(), 1);
    }

    #[test]
    fn acl_classification() {
        assert!(FheOp::AllowThis.is_acl());
        assert!(FheOp::AllowTransient.is_acl());
        assert!(!FheOp::Add.is_acl());
        assert!(!FheOp::Select.is_acl());
    }

    #[test]
    fn display() {
        assert_eq!(FheOp::Add.to_string(), "add");
        assert_eq!(
            FheOp::Widen {
                from: EWidth::W8,
                to: EWidth::W128
            }
            .to_string(),
            "widen(euint8→euint128)"
        );
        assert_eq!(
            FheOp::FromExternal {
                ty: EType::Euint(EWidth::W32)
            }
            .to_string(),
            "from-external(externalEuint32)"
        );
    }
}
