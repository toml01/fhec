//! Expression/statement fragments for the byte-patch emitter.
//!
//! A fragment never duplicates source text: it references original bytes by
//! range, generated temporaries by name, or short literal replacement text.
//! `Display` implementations are for diagnostics and tests only — real output
//! is rendered by a target profile and spliced by the emitter (spec §2.5).

use std::fmt;

use crate::etype::EType;
use crate::op::FheOp;

/// A 0-based half-open byte range into the original source (spec §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ByteRange {
    /// Inclusive start offset.
    pub start: usize,
    /// Exclusive end offset.
    pub end: usize,
}

impl ByteRange {
    /// Creates a range; `start` must not exceed `end`.
    pub fn new(start: usize, end: usize) -> Self {
        debug_assert!(start <= end, "byte range {start}..{end} is inverted");
        ByteRange { start, end }
    }

    /// The number of bytes covered.
    pub fn len(self) -> usize {
        self.end - self.start
    }

    /// Whether the range covers zero bytes (a pure insertion point).
    pub fn is_empty(self) -> bool {
        self.start == self.end
    }
}

impl fmt::Display for ByteRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "«{}..{}»", self.start, self.end)
    }
}

/// A leaf operand of an IR expression.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Operand {
    /// Splice the original source bytes at this range.
    Source(ByteRange),
    /// A generated temporary, by name (spec §2.4 naming discipline).
    Temp(String),
    /// Literal replacement text (e.g. `1`, `msg.sender`).
    Lit(String),
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Source(r) => write!(f, "{r}"),
            Operand::Temp(name) => f.write_str(name),
            Operand::Lit(text) => f.write_str(text),
        }
    }
}

/// An IR expression: a leaf operand or an FHE call over sub-expressions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Expr {
    /// A leaf operand.
    Operand(Operand),
    /// An FHE operation applied to arguments, in call order.
    Call {
        /// The abstract operation.
        op: FheOp,
        /// Arguments in call order (length must equal `op.arity()`).
        args: Vec<Expr>,
    },
}

impl Expr {
    /// Leaf referencing original source bytes.
    pub fn source(range: ByteRange) -> Self {
        Expr::Operand(Operand::Source(range))
    }

    /// Leaf referencing a generated temporary.
    pub fn temp(name: impl Into<String>) -> Self {
        Expr::Operand(Operand::Temp(name.into()))
    }

    /// Leaf holding literal replacement text.
    pub fn lit(text: impl Into<String>) -> Self {
        Expr::Operand(Operand::Lit(text.into()))
    }

    /// An FHE call node.
    pub fn call(op: FheOp, args: Vec<Expr>) -> Self {
        debug_assert_eq!(args.len(), op.arity(), "arity mismatch for {op}");
        Expr::Call { op, args }
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Operand(operand) => write!(f, "{operand}"),
            Expr::Call { op, args } => {
                write!(f, "{op}(")?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{arg}")?;
                }
                f.write_str(")")
            }
        }
    }
}

/// The declared type of a generated temporary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TempType {
    /// An encrypted type.
    Encrypted(EType),
    /// A plaintext Solidity type, spelled as source text (e.g. `address`,
    /// `uint256`) — used for hoisted keys and callees (spec §5.2, §8.2).
    Plain(String),
}

impl fmt::Display for TempType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TempType::Encrypted(t) => write!(f, "{t}"),
            TempType::Plain(text) => f.write_str(text),
        }
    }
}

/// An IR statement fragment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Stmt {
    /// `<ty> <name> = <value>;` — declaration of a generated temporary.
    DeclTemp {
        /// Declared type of the temporary.
        ty: TempType,
        /// Temporary name (spec §2.4).
        name: String,
        /// Initializer.
        value: Expr,
    },
    /// `<lvalue> = <value>;` — assignment to an existing location.
    Assign {
        /// The assigned location (source range, temp, or literal text).
        lvalue: Operand,
        /// Assigned value.
        value: Expr,
    },
    /// `<expr>;` — expression statement (ACL calls, spec §8).
    Expr(Expr),
}

impl fmt::Display for Stmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Stmt::DeclTemp { ty, name, value } => write!(f, "{ty} {name} = {value};"),
            Stmt::Assign { lvalue, value } => write!(f, "{lvalue} = {value};"),
            Stmt::Expr(e) => write!(f, "{e};"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::etype::EWidth;

    #[test]
    fn byte_range_basics() {
        let r = ByteRange::new(4, 10);
        assert_eq!(r.len(), 6);
        assert!(!r.is_empty());
        assert!(ByteRange::new(4, 4).is_empty());
        assert_eq!(r.to_string(), "«4..10»");
    }

    #[test]
    fn expr_display_is_debuggable() {
        // count = FHE.add(count, FHE.asEuint32(1)) as abstract IR:
        let e = Expr::call(
            FheOp::Add,
            vec![
                Expr::source(ByteRange::new(100, 105)),
                Expr::call(
                    FheOp::TrivialEncrypt {
                        to: EType::Euint(EWidth::W32),
                    },
                    vec![Expr::lit("1")],
                ),
            ],
        );
        assert_eq!(e.to_string(), "add(«100..105», trivial-encrypt→euint32(1))");
    }

    #[test]
    fn stmt_display() {
        let s = Stmt::DeclTemp {
            ty: TempType::Encrypted(EType::Ebool),
            name: "__fhe_cond_0".into(),
            value: Expr::source(ByteRange::new(10, 20)),
        };
        assert_eq!(s.to_string(), "ebool __fhe_cond_0 = «10..20»;");

        let acl = Stmt::Expr(Expr::call(
            FheOp::AllowThis,
            vec![Expr::temp("__fhe_ret_0")],
        ));
        assert_eq!(acl.to_string(), "allow-this(__fhe_ret_0);");
    }
}
