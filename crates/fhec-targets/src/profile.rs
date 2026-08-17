//! The [`TargetProfile`] trait and its error type.

use std::fmt;

use fhec_ir::{EType, FheOp};

/// Capability flags of a target profile.
///
/// Non-exhaustive: new flags may be added without a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Capabilities {
    /// Whether the library offers a synchronous `decrypt` operation.
    /// CoFHE at the pinned revision does not (only `verifyDecryptResult`).
    pub has_decrypt: bool,
}

/// A typed profile-level failure.
///
/// [`ProfileError::Unsupported`] is the signal behind diagnostic FHE5001
/// (op-not-in-profile-version, spec §1.5); the checker maps it to a
/// user-facing error carrying the source span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    /// The operation does not exist for these operand types in the pinned
    /// profile version.
    Unsupported {
        /// The rejected operation.
        op: FheOp,
        /// The encrypted operand types as queried.
        operands: Vec<EType>,
    },
    /// The operand or argument count does not match the operation's shape.
    /// This indicates a caller bug, not a profile gap.
    WrongArity {
        /// The operation.
        op: FheOp,
        /// Expected count.
        expected: usize,
        /// Provided count.
        got: usize,
    },
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileError::Unsupported { op, operands } => {
                write!(f, "operation `{op}` is not supported for operand types (")?;
                for (i, t) in operands.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{t}")?;
                }
                f.write_str(") in this profile version")
            }
            ProfileError::WrongArity { op, expected, got } => {
                write!(
                    f,
                    "operation `{op}` expects {expected} operand(s), got {got}"
                )
            }
        }
    }
}

impl std::error::Error for ProfileError {}

/// A versioned mapping from abstract FHE-IR to one concrete FHE library
/// release (spec §1.5). Object-safe: passes and the checker hold a
/// `dyn TargetProfile`.
///
/// Throughout this trait, `operands` lists the *encrypted* operand types in
/// call order, omitting arguments that are not encrypted values:
///
/// - binary ops, comparisons: `[lhs, rhs]`
/// - unary ops: `[operand]`
/// - select: `[cond, if_true, if_false]`
/// - `AllowThis`/`AllowSender`/`AllowGlobal`: `[handle]`
/// - `AllowTransient`: `[handle]` (the account argument is a plain address)
/// - `TrivialEncrypt`/`FromInStruct`: `[]` (input is plaintext / a struct)
/// - `Widen`: `[source]` (must equal the op's `from` width)
pub trait TargetProfile {
    /// Profile family identifier (e.g. `"cofhe"`).
    fn id(&self) -> &str;

    /// Pinned library version this profile describes (e.g. `"0.1.x"`).
    fn version(&self) -> &str;

    /// The Solidity pragma range supported source files must satisfy
    /// (spec §2.1), e.g. `">=0.8.25 <0.9.0"`.
    fn pragma_range(&self) -> &str;

    /// Import statements the output file must contain for rendered calls to
    /// resolve, each a complete line of Solidity.
    fn import_lines(&self) -> Vec<String>;

    /// Capability flags of the pinned library version.
    fn capabilities(&self) -> Capabilities;

    /// Types an operation application.
    ///
    /// Returns the encrypted result type, `Ok(None)` for void operations
    /// (ACL calls), or [`ProfileError::Unsupported`] when the pinned library
    /// version lacks the combination (→ FHE5001).
    fn result_type(&self, op: FheOp, operands: &[EType]) -> Result<Option<EType>, ProfileError>;

    /// Renders the concrete library call from pre-rendered argument texts.
    ///
    /// `args` holds *all* call arguments in order (length must equal
    /// [`FheOp::arity`]), including plaintext ones — e.g. `AllowTransient`
    /// takes `[handle_text, account_text]`. Validates the operation against
    /// the signature table before rendering.
    fn render_call(
        &self,
        op: FheOp,
        operands: &[EType],
        args: &[&str],
    ) -> Result<String, ProfileError>;

    /// Whether the library provides an explicit cast from `from` to `to`.
    ///
    /// This reflects raw library availability. The dialect's typing rules
    /// are stricter (implicit narrowing is forbidden, spec §3.3 rule 3);
    /// that policy belongs to the checker, not the profile.
    fn can_cast(&self, from: EType, to: EType) -> bool;

    /// The library's name for an ACL operation (e.g. `"allowThis"`), used by
    /// the ACL pass for dedupe matching (spec §8.6). `None` for non-ACL ops.
    fn acl_fn_name(&self, op: FheOp) -> Option<String>;

    /// The encrypted-input struct parameter type for an encrypted type
    /// (e.g. `"InEuint32"`, spec §2.3).
    fn in_struct_type(&self, ty: EType) -> String;

    /// The fully qualified conversion function used both for input-struct
    /// conversion and trivial encryption (e.g. `"FHE.asEuint32"`).
    fn conversion_fn(&self, ty: EType) -> String;
}
