//! Checker diagnostics, mirroring the spec §10.2 fields.

use solar_interface::Span;

/// Diagnostic severity (spec §10.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// A conformance violation; transpilation of the contract is refused.
    Error,
    /// A suspicious construct; transpilation proceeds.
    Warning,
    /// Informational (used by `--acl=suggest`).
    Note,
}

/// A suggested textual replacement (spec §9, §10.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixIt {
    /// The span the replacement applies to.
    pub span: Span,
    /// The replacement text.
    pub replacement: String,
    /// Whether `--fix` may apply it automatically.
    pub safe: bool,
}

/// One checker diagnostic.
///
/// Spans are raw solar [`Span`]s (session-global byte positions); the CLI
/// converts them to per-file offsets and line/column via the session's source
/// map when rendering.
#[derive(Clone, Debug)]
pub struct Diagnostic {
    /// Stable catalog code (`"FHE2001"`, spec §9).
    pub code: &'static str,
    /// Severity per the catalog.
    pub severity: Severity,
    /// The source span of the offending construct.
    pub span: Span,
    /// Human-readable message.
    pub message: String,
    /// Suggested fixes, possibly empty.
    pub fixits: Vec<FixIt>,
    /// The spec section that defines the rule (`"§3.2"`), when applicable.
    pub rule: Option<&'static str>,
}

impl Diagnostic {
    /// Creates an error diagnostic.
    pub fn error(code: &'static str, span: Span, message: impl Into<String>) -> Self {
        Diagnostic {
            code,
            severity: Severity::Error,
            span,
            message: message.into(),
            fixits: Vec::new(),
            rule: None,
        }
    }

    /// Attaches the defining spec section.
    pub fn with_rule(mut self, rule: &'static str) -> Self {
        self.rule = Some(rule);
        self
    }

    /// Attaches a fix-it.
    pub fn with_fixit(mut self, fixit: FixIt) -> Self {
        self.fixits.push(fixit);
        self
    }
}

/// Stable diagnostic codes emitted by this crate (spec §9).
pub mod codes {
    /// in-sugar-non-encrypted-type (§2.3).
    pub const IN_SUGAR_NON_ENCRYPTED: &str = "FHE1010";
    /// in-sugar-name-collision (§2.3).
    pub const IN_SUGAR_NAME_COLLISION: &str = "FHE1011";
    /// in-sugar-bad-position (§2.3).
    pub const IN_SUGAR_BAD_POSITION: &str = "FHE1012";
    /// encrypted-meets-unknown (§3.2).
    pub const ENCRYPTED_MEETS_UNKNOWN: &str = "FHE2001";
    /// incompatible-encrypted-operands (§3.3, §4.1).
    pub const INCOMPATIBLE_ENCRYPTED: &str = "FHE2002";
    /// literal-out-of-range (§3.3).
    pub const LITERAL_OUT_OF_RANGE: &str = "FHE2003";
    /// implicit-narrowing-required (§3.3, §4.3).
    pub const NARROWING_REQUIRED: &str = "FHE2004";
    /// unary-minus-on-encrypted (§3.3).
    pub const UNARY_MINUS: &str = "FHE2005";
    /// operator-unsupported-for-encrypted-type (§4.1).
    pub const OPERATOR_UNSUPPORTED: &str = "FHE2006";
    /// possibly-uninitialized-encrypted (§6).
    pub const POSSIBLY_UNINITIALIZED: &str = "FHE2007";
    /// plaintext-operand-not-convertible (§3.3).
    pub const NOT_CONVERTIBLE: &str = "FHE2008";
    /// condition-not-ebool (§3.3).
    pub const CONDITION_NOT_EBOOL: &str = "FHE2009";
    /// encrypted-op-in-view-or-pure (§3.4).
    pub const FHE_IN_VIEW_OR_PURE: &str = "FHE2010";
    /// inc-dec-value-used (§4.2).
    pub const INC_DEC_VALUE_USED: &str = "FHE2011";
    /// return-in-encrypted-branch (§7.1).
    pub const RETURN_IN_BRANCH: &str = "FHE3001";
    /// break-continue-in-encrypted-branch (§7.1).
    pub const BREAK_CONTINUE_IN_BRANCH: &str = "FHE3002";
    /// revert-family-in-encrypted-branch (§7.1).
    pub const REVERT_IN_BRANCH: &str = "FHE3003";
    /// external-call-in-encrypted-branch (§7.1).
    pub const EXTERNAL_CALL_IN_BRANCH: &str = "FHE3004";
    /// emit-in-encrypted-branch (§7.1).
    pub const EMIT_IN_BRANCH: &str = "FHE3005";
    /// plaintext-write-in-encrypted-branch (§7.1).
    pub const PLAINTEXT_WRITE_IN_BRANCH: &str = "FHE3006";
    /// plaintext-control-flow-in-encrypted-branch (§7.1).
    pub const PLAINTEXT_FLOW_IN_BRANCH: &str = "FHE3007";
    /// unverified-call-in-encrypted-branch (§7.1).
    pub const UNVERIFIED_CALL_IN_BRANCH: &str = "FHE3008";
    /// inline-assembly-in-encrypted-branch (§7.1).
    pub const ASSEMBLY_IN_BRANCH: &str = "FHE3009";
    /// delete-on-encrypted (§7.1, §7.2).
    pub const DELETE_ON_ENCRYPTED: &str = "FHE3010";
    /// side-effecting-encrypted-operand (§5.5).
    pub const SIDE_EFFECT_OPERAND: &str = "FHE3012";
    /// encrypted-index (§7.2).
    pub const ENCRYPTED_INDEX: &str = "FHE3020";
    /// encrypted-loop-condition (§5.6, §7.2).
    pub const ENCRYPTED_LOOP: &str = "FHE3021";
    /// ebool-in-plaintext-bool-context (§7.2).
    pub const EBOOL_AS_BOOL: &str = "FHE3022";
    /// op-not-in-profile-version (§1.5).
    pub const OP_NOT_IN_PROFILE: &str = "FHE5001";
}
