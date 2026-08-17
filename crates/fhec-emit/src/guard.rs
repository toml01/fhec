//! Re-parse guards (spec §2.5): every rendered fragment is re-parsed before
//! splicing, and the whole output is re-parsed after. A guard failure means
//! an earlier stage rendered invalid Solidity — an internal error, reported
//! as FHE9003 (fragment) or FHE9002 (output), never spliced.

use std::fmt;

use crate::error::EmitError;

/// What kind of rendered text a fragment guard checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentKind {
    /// One or more statements (temp declarations, assignments, ACL calls).
    Statement,
    /// A single expression (a lowered operator or select call).
    Expression,
}

impl fmt::Display for FragmentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FragmentKind::Statement => "statement",
            FragmentKind::Expression => "expression",
        })
    }
}

/// Validates a rendered fragment by wrapping it in a minimal synthetic
/// contract and parsing it (parse only — no name or type resolution).
pub fn validate_fragment(kind: FragmentKind, text: &str) -> Result<(), EmitError> {
    let wrapped = match kind {
        FragmentKind::Statement => format!(
            "contract __FhecReparseGuard {{ function __fhecGuard() private {{\n{text}\n}} }}"
        ),
        FragmentKind::Expression => format!(
            "contract __FhecReparseGuard {{ function __fhecGuard() private {{\n__fhecProbe(({text}));\n}} }}"
        ),
    };
    fhec_syntax::parse_source("__fhec_fragment_guard.sol", &wrapped).map_err(|diagnostics| {
        EmitError::FragmentReparse {
            kind,
            text: text.to_string(),
            diagnostics,
        }
    })
}

/// Validates a complete output file by re-parsing it (spec §2.5).
pub fn validate_output(name: &str, full_text: &str) -> Result<(), EmitError> {
    fhec_syntax::parse_source(name, full_text).map_err(|diagnostics| EmitError::OutputReparse {
        name: name.to_string(),
        diagnostics,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_statements() {
        validate_fragment(
            FragmentKind::Statement,
            "euint32 __fhe_val_0 = FHE.add(count, FHE.asEuint32(1));\nFHE.allowThis(count);",
        )
        .expect("valid statements must pass");
    }

    #[test]
    fn accepts_valid_expression() {
        validate_fragment(
            FragmentKind::Expression,
            "FHE.select(__fhe_cond_0, __fhe_then_1, __fhe_pre_2)",
        )
        .expect("valid expression must pass");
    }

    #[test]
    fn rejects_truncated_call() {
        let err = validate_fragment(FragmentKind::Expression, "FHE.add(a,").unwrap_err();
        assert_eq!(err.code(), "FHE9003");
        assert!(matches!(err, EmitError::FragmentReparse { .. }));
    }

    #[test]
    fn rejects_broken_statement() {
        let err = validate_fragment(FragmentKind::Statement, "euint32 = ;").unwrap_err();
        assert_eq!(err.code(), "FHE9003");
    }

    #[test]
    fn output_guard() {
        validate_output(
            "ok.sol",
            "pragma solidity ^0.8.25;\ncontract C { uint256 x; }\n",
        )
        .expect("valid file must pass");

        let err = validate_output("bad.sol", "contract {").unwrap_err();
        assert_eq!(err.code(), "FHE9002");
        assert!(matches!(err, EmitError::OutputReparse { .. }));
    }
}
