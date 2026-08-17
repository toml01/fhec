//! The standard-JSON output schema, as produced by `solc --standard-json`.
//!
//! Everything here is deliberately permissive: fields solc omits deserialise to
//! defaults, unknown fields are ignored, and the untouched response is kept on
//! [`CompileOutput::raw`]. Nothing panics on unexpected shapes.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;

use semver::Version;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::diagnostic::{
    Diagnostic, ForwardedSolc, LabelledSpan, LineIndex, Severity, Span, SOLC_DIAGNOSTIC_CODE,
};

/// The sentinel solc uses for "no offset".
const NO_OFFSET: i64 = -1;

/// solc's own diagnostic severity.
///
/// Unknown values are preserved verbatim in [`SolcSeverity::Other`] rather than
/// being dropped, so a future solc release cannot make this crate lose data.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SolcSeverity {
    /// Compilation failed.
    Error,
    /// A warning that does not fail compilation.
    Warning,
    /// Informational output.
    Info,
    /// A severity this crate does not know, kept as solc wrote it.
    Other(String),
}

impl SolcSeverity {
    /// The wire spelling of this severity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
            Self::Other(text) => text,
        }
    }

    /// Whether this severity fails the compile gate.
    #[must_use]
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error)
    }
}

impl fmt::Display for SolcSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for SolcSeverity {
    fn from(text: &str) -> Self {
        match text {
            "error" => Self::Error,
            "warning" => Self::Warning,
            "info" => Self::Info,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl Serialize for SolcSeverity {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SolcSeverity {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Ok(Self::from(text.as_str()))
    }
}

/// Deserialises solc's `errorCode`, which has been both a JSON string and a
/// JSON number across releases.
fn deserialize_error_code<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Text(String),
        Number(serde_json::Number),
    }

    let raw = Option::<Raw>::deserialize(deserializer)?;
    Ok(raw.map(|raw| match raw {
        Raw::Text(text) => text,
        Raw::Number(number) => number.to_string(),
    }))
}

/// The default for a missing `start`/`end` in a source location.
fn no_offset() -> i64 {
    NO_OFFSET
}

/// A location inside one standard-JSON source, exactly as solc reported it.
///
/// `start` and `end` are kept as raw `i64` so solc's `-1` sentinel survives a
/// round trip; use [`SolcSourceLocation::byte_range`] for the checked view.
/// This losslessness is what later lets `fhec-emit` remap the range back to the
/// originating `.fsol` span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolcSourceLocation {
    /// The standard-JSON source key the offsets apply to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// 0-based inclusive start offset in bytes, or `-1` when unknown.
    #[serde(default = "no_offset")]
    pub start: i64,
    /// 0-based exclusive end offset in bytes, or `-1` when unknown.
    #[serde(default = "no_offset")]
    pub end: i64,
    /// solc's label for a secondary location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl SolcSourceLocation {
    /// The half-open byte range, when solc supplied a usable one.
    ///
    /// Returns `None` if either offset is the `-1` sentinel or the range is
    /// inverted.
    #[must_use]
    pub fn byte_range(&self) -> Option<Range<usize>> {
        if self.start < 0 || self.end < 0 || self.end < self.start {
            return None;
        }
        let start = usize::try_from(self.start).ok()?;
        let end = usize::try_from(self.end).ok()?;
        Some(start..end)
    }
}

/// One entry of the standard-JSON `errors[]` array.
///
/// Every field solc documents is preserved, including the pretty-printed
/// `formattedMessage` and all secondary locations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SolcDiagnostic {
    /// How severe solc considers the problem.
    pub severity: SolcSeverity,
    /// solc's numeric error code, as a string (for example `"6359"`).
    #[serde(
        default,
        deserialize_with = "deserialize_error_code",
        skip_serializing_if = "Option::is_none"
    )]
    pub error_code: Option<String>,
    /// solc's diagnostic class, for example `"TypeError"`. Wire name `type`.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The solc subsystem that raised the diagnostic, usually `"general"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    /// The bare message.
    #[serde(default)]
    pub message: String,
    /// solc's pretty-printed rendering, with source excerpt and carets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formatted_message: Option<String>,
    /// The primary location, absent for diagnostics that have none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_location: Option<SolcSourceLocation>,
    /// Additional locations, for example the other definition in a clash.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secondary_source_locations: Vec<SolcSourceLocation>,
}

impl SolcDiagnostic {
    /// Whether this diagnostic fails the compile gate.
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.severity.is_error()
    }
}

/// The compiled form of one contract, present only when artifacts were
/// requested through [`crate::OutputSelection::Artifacts`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractArtifact {
    /// The contract ABI, as solc emitted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abi: Option<serde_json::Value>,
    /// The metadata blob, as a JSON string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
    /// EVM-specific outputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evm: Option<EvmArtifact>,
}

/// The `evm` sub-object of a contract artifact.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmArtifact {
    /// Creation bytecode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytecode: Option<BytecodeArtifact>,
    /// Runtime bytecode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployed_bytecode: Option<BytecodeArtifact>,
}

/// One bytecode object.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BytecodeArtifact {
    /// The hex-encoded bytecode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// solc's own source map for the bytecode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_map: Option<String>,
}

/// The subset of the standard-JSON response this crate models.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct StandardJsonOutput {
    #[serde(default)]
    pub(crate) errors: Vec<SolcDiagnostic>,
    #[serde(default)]
    pub(crate) contracts: BTreeMap<String, BTreeMap<String, ContractArtifact>>,
}

/// The result of one `solc --standard-json` run.
///
/// A run that reports errors is still a successful *invocation*: the process
/// started, produced parsable output, and the diagnostics are available. Use
/// [`CompileOutput::is_success`] for the compile-gate verdict.
#[derive(Debug, Clone)]
pub struct CompileOutput {
    diagnostics: Vec<SolcDiagnostic>,
    contracts: BTreeMap<String, BTreeMap<String, ContractArtifact>>,
    raw: serde_json::Value,
    solc_version: Version,
    line_index: BTreeMap<String, LineIndex>,
}

impl CompileOutput {
    /// Builds an output from a parsed response plus the sources that produced
    /// it, indexing those sources so spans can be resolved to line/column.
    pub(crate) fn new(
        parsed: StandardJsonOutput,
        raw: serde_json::Value,
        solc_version: Version,
        sources: &BTreeMap<String, String>,
    ) -> Self {
        let line_index = sources
            .iter()
            .map(|(path, content)| (path.clone(), LineIndex::new(content)))
            .collect();
        Self {
            diagnostics: parsed.errors,
            contracts: parsed.contracts,
            raw,
            solc_version,
            line_index,
        }
    }

    /// Every diagnostic solc reported, in solc's own order.
    #[must_use]
    pub fn diagnostics(&self) -> &[SolcDiagnostic] {
        &self.diagnostics
    }

    /// Only the diagnostics that fail the compile gate.
    pub fn errors(&self) -> impl Iterator<Item = &SolcDiagnostic> {
        self.diagnostics.iter().filter(|diag| diag.is_error())
    }

    /// Whether the compile gate passes, that is, no diagnostic has severity
    /// `error`.
    #[must_use]
    pub fn is_success(&self) -> bool {
        !self.diagnostics.iter().any(SolcDiagnostic::is_error)
    }

    /// Artifacts keyed by source path and then contract name.
    ///
    /// Empty unless the input asked for [`crate::OutputSelection::Artifacts`]
    /// or a custom selection.
    #[must_use]
    pub fn contracts(&self) -> &BTreeMap<String, BTreeMap<String, ContractArtifact>> {
        &self.contracts
    }

    /// The untouched standard-JSON response, for anything this crate does not
    /// model.
    #[must_use]
    pub fn raw(&self) -> &serde_json::Value {
        &self.raw
    }

    /// The version of the `solc` binary that produced this output.
    #[must_use]
    pub fn solc_version(&self) -> &Version {
        &self.solc_version
    }

    /// Every solc diagnostic re-expressed as a spec §9 `FHE6000` diagnostic.
    ///
    /// Spans point into the *emitted* Solidity. Remapping them onto the
    /// originating `.fsol` is `fhec-emit`'s job; the byte offsets are carried
    /// through unchanged so that remapping stays exact.
    #[must_use]
    pub fn fhe_diagnostics(&self) -> Vec<Diagnostic> {
        self.diagnostics
            .iter()
            .map(|diag| self.to_fhe_diagnostic(diag))
            .collect()
    }

    /// Re-expresses a single solc diagnostic as an `FHE6000` diagnostic.
    #[must_use]
    pub fn to_fhe_diagnostic(&self, diag: &SolcDiagnostic) -> Diagnostic {
        let span = diag
            .source_location
            .as_ref()
            .map_or_else(|| Span::unknown(""), |loc| self.span_for(loc));
        let secondary_spans = diag
            .secondary_source_locations
            .iter()
            .map(|loc| LabelledSpan {
                span: self.span_for(loc),
                message: loc.message.clone(),
            })
            .collect();
        Diagnostic {
            code: SOLC_DIAGNOSTIC_CODE.to_owned(),
            severity: Severity::from_solc(&diag.severity),
            span,
            message: diag.message.clone(),
            fixits: Vec::new(),
            rule: None,
            solc: Some(ForwardedSolc {
                code: diag.error_code.clone(),
                severity: diag.severity.clone(),
                kind: diag.kind.clone(),
                formatted_message: diag.formatted_message.clone(),
                secondary_spans,
            }),
        }
    }

    /// Converts a solc location into a spec span, resolving line/column from
    /// the indexed source when the file is one we submitted.
    fn span_for(&self, loc: &SolcSourceLocation) -> Span {
        let file = loc.file.clone().unwrap_or_default();
        let Some(range) = loc.byte_range() else {
            return Span::unknown(file);
        };
        let Some(index) = self.line_index.get(&file) else {
            // solc named a file we did not submit (or none at all): keep the
            // offsets, leave line/column at the start of the file.
            return Span {
                file,
                start_byte: range.start,
                end_byte: range.end,
                start_line: 1,
                start_col: 1,
                end_line: 1,
                end_col: 1,
            };
        };
        let (start_line, start_col) = index.line_col(range.start);
        let (end_line, end_col) = index.line_col(range.end);
        Span {
            file,
            start_byte: range.start,
            end_byte: range.end,
            start_line,
            start_col,
            end_line,
            end_col,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output_with(response: &str, sources: &[(&str, &str)]) -> CompileOutput {
        let raw: serde_json::Value = serde_json::from_str(response).expect("valid fixture");
        let parsed: StandardJsonOutput =
            serde_json::from_value(raw.clone()).expect("fixture matches the schema");
        let sources = sources
            .iter()
            .map(|(path, content)| ((*path).to_owned(), (*content).to_owned()))
            .collect();
        CompileOutput::new(parsed, raw, Version::new(0, 8, 28), &sources)
    }

    const TYPE_ERROR: &str = r#"{
        "errors": [{
            "component": "general",
            "errorCode": "6359",
            "formattedMessage": "TypeError: nope\n --> A.sol:3:66:\n",
            "message": "Return argument type bool is not implicitly convertible.",
            "severity": "error",
            "sourceLocation": {"end": 12, "file": "A.sol", "start": 8},
            "type": "TypeError"
        }],
        "sources": {}
    }"#;

    #[test]
    fn parses_and_wraps_a_type_error() {
        let out = output_with(TYPE_ERROR, &[("A.sol", "line1\nab\ncdef\n")]);
        assert!(!out.is_success());
        assert_eq!(out.errors().count(), 1);

        let diag = &out.diagnostics()[0];
        assert_eq!(diag.error_code.as_deref(), Some("6359"));
        assert_eq!(diag.kind.as_deref(), Some("TypeError"));
        assert_eq!(diag.severity, SolcSeverity::Error);

        let fhe = out.fhe_diagnostics();
        assert_eq!(fhe.len(), 1);
        let fhe = &fhe[0];
        assert_eq!(fhe.code, "FHE6000");
        assert_eq!(fhe.severity, Severity::Error);
        assert_eq!(fhe.span.file, "A.sol");
        // Offsets survive verbatim, so fhec-emit can remap them later.
        assert_eq!(fhe.span.start_byte, 8);
        assert_eq!(fhe.span.end_byte, 12);
        // "line1\nab\ncdef\n": offset 8 is the newline ending line 2.
        assert_eq!((fhe.span.start_line, fhe.span.start_col), (2, 3));
        assert_eq!((fhe.span.end_line, fhe.span.end_col), (3, 4));
        let forwarded = fhe.solc.as_ref().expect("FHE6000 carries the solc payload");
        assert_eq!(forwarded.code.as_deref(), Some("6359"));
        assert_eq!(forwarded.severity, SolcSeverity::Error);
    }

    #[test]
    fn accepts_a_numeric_error_code() {
        let out = output_with(
            r#"{"errors":[{"severity":"warning","errorCode":1878,"message":"spdx"}]}"#,
            &[],
        );
        assert_eq!(out.diagnostics()[0].error_code.as_deref(), Some("1878"));
        assert!(out.is_success(), "a warning does not fail the gate");
    }

    #[test]
    fn tolerates_a_diagnostic_without_a_location() {
        let out = output_with(r#"{"errors":[{"severity":"error","message":"boom"}]}"#, &[]);
        let fhe = &out.fhe_diagnostics()[0];
        assert!(fhe.span.is_unknown());
        assert_eq!(fhe.message, "boom");
    }

    #[test]
    fn tolerates_the_minus_one_offset_sentinel() {
        let out = output_with(
            r#"{"errors":[{"severity":"error","message":"x","sourceLocation":{"file":"A.sol","start":-1,"end":-1}}]}"#,
            &[("A.sol", "contract A {}")],
        );
        let loc = out.diagnostics()[0]
            .source_location
            .as_ref()
            .expect("location present");
        assert_eq!(loc.byte_range(), None);
        assert_eq!(out.fhe_diagnostics()[0].span.start_byte, 0);
    }

    #[test]
    fn keeps_secondary_locations() {
        let out = output_with(
            r#"{"errors":[{"severity":"error","message":"clash",
                "sourceLocation":{"file":"A.sol","start":0,"end":2},
                "secondarySourceLocations":[{"file":"A.sol","start":4,"end":6,"message":"other"}]}]}"#,
            &[("A.sol", "ab\ncd\n")],
        );
        let forwarded = out.fhe_diagnostics()[0]
            .solc
            .clone()
            .expect("payload present");
        assert_eq!(forwarded.secondary_spans.len(), 1);
        assert_eq!(forwarded.secondary_spans[0].span.start_byte, 4);
        assert_eq!(
            forwarded.secondary_spans[0].message.as_deref(),
            Some("other")
        );
    }

    #[test]
    fn unknown_severity_round_trips() {
        let out = output_with(
            r#"{"errors":[{"severity":"catastrophe","message":"?"}]}"#,
            &[],
        );
        assert_eq!(
            out.diagnostics()[0].severity,
            SolcSeverity::Other("catastrophe".to_owned())
        );
        assert!(out.is_success(), "unknown severities do not fail the gate");
        assert_eq!(out.fhe_diagnostics()[0].severity, Severity::Warning);
    }

    #[test]
    fn empty_response_is_a_pass() {
        let out = output_with("{}", &[]);
        assert!(out.is_success());
        assert!(out.diagnostics().is_empty());
        assert!(out.contracts().is_empty());
    }
}
