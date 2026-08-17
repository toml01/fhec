//! The fhec diagnostic shape (spec §9 catalog, §10.2 JSON schema) and the
//! `FHE6000` wrapper used to forward solc diagnostics.
//!
//! Spec §9 reserves the `FHE6xxx` range for *forwarded solc diagnostics* and
//! assigns exactly one code in it:
//!
//! | Code | Severity | Name |
//! |---|---|---|
//! | FHE6000 | (forwarded) | solc-diagnostic (carries solc's own code, severity, and the remapped `.fsol` span) |
//!
//! So every solc diagnostic becomes one [`Diagnostic`] with `code == "FHE6000"`
//! and a [`ForwardedSolc`] payload carrying solc's own code, severity and kind.
//! The severity of the wrapper is solc's severity, mapped onto the fhec
//! severity ladder — a solc error stays an error.
//!
//! # Spans and remapping
//!
//! The spans produced here point into the **emitted** Solidity, not into the
//! original `.fsol`. Remapping them back through `generated/.fhec/manifest.json`
//! is `fhec-emit`'s job. To keep that remapping lossless, [`Span`] carries the
//! byte offsets exactly as solc reported them (0-based, half-open) alongside the
//! derived 1-based line/column pair; the raw solc location is also preserved
//! verbatim on [`crate::SolcDiagnostic`].

use serde::{Deserialize, Serialize};

use crate::output::SolcSeverity;

/// The spec §9 code under which every solc diagnostic is forwarded.
pub const SOLC_DIAGNOSTIC_CODE: &str = "FHE6000";

/// Diagnostic severity, per the spec §10.2 schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Compilation must be treated as failed.
    Error,
    /// Something suspicious that does not fail the build.
    Warning,
    /// Additional context attached to another diagnostic.
    Note,
}

impl Severity {
    /// Maps a solc severity onto the fhec ladder.
    ///
    /// solc's `info` becomes a [`Severity::Note`]. An unrecognised severity is
    /// conservatively reported as a [`Severity::Warning`] rather than being
    /// silently downgraded to a note.
    #[must_use]
    pub fn from_solc(severity: &SolcSeverity) -> Self {
        match severity {
            SolcSeverity::Error => Self::Error,
            SolcSeverity::Warning | SolcSeverity::Other(_) => Self::Warning,
            SolcSeverity::Info => Self::Note,
        }
    }
}

/// A source span, per the spec §10.2 schema.
///
/// Byte offsets are 0-based and half-open; lines and columns are 1-based and
/// columns count UTF-8 bytes, not grapheme clusters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    /// The file the span points into. Empty when solc reported no location.
    pub file: String,
    /// Inclusive start offset, in bytes from the start of the file.
    pub start_byte: usize,
    /// Exclusive end offset, in bytes from the start of the file.
    pub end_byte: usize,
    /// 1-based line of `start_byte`.
    pub start_line: u32,
    /// 1-based column of `start_byte`, counted in UTF-8 bytes.
    pub start_col: u32,
    /// 1-based line of `end_byte`.
    pub end_line: u32,
    /// 1-based column of `end_byte`, counted in UTF-8 bytes.
    pub end_col: u32,
}

impl Span {
    /// A span for a diagnostic that solc did not attach a location to.
    #[must_use]
    pub fn unknown(file: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            start_byte: 0,
            end_byte: 0,
            start_line: 1,
            start_col: 1,
            end_line: 1,
            end_col: 1,
        }
    }

    /// Whether this span carries no usable position information.
    #[must_use]
    pub fn is_unknown(&self) -> bool {
        self.file.is_empty() && self.start_byte == 0 && self.end_byte == 0
    }
}

/// A machine-applicable edit, per the spec §10.2 schema.
///
/// Forwarded solc diagnostics never carry fix-its; the type exists so the
/// serialised shape matches the schema the conformance harness compares
/// against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixIt {
    /// The range to replace.
    pub span: Span,
    /// The text to put there.
    pub replacement: String,
    /// Whether `--fix` may apply the edit without asking.
    pub safe: bool,
}

/// A secondary span with an optional label, built from solc's
/// `secondarySourceLocations`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelledSpan {
    /// Where the secondary location points.
    pub span: Span,
    /// solc's note for the location, when it supplied one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// solc's own identity, carried by every `FHE6000` diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardedSolc {
    /// solc's numeric error code, as a string (for example `"6359"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// solc's own severity, before it was mapped onto [`Severity`].
    pub severity: SolcSeverity,
    /// solc's diagnostic class, for example `"TypeError"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// solc's pretty-printed rendering, with the source excerpt and carets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formatted_message: Option<String>,
    /// Secondary locations solc attached to the diagnostic.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secondary_spans: Vec<LabelledSpan>,
}

/// A fhec diagnostic, serialising to the spec §10.2 JSON schema.
///
/// The `solc` field is an additive extension used only by `FHE6000`; it is
/// omitted from the JSON for every other code, so the base schema is preserved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// The stable catalog code, for example `"FHE6000"`.
    pub code: String,
    /// How severe the diagnostic is.
    pub severity: Severity,
    /// Where it applies.
    pub span: Span,
    /// The human-readable text.
    pub message: String,
    /// Machine-applicable edits, empty for forwarded solc diagnostics.
    #[serde(default)]
    pub fixits: Vec<FixIt>,
    /// The spec rule the diagnostic comes from, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// The forwarded solc payload, present exactly for `FHE6000`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solc: Option<ForwardedSolc>,
}

impl Diagnostic {
    /// Whether this diagnostic fails the compile gate.
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }
}

/// A byte-offset to line/column index over one source file.
///
/// Built once per source when a [`crate::CompileOutput`] is constructed, so
/// mapping a diagnostic costs a binary search rather than a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineIndex {
    /// Byte offset of the first character of each line; always starts with `0`.
    line_starts: Vec<usize>,
    /// Total length of the indexed text, in bytes.
    len: usize,
}

impl LineIndex {
    /// Indexes `text`.
    #[must_use]
    pub fn new(text: &str) -> Self {
        let mut line_starts = vec![0usize];
        line_starts.extend(
            text.bytes()
                .enumerate()
                .filter(|(_, byte)| *byte == b'\n')
                .map(|(offset, _)| offset + 1),
        );
        Self {
            line_starts,
            len: text.len(),
        }
    }

    /// Total length of the indexed text, in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the indexed text is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Resolves a 0-based byte offset to a 1-based line and column.
    ///
    /// Offsets past the end of the file are clamped to the end rather than
    /// panicking, because the offsets come from an external process.
    #[must_use]
    pub fn line_col(&self, byte: usize) -> (u32, u32) {
        let byte = byte.min(self.len);
        // `partition_point` gives the count of line starts at or before `byte`,
        // which is exactly the 1-based line number.
        let line = self.line_starts.partition_point(|start| *start <= byte);
        let line = line.max(1);
        let start = self.line_starts.get(line - 1).copied().unwrap_or(0);
        let col = byte.saturating_sub(start) + 1;
        (clamp_u32(line), clamp_u32(col))
    }
}

/// Narrows a `usize` to `u32`, saturating rather than wrapping.
fn clamp_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_col_is_one_based() {
        let index = LineIndex::new("abc\ndef\n");
        assert_eq!(index.line_col(0), (1, 1));
        assert_eq!(index.line_col(2), (1, 3));
        assert_eq!(index.line_col(4), (2, 1));
        assert_eq!(index.line_col(7), (2, 4));
    }

    #[test]
    fn line_col_counts_utf8_bytes() {
        // "é" is two bytes, so the column after it is 3, not 2.
        let index = LineIndex::new("é!");
        assert_eq!(index.line_col(2), (1, 3));
    }

    #[test]
    fn line_col_clamps_out_of_range_offsets() {
        let index = LineIndex::new("ab");
        assert_eq!(index.line_col(9_999), (1, 3));
    }

    #[test]
    fn empty_text_is_one_one() {
        let index = LineIndex::new("");
        assert!(index.is_empty());
        assert_eq!(index.line_col(0), (1, 1));
    }

    #[test]
    fn diagnostic_serialises_to_the_spec_schema() {
        let diag = Diagnostic {
            code: SOLC_DIAGNOSTIC_CODE.to_owned(),
            severity: Severity::Error,
            span: Span {
                file: "generated/A.sol".to_owned(),
                start_byte: 122,
                end_byte: 126,
                start_line: 3,
                start_col: 66,
                end_line: 3,
                end_col: 70,
            },
            message: "boom".to_owned(),
            fixits: Vec::new(),
            rule: None,
            solc: None,
        };
        let value = serde_json::to_value(&diag).expect("diagnostic serialises");
        assert_eq!(value["code"], "FHE6000");
        assert_eq!(value["severity"], "error");
        assert_eq!(value["span"]["start_byte"], 122);
        assert_eq!(value["span"]["start_line"], 3);
        assert!(value["fixits"].is_array());
        assert!(value.get("rule").is_none());
        assert!(value.get("solc").is_none());
    }

    #[test]
    fn solc_severities_map_onto_the_fhec_ladder() {
        assert_eq!(Severity::from_solc(&SolcSeverity::Error), Severity::Error);
        assert_eq!(
            Severity::from_solc(&SolcSeverity::Warning),
            Severity::Warning
        );
        assert_eq!(Severity::from_solc(&SolcSeverity::Info), Severity::Note);
        assert_eq!(
            Severity::from_solc(&SolcSeverity::Other("weird".to_owned())),
            Severity::Warning
        );
    }
}
