//! Diagnostic model and rendering.
//!
//! The JSON shape mirrors spec §10.2 exactly (field names and order); the human
//! renderer is presentation-only and additionally shows the docs link, which §9
//! recommends but §10.2 deliberately leaves out of the interchange schema.

use serde::{Deserialize, Serialize};

/// Diagnostic severity, serialized lowercase per spec §10.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Note,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Note => "note",
        };
        f.write_str(s)
    }
}

/// A source span per spec §10.2: byte offsets are 0-based half-open; lines and
/// columns are 1-based and columns count UTF-8 bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub file: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
}

impl Span {
    /// A whole-file span anchored at the first byte (used when no finer span is
    /// available, e.g. for rendered parser output we cannot yet map back).
    pub fn file_level(file: &str) -> Self {
        Span {
            file: file.to_string(),
            start_byte: 0,
            end_byte: 0,
            start_line: 1,
            start_col: 1,
            end_line: 1,
            end_col: 1,
        }
    }

    /// Builds a span from byte offsets into `content`, computing 1-based
    /// line/column positions (columns in UTF-8 bytes) per spec §10.2.
    pub fn from_bytes(file: &str, content: &str, start_byte: usize, end_byte: usize) -> Self {
        let (start_line, start_col) = line_col(content, start_byte);
        let (end_line, end_col) = line_col(content, end_byte);
        Span {
            file: file.to_string(),
            start_byte,
            end_byte,
            start_line,
            start_col,
            end_line,
            end_col,
        }
    }
}

/// 1-based (line, column) for a byte offset; columns count UTF-8 bytes.
pub fn line_col(content: &str, byte: usize) -> (u32, u32) {
    let byte = byte.min(content.len());
    let mut line: u32 = 1;
    let mut line_start = 0usize;
    for (i, b) in content.bytes().enumerate() {
        if i >= byte {
            break;
        }
        if b == b'\n' {
            line += 1;
            line_start = i + 1;
        }
    }
    (line, (byte - line_start + 1) as u32)
}

/// A suggested replacement per spec §10.2. `safe: true` fix-its may be
/// auto-applied by `--fix` (not implemented yet).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixIt {
    pub span: Span,
    pub replacement: String,
    pub safe: bool,
}

/// One diagnostic, shaped for spec §10.2 JSON interchange.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub severity: Severity,
    pub span: Span,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixits: Vec<FixIt>,
    /// Spec section reference, e.g. "§5.2".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

impl Diagnostic {
    pub fn new(code: &str, severity: Severity, span: Span, message: impl Into<String>) -> Self {
        Diagnostic {
            code: code.to_string(),
            severity,
            span,
            message: message.into(),
            fixits: Vec::new(),
            rule: None,
        }
    }

    /// Documentation link for this code (placeholder domain).
    pub fn docs_link(&self) -> String {
        format!("https://fhec.dev/errors/{}", self.code)
    }
}

/// Renders a diagnostic list as the spec §10.2 JSON array (pretty-printed).
pub fn render_json(diags: &[Diagnostic]) -> String {
    serde_json::to_string_pretty(diags).expect("diagnostics serialize")
}

/// Renders one diagnostic rustc-style. `content` is the text of `span.file`
/// when available; without it the source line and caret are omitted.
pub fn render_human(diag: &Diagnostic, content: Option<&str>) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{}[{}]: {}\n",
        diag.severity, diag.code, diag.message
    ));
    out.push_str(&format!(
        "  --> {}:{}:{}\n",
        diag.span.file, diag.span.start_line, diag.span.start_col
    ));
    if let Some(content) = content {
        if let Some(line_text) = content.lines().nth(diag.span.start_line as usize - 1) {
            let line_no = diag.span.start_line.to_string();
            let gutter = " ".repeat(line_no.len());
            out.push_str(&format!("{gutter} |\n"));
            out.push_str(&format!("{line_no} | {line_text}\n"));
            let col0 = diag.span.start_col as usize - 1;
            let caret_end = if diag.span.end_line == diag.span.start_line {
                (diag.span.end_col as usize - 1).min(line_text.len())
            } else {
                line_text.len()
            };
            let carets = caret_end.saturating_sub(col0).max(1);
            out.push_str(&format!(
                "{gutter} | {}{}\n",
                " ".repeat(col0.min(line_text.len())),
                "^".repeat(carets)
            ));
        }
    }
    out.push_str(&format!("  = docs: {}\n", diag.docs_link()));
    out
}

/// True when any diagnostic is an error (drives the process exit code).
pub fn has_errors(diags: &[Diagnostic]) -> bool {
    diags.iter().any(|d| d.severity == Severity::Error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_col_basics() {
        let s = "ab\ncd\n";
        assert_eq!(line_col(s, 0), (1, 1));
        assert_eq!(line_col(s, 1), (1, 2));
        assert_eq!(line_col(s, 3), (2, 1));
        assert_eq!(line_col(s, 4), (2, 2));
        // Offset at EOF clamps to the last position.
        assert_eq!(line_col(s, 6), (3, 1));
    }

    #[test]
    fn json_matches_spec_schema() {
        let content = "contract C {\n    uint x\n}\n";
        let span = Span::from_bytes("input.fsol", content, 17, 23);
        let mut d = Diagnostic::new("FHE1002", Severity::Error, span, "expected `;`");
        d.rule = Some("§2.2".to_string());
        let expected = r#"[
  {
    "code": "FHE1002",
    "severity": "error",
    "span": {
      "file": "input.fsol",
      "start_byte": 17,
      "end_byte": 23,
      "start_line": 2,
      "start_col": 5,
      "end_line": 2,
      "end_col": 11
    },
    "message": "expected `;`",
    "rule": "§2.2"
  }
]"#;
        assert_eq!(render_json(&[d]), expected);
    }

    #[test]
    fn human_renderer_caret() {
        let content = "contract C {\n    uint x\n}\n";
        let span = Span::from_bytes("input.fsol", content, 17, 23);
        let d = Diagnostic::new("FHE1002", Severity::Error, span, "expected `;`");
        let rendered = render_human(&d, Some(content));
        let expected = "error[FHE1002]: expected `;`\n  --> input.fsol:2:5\n  |\n2 |     uint x\n  |     ^^^^^^\n  = docs: https://fhec.dev/errors/FHE1002\n";
        assert_eq!(rendered, expected);
    }

    #[test]
    fn fixits_serialize_when_present() {
        let span = Span::file_level("a.fsol");
        let mut d = Diagnostic::new("FHE2005", Severity::Error, span.clone(), "unary minus");
        d.fixits.push(FixIt {
            span,
            replacement: "FHE.sub(FHE.asEuint32(0), x)".to_string(),
            safe: false,
        });
        let json = render_json(&[d.clone()]);
        assert!(json.contains("\"replacement\""));
        let back: Vec<Diagnostic> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, vec![d]);
    }
}
