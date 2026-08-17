//! Typed emitter errors, mapped to the internal-invariant diagnostic codes
//! (spec §9: FHE9001–FHE9003). The emitter never panics on bad input — a
//! violated plan invariant is a bug in an earlier stage and must surface as
//! a diagnosable error.

use std::fmt;
use std::path::PathBuf;

use fhec_ir::ByteRange;

use crate::guard::FragmentKind;

/// An error raised while applying a rewrite plan or writing output.
#[derive(Debug)]
pub enum EmitError {
    /// A patch range lies outside the original file (FHE9001).
    PatchOutOfBounds {
        /// Source file the plan applies to.
        path: String,
        /// The offending range.
        range: ByteRange,
        /// Length of the original file in bytes.
        file_len: usize,
    },
    /// A patch range starts or ends inside a UTF-8 character (FHE9001).
    PatchSplitsUtf8 {
        /// Source file the plan applies to.
        path: String,
        /// The offending range.
        range: ByteRange,
    },
    /// Two patches overlap after normalization to canonical order (FHE9001).
    PatchOverlap {
        /// Source file the plan applies to.
        path: String,
        /// The earlier patch's range (canonical order).
        first: ByteRange,
        /// The overlapping later patch's range.
        second: ByteRange,
    },
    /// A rendered fragment does not re-parse (FHE9003, spec §2.5).
    FragmentReparse {
        /// What kind of fragment was checked.
        kind: FragmentKind,
        /// The offending rendered text.
        text: String,
        /// Parser diagnostics.
        diagnostics: Vec<String>,
    },
    /// A complete output file does not re-parse (FHE9002, spec §2.5).
    OutputReparse {
        /// Output file name used for parsing.
        name: String,
        /// Parser diagnostics.
        diagnostics: Vec<String>,
    },
    /// A mirror path would escape the output root (FHE9001).
    PathEscape {
        /// The offending relative path.
        path: PathBuf,
    },
    /// An I/O failure while writing the mirror tree or manifest (FHE9001).
    Io {
        /// The path being written or removed.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
}

impl EmitError {
    /// The stable diagnostic code for this error (spec §9).
    pub fn code(&self) -> &'static str {
        match self {
            EmitError::PatchOutOfBounds { .. }
            | EmitError::PatchSplitsUtf8 { .. }
            | EmitError::PatchOverlap { .. }
            | EmitError::PathEscape { .. }
            | EmitError::Io { .. } => "FHE9001",
            EmitError::OutputReparse { .. } => "FHE9002",
            EmitError::FragmentReparse { .. } => "FHE9003",
        }
    }
}

impl fmt::Display for EmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmitError::PatchOutOfBounds {
                path,
                range,
                file_len,
            } => write!(
                f,
                "[{}] patch range {range} is out of bounds for {path} ({file_len} bytes)",
                self.code()
            ),
            EmitError::PatchSplitsUtf8 { path, range } => write!(
                f,
                "[{}] patch range {range} splits a UTF-8 character in {path}",
                self.code()
            ),
            EmitError::PatchOverlap {
                path,
                first,
                second,
            } => write!(
                f,
                "[{}] overlapping patches in {path}: {first} and {second}",
                self.code()
            ),
            EmitError::FragmentReparse {
                kind,
                text,
                diagnostics,
            } => write!(
                f,
                "[{}] rendered {kind} fragment does not parse: {text:?} ({})",
                self.code(),
                diagnostics.join("; ")
            ),
            EmitError::OutputReparse { name, diagnostics } => write!(
                f,
                "[{}] output {name} does not re-parse as Solidity ({})",
                self.code(),
                diagnostics.join("; ")
            ),
            EmitError::PathEscape { path } => write!(
                f,
                "[{}] mirror path {} escapes the output root",
                self.code(),
                path.display()
            ),
            EmitError::Io { path, source } => {
                write!(
                    f,
                    "[{}] io error at {}: {source}",
                    self.code(),
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for EmitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EmitError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
