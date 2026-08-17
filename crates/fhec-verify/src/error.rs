//! Typed errors for `solc` discovery and invocation.
//!
//! Every failure mode of this crate is a [`VerifyError`] variant. Nothing in
//! this crate panics on malformed compiler output or on a missing binary.

use std::fmt;
use std::path::PathBuf;

use semver::{Version, VersionReq};

/// Text appended to "no solc found" errors so a user can act on the failure.
pub const INSTALL_HINT: &str = "\
install a compatible solc with one of:\n  \
* `foundryup` (installs Foundry; `forge build` then downloads solc on demand)\n  \
* `cargo install svm-rs` followed by `svm install <version>`\n  \
* download an official build from https://binaries.soliditylang.org and place it at \
<svm-home>/<version>/solc-<version>\n\
or point fhec at an existing binary with the FHEC_SOLC environment variable";

/// Where a candidate `solc` binary came from.
///
/// The order of the variants is the order in which discovery consults them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SolcOrigin {
    /// An explicit path supplied by the caller.
    Explicit,
    /// The `FHEC_SOLC` environment variable.
    Env,
    /// A `solc` executable found on `PATH`.
    Path,
    /// A version-directory under an svm-rs / Foundry home.
    SvmHome,
}

impl fmt::Display for SolcOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Explicit => "explicit path",
            Self::Env => "FHEC_SOLC",
            Self::Path => "PATH",
            Self::SvmHome => "svm home",
        };
        f.write_str(text)
    }
}

/// One location that discovery inspected, together with why it was rejected.
///
/// Collected into [`VerifyError::SolcNotFound`] so the user can see exactly
/// what was tried instead of a bare "not found".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolcSearchStep {
    /// Which discovery step produced this candidate.
    pub origin: SolcOrigin,
    /// The path that was considered, when there was one.
    pub path: Option<PathBuf>,
    /// Human-readable reason the candidate was not used.
    pub reason: String,
}

impl fmt::Display for SolcSearchStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            Some(path) => write!(f, "{} ({}): {}", self.origin, path.display(), self.reason),
            None => write!(f, "{}: {}", self.origin, self.reason),
        }
    }
}

/// Renders a search trail as an indented, one-entry-per-line block.
fn render_steps(steps: &[SolcSearchStep]) -> String {
    if steps.is_empty() {
        return "  (nothing was searched)".to_owned();
    }
    steps
        .iter()
        .map(|step| format!("  - {step}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Truncates `text` so error messages stay readable when solc emits a wall of
/// output.
fn snippet(text: &str) -> String {
    const LIMIT: usize = 400;
    let trimmed = text.trim();
    if trimmed.len() <= LIMIT {
        return trimmed.to_owned();
    }
    let mut end = LIMIT;
    while end > 0 && !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &trimmed[..end])
}

/// Everything that can go wrong while discovering, version-checking or running
/// `solc`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// No binary satisfying the requested version requirement was found.
    #[error(
        "no solc binary matching `{requirement}` was found\nsearched:\n{}\n{INSTALL_HINT}",
        render_steps(.searched)
    )]
    SolcNotFound {
        /// The semver requirement that had to be satisfied.
        requirement: VersionReq,
        /// Every location that was inspected, and why it was rejected.
        searched: Vec<SolcSearchStep>,
    },

    /// A binary was named explicitly but reports a version outside the request.
    #[error("solc at `{}` is {found}, which does not satisfy `{requirement}`", .path.display())]
    VersionMismatch {
        /// The binary that was probed.
        path: PathBuf,
        /// The version it reported.
        found: Box<Version>,
        /// The requirement it had to satisfy.
        requirement: VersionReq,
    },

    /// `solc --version` produced output this crate could not understand.
    #[error("could not parse the version reported by solc at `{}`: {}", .path.display(), snippet(.output))]
    VersionUnparsable {
        /// The binary that was probed.
        path: PathBuf,
        /// The raw combined output of `solc --version`.
        output: String,
    },

    /// A caller-supplied version requirement is not valid semver.
    #[error("`{text}` is not a valid semver requirement")]
    InvalidRequirement {
        /// The rejected text.
        text: String,
        /// The underlying parser error.
        #[source]
        source: semver::Error,
    },

    /// The `solc` process could not be started.
    #[error("could not run solc at `{}`", .path.display())]
    Spawn {
        /// The binary that could not be started.
        path: PathBuf,
        /// The underlying operating-system error.
        #[source]
        source: std::io::Error,
    },

    /// The `solc` process exited unsuccessfully without usable JSON on stdout.
    #[error(
        "solc at `{}` failed{}: {}",
        .path.display(),
        .status.map_or_else(|| " (killed by a signal)".to_owned(), |c| format!(" with exit code {c}")),
        snippet(.stderr)
    )]
    SolcFailed {
        /// The binary that failed.
        path: PathBuf,
        /// The exit code, when the process was not killed by a signal.
        status: Option<i32>,
        /// Whatever the process wrote to stderr.
        stderr: String,
    },

    /// The standard-JSON payload could not be handed to solc.
    #[error("could not write the standard-JSON input to solc at `{}`", .path.display())]
    StdinWrite {
        /// The binary that was being fed.
        path: PathBuf,
        /// The underlying operating-system error.
        #[source]
        source: std::io::Error,
    },

    /// The standard-JSON input could not be serialised.
    #[error("could not serialise the standard-JSON input")]
    SerializeInput(#[source] serde_json::Error),

    /// solc wrote something that is not the standard-JSON output schema.
    #[error("solc at `{}` produced output that is not standard JSON: {}", .path.display(), snippet(.output))]
    MalformedOutput {
        /// The binary whose output could not be read.
        path: PathBuf,
        /// A truncated copy of the offending output.
        output: String,
        /// The underlying deserialisation error.
        #[source]
        source: serde_json::Error,
    },

    /// A best-effort install was requested but no installer is available.
    #[error("cannot install solc {version}: {reason}\n{INSTALL_HINT}")]
    InstallUnavailable {
        /// The version that was requested.
        version: Box<Version>,
        /// Why no install was attempted.
        reason: String,
    },

    /// A best-effort install ran but did not produce a usable binary.
    #[error("installing solc {version} via {installer} failed: {}\n{INSTALL_HINT}", snippet(.details))]
    InstallFailed {
        /// The version that was requested.
        version: Box<Version>,
        /// The tool that was used (`svm` or `forge`).
        installer: String,
        /// Whatever the installer reported.
        details: String,
    },

    /// An internal invariant of this crate did not hold.
    ///
    /// Reported as an error rather than a panic, per the `FHE9xxx` convention of
    /// surfacing internal invariants as diagnostics.
    #[error("internal fhec-verify error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_lists_the_search_trail() {
        let err = VerifyError::SolcNotFound {
            requirement: VersionReq::parse(">=0.8.25, <0.9.0").expect("static requirement"),
            searched: vec![SolcSearchStep {
                origin: SolcOrigin::Path,
                path: None,
                reason: "no `solc` on PATH".to_owned(),
            }],
        };
        let text = err.to_string();
        assert!(text.contains(">=0.8.25, <0.9.0"), "{text}");
        assert!(text.contains("no `solc` on PATH"), "{text}");
        assert!(text.contains("foundryup"), "{text}");
    }

    #[test]
    fn snippet_truncates_on_a_char_boundary() {
        let text = "é".repeat(500);
        let out = snippet(&text);
        assert!(out.ends_with('…'));
        assert!(out.len() < text.len());
    }
}
