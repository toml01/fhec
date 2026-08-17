//! Driving `solc --standard-json` as a subprocess.

use std::io::Write as _;
use std::process::{Command, Stdio};

use semver::VersionReq;

use crate::discovery::{self, DiscoveryOptions, SolcBinary};
use crate::error::VerifyError;
use crate::input::CompileInput;
use crate::output::{CompileOutput, StandardJsonOutput};

/// A located `solc` binary, ready to compile standard-JSON inputs.
///
/// # Example
///
/// ```no_run
/// use fhec_verify::{CompileInput, SolcRunner};
///
/// # fn main() -> Result<(), fhec_verify::VerifyError> {
/// let runner = SolcRunner::discover_default()?;
/// let input = CompileInput::new().with_source(
///     "generated/A.sol",
///     "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.25;\ncontract A {}\n",
/// );
/// let output = runner.compile(&input)?;
/// assert!(output.is_success());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolcRunner {
    binary: SolcBinary,
}

impl SolcRunner {
    /// Wraps an already-located binary.
    #[must_use]
    pub fn new(binary: SolcBinary) -> Self {
        Self { binary }
    }

    /// Finds a compiler using [`crate::discovery::DEFAULT_SOLC_REQUIREMENT`].
    ///
    /// # Errors
    ///
    /// Whatever [`crate::discovery::discover`] returns.
    pub fn discover_default() -> Result<Self, VerifyError> {
        Self::discover(&DiscoveryOptions::default())
    }

    /// Finds a compiler satisfying `requirement`, written as semver text such
    /// as `">=0.8.25, <0.9.0"`.
    ///
    /// # Errors
    ///
    /// [`VerifyError::InvalidRequirement`] for unparsable text, plus whatever
    /// [`crate::discovery::discover`] returns.
    pub fn for_requirement(requirement: &str) -> Result<Self, VerifyError> {
        let requirement = discovery::parse_requirement(requirement)?;
        Self::discover(&DiscoveryOptions::new(requirement))
    }

    /// Finds a compiler with full control over the search.
    ///
    /// # Errors
    ///
    /// Whatever [`crate::discovery::discover`] returns.
    pub fn discover(options: &DiscoveryOptions) -> Result<Self, VerifyError> {
        discovery::discover(options).map(Self::new)
    }

    /// Uses the binary at `path`, after checking it satisfies `requirement`.
    ///
    /// # Errors
    ///
    /// [`VerifyError::Spawn`], [`VerifyError::VersionUnparsable`] or
    /// [`VerifyError::VersionMismatch`].
    pub fn at_path(
        path: impl Into<std::path::PathBuf>,
        requirement: &VersionReq,
    ) -> Result<Self, VerifyError> {
        SolcBinary::probe_checked(path, requirement).map(Self::new)
    }

    /// The binary this runner drives.
    #[must_use]
    pub fn binary(&self) -> &SolcBinary {
        &self.binary
    }

    /// Compiles `input` with `solc --standard-json`.
    ///
    /// Returns `Ok` whenever solc ran and produced parsable standard JSON, even
    /// if that JSON reports compilation errors — inspect
    /// [`CompileOutput::is_success`] for the gate verdict. Never accesses the
    /// network and never installs anything.
    ///
    /// # Errors
    ///
    /// [`VerifyError::SerializeInput`], [`VerifyError::Spawn`],
    /// [`VerifyError::StdinWrite`], [`VerifyError::SolcFailed`],
    /// [`VerifyError::MalformedOutput`] or [`VerifyError::Internal`].
    pub fn compile(&self, input: &CompileInput) -> Result<CompileOutput, VerifyError> {
        let payload =
            serde_json::to_vec(&input.to_standard_json()).map_err(VerifyError::SerializeInput)?;
        let path = self.binary.path().to_path_buf();

        let mut child = Command::new(&path)
            .arg("--standard-json")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| VerifyError::Spawn {
                path: path.clone(),
                source,
            })?;

        let mut stdin = child.stdin.take().ok_or_else(|| {
            VerifyError::Internal("solc stdin was piped but is not available".to_owned())
        })?;
        // Write on a worker thread: solc can start writing stdout before it has
        // consumed all of stdin, and a single-threaded write would deadlock on a
        // full pipe for large source sets.
        let writer =
            std::thread::spawn(move || stdin.write_all(&payload).and_then(|()| stdin.flush()));

        let finished = child
            .wait_with_output()
            .map_err(|source| VerifyError::Spawn {
                path: path.clone(),
                source,
            })?;
        let write_result = writer.join().map_err(|_| {
            VerifyError::Internal("the thread feeding solc's stdin panicked".to_owned())
        })?;

        let stdout = String::from_utf8_lossy(&finished.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&finished.stderr).into_owned();

        // A broken pipe here just means solc exited early; the real diagnosis is
        // in its own output, so only surface the write error if nothing useful
        // came back.
        if let Err(source) = write_result {
            if stdout.trim().is_empty() {
                return Err(VerifyError::StdinWrite { path, source });
            }
            log::debug!("solc closed stdin early: {source}");
        }

        if stdout.trim().is_empty() {
            return Err(VerifyError::SolcFailed {
                path,
                status: finished.status.code(),
                stderr,
            });
        }

        let raw: serde_json::Value =
            serde_json::from_str(&stdout).map_err(|source| VerifyError::MalformedOutput {
                path: path.clone(),
                output: stdout.clone(),
                source,
            })?;
        let parsed: StandardJsonOutput =
            serde_json::from_value(raw.clone()).map_err(|source| VerifyError::MalformedOutput {
                path: path.clone(),
                output: stdout,
                source,
            })?;

        if !finished.status.success() {
            log::warn!(
                "solc exited with {:?} but produced standard JSON; using it",
                finished.status.code()
            );
        }

        Ok(CompileOutput::new(
            parsed,
            raw,
            self.binary.version().clone(),
            &input.sources,
        ))
    }
}
