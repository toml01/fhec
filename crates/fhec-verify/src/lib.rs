//! solc runner (standard JSON) + error remapping.
//!
//! Stage 8 of the fhec pipeline. After `fhec-emit` has written Solidity, this
//! crate compiles that output with a real `solc` as a verification gate and
//! turns whatever solc says into structured diagnostics.
//!
//! # What it does
//!
//! * finds a `solc` binary and checks it against a semver requirement
//!   ([`discovery`]);
//! * builds a standard-JSON request from an in-memory source map
//!   ([`CompileInput`]) — the caller supplies **every** source, so solc never
//!   resolves an import from the filesystem;
//! * runs `solc --standard-json` and parses the response ([`SolcRunner`]);
//! * exposes solc's `errors[]` both verbatim ([`SolcDiagnostic`]) and wrapped as
//!   spec §9 `FHE6000` diagnostics ([`Diagnostic`]).
//!
//! # What it does not do
//!
//! It does not remap spans back onto the original `.fsol`. That needs the
//! emitter's `generated/.fhec/manifest.json` and belongs to `fhec-emit`. What
//! this crate guarantees is that the remapping *can* be exact: solc's byte
//! offsets are carried through untouched on both [`SolcSourceLocation`] and
//! [`Span`].
//!
//! # Example
//!
//! ```no_run
//! use fhec_verify::{CompileInput, Severity, SolcRunner};
//!
//! # fn main() -> Result<(), fhec_verify::VerifyError> {
//! let runner = SolcRunner::for_requirement(">=0.8.25, <0.9.0")?;
//! let input = CompileInput::new().with_source(
//!     "generated/Counter.sol",
//!     "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.25;\ncontract Counter {}\n",
//! );
//!
//! let output = runner.compile(&input)?;
//! for diagnostic in output.fhe_diagnostics() {
//!     assert_eq!(diagnostic.code, "FHE6000");
//!     if diagnostic.severity == Severity::Error {
//!         eprintln!("{} at {}:{}", diagnostic.message, diagnostic.span.file, diagnostic.span.start_line);
//!     }
//! }
//! assert!(output.is_success());
//! # Ok(())
//! # }
//! ```
//!
//! # Environment
//!
//! * `FHEC_SOLC` — an exact binary to use, overriding the search.
//! * `FHEC_SVM_HOME` / `SVM_HOME` — where to look for svm-rs compilers.
//! * `FHEC_NO_SOLC_INSTALL` — forbid [`discovery::ensure_solc`] from downloading.

#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod diagnostic;
pub mod discovery;
pub mod error;
pub mod input;
pub mod output;
pub mod runner;

pub use crate::diagnostic::{
    Diagnostic, FixIt, ForwardedSolc, LabelledSpan, LineIndex, Severity, Span, SOLC_DIAGNOSTIC_CODE,
};
pub use crate::discovery::{
    default_requirement, discover, ensure_solc, DiscoveryOptions, SolcBinary,
    DEFAULT_SOLC_REQUIREMENT,
};
pub use crate::error::{SolcOrigin, SolcSearchStep, VerifyError};
pub use crate::input::{
    CompileInput, CompileSettings, Optimizer, OutputSelection, DEFAULT_EVM_VERSION,
};
pub use crate::output::{
    BytecodeArtifact, CompileOutput, ContractArtifact, EvmArtifact, SolcDiagnostic, SolcSeverity,
    SolcSourceLocation,
};
pub use crate::runner::SolcRunner;
