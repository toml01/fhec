//! Shared helpers for the integration tests.
//!
//! Every test that needs a real `solc` (or the sibling `cofhe-contracts`
//! checkout) asks for it here first. When it is missing the helper prints a
//! skip message and the test returns early, so CI without a compiler stays
//! green instead of failing.

#![allow(dead_code)]

use fhec_verify::{SolcRunner, VerifyError};

/// The requirement every test compiles against.
pub const REQUIREMENT: &str = ">=0.8.25, <0.9.0";

/// A runner for the tests, or `None` with a skip message already printed.
pub fn solc_runner() -> Option<SolcRunner> {
    match SolcRunner::for_requirement(REQUIREMENT) {
        Ok(runner) => {
            eprintln!(
                "using solc {} at {}",
                runner.binary().version(),
                runner.binary().path().display()
            );
            Some(runner)
        }
        Err(err) => {
            eprintln!("SKIP: no solc matching `{REQUIREMENT}` is available.\n{err}");
            None
        }
    }
}

/// Asserts a discovery error is the "nothing found" variant.
pub fn is_not_found(err: &VerifyError) -> bool {
    matches!(err, VerifyError::SolcNotFound { .. })
}

/// A minimal, valid contract at the given pragma.
pub fn valid_contract(name: &str) -> String {
    format!(
        "// SPDX-License-Identifier: MIT\n\
         pragma solidity >=0.8.25 <0.9.0;\n\
         \n\
         contract {name} {{\n\
         \x20   uint256 private value;\n\
         \n\
         \x20   function set(uint256 next) external {{\n\
         \x20       value = next;\n\
         \x20   }}\n\
         \n\
         \x20   function get() external view returns (uint256) {{\n\
         \x20       return value;\n\
         \x20   }}\n\
         }}\n"
    )
}
