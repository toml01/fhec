//! End-to-end compilation against a real `solc`.

mod common;

use fhec_verify::{CompileInput, CompileSettings, OutputSelection, Severity, SOLC_DIAGNOSTIC_CODE};

/// (a) A trivial valid contract compiles with no diagnostics at all.
#[test]
fn a_valid_contract_compiles_cleanly() {
    let Some(runner) = common::solc_runner() else {
        return;
    };

    let input =
        CompileInput::new().with_source("generated/Counter.sol", common::valid_contract("Counter"));
    let output = runner.compile(&input).expect("solc ran");

    assert!(
        output.is_success(),
        "expected a clean compile, got {:?}",
        output.diagnostics()
    );
    assert!(
        output.diagnostics().is_empty(),
        "a well-formed contract with an SPDX tag should not even warn: {:?}",
        output.diagnostics()
    );
    assert!(output.fhe_diagnostics().is_empty());
    assert_eq!(output.solc_version(), runner.binary().version());
    // Errors-only selection is the default, so no artifacts come back.
    assert!(output.contracts().is_empty());
}

/// (b) A deliberate type error surfaces with the right severity and location.
#[test]
fn a_type_error_surfaces_with_severity_and_location() {
    let Some(runner) = common::solc_runner() else {
        return;
    };

    let source = "// SPDX-License-Identifier: MIT\n\
                  pragma solidity >=0.8.25 <0.9.0;\n\
                  \n\
                  contract Broken {\n\
                  \x20   function f() public pure returns (uint256) {\n\
                  \x20       return true;\n\
                  \x20   }\n\
                  }\n";
    let input = CompileInput::new().with_source("generated/Broken.sol", source);
    let output = runner.compile(&input).expect("solc ran");

    assert!(!output.is_success(), "the type error must fail the gate");
    let errors: Vec<_> = output.errors().collect();
    assert_eq!(errors.len(), 1, "got {:?}", output.diagnostics());

    let error = errors[0];
    assert_eq!(error.severity.as_str(), "error");
    assert_eq!(error.kind.as_deref(), Some("TypeError"));
    assert_eq!(
        error.error_code.as_deref(),
        Some("6359"),
        "solc's stable code for a bad return type"
    );
    assert!(
        error.message.contains("not implicitly convertible"),
        "unexpected message: {}",
        error.message
    );
    assert!(
        error
            .formatted_message
            .as_deref()
            .unwrap_or_default()
            .contains("Broken.sol"),
        "the pretty rendering names the file"
    );

    // The raw solc offsets must land exactly on the `true` literal.
    let location = error.source_location.as_ref().expect("a primary location");
    assert_eq!(location.file.as_deref(), Some("generated/Broken.sol"));
    let range = location.byte_range().expect("a usable byte range");
    assert_eq!(&source[range.clone()], "true");

    // ...and the FHE6000 wrapper must preserve them losslessly while adding
    // 1-based line/column.
    let diagnostics = output.fhe_diagnostics();
    assert_eq!(diagnostics.len(), 1);
    let diag = &diagnostics[0];
    assert_eq!(diag.code, SOLC_DIAGNOSTIC_CODE);
    assert_eq!(diag.severity, Severity::Error);
    assert!(diag.is_error());
    assert_eq!(diag.span.file, "generated/Broken.sol");
    assert_eq!(diag.span.start_byte, range.start);
    assert_eq!(diag.span.end_byte, range.end);
    assert_eq!(diag.span.start_line, 6, "`return true;` is on line 6");
    assert_eq!(diag.span.end_line, 6);
    assert!(diag.span.start_col > 1);
    assert!(diag.fixits.is_empty());

    let forwarded = diag.solc.as_ref().expect("FHE6000 carries solc's identity");
    assert_eq!(forwarded.code.as_deref(), Some("6359"));
    assert_eq!(forwarded.kind.as_deref(), Some("TypeError"));
    assert!(forwarded.formatted_message.is_some());

    // The §10.2 JSON shape is what tooling consumes.
    let json = serde_json::to_value(diag).expect("serialises");
    assert_eq!(json["code"], "FHE6000");
    assert_eq!(json["severity"], "error");
    assert_eq!(json["span"]["start_line"], 6);
}

/// A warning is forwarded without failing the gate.
#[test]
fn a_warning_does_not_fail_the_gate() {
    let Some(runner) = common::solc_runner() else {
        return;
    };

    // No SPDX identifier and no licence: solc warns (code 1878).
    let input = CompileInput::new().with_source(
        "generated/Unlicensed.sol",
        "pragma solidity >=0.8.25 <0.9.0;\ncontract Unlicensed {}\n",
    );
    let output = runner.compile(&input).expect("solc ran");

    assert!(output.is_success(), "warnings do not fail the gate");
    assert_eq!(output.errors().count(), 0);
    assert!(
        !output.diagnostics().is_empty(),
        "solc should warn about the missing SPDX identifier"
    );
    let diag = &output.fhe_diagnostics()[0];
    assert_eq!(diag.code, SOLC_DIAGNOSTIC_CODE);
    assert_eq!(diag.severity, Severity::Warning);
}

/// A multi-file input resolves imports purely from the supplied source map.
#[test]
fn imports_resolve_from_the_supplied_sources_only() {
    let Some(runner) = common::solc_runner() else {
        return;
    };

    let input = CompileInput::new()
        .with_source(
            "generated/Main.sol",
            "// SPDX-License-Identifier: MIT\n\
             pragma solidity >=0.8.25 <0.9.0;\n\
             import {Helper} from \"./lib/Helper.sol\";\n\
             contract Main {\n\
             \x20   function twice(uint256 n) external pure returns (uint256) {\n\
             \x20       return Helper.twice(n);\n\
             \x20   }\n\
             }\n",
        )
        .with_source(
            "generated/lib/Helper.sol",
            "// SPDX-License-Identifier: MIT\n\
             pragma solidity >=0.8.25 <0.9.0;\n\
             library Helper {\n\
             \x20   function twice(uint256 n) internal pure returns (uint256) {\n\
             \x20       return n * 2;\n\
             \x20   }\n\
             }\n",
        );

    let output = runner.compile(&input).expect("solc ran");
    assert!(
        output.is_success(),
        "relative imports must resolve against the virtual path: {:?}",
        output.diagnostics()
    );
}

/// A missing import is reported rather than silently resolved from disk.
#[test]
fn a_missing_import_is_an_error_not_a_disk_lookup() {
    let Some(runner) = common::solc_runner() else {
        return;
    };

    let input = CompileInput::new().with_source(
        "generated/Main.sol",
        "// SPDX-License-Identifier: MIT\n\
         pragma solidity >=0.8.25 <0.9.0;\n\
         import {Nope} from \"@openzeppelin/contracts/utils/Strings.sol\";\n\
         contract Main {}\n",
    );

    let output = runner.compile(&input).expect("solc ran");
    assert!(!output.is_success());
    assert!(
        output
            .errors()
            .any(|diag| diag.kind.as_deref() == Some("ParserError")
                && diag.message.contains("not found")),
        "expected a source-not-found parser error, got {:?}",
        output.diagnostics()
    );
}

/// Artifacts come back when the caller asks for them.
#[test]
fn artifact_selection_returns_bytecode() {
    let Some(runner) = common::solc_runner() else {
        return;
    };

    let settings = CompileSettings {
        output: OutputSelection::Artifacts,
        ..CompileSettings::default()
    };
    let input = CompileInput::new()
        .with_source("generated/Counter.sol", common::valid_contract("Counter"))
        .with_settings(settings);

    let output = runner.compile(&input).expect("solc ran");
    assert!(output.is_success(), "{:?}", output.diagnostics());

    let contract = output
        .contracts()
        .get("generated/Counter.sol")
        .and_then(|file| file.get("Counter"))
        .expect("the Counter artifact");
    let bytecode = contract
        .evm
        .as_ref()
        .and_then(|evm| evm.bytecode.as_ref())
        .and_then(|bytecode| bytecode.object.as_deref())
        .expect("creation bytecode");
    assert!(!bytecode.is_empty());
    assert!(contract.abi.is_some());
    assert!(output.raw().get("contracts").is_some());
}

/// Byte offsets survive a compile of a file containing multi-byte characters,
/// which is what makes the later `.fsol` remapping safe.
#[test]
fn offsets_are_utf8_byte_offsets() {
    let Some(runner) = common::solc_runner() else {
        return;
    };

    let source = "// SPDX-License-Identifier: MIT\n\
                  // héllo — a comment with multi-byte characters\n\
                  pragma solidity >=0.8.25 <0.9.0;\n\
                  contract Broken {\n\
                  \x20   function f() public pure returns (uint256) {\n\
                  \x20       return true;\n\
                  \x20   }\n\
                  }\n";
    let input = CompileInput::new().with_source("generated/Broken.sol", source);
    let output = runner.compile(&input).expect("solc ran");

    let error = output.errors().next().expect("the type error");
    let range = error
        .source_location
        .as_ref()
        .and_then(fhec_verify::SolcSourceLocation::byte_range)
        .expect("a byte range");
    assert_eq!(
        &source[range], "true",
        "solc offsets index bytes, so slicing the source directly must work"
    );
}
