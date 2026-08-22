//! The gate running against the real CoFHE profile library.
//!
//! This is the test that proves stage 8 works on output that imports `FHE.sol`:
//! it walks the import graph of the real `cofhe-contracts` checkout, feeds every
//! source into solc through the standard-JSON `sources` map, and compiles a
//! wrapper contract of the kind `fhec-emit` produces.
//!
//! It uses the pinned npm package from the workspace's pnpm install by
//! default; point `FHEC_COFHE_CONTRACTS` at a package or checkout to
//! override. When the library is missing the test prints a skip message and
//! passes.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fhec_verify::{CompileInput, Severity};

/// The virtual path of the profile library entry point.
const FHE_SOL: &str = "contracts/FHE.sol";

/// The pinned CoFHE library, if one is usable: the workspace's pnpm install
/// by default (published npm layout, FHE.sol at the package root), or a
/// `FHEC_COFHE_CONTRACTS` override (package or checkout layout).
fn cofhe_root() -> Option<PathBuf> {
    let root = std::env::var_os("FHEC_COFHE_CONTRACTS").map_or_else(
        || {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../packages/difftest/node_modules/@fhenixprotocol/cofhe-contracts")
        },
        PathBuf::from,
    );
    if root.join("FHE.sol").is_file() || root.join("contracts/FHE.sol").is_file() {
        return Some(root);
    }
    eprintln!(
        "SKIP: no cofhe-contracts library at {} (set FHEC_COFHE_CONTRACTS)",
        root.display()
    );
    None
}

/// Maps a virtual import path onto a file of the library install.
///
/// Paths under `contracts/` come from the library itself (checkout layout
/// directly, package layout with the prefix stripped); anything else is a
/// bare package specifier and is looked up node-style, mirroring what a
/// Hardhat or Foundry remapping would do.
fn resolve_on_disk(root: &Path, virtual_path: &str) -> Option<PathBuf> {
    if let Some(rest) = virtual_path.strip_prefix("contracts/") {
        for direct in [root.join(virtual_path), root.join(rest)] {
            if direct.is_file() {
                return Some(direct);
            }
        }
    }
    for modules in [
        root.join("node_modules"),
        root.join("contracts").join("node_modules"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packages/difftest/node_modules"),
    ] {
        let candidate = modules.join(virtual_path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Normalises `spec` against the directory of `importer`, both as virtual paths.
fn resolve_import(importer: &str, spec: &str) -> String {
    if !spec.starts_with('.') {
        return spec.to_owned();
    }
    let mut segments: Vec<&str> = importer
        .rsplit_once('/')
        .map_or_else(Vec::new, |(dir, _)| dir.split('/').collect());
    for part in spec.split('/') {
        match part {
            "." | "" => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    segments.join("/")
}

/// Every import specifier in `source`, in order.
///
/// A deliberately small scanner: it looks at statements that begin with the
/// `import` keyword and takes the first quoted string in each. That covers every
/// import form the CoFHE and OpenZeppelin sources actually use.
fn import_specs(source: &str) -> Vec<String> {
    let mut specs = Vec::new();
    let mut statement = String::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if statement.is_empty() {
            let is_import = trimmed
                .strip_prefix("import")
                .is_some_and(|rest| rest.starts_with(|c: char| c.is_whitespace() || c == '"'));
            if !is_import {
                continue;
            }
        }
        statement.push_str(trimmed);
        statement.push(' ');
        if !trimmed.contains(';') {
            continue;
        }
        if let Some(spec) = first_quoted(&statement) {
            specs.push(spec);
        }
        statement.clear();
    }
    specs
}

/// The first double-quoted run in `text`.
fn first_quoted(text: &str) -> Option<String> {
    let (_, rest) = text.split_once('"')?;
    let (inner, _) = rest.split_once('"')?;
    Some(inner.to_owned())
}

/// Reads the transitive import closure of `entries` into a standard-JSON
/// sources map. Returns the unresolved specifier if the graph is not closed.
fn read_closure(root: &Path, entries: &[&str]) -> Result<BTreeMap<String, String>, String> {
    let mut sources = BTreeMap::new();
    let mut queue: Vec<String> = entries.iter().map(|entry| (*entry).to_owned()).collect();

    while let Some(virtual_path) = queue.pop() {
        if sources.contains_key(&virtual_path) {
            continue;
        }
        let disk = resolve_on_disk(root, &virtual_path)
            .ok_or_else(|| format!("cannot resolve `{virtual_path}` under {}", root.display()))?;
        let content = std::fs::read_to_string(&disk)
            .map_err(|err| format!("cannot read {}: {err}", disk.display()))?;
        for spec in import_specs(&content) {
            queue.push(resolve_import(&virtual_path, &spec));
        }
        sources.insert(virtual_path, content);
    }
    Ok(sources)
}

/// A wrapper of the shape `fhec-emit` produces: it imports the profile library
/// and calls into it.
fn wrapper_contract() -> String {
    format!(
        "// SPDX-License-Identifier: MIT\n\
         pragma solidity >=0.8.25 <0.9.0;\n\
         \n\
         import {{FHE, euint32}} from \"{FHE_SOL}\";\n\
         \n\
         contract Wrapped {{\n\
         \x20   euint32 private total;\n\
         \n\
         \x20   function accumulate(euint32 lhs, euint32 rhs) external {{\n\
         \x20       euint32 sum = FHE.add(lhs, rhs);\n\
         \x20       FHE.allowThis(sum);\n\
         \x20       total = sum;\n\
         \x20   }}\n\
         }}\n"
    )
}

/// (d) The real profile library compiles through the gate.
#[test]
fn the_real_cofhe_library_compiles() {
    let Some(runner) = common::solc_runner() else {
        return;
    };
    let Some(root) = cofhe_root() else {
        return;
    };

    let sources = match read_closure(&root, &[FHE_SOL, "contracts/ICofhe.sol"]) {
        Ok(sources) => sources,
        Err(reason) => {
            eprintln!("SKIP: the CoFHE import graph is not closed on disk: {reason}");
            return;
        }
    };
    eprintln!(
        "compiling {} CoFHE sources: {:?}",
        sources.len(),
        sources.keys().collect::<Vec<_>>()
    );
    assert!(
        sources.contains_key("@openzeppelin/contracts/utils/Strings.sol"),
        "the closure must pull in the OpenZeppelin dependency"
    );

    let input = CompileInput {
        sources,
        ..CompileInput::new()
    };
    let output = runner.compile(&input).expect("solc ran");

    let errors: Vec<_> = output.errors().collect();
    assert!(
        errors.is_empty(),
        "the pinned CoFHE library must compile cleanly: {errors:#?}"
    );
    assert!(output.is_success());
}

/// A wrapper contract that imports `FHE.sol` compiles, and every diagnostic it
/// does produce is a well-formed `FHE6000`.
#[test]
fn a_wrapper_importing_fhe_sol_compiles() {
    let Some(runner) = common::solc_runner() else {
        return;
    };
    let Some(root) = cofhe_root() else {
        return;
    };

    let mut sources = match read_closure(&root, &[FHE_SOL]) {
        Ok(sources) => sources,
        Err(reason) => {
            eprintln!("SKIP: the CoFHE import graph is not closed on disk: {reason}");
            return;
        }
    };
    sources.insert("generated/Wrapped.sol".to_owned(), wrapper_contract());

    let input = CompileInput {
        sources,
        ..CompileInput::new()
    };
    let output = runner.compile(&input).expect("solc ran");

    let errors: Vec<_> = output.errors().collect();
    assert!(
        errors.is_empty(),
        "emitted CoFHE output must pass the gate: {errors:#?}"
    );
    for diagnostic in output.fhe_diagnostics() {
        assert_eq!(diagnostic.code, "FHE6000");
        assert_ne!(diagnostic.severity, Severity::Error);
        assert!(diagnostic.solc.is_some());
    }
}

/// A wrapper that misuses the library fails the gate, and the diagnostic points
/// into the generated file rather than into the library.
#[test]
fn a_broken_wrapper_is_reported_against_the_generated_file() {
    let Some(runner) = common::solc_runner() else {
        return;
    };
    let Some(root) = cofhe_root() else {
        return;
    };

    let mut sources = match read_closure(&root, &[FHE_SOL]) {
        Ok(sources) => sources,
        Err(reason) => {
            eprintln!("SKIP: the CoFHE import graph is not closed on disk: {reason}");
            return;
        }
    };
    // `FHE.add` has no overload taking a plain uint256, which is exactly the
    // kind of mistake a bad lowering would produce.
    let broken = format!(
        "// SPDX-License-Identifier: MIT\n\
         pragma solidity >=0.8.25 <0.9.0;\n\
         import {{FHE, euint32}} from \"{FHE_SOL}\";\n\
         contract Wrapped {{\n\
         \x20   function bad(euint32 lhs) external returns (euint32) {{\n\
         \x20       return FHE.add(lhs, uint256(1));\n\
         \x20   }}\n\
         }}\n"
    );
    sources.insert("generated/Wrapped.sol".to_owned(), broken);

    let input = CompileInput {
        sources,
        ..CompileInput::new()
    };
    let output = runner.compile(&input).expect("solc ran");

    assert!(!output.is_success(), "the misuse must fail the gate");
    let diagnostics = output.fhe_diagnostics();
    let blamed = diagnostics
        .iter()
        .find(|diag| diag.severity == Severity::Error)
        .expect("an error diagnostic");
    assert_eq!(blamed.code, "FHE6000");
    assert_eq!(
        blamed.span.file, "generated/Wrapped.sol",
        "the blame must land on the emitted file, not on the library"
    );
    assert!(blamed.span.start_line >= 6, "{:?}", blamed.span);
    assert!(blamed
        .solc
        .as_ref()
        .and_then(|solc| solc.code.as_deref())
        .is_some());
}

#[test]
fn relative_imports_normalise_against_the_importer() {
    assert_eq!(
        resolve_import("contracts/FHE.sol", "./ICofhe.sol"),
        "contracts/ICofhe.sol"
    );
    assert_eq!(
        resolve_import(
            "@openzeppelin/contracts/utils/math/Math.sol",
            "../Panic.sol"
        ),
        "@openzeppelin/contracts/utils/Panic.sol"
    );
    assert_eq!(
        resolve_import(
            "@openzeppelin/contracts/utils/Strings.sol",
            "./math/SafeCast.sol"
        ),
        "@openzeppelin/contracts/utils/math/SafeCast.sol"
    );
    assert_eq!(
        resolve_import(
            "contracts/FHE.sol",
            "@openzeppelin/contracts/utils/Strings.sol"
        ),
        "@openzeppelin/contracts/utils/Strings.sol"
    );
}

#[test]
fn the_import_scanner_reads_every_form() {
    let source = "pragma solidity ^0.8.25;\n\
                  import \"./bare.sol\";\n\
                  import {A, B} from \"./named.sol\";\n\
                  import {\n    C\n} from \"./multiline.sol\";\n\
                  import * as Lib from \"./star.sol\";\n\
                  // import \"./commented.sol\";\n\
                  contract X {}\n";
    assert_eq!(
        import_specs(source),
        vec!["./bare.sol", "./named.sol", "./multiline.sol", "./star.sol"]
    );
}
