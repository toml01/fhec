//! End-to-end gate: a full dialect contract (in-sugar + operators + encrypted
//! if + auto-ACL) is lowered, spliced, and compiled with real solc against the
//! real pinned CoFHE library (spec §10.3 criterion (c)).
//!
//! Skips cleanly when no solc or no cofhe-contracts checkout is available;
//! on the development machine both are present and the test must run.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fhec_lower::{lower, AclMode, LowerOptions};
use fhec_targets::CofheProfile;
use fhec_verify::{CompileInput, SolcRunner};
use solar_parse::{
    ast,
    interface::{source_map::FileName, ColorChoice, Session},
    Parser,
};

const DIALECT_INPUT: &str = "\
// SPDX-License-Identifier: MIT
pragma solidity >=0.8.25 <0.9.0;

import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";

interface ICounterSink {
    function absorb(euint32 value) external;
}

contract EncryptedCounter {
    euint32 public count;
    ICounterSink sink;

    function setCount(in euint32 newCount) external {
        count = newCount;
    }

    function flush() external {
        sink.absorb(count);
    }

    function increment(uint32 step) external {
        count = count + step;
    }

    function capAt(in euint32 cap) external {
        if (FHE.gt(count, cap)) {
            count = cap;
        }
    }

    function getCount() external returns (euint32) {
        return count;
    }
}
";

fn transpile(name: &str, src: &str) -> (String, bool) {
    let sess = Session::builder()
        .with_buffer_emitter(ColorChoice::Never)
        .build();
    sess.enter(|| {
        let arena = ast::Arena::new();
        let mut parser = Parser::from_source_code(
            &sess,
            &arena,
            FileName::Custom(name.to_string()),
            src.to_string(),
        )
        .expect("source registration must succeed");
        let unit = parser.parse_file().unwrap_or_else(|e| {
            e.emit();
            panic!("input must parse");
        });
        let unit: &ast::SourceUnit<'_> = arena.alloc(unit);
        let files = vec![fhec_bind::SourceFile {
            name: name.to_string(),
            ast: unit,
        }];
        let bound = fhec_bind::bind(vec![fhec_bind::SourceFile {
            name: name.to_string(),
            ast: unit,
        }]);
        assert!(bound.diagnostics().is_empty(), "{:?}", bound.diagnostics());
        let profile = CofheProfile::v0_2();
        let checked = fhec_check::check(&files, &bound, &profile, sess.source_map());
        assert!(
            !checked.has_errors(),
            "input must check clean: {:?}",
            checked
                .diagnostics
                .iter()
                .map(|d| format!("{}: {}", d.code, d.message))
                .collect::<Vec<_>>()
        );
        let result = lower(
            &files,
            &bound,
            &checked,
            &profile,
            sess.source_map(),
            &LowerOptions {
                acl_mode: AclMode::Insert,
            },
        );
        assert!(result.failed_files.is_empty());
        let spliced = fhec_emit::splice(src, &result.plan.files[0]).expect("plan must splice");
        fhec_emit::validate_output(name, &spliced.text).expect("output must re-parse");
        (spliced.text, result.plan.files[0].is_empty())
    })
}

// --- minimal import-closure reader (mirrors fhec-verify/tests/cofhe.rs) -----

/// The pinned `@fhenixprotocol/cofhe-contracts` library: the workspace's
/// pnpm install by default (published npm layout, FHE.sol at the package
/// root); `FHEC_COFHE_CONTRACTS` overrides and also accepts a repository
/// checkout layout (`contracts/FHE.sol`).
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
    eprintln!("SKIP: no cofhe-contracts library at {}", root.display());
    None
}

fn resolve_on_disk(root: &Path, virtual_path: &str) -> Option<PathBuf> {
    if virtual_path.starts_with("contracts/") {
        let direct = root.join(virtual_path);
        if direct.is_file() {
            return Some(direct);
        }
    }
    // The profile package specifier maps onto the library itself, in either
    // layout (package: FHE.sol at the root; checkout: under contracts/).
    if let Some(rest) = virtual_path.strip_prefix("@fhenixprotocol/cofhe-contracts/") {
        for direct in [root.join(rest), root.join("contracts").join(rest)] {
            if direct.is_file() {
                return Some(direct);
            }
        }
    }
    // Other bare specifiers (e.g. @openzeppelin/contracts, imported by
    // FHE.sol) resolve through node_modules next to the library, falling
    // back to the workspace's own install.
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

fn import_specs(source: &str) -> Vec<String> {
    let mut specs = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim();
        let is_import = trimmed
            .strip_prefix("import")
            .is_some_and(|rest| rest.starts_with(|c: char| c.is_whitespace() || c == '"'));
        if !is_import {
            continue;
        }
        if let Some((_, rest)) = trimmed.split_once('"') {
            if let Some((inner, _)) = rest.split_once('"') {
                specs.push(inner.to_owned());
            }
        }
    }
    specs
}

fn read_closure(
    root: &Path,
    seed: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, String> {
    let mut sources = BTreeMap::new();
    let mut queue: Vec<String> = Vec::new();
    for (path, content) in seed {
        for spec in import_specs(&content) {
            queue.push(resolve_import(&path, &spec));
        }
        sources.insert(path, content);
    }
    while let Some(virtual_path) = queue.pop() {
        if sources.contains_key(&virtual_path) {
            continue;
        }
        let disk = resolve_on_disk(root, &virtual_path)
            .ok_or_else(|| format!("cannot resolve `{virtual_path}`"))?;
        let content = std::fs::read_to_string(&disk)
            .map_err(|err| format!("cannot read {}: {err}", disk.display()))?;
        for spec in import_specs(&content) {
            queue.push(resolve_import(&virtual_path, &spec));
        }
        sources.insert(virtual_path, content);
    }
    Ok(sources)
}

#[test]
fn dialect_counter_lowers_and_compiles_with_real_solc() {
    let (output, no_op) = transpile("contracts/EncryptedCounter.fsol", DIALECT_INPUT);
    assert!(!no_op, "the dialect input must produce patches");

    // Shape checks on the lowered output.
    for needle in [
        "externalEuint32 newCount_input",
        "bytes memory inputProof",
        "euint32 newCount = FHE.asEuint32(newCount_input, inputProof);",
        "count = FHE.add(count, FHE.asEuint32(step));",
        "FHE.allowThis(count);",
        "FHE.allowSender(count);",
        "FHE.select(",
        "FHE.allowTransient(count, address(sink));",
        "FHE.allowTransient(__fhe_ret_0, msg.sender);",
    ] {
        assert!(output.contains(needle), "missing `{needle}` in:\n{output}");
    }
    assert!(!output.contains(" in euint32"), "sugar must be gone");

    // Idempotence on the full contract (spec §1.4).
    let (second, second_no_op) = transpile("contracts/EncryptedCounter.fsol", &output);
    assert_eq!(second, output, "T(T(x)) != T(x)");
    let _ = second_no_op; // patches may exist but must not change bytes

    // The compile gate (spec §10.3 (c)).
    let Ok(runner) = SolcRunner::for_requirement(">=0.8.25, <0.9.0") else {
        eprintln!("SKIP: no suitable solc available");
        return;
    };
    let Some(root) = cofhe_root() else {
        return;
    };
    let mut seed = BTreeMap::new();
    seed.insert("contracts/EncryptedCounter.sol".to_string(), output);
    let sources = match read_closure(&root, seed) {
        Ok(s) => s,
        Err(reason) => {
            eprintln!("SKIP: import graph not closed: {reason}");
            return;
        }
    };
    let input = CompileInput {
        sources,
        ..CompileInput::new()
    };
    let compiled = runner.compile(&input).expect("solc ran");
    let errors: Vec<_> = compiled.errors().collect();
    assert!(
        errors.is_empty(),
        "the lowered contract must compile cleanly: {errors:#?}"
    );
    assert!(compiled.is_success());
}
