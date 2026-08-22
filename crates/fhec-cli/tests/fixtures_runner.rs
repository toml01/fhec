//! Conformance runner over the `fixtures/` corpus (spec §10).
//!
//! Areas (spec §10.1, extensible):
//! - golden: `operators/`, `select/`, `acl/`, `sugar/`, `imports/`,
//!   `contracts/` — `fhec build` output must be byte-identical to
//!   `expected.sol` (or the `expected/` tree) and diagnostics must match.
//! - check: `typing/`, `reject/` — `fhec check` (or `build` when a
//!   `build-only` marker file is present) must exit 1 with exactly the
//!   expected diagnostics.
//! - `noop/` — plain-Solidity must-not-touch corpus: output byte-identical
//!   to the input, manifest `no_op: true` (spec §10.4 property 2).
//! - `sourcemap/` — pipeline-accepted, solc-rejected inputs: FHE6000 must
//!   remap to the pinned `.fsol` spans.
//!
//! Fixture markers: `fhec.toml` (per-case config), `build-only`,
//! `no-verify`. Diagnostic matching is order-insensitive with exact spans
//! (§10.3); an expected entry may use `message_prefix` instead of `message`
//! (§10.2), and `fixits`/`rule` are compared only when the expected entry
//! carries them.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const DEFAULT_COFHE_ROOT: &str = "/Users/toml/dev/cofhe-contracts";
const GOLDEN_AREAS: &[&str] = &[
    "operators",
    "select",
    "acl",
    "sugar",
    "imports",
    "contracts",
];
const CHECK_AREAS: &[&str] = &["typing", "reject"];

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn fhec(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fhec"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("fhec binary runs")
}

fn cofhe_contracts_dir() -> Option<PathBuf> {
    let root = std::env::var_os("FHEC_COFHE_CONTRACTS")
        .map_or_else(|| PathBuf::from(DEFAULT_COFHE_ROOT), PathBuf::from);
    let contracts = root.join("contracts");
    contracts.join("FHE.sol").is_file().then_some(contracts)
}

fn have_solc() -> bool {
    fhec_verify::SolcRunner::for_requirement(">=0.8.25, <0.9.0").is_ok()
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Non-hidden fixture subdirectories of `area`, sorted; `None` when the
/// area directory itself is missing.
fn fixture_dirs(area: &str) -> Option<Vec<PathBuf>> {
    let dir = fixtures_root().join(area);
    let entries = std::fs::read_dir(&dir).ok()?;
    let mut v: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    v.sort();
    Some(v)
}

/// Materializes the fixture as a temp project; returns the project root.
fn setup_project(fixture: &Path, tmp: &Path, cofhe: Option<&Path>) {
    let contracts = tmp.join("contracts");
    std::fs::create_dir_all(&contracts).unwrap();
    for entry in std::fs::read_dir(fixture).unwrap().filter_map(Result::ok) {
        let p = entry.path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let is_source = std::path::Path::new(&name)
            .extension()
            .is_some_and(|e| e == "fsol" || e == "sol")
            && !name.starts_with("expected");
        if is_source {
            std::fs::copy(&p, contracts.join(&name)).unwrap();
        }
    }
    let case_toml = fixture.join("fhec.toml");
    if case_toml.is_file() {
        std::fs::copy(&case_toml, tmp.join("fhec.toml")).unwrap();
    } else {
        std::fs::write(tmp.join("fhec.toml"), "").unwrap();
    }
    if let Some(contracts_dir) = cofhe {
        let scope = tmp.join("node_modules/@fhenixprotocol");
        std::fs::create_dir_all(&scope).unwrap();
        std::os::unix::fs::symlink(contracts_dir, scope.join("cofhe-contracts")).unwrap();
    }
}

/// Parses a `--json` stdout (empty stdout means "no diagnostics").
fn parse_diags(stdout: &[u8]) -> Vec<serde_json::Value> {
    let text = String::from_utf8_lossy(stdout);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    serde_json::from_str::<Vec<serde_json::Value>>(trimmed)
        .unwrap_or_else(|e| panic!("diagnostics must be a JSON array: {e}\n{trimmed}"))
}

/// One diagnostic's identity for order-insensitive comparison.
fn diag_key(d: &serde_json::Value) -> String {
    let span = &d["span"];
    format!(
        "{}|{}|{}|{}..{}",
        d["code"].as_str().unwrap_or("?"),
        d["severity"].as_str().unwrap_or("?"),
        span["file"].as_str().unwrap_or("?"),
        span["start_byte"],
        span["end_byte"],
    )
}

/// Compares produced diagnostics against the fixture's expectations
/// (§10.3: order-insensitive, spans exact; `message_prefix` allowed).
fn match_diags(fixture: &Path, produced: &[serde_json::Value], failures: &mut Vec<String>) {
    let expected: Vec<serde_json::Value> = serde_json::from_str(&read(
        &fixture.join("expected.diagnostics.json"),
    ))
    .unwrap_or_else(|e| panic!("{}: bad expected.diagnostics.json: {e}", fixture.display()));

    let mut got: Vec<&serde_json::Value> = produced.iter().collect();
    got.sort_by_key(|d| diag_key(d));
    let mut want: Vec<&serde_json::Value> = expected.iter().collect();
    want.sort_by_key(|d| diag_key(d));

    if got.len() != want.len() {
        failures.push(format!(
            "{}: expected {} diagnostics, got {}:\n{}",
            fixture.display(),
            want.len(),
            got.len(),
            serde_json::to_string_pretty(&produced).unwrap()
        ));
        return;
    }
    for (g, w) in got.iter().zip(want.iter()) {
        if diag_key(g) != diag_key(w) {
            failures.push(format!(
                "{}: diagnostic mismatch\n  want {}\n  got  {}",
                fixture.display(),
                diag_key(w),
                diag_key(g)
            ));
            continue;
        }
        // Span exactness beyond the key: lines/cols.
        for f in ["start_line", "start_col", "end_line", "end_col"] {
            if g["span"][f] != w["span"][f] {
                failures.push(format!(
                    "{}: span field {f} differs: want {} got {}",
                    fixture.display(),
                    w["span"][f],
                    g["span"][f]
                ));
            }
        }
        if let Some(prefix) = w.get("message_prefix").and_then(|m| m.as_str()) {
            let msg = g["message"].as_str().unwrap_or_default();
            if !msg.starts_with(prefix) {
                failures.push(format!(
                    "{}: message `{msg}` does not start with `{prefix}`",
                    fixture.display()
                ));
            }
        } else if g["message"] != w["message"] {
            failures.push(format!(
                "{}: message differs\n  want {}\n  got  {}",
                fixture.display(),
                w["message"],
                g["message"]
            ));
        }
        if w.get("fixits").is_some() && g.get("fixits") != w.get("fixits") {
            failures.push(format!("{}: fixits differ", fixture.display()));
        }
        if w.get("rule").is_some() && g.get("rule") != w.get("rule") {
            failures.push(format!("{}: rule differs", fixture.display()));
        }
    }
}

/// Compares the generated tree against the fixture's expected output(s).
fn match_outputs(fixture: &Path, generated: &Path, failures: &mut Vec<String>) {
    let expected_dir = fixture.join("expected");
    let mut expected_files: Vec<(String, PathBuf)> = Vec::new();
    if expected_dir.is_dir() {
        for e in std::fs::read_dir(&expected_dir)
            .unwrap()
            .filter_map(Result::ok)
        {
            let p = e.path();
            expected_files.push((p.file_name().unwrap().to_string_lossy().into_owned(), p));
        }
    } else {
        let single = fixture.join("expected.sol");
        // The single output keeps the input's stem with a `.sol` extension.
        let mut outs: Vec<PathBuf> = std::fs::read_dir(generated)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "sol"))
            .collect();
        if outs.len() != 1 {
            failures.push(format!(
                "{}: expected exactly one generated .sol, got {outs:?}",
                fixture.display()
            ));
            return;
        }
        let out = outs.remove(0);
        expected_files.push((
            out.file_name().unwrap().to_string_lossy().into_owned(),
            single,
        ));
    }
    for (name, exp_path) in expected_files {
        let got_path = generated.join(&name);
        if !got_path.is_file() {
            failures.push(format!("{}: missing generated {name}", fixture.display()));
            continue;
        }
        if read(&got_path) != read(&exp_path) {
            failures.push(format!(
                "{}: generated {name} differs from {}",
                fixture.display(),
                exp_path.display()
            ));
        }
    }
}

fn finish(area_kind: &str, count: usize, failures: Vec<String>) {
    assert!(count > 0, "no {area_kind} fixtures found — path bug?");
    assert!(
        failures.is_empty(),
        "{} of {count} {area_kind} fixtures failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!("{area_kind}: {count} fixtures passed");
}

#[test]
fn golden_fixtures() {
    let cofhe = cofhe_contracts_dir();
    let gate = cofhe.is_some() && have_solc();
    if !gate {
        eprintln!("NOTE: solc gate unavailable; golden fixtures run with --no-verify");
    }
    let mut failures = Vec::new();
    let mut count = 0;
    for area in GOLDEN_AREAS {
        let dirs = fixture_dirs(area).unwrap_or_else(|| panic!("missing area dir {area}"));
        assert!(!dirs.is_empty(), "area {area} is empty — path bug?");
        for fixture in dirs {
            count += 1;
            let tmp = tempfile::tempdir().unwrap();
            setup_project(&fixture, tmp.path(), cofhe.as_deref());
            let mut args = vec!["build", "--json", "--self-check"];
            if !gate || fixture.join("no-verify").is_file() {
                args.push("--no-verify");
            }
            let out = fhec(tmp.path(), &args);
            if out.status.code() != Some(0) {
                failures.push(format!(
                    "{}: build exited {:?}\nstderr: {}",
                    fixture.display(),
                    out.status.code(),
                    String::from_utf8_lossy(&out.stderr)
                ));
                continue;
            }
            match_outputs(&fixture, &tmp.path().join("generated"), &mut failures);
            match_diags(&fixture, &parse_diags(&out.stdout), &mut failures);
            eprintln!("PASS golden {}", fixture.display());
        }
    }
    finish("golden", count, failures);
}

#[test]
fn rejection_fixtures() {
    let cofhe = cofhe_contracts_dir();
    let mut failures = Vec::new();
    let mut count = 0;
    for area in CHECK_AREAS {
        let dirs = fixture_dirs(area).unwrap_or_else(|| panic!("missing area dir {area}"));
        assert!(!dirs.is_empty(), "area {area} is empty — path bug?");
        for fixture in dirs {
            count += 1;
            let tmp = tempfile::tempdir().unwrap();
            setup_project(&fixture, tmp.path(), cofhe.as_deref());
            let out = if fixture.join("build-only").is_file() {
                fhec(tmp.path(), &["build", "--json", "--no-verify"])
            } else {
                fhec(tmp.path(), &["check", "--json"])
            };
            if out.status.code() != Some(1) {
                failures.push(format!(
                    "{}: expected exit 1, got {:?}\nstderr: {}",
                    fixture.display(),
                    out.status.code(),
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
            match_diags(&fixture, &parse_diags(&out.stdout), &mut failures);
            eprintln!("PASS reject {}", fixture.display());
        }
    }
    finish("rejection", count, failures);
}

#[test]
fn noop_fixtures() {
    let cofhe = cofhe_contracts_dir();
    let gate = cofhe.is_some() && have_solc();
    let mut failures = Vec::new();
    let mut count = 0;
    let dirs = fixture_dirs("noop").expect("missing area dir noop");
    assert!(!dirs.is_empty(), "area noop is empty — path bug?");
    for fixture in dirs {
        count += 1;
        let tmp = tempfile::tempdir().unwrap();
        setup_project(&fixture, tmp.path(), cofhe.as_deref());
        let mut args = vec!["build", "--json", "--self-check"];
        if !gate || fixture.join("no-verify").is_file() {
            args.push("--no-verify");
        }
        let out = fhec(tmp.path(), &args);
        if out.status.code() != Some(0) {
            failures.push(format!(
                "{}: build exited {:?}\nstderr: {}",
                fixture.display(),
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            ));
            continue;
        }
        // §10.4 property 2: byte-identical pass-through.
        let input_name = std::fs::read_dir(&fixture)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .find(|n| n.starts_with("input."))
            .expect("noop fixture has an input file");
        let out_name = input_name.replace(".fsol", ".sol");
        let input = read(&fixture.join(&input_name));
        let generated = read(&tmp.path().join("generated").join(&out_name));
        if input != generated {
            failures.push(format!("{}: output differs from input", fixture.display()));
        }
        // Manifest must record the file as a no-op.
        let manifest: serde_json::Value =
            serde_json::from_str(&read(&tmp.path().join("generated/.fhec/manifest.json")))
                .expect("manifest parses");
        let is_noop = manifest["files"]
            .as_array()
            .and_then(|fs| fs.iter().find(|f| f["output"] == out_name.as_str()))
            .map(|f| f["no_op"] == true);
        if is_noop != Some(true) {
            failures.push(format!(
                "{}: manifest no_op is not true: {manifest}",
                fixture.display()
            ));
        }
        match_diags(&fixture, &parse_diags(&out.stdout), &mut failures);
        eprintln!("PASS noop {}", fixture.display());
    }
    finish("noop", count, failures);
}

#[test]
fn sourcemap_fixtures() {
    let Some(cofhe) = cofhe_contracts_dir() else {
        eprintln!("SKIP: no cofhe-contracts checkout for sourcemap fixtures");
        return;
    };
    if !have_solc() {
        eprintln!("SKIP: no suitable solc for sourcemap fixtures");
        return;
    }
    let mut failures = Vec::new();
    let mut count = 0;
    let dirs = fixture_dirs("sourcemap").expect("missing area dir sourcemap");
    assert!(!dirs.is_empty(), "area sourcemap is empty — path bug?");
    for fixture in dirs {
        count += 1;
        let tmp = tempfile::tempdir().unwrap();
        setup_project(&fixture, tmp.path(), Some(&cofhe));
        let out = fhec(tmp.path(), &["build", "--json"]);
        if out.status.code() != Some(1) {
            failures.push(format!(
                "{}: expected exit 1, got {:?}",
                fixture.display(),
                out.status.code()
            ));
        }
        match_diags(&fixture, &parse_diags(&out.stdout), &mut failures);
        eprintln!("PASS sourcemap {}", fixture.display());
    }
    finish("sourcemap", count, failures);
}
