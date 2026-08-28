//! Integration tests driving the built `fhec` binary end-to-end.

use std::path::Path;
use std::process::{Command, Output};

fn fhec(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fhec"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("fhec binary runs")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn init_then_check_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let out = fhec(tmp.path(), &["init"]);
    assert_eq!(out.status.code(), Some(0), "init: {}", stderr(&out));
    assert!(tmp.path().join("fhec.toml").is_file());
    assert!(tmp.path().join("contracts/Counter.fsol").is_file());

    let out = fhec(tmp.path(), &["check"]);
    assert_eq!(out.status.code(), Some(0), "check: {}", stderr(&out));
    assert!(stdout(&out).is_empty());
    let err = stderr(&out);
    assert!(
        err.contains("file(s) checked clean"),
        "expected check summary on stderr: {err}"
    );
    assert!(err.contains("rewrite site(s)"), "stderr: {err}");
    assert!(err.contains("config hash"), "stderr: {err}");

    // `--json` keeps the spec §10.2 stream silent on a clean project.
    let out = fhec(tmp.path(), &["check", "--json"]);
    assert_eq!(out.status.code(), Some(0), "check --json: {}", stderr(&out));
    assert!(stdout(&out).is_empty(), "stdout: {}", stdout(&out));
    assert!(
        !stderr(&out).contains("checked clean"),
        "summary must not leak onto --json stderr: {}",
        stderr(&out)
    );

    // init refuses to overwrite.
    let out = fhec(tmp.path(), &["init"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("refusing to overwrite"));
}

#[test]
fn check_warns_when_include_matches_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(fhec(tmp.path(), &["init"]).status.code(), Some(0));
    std::fs::create_dir_all(tmp.path().join("empty")).unwrap();
    std::fs::write(tmp.path().join("fhec.toml"), "[project]\nsrc = \"empty\"\n").unwrap();

    let out = fhec(tmp.path(), &["check"]);
    assert_eq!(out.status.code(), Some(0), "check: {}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("FHE1007"), "stderr: {err}");
    assert!(err.contains("0 file(s) checked clean"), "stderr: {err}");

    let out = fhec(tmp.path(), &["check", "--json"]);
    assert_eq!(out.status.code(), Some(0), "check --json: {}", stderr(&out));
    assert!(
        !stderr(&out).contains("checked clean"),
        "summary must not leak onto --json stderr: {}",
        stderr(&out)
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON array");
    let arr = parsed.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["code"], "FHE1007");
    assert_eq!(arr[0]["severity"], "warning");
}

#[test]
fn unresolved_relative_import_gets_a_safe_extension_fixit() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("fhec.toml"), "").unwrap();
    std::fs::create_dir_all(tmp.path().join("contracts")).unwrap();
    std::fs::write(
        tmp.path().join("contracts/A.fsol"),
        "pragma solidity ^0.8.25;\ncontract A {}\n",
    )
    .unwrap();
    let b_path = tmp.path().join("contracts/B.fsol");
    std::fs::write(
        &b_path,
        "pragma solidity ^0.8.25;\nimport \"./A.sol\";\ncontract B {}\n",
    )
    .unwrap();

    let out = fhec(tmp.path(), &["check", "--json"]);
    assert_eq!(out.status.code(), Some(1), "check: {}", stderr(&out));
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON array");
    let arr = parsed.as_array().expect("array");
    let fhe1003 = arr
        .iter()
        .find(|d| d["code"] == "FHE1003")
        .unwrap_or_else(|| panic!("no FHE1003 in {arr:?}"));
    let fixits = fhe1003["fixits"].as_array().expect("fixits array");
    assert_eq!(fixits.len(), 1, "diag: {fhe1003}");
    assert_eq!(fixits[0]["safe"], true);
    let replacement = fixits[0]["replacement"].as_str().expect("replacement");
    assert!(
        replacement.contains("A.fsol"),
        "replacement should swap to .fsol: {replacement}"
    );

    let out = fhec(tmp.path(), &["check", "--fix"]);
    assert_eq!(out.status.code(), Some(0), "fix: {}", stderr(&out));
    let fixed = std::fs::read_to_string(&b_path).unwrap();
    assert!(
        fixed.contains("import \"./A.fsol\""),
        "fix-it not applied:\n{fixed}"
    );
    assert!(
        !fixed.contains("import \"./A.sol\""),
        "old specifier remains:\n{fixed}"
    );
}

#[test]
fn extension_fixit_is_absent_when_swapped_file_was_not_discovered() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("fhec.toml"),
        "[project]\nexclude = [\"Hidden.fsol\"]\n",
    )
    .unwrap();
    std::fs::create_dir_all(tmp.path().join("contracts")).unwrap();
    std::fs::write(
        tmp.path().join("contracts/Hidden.fsol"),
        "pragma solidity ^0.8.25;\ncontract Hidden {}\n",
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("contracts/User.fsol"),
        "pragma solidity ^0.8.25;\nimport \"./Hidden.sol\";\ncontract User {}\n",
    )
    .unwrap();

    let out = fhec(tmp.path(), &["check", "--json"]);
    assert_eq!(out.status.code(), Some(1), "check: {}", stderr(&out));
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON array");
    let arr = parsed.as_array().expect("array");
    let fhe1003 = arr
        .iter()
        .find(|d| d["code"] == "FHE1003")
        .unwrap_or_else(|| panic!("no FHE1003 in {arr:?}"));
    let fixits = fhe1003.get("fixits").and_then(|v| v.as_array());
    assert!(
        fixits.is_none() || fixits.unwrap().is_empty(),
        "must not attach a safe fix-it for an undiscovered file: {fhe1003}"
    );

    let out = fhec(tmp.path(), &["check", "--fix"]);
    assert_eq!(out.status.code(), Some(1), "fix: {}", stderr(&out));
    assert!(
        stderr(&out).contains("no safe fix-its to apply"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn parse_error_reports_fhe1002_human_and_json() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(fhec(tmp.path(), &["init"]).status.code(), Some(0));
    std::fs::write(
        tmp.path().join("contracts/Bad.fsol"),
        "pragma solidity ^0.8.25;\ncontract {\n",
    )
    .unwrap();

    let out = fhec(tmp.path(), &["check"]);
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("error[FHE1002]"), "stderr: {err}");
    assert!(err.contains("Bad.fsol"), "stderr: {err}");

    let out = fhec(tmp.path(), &["check", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON array");
    let arr = parsed.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["code"], "FHE1002");
    assert_eq!(arr[0]["severity"], "error");
    assert_eq!(arr[0]["span"]["file"], "Bad.fsol");
    assert_eq!(arr[0]["span"]["start_line"], 1);
}

#[test]
fn missing_config_reports_draft_code() {
    let tmp = tempfile::tempdir().unwrap();
    let out = fhec(tmp.path(), &["check"]);
    // Guard: if some ancestor of the tempdir carries a fhec.toml this test
    // cannot assert anything meaningful.
    if out.status.code() == Some(0) {
        return;
    }
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("FHE1004"), "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("fhec init"));
}

#[test]
fn bad_pragma_reports_fhe1001() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(fhec(tmp.path(), &["init"]).status.code(), Some(0));
    std::fs::write(
        tmp.path().join("contracts/Old.fsol"),
        "pragma solidity ^0.8.0;\ncontract Old {}\n",
    )
    .unwrap();
    let out = fhec(tmp.path(), &["check"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("FHE1001"), "stderr: {}", stderr(&out));
}

#[test]
fn explain_known_and_unknown() {
    let tmp = tempfile::tempdir().unwrap();
    let out = fhec(tmp.path(), &["explain", "FHE2007"]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    assert!(text.contains("possibly-uninitialized-encrypted"), "{text}");
    assert!(text.contains("§6"), "{text}");

    let out = fhec(tmp.path(), &["explain", "FHE1007"]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    assert!(text.contains("no-files-matched"), "{text}");

    let out = fhec(tmp.path(), &["explain", "FHE0000"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn explain_covers_the_precondition_codes() {
    let tmp = tempfile::tempdir().unwrap();
    for (code, name) in [
        ("FHE1017", "precondition-bad-position"),
        ("FHE3014", "encrypted-input-used-in-precondition"),
        ("FHE3015", "precondition-forbidden-effect"),
    ] {
        let out = fhec(tmp.path(), &["explain", code]);
        assert_eq!(out.status.code(), Some(0), "{code}");
        let text = stdout(&out);
        assert!(text.contains(name), "{code}: {text}");
        assert!(text.contains("§2.7"), "{code}: {text}");
    }
}

#[test]
fn explain_covers_the_proof_binder_codes() {
    let tmp = tempfile::tempdir().unwrap();
    for (code, name) in [
        ("FHE1013", "in-sugar-proof-binding-invalid"),
        ("FHE1014", "in-sugar-proof-binding-inconsistent"),
    ] {
        let out = fhec(tmp.path(), &["explain", code]);
        assert_eq!(out.status.code(), Some(0), "{code}");
        let text = stdout(&out);
        assert!(text.contains(name), "{code}: {text}");
        assert!(text.contains("§2.3"), "{code}: {text}");
    }
}

#[test]
fn invalid_acl_mode_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let out = fhec(tmp.path(), &["check", "--acl", "bogus"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("invalid --acl mode"));
}

#[test]
fn init_then_config_prints_effective_json() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(fhec(tmp.path(), &["init"]).status.code(), Some(0));

    let out = fhec(tmp.path(), &["config"]);
    assert_eq!(out.status.code(), Some(0), "config: {}", stderr(&out));
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("config stdout is JSON");
    let obj = parsed.as_object().expect("object");
    assert_eq!(obj["project"]["src"], "contracts");
    assert_eq!(obj["project"]["out"], "generated");
    assert_eq!(obj["target"]["profile"], "cofhe");
    assert_eq!(obj["acl"]["mode"], "insert");
    let path = obj["path"].as_str().expect("path string");
    assert!(path.ends_with("fhec.toml"), "path: {path}");
    let root = obj["root"].as_str().expect("root string");
    assert_eq!(
        Path::new(root).canonicalize().unwrap(),
        tmp.path().canonicalize().unwrap()
    );
    let hash = obj["hash"].as_str().expect("hash string");
    assert_eq!(hash.len(), 64, "hash: {hash}");
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()), "hash: {hash}");
    assert!(!obj.contains_key("strictness"));
    assert!(!obj.contains_key("text"));
}

#[test]
fn config_missing_reports_draft_code() {
    let tmp = tempfile::tempdir().unwrap();
    let out = fhec(tmp.path(), &["config"]);
    // Guard: if some ancestor of the tempdir carries a fhec.toml this test
    // cannot assert anything meaningful.
    if out.status.code() == Some(0) {
        return;
    }
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("FHE1004"), "stderr: {}", stderr(&out));
}

#[test]
fn help_documents_all_solc_warnings() {
    let tmp = tempfile::tempdir().unwrap();
    let out = fhec(tmp.path(), &["build", "--help"]);
    assert_eq!(out.status.code(), Some(0), "help: {}", stderr(&out));
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        text.contains("--all-solc-warnings"),
        "expected flag in CLI help: {text}"
    );
    assert!(
        text.contains("project.src"),
        "expected the flag to mention project.src: {text}"
    );
}

#[test]
fn watch_rejected_on_non_build_commands() {
    let tmp = tempfile::tempdir().unwrap();
    for args in [
        ["init", "--watch"].as_slice(),
        ["explain", "FHE2007", "--watch"].as_slice(),
        ["clean", "--watch"].as_slice(),
        ["config", "--watch"].as_slice(),
    ] {
        let out = fhec(tmp.path(), args);
        assert_eq!(out.status.code(), Some(2), "args: {args:?}");
        assert!(
            stderr(&out).contains("--watch is only valid with build or check"),
            "stderr: {}",
            stderr(&out)
        );
    }
}

#[test]
fn clean_removes_only_the_out_dir() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(fhec(tmp.path(), &["init"]).status.code(), Some(0));
    let out_dir = tmp.path().join("generated");
    std::fs::create_dir_all(out_dir.join(".fhec")).unwrap();
    std::fs::write(out_dir.join("Counter.sol"), "contract Counter {}").unwrap();

    let out = fhec(tmp.path(), &["clean"]);
    assert_eq!(out.status.code(), Some(0), "clean: {}", stderr(&out));
    assert!(!out_dir.exists());
    assert!(tmp.path().join("contracts/Counter.fsol").is_file());

    // Cleaning again is a quiet no-op.
    let out = fhec(tmp.path(), &["clean"]);
    assert_eq!(out.status.code(), Some(0));
}
