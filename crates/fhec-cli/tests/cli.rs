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

    // init refuses to overwrite.
    let out = fhec(tmp.path(), &["init"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("refusing to overwrite"));
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

    let out = fhec(tmp.path(), &["explain", "FHE0000"]);
    assert_eq!(out.status.code(), Some(2));
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
