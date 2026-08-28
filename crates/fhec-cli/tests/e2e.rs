//! End-to-end tests for the wired pipeline: init → build → verify, the
//! §1.4 no-op/idempotence properties, --frozen, --fix, and FHE6000 span
//! remapping. Tests that need the pinned CoFHE library package or a solc
//! binary skip with a message when either is unavailable (both exist on the
//! dev machine: the package comes from the workspace's pnpm install).

use std::path::{Path, PathBuf};
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

/// The pinned `@fhenixprotocol/cofhe-contracts` package (FHE.sol at its
/// root — the published npm layout) plus the `@openzeppelin/contracts`
/// package FHE.sol imports from. Defaults to the workspace's own pnpm
/// install; `FHEC_COFHE_CONTRACTS` overrides the library location and
/// accepts a repository checkout layout (`contracts/FHE.sol`) too.
fn cofhe_packages() -> Option<(PathBuf, PathBuf)> {
    let modules =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packages/difftest/node_modules");
    let root = std::env::var_os("FHEC_COFHE_CONTRACTS").map_or_else(
        || modules.join("@fhenixprotocol/cofhe-contracts"),
        PathBuf::from,
    );
    let pkg = if root.join("FHE.sol").is_file() {
        root
    } else if root.join("contracts/FHE.sol").is_file() {
        root.join("contracts")
    } else {
        eprintln!("SKIP: no cofhe-contracts library at {}", root.display());
        return None;
    };
    for oz in [
        pkg.join("node_modules/@openzeppelin/contracts"),
        modules.join("@openzeppelin/contracts"),
    ] {
        if oz.join("package.json").is_file() {
            return Some((pkg, oz));
        }
    }
    eprintln!(
        "SKIP: no @openzeppelin/contracts install next to {}",
        pkg.display()
    );
    None
}

fn have_solc() -> bool {
    if fhec_verify::SolcRunner::for_requirement(">=0.8.25, <0.9.0").is_ok() {
        true
    } else {
        eprintln!("SKIP: no suitable solc available");
        false
    }
}

/// Symlinks the pinned cofhe-contracts package (and the OpenZeppelin
/// package its FHE.sol imports) into the project's node_modules under the
/// published package names.
fn link_node_modules(project: &Path, contracts: &Path, openzeppelin: &Path) {
    let scope = project.join("node_modules/@fhenixprotocol");
    std::fs::create_dir_all(&scope).unwrap();
    std::os::unix::fs::symlink(contracts, scope.join("cofhe-contracts")).unwrap();
    let oz_scope = project.join("node_modules/@openzeppelin");
    std::fs::create_dir_all(&oz_scope).unwrap();
    std::os::unix::fs::symlink(openzeppelin, oz_scope.join("contracts")).unwrap();
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn dogfood_build_end_to_end() {
    let Some((contracts, openzeppelin)) = cofhe_packages() else {
        return;
    };
    if !have_solc() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    assert_eq!(fhec(root, &["init"]).status.code(), Some(0));
    link_node_modules(root, &contracts, &openzeppelin);

    // Build with the hidden §1.4 self-check on.
    let out = fhec(root, &["build", "--verbose", "--self-check"]);
    assert_eq!(out.status.code(), Some(0), "build: {}", stderr(&out));

    let generated = root.join("generated/Counter.sol");
    let text = read(&generated);
    for needle in [
        "externalEuint32 amount_input",
        "bytes memory inputProof",
        "euint32 amount = FHE.asEuint32(amount_input, inputProof);",
        "FHE.select(",
        "FHE.allowThis(count);",
        "FHE.allowSender(count);",
    ] {
        assert!(text.contains(needle), "missing `{needle}` in:\n{text}");
    }
    assert!(!text.contains(" in euint32"), "sugar must be lowered");

    // The manifest exists, parses, and maps the patched file.
    let manifest_text = read(&root.join("generated/.fhec/manifest.json"));
    let manifest: serde_json::Value = serde_json::from_str(&manifest_text).unwrap();
    assert_eq!(manifest["tool"], "fhec");
    let files = manifest["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["output"], "Counter.sol");
    assert_eq!(files[0]["source"], "Counter.fsol");
    assert_eq!(files[0]["no_op"], false);
    assert!(!files[0]["mappings"].as_array().unwrap().is_empty());

    // Rebuild: byte-identical outputs (determinism + §1.4).
    let before = text.clone();
    let out = fhec(root, &["build"]);
    assert_eq!(out.status.code(), Some(0), "rebuild: {}", stderr(&out));
    assert_eq!(read(&generated), before, "rebuild changed the output");
    assert_eq!(
        read(&root.join("generated/.fhec/manifest.json")),
        manifest_text
    );

    // --frozen is green right after a build.
    let out = fhec(root, &["build", "--frozen"]);
    assert_eq!(out.status.code(), Some(0), "frozen: {}", stderr(&out));

    // Touching a generated file turns --frozen red.
    std::fs::write(&generated, format!("{before}\n// drift\n")).unwrap();
    let out = fhec(root, &["build", "--frozen", "--no-verify"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("differs"), "stderr: {}", stderr(&out));
    std::fs::write(&generated, &before).unwrap();

    // An orphan file turns --frozen red.
    std::fs::write(root.join("generated/Orphan.sol"), "contract O {}").unwrap();
    let out = fhec(root, &["build", "--frozen", "--no-verify"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("orphan"), "stderr: {}", stderr(&out));
    std::fs::remove_file(root.join("generated/Orphan.sol")).unwrap();

    // Editing the source turns --frozen red.
    let src_path = root.join("contracts/Counter.fsol");
    let src = read(&src_path);
    std::fs::write(&src_path, src.replace("count + amount", "amount + count")).unwrap();
    let out = fhec(root, &["build", "--frozen", "--no-verify"]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
}

#[test]
fn plain_sol_passes_through_byte_identical() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(root.join("fhec.toml"), "").unwrap();
    std::fs::create_dir_all(root.join("contracts")).unwrap();
    let source = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.25;\n\ncontract Plain {\n    uint256 public x;\n\n    function bump() external {\n        x += 1;\n    }\n}\n";
    std::fs::write(root.join("contracts/Plain.sol"), source).unwrap();

    let out = fhec(root, &["build", "--no-verify"]);
    assert_eq!(out.status.code(), Some(0), "build: {}", stderr(&out));
    assert_eq!(read(&root.join("generated/Plain.sol")), source);
    let manifest: serde_json::Value =
        serde_json::from_str(&read(&root.join("generated/.fhec/manifest.json"))).unwrap();
    assert_eq!(manifest["files"][0]["no_op"], true);

    // With solc available, the gate accepts the pass-through tree too.
    if have_solc() {
        let out = fhec(root, &["build"]);
        assert_eq!(out.status.code(), Some(0), "gated build: {}", stderr(&out));
    }
}

#[test]
fn fhe6000_remaps_to_original_fsol_position() {
    let Some((contracts, openzeppelin)) = cofhe_packages() else {
        return;
    };
    if !have_solc() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(root.join("fhec.toml"), "").unwrap();
    std::fs::create_dir_all(root.join("contracts")).unwrap();
    link_node_modules(root, &contracts, &openzeppelin);

    // The sugar patch near the top shifts every later offset, so the solc
    // error about `missingFn` exercises the delta-remap path. Our pipeline
    // accepts the call (Unknown, positive-fragment discipline); solc rejects
    // it. `missingFn(1);` sits on line 10 of the original source.
    let source = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";

contract Broken {
    euint32 count;

    function set(in euint32 v) external {
        missingFn(1);
        count = v;
    }
}
";
    std::fs::write(root.join("contracts/Broken.fsol"), source).unwrap();

    let out = fhec(root, &["build", "--json"]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("json diagnostics");
    let arr = parsed.as_array().unwrap();
    let fhe6000 = arr
        .iter()
        .find(|d| d["code"] == "FHE6000" && d["severity"] == "error")
        .unwrap_or_else(|| panic!("no FHE6000 in {arr:?}"));
    assert_eq!(fhe6000["span"]["file"], "Broken.fsol");
    assert_eq!(fhe6000["span"]["start_line"], 10, "diag: {fhe6000:?}");
}

#[test]
fn fix_applies_suggest_mode_acl_fixits() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(root.join("fhec.toml"), "[acl]\nmode = \"suggest\"\n").unwrap();
    std::fs::create_dir_all(root.join("contracts")).unwrap();
    let source = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";

contract Vault {
    euint32 count;

    function set(in euint32 v) external {
        count = v;
    }
}
";
    let src_path = root.join("contracts/Vault.fsol");
    std::fs::write(&src_path, source).unwrap();

    // Suggest mode: the missing ACL grants surface as notes, exit 0.
    let out = fhec(root, &["check", "--json"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let notes: Vec<_> = parsed
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["code"] == "FHE4010")
        .collect();
    assert!(!notes.is_empty(), "expected FHE4010 notes: {parsed}");
    assert_eq!(notes[0]["severity"], "note");

    // --fix applies the safe insertion to the original source. `count` is a
    // simple state variable (no key at all), so R1 only guesses `allowThis`
    // (issue #70): guessing `allowSender` for a slot not provably keyed by
    // `msg.sender` would be a confidentiality leak.
    let out = fhec(root, &["check", "--fix"]);
    assert_eq!(out.status.code(), Some(0), "fix: {}", stderr(&out));
    let fixed = read(&src_path);
    assert!(
        fixed.contains("FHE.allowThis(count);"),
        "fix-it not applied:\n{fixed}"
    );
    assert!(
        !fixed.contains("FHE.allowSender(count);"),
        "the sender grant must not be guessed for a slot with no owner key:\n{fixed}"
    );

    // Idempotent: the grants exist now, so no note and nothing to fix.
    let out = fhec(root, &["check", "--json"]);
    assert_eq!(out.status.code(), Some(0));
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap_or_default();
    if let Some(arr) = parsed.as_array() {
        assert!(
            arr.iter().all(|d| d["code"] != "FHE4010"),
            "notes should be gone: {parsed}"
        );
    }
}

#[test]
fn missing_node_modules_gives_install_advice() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    assert_eq!(fhec(root, &["init"]).status.code(), Some(0));

    let out = fhec(root, &["build"]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("FHE6000"), "stderr: {err}");
    assert!(err.contains("cannot resolve import"), "stderr: {err}");
    assert!(err.contains("npm install"), "stderr: {err}");

    let out = fhec(root, &["build", "--no-verify"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(root.join("generated/Counter.sol").is_file());
}

#[test]
fn third_party_solc_warnings_are_suppressed_by_default() {
    if !have_solc() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(root.join("fhec.toml"), "[project]\nsrc = \"contracts\"\n").unwrap();
    std::fs::create_dir_all(root.join("contracts")).unwrap();
    std::fs::create_dir_all(root.join("node_modules/noisy")).unwrap();
    std::fs::write(
        root.join("node_modules/noisy/Lib.sol"),
        "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
contract Lib {
    function f() public pure returns (uint) {
        return 1;
        uint x = 2;
    }
}
",
    )
    .unwrap();
    std::fs::write(
        root.join("contracts/User.sol"),
        "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
import \"noisy/Lib.sol\";
contract User is Lib {
    function g() public pure returns (uint) {
        return 1;
        uint y = 2;
    }
}
",
    )
    .unwrap();

    let out = fhec(root, &["build", "--json"]);
    assert_eq!(out.status.code(), Some(0), "build: {}", stderr(&out));
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout(&out)).unwrap_or_else(|_| serde_json::json!([]));
    let arr = parsed.as_array().cloned().unwrap_or_default();
    let warnings: Vec<_> = arr
        .iter()
        .filter(|d| d["code"] == "FHE6000" && d["severity"] == "warning")
        .collect();
    assert!(
        warnings.iter().any(|d| d["span"]["file"] == "User.sol"),
        "expected an in-src warning: {arr:?}"
    );
    assert!(
        warnings
            .iter()
            .all(|d| d["span"]["file"] != "noisy/Lib.sol"),
        "third-party warning leaked: {arr:?}"
    );

    let out = fhec(root, &["build", "--json", "--all-solc-warnings"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "build --all-solc-warnings: {}",
        stderr(&out)
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout(&out)).unwrap_or_else(|_| serde_json::json!([]));
    let arr = parsed.as_array().cloned().unwrap_or_default();
    assert!(
        arr.iter()
            .any(|d| d["code"] == "FHE6000" && d["span"]["file"] == "noisy/Lib.sol"),
        "flag must restore the third-party warning: {arr:?}"
    );
}

#[test]
fn third_party_solc_errors_are_always_forwarded() {
    if !have_solc() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(root.join("fhec.toml"), "[project]\nsrc = \"contracts\"\n").unwrap();
    std::fs::create_dir_all(root.join("contracts")).unwrap();
    std::fs::create_dir_all(root.join("node_modules/noisy")).unwrap();
    std::fs::write(
        root.join("node_modules/noisy/Lib.sol"),
        "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
contract Lib {
    function f() public pure {
        missingFn();
    }
}
",
    )
    .unwrap();
    std::fs::write(
        root.join("contracts/User.sol"),
        "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
import \"noisy/Lib.sol\";
contract User is Lib {}
",
    )
    .unwrap();

    let out = fhec(root, &["build", "--json"]);
    assert_eq!(out.status.code(), Some(1), "build: {}", stderr(&out));
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("json diagnostics");
    let arr = parsed.as_array().unwrap();
    assert!(
        arr.iter().any(|d| d["code"] == "FHE6000"
            && d["severity"] == "error"
            && d["span"]["file"] == "noisy/Lib.sol"),
        "expected a forwarded third-party error: {arr:?}"
    );
}

#[test]
fn a_wrong_shared_return_assumption_is_caught_by_solc() {
    // Spec §2.8 restriction 8 downgrades FHE2012 to a warning when only an
    // unreadable base blocks the proof, on the ground that the generated
    // `share` call is type-checked downstream. This test is that ground:
    // without it the warning rests on an unproven claim.
    let Some((contracts, openzeppelin)) = cofhe_packages() else {
        return;
    };
    if !have_solc() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(root.join("fhec.toml"), "").unwrap();
    std::fs::create_dir_all(root.join("contracts")).unwrap();
    link_node_modules(root, &contracts, &openzeppelin);

    // `L.pub` really returns `uint256`. The unreadable base makes the
    // checker unable to prove that, so it warns and emits
    // `FHE.shareEuint64(L.pub(a), msg.sender)`.
    let source = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";
import { ReentrancyGuardTransient } from \"@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol\";

library L {
    function pub(euint64 a) internal pure returns (uint256) {
        return 1;
    }
}

contract Wrong is ReentrancyGuardTransient {
    function f(euint64 a) external returns (shared(msg.sender) euint64) {
        return L.pub(a);
    }
}
";
    std::fs::write(root.join("contracts/Wrong.fsol"), source).unwrap();

    let out = fhec(root, &["build", "--json"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("json diagnostics");
    let arr = parsed.as_array().unwrap();

    assert!(
        arr.iter()
            .any(|d| d["code"] == "FHE2012" && d["severity"] == "warning"),
        "expected the FHE2012 warning: {arr:?}"
    );
    let solc = arr
        .iter()
        .find(|d| d["code"] == "FHE6000" && d["severity"] == "error")
        .unwrap_or_else(|| panic!("solc must reject the wrong assumption: {arr:?}"));
    assert!(
        solc["message"]
            .as_str()
            .unwrap()
            .contains("uint256 to euint64"),
        "diag: {solc:?}"
    );
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
}
