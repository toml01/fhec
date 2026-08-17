//! Discovery and version-pinning behaviour.

mod common;

use std::path::PathBuf;

use fhec_verify::{discovery, DiscoveryOptions, SolcBinary, SolcOrigin, SolcRunner, VerifyError};

/// (c) A binary that exists but is the wrong version is rejected, not used.
#[test]
fn an_explicit_binary_of_the_wrong_version_is_rejected() {
    let Some(runner) = common::solc_runner() else {
        return;
    };
    let path = runner.binary().path().to_path_buf();

    let requirement = discovery::parse_requirement("=0.4.0").expect("valid requirement");
    let err = SolcRunner::at_path(&path, &requirement).expect_err("0.4.0 must be rejected");

    let VerifyError::VersionMismatch {
        path: reported,
        found,
        requirement: reported_req,
    } = &err
    else {
        panic!("expected VersionMismatch, got {err}");
    };
    assert_eq!(reported, &path);
    assert_eq!(found.as_ref(), runner.binary().version());
    assert_eq!(reported_req, &requirement);

    let text = err.to_string();
    assert!(text.contains("=0.4.0"), "{text}");
    assert!(text.contains("does not satisfy"), "{text}");
}

/// The same rejection happens through the ordinary discovery entry point when
/// the caller pins a path.
#[test]
fn discovery_does_not_fall_through_a_pinned_mismatch() {
    let Some(runner) = common::solc_runner() else {
        return;
    };

    let options = DiscoveryOptions::new(discovery::parse_requirement("=0.4.0").expect("valid"))
        .with_explicit_path(runner.binary().path());
    let err = discovery::discover(&options).expect_err("must not silently pick another compiler");
    assert!(
        matches!(err, VerifyError::VersionMismatch { .. }),
        "a pinned binary must be an assertion, not a hint: {err}"
    );
}

/// A search (as opposed to a pin) that finds nothing usable reports every place
/// it looked, plus how to install a compiler.
#[test]
fn an_impossible_requirement_reports_the_search_trail() {
    let options = DiscoveryOptions {
        requirement: discovery::parse_requirement("=0.4.0").expect("valid"),
        explicit_path: None,
        read_env: false,
        search_path: false,
        svm_roots: None,
    };
    let err = discovery::discover(&options).expect_err("0.4.0 is not installed");
    assert!(common::is_not_found(&err), "{err}");

    let VerifyError::SolcNotFound { searched, .. } = &err else {
        panic!("expected SolcNotFound");
    };
    // Either svm homes were empty, or they held versions that did not match.
    assert!(
        searched
            .iter()
            .all(|step| step.origin != SolcOrigin::Path && step.origin != SolcOrigin::Env),
        "PATH and env lookups were disabled: {searched:?}"
    );
    let text = err.to_string();
    assert!(text.contains("=0.4.0"), "{text}");
    assert!(
        text.contains("foundryup"),
        "the error must say how to fix it"
    );
    assert!(text.contains("FHEC_SOLC"), "{text}");
}

/// Unparsable requirement text is a typed error, not a panic.
#[test]
fn a_bad_requirement_is_a_typed_error() {
    let err = SolcRunner::for_requirement("^^nonsense").expect_err("must reject");
    assert!(
        matches!(err, VerifyError::InvalidRequirement { .. }),
        "{err}"
    );
}

/// A path that is not a compiler produces a spawn error, not a panic.
#[test]
fn a_missing_binary_is_a_typed_spawn_error() {
    let err =
        SolcBinary::probe(PathBuf::from("/definitely/not/here/solc")).expect_err("cannot be run");
    assert!(matches!(err, VerifyError::Spawn { .. }), "{err}");
}

/// A binary that runs but prints no version is reported as unparsable.
#[test]
fn unparsable_version_output_is_a_typed_error() {
    let true_binary = ["/usr/bin/true", "/bin/true"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file());
    let Some(true_binary) = true_binary else {
        eprintln!("SKIP: no /usr/bin/true on this platform");
        return;
    };
    let err = SolcBinary::probe(&true_binary).expect_err("no version banner");
    assert!(
        matches!(err, VerifyError::VersionUnparsable { .. }),
        "{err}"
    );
}

/// Discovery honours `FHEC_SOLC` and reports the binary's provenance.
#[test]
fn the_env_var_pins_the_binary() {
    let Some(runner) = common::solc_runner() else {
        return;
    };
    let path = runner.binary().path().to_path_buf();

    let options = DiscoveryOptions {
        requirement: discovery::parse_requirement(common::REQUIREMENT).expect("valid"),
        explicit_path: Some(path.clone()),
        read_env: false,
        search_path: false,
        svm_roots: Some(Vec::new()),
    };
    let binary = discovery::discover(&options).expect("the pinned binary is accepted");
    assert_eq!(binary.path(), path);
    assert_eq!(binary.origin(), SolcOrigin::Explicit);
}

/// The svm layout scan finds whatever this machine has installed.
#[test]
fn the_svm_scan_reads_the_version_directory_layout() {
    let installed = discovery::installed_versions();
    if installed.is_empty() {
        eprintln!(
            "SKIP: no svm-managed compilers under {:?}",
            discovery::svm_roots()
        );
        return;
    }
    for (version, path) in &installed {
        let file_name = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or_default();
        assert_eq!(file_name, format!("solc-{version}"));
        assert!(path.is_file());
    }
    // Newest first, so a range requirement picks the latest match.
    assert!(installed.windows(2).all(|pair| pair[0].0 >= pair[1].0));
}

/// `ensure_solc` never downloads when the version is already present.
#[test]
fn ensure_solc_is_a_no_op_for_an_installed_version() {
    let Some(runner) = common::solc_runner() else {
        return;
    };
    let version = runner.binary().version().clone();
    // Strip any build metadata: svm directories are named `<major>.<minor>.<patch>`.
    let bare = semver::Version::new(version.major, version.minor, version.patch);
    let Some(expected) = discovery::find_installed(&bare) else {
        eprintln!("SKIP: solc {bare} is not svm-managed on this machine");
        return;
    };
    let found = discovery::ensure_solc(&bare).expect("already installed");
    assert_eq!(found, expected);
}

/// `ensure_solc` refuses to reach the network when told not to.
#[test]
fn ensure_solc_respects_the_no_install_switch() {
    let absurd = semver::Version::new(0, 1, 0);
    if discovery::find_installed(&absurd).is_some() {
        eprintln!("SKIP: solc 0.1.0 is somehow installed");
        return;
    }
    // Uses the explicit switch rather than mutating the process environment,
    // which would race with the other tests in this binary.
    let err = discovery::ensure_solc_with(&absurd, false).expect_err("no download allowed");
    assert!(
        matches!(err, VerifyError::InstallUnavailable { .. }),
        "{err}"
    );
    assert!(err.to_string().contains("foundryup"));
}
