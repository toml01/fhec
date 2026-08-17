//! Finding a `solc` binary and checking its version.
//!
//! # Search order
//!
//! 1. an explicit path passed by the caller ([`DiscoveryOptions::explicit_path`]);
//! 2. the `FHEC_SOLC` environment variable;
//! 3. a `solc` executable on `PATH`;
//! 4. a version directory under an svm-rs / Foundry home, laid out as
//!    `<svm-home>/<version>/solc-<version>`.
//!
//! Steps 1 and 2 are *assertions*: if the named binary exists but reports the
//! wrong version, discovery fails with [`VerifyError::VersionMismatch`] instead
//! of quietly falling through to a different compiler. Steps 3 and 4 are
//! *searches*: a mismatch there is recorded and the next candidate is tried.
//!
//! # svm homes
//!
//! svm-rs (which Foundry embeds) keeps compilers in a per-platform data
//! directory. All of the following are checked, in order:
//!
//! * `$FHEC_SVM_HOME`
//! * `$SVM_HOME`
//! * `~/.svm` — the documented svm-rs layout
//! * `~/Library/Application Support/svm` — where svm-rs actually lands on macOS
//! * `$XDG_DATA_HOME/svm` and `~/.local/share/svm` — the Linux data-dir variants
//!
//! Discovery never touches the network. [`ensure_solc`] does, and only when it
//! is called explicitly.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use semver::{Version, VersionReq};

use crate::error::{SolcOrigin, SolcSearchStep, VerifyError};

/// The environment variable that pins an exact `solc` binary.
pub const SOLC_ENV_VAR: &str = "FHEC_SOLC";

/// The environment variable that overrides the svm home.
pub const SVM_HOME_ENV_VAR: &str = "FHEC_SVM_HOME";

/// The environment variable that disables [`ensure_solc`]'s network access.
pub const NO_INSTALL_ENV_VAR: &str = "FHEC_NO_SOLC_INSTALL";

/// The version requirement fhec targets by default.
///
/// Matches the tightest pragma in the pinned `CoFHE` profile library
/// (`ICofhe.sol` requires `>=0.8.25 <0.9.0`).
pub const DEFAULT_SOLC_REQUIREMENT: &str = ">=0.8.25, <0.9.0";

/// Parses [`DEFAULT_SOLC_REQUIREMENT`], falling back to `*` if that constant
/// were ever made invalid (a unit test guards against it).
#[must_use]
pub fn default_requirement() -> VersionReq {
    VersionReq::parse(DEFAULT_SOLC_REQUIREMENT).unwrap_or(VersionReq::STAR)
}

/// Parses a caller-supplied requirement into a [`VersionReq`].
///
/// # Errors
///
/// [`VerifyError::InvalidRequirement`] if `text` is not valid semver.
pub fn parse_requirement(text: &str) -> Result<VersionReq, VerifyError> {
    VersionReq::parse(text).map_err(|source| VerifyError::InvalidRequirement {
        text: text.to_owned(),
        source,
    })
}

/// A `solc` executable that has been located and version-checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolcBinary {
    path: PathBuf,
    version: Version,
    origin: SolcOrigin,
}

impl SolcBinary {
    /// Where the executable lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The version it reported, including any build metadata.
    #[must_use]
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// Which discovery step produced it.
    #[must_use]
    pub fn origin(&self) -> SolcOrigin {
        self.origin
    }

    /// Runs `solc --version` on `path` and records what it reported.
    ///
    /// # Errors
    ///
    /// [`VerifyError::Spawn`] if the process cannot start, or
    /// [`VerifyError::VersionUnparsable`] if its output has no readable version.
    pub fn probe(path: impl Into<PathBuf>) -> Result<Self, VerifyError> {
        Self::probe_with_origin(path.into(), SolcOrigin::Explicit)
    }

    /// Like [`SolcBinary::probe`], but also asserts the version requirement.
    ///
    /// # Errors
    ///
    /// Everything [`SolcBinary::probe`] returns, plus
    /// [`VerifyError::VersionMismatch`] when the binary is the wrong version.
    pub fn probe_checked(
        path: impl Into<PathBuf>,
        requirement: &VersionReq,
    ) -> Result<Self, VerifyError> {
        let binary = Self::probe(path)?;
        binary.require(requirement)?;
        Ok(binary)
    }

    /// Fails unless this binary satisfies `requirement`.
    ///
    /// # Errors
    ///
    /// [`VerifyError::VersionMismatch`] when it does not.
    pub fn require(&self, requirement: &VersionReq) -> Result<(), VerifyError> {
        if version_matches(&self.version, requirement) {
            return Ok(());
        }
        Err(VerifyError::VersionMismatch {
            path: self.path.clone(),
            found: Box::new(self.version.clone()),
            requirement: requirement.clone(),
        })
    }

    fn probe_with_origin(path: PathBuf, origin: SolcOrigin) -> Result<Self, VerifyError> {
        let output = Command::new(&path)
            .arg("--version")
            .output()
            .map_err(|source| VerifyError::Spawn {
                path: path.clone(),
                source,
            })?;
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        if text.trim().is_empty() {
            text = String::from_utf8_lossy(&output.stderr).into_owned();
        }
        let version =
            parse_version_output(&text).ok_or_else(|| VerifyError::VersionUnparsable {
                path: path.clone(),
                output: text,
            })?;
        Ok(Self {
            path,
            version,
            origin,
        })
    }
}

/// Whether `version` satisfies `requirement`.
///
/// solc stamps its git commit into semver build metadata
/// (`0.8.28+commit.7893614a.Darwin.appleclang`); build metadata is ignored by
/// semver comparison, so the raw version can be matched directly.
#[must_use]
pub fn version_matches(version: &Version, requirement: &VersionReq) -> bool {
    requirement.matches(version)
}

/// Extracts the version from `solc --version` output.
///
/// The output looks like:
///
/// ```text
/// solc, the solidity compiler commandline interface
/// Version: 0.8.28+commit.7893614a.Darwin.appleclang
/// ```
///
/// Returns `None` when no line carries a parsable version.
#[must_use]
pub fn parse_version_output(text: &str) -> Option<Version> {
    for line in text.lines() {
        let candidate = line
            .split_once("Version:")
            .map_or_else(|| line.trim(), |(_, rest)| rest.trim());
        let token = candidate.split_whitespace().next().unwrap_or_default();
        if let Ok(version) = Version::parse(token) {
            return Some(version);
        }
    }
    None
}

/// How to look for a compiler.
#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    /// The version requirement every candidate must satisfy.
    pub requirement: VersionReq,
    /// A binary named outright by the caller. Checked first, and a version
    /// mismatch here is fatal rather than a reason to keep looking.
    pub explicit_path: Option<PathBuf>,
    /// Whether to consult [`SOLC_ENV_VAR`].
    pub read_env: bool,
    /// Whether to search `PATH`.
    pub search_path: bool,
    /// svm homes to scan. `None` means "use [`svm_roots`]".
    pub svm_roots: Option<Vec<PathBuf>>,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            requirement: default_requirement(),
            explicit_path: None,
            read_env: true,
            search_path: true,
            svm_roots: None,
        }
    }
}

impl DiscoveryOptions {
    /// Options for a specific requirement, everything else at its default.
    #[must_use]
    pub fn new(requirement: VersionReq) -> Self {
        Self {
            requirement,
            ..Self::default()
        }
    }

    /// Sets the explicit path, builder-style.
    #[must_use]
    pub fn with_explicit_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.explicit_path = Some(path.into());
        self
    }

    /// Restricts the search to the svm homes given, builder-style.
    #[must_use]
    pub fn with_svm_roots(mut self, roots: Vec<PathBuf>) -> Self {
        self.svm_roots = Some(roots);
        self
    }
}

/// The user's home directory, if the environment names one.
#[must_use]
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// Every directory that may hold an svm-rs / Foundry compiler tree, in search
/// order. Directories that do not exist are still returned, so a failed search
/// can report what it looked at.
#[must_use]
pub fn svm_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut push = |path: PathBuf| {
        if !roots.contains(&path) {
            roots.push(path);
        }
    };

    for var in [SVM_HOME_ENV_VAR, "SVM_HOME"] {
        if let Some(value) = std::env::var_os(var) {
            if !value.is_empty() {
                push(PathBuf::from(value));
            }
        }
    }
    if let Some(home) = home_dir() {
        push(home.join(".svm"));
        push(home.join("Library").join("Application Support").join("svm"));
        push(home.join(".local").join("share").join("svm"));
    }
    if let Some(data) = std::env::var_os("XDG_DATA_HOME") {
        if !data.is_empty() {
            push(PathBuf::from(data).join("svm"));
        }
    }
    roots
}

/// Every `(version, path)` pair installed under `root`, following the
/// `<root>/<version>/solc-<version>` layout.
#[must_use]
pub fn installed_in(root: &Path) -> Vec<(Version, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(version) = Version::parse(name) else {
            continue;
        };
        let candidate = entry.path().join(format!("solc-{name}"));
        if candidate.is_file() {
            found.push((version, candidate));
        }
    }
    found.sort_by(|left, right| right.0.cmp(&left.0));
    found
}

/// Every installed compiler across all [`svm_roots`], newest first.
#[must_use]
pub fn installed_versions() -> Vec<(Version, PathBuf)> {
    let mut found: Vec<(Version, PathBuf)> = Vec::new();
    let mut seen = BTreeSet::new();
    for root in svm_roots() {
        for (version, path) in installed_in(&root) {
            if seen.insert(version.clone()) {
                found.push((version, path));
            }
        }
    }
    found.sort_by(|left, right| right.0.cmp(&left.0));
    found
}

/// Looks for an executable named `solc` on `PATH`.
#[must_use]
pub fn solc_on_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(executable_name()))
        .find(|candidate| is_executable_file(candidate))
}

/// The platform's file name for the compiler executable.
fn executable_name() -> &'static str {
    if cfg!(windows) {
        "solc.exe"
    } else {
        "solc"
    }
}

/// Whether `path` is a file the current process could execute.
fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Finds a compiler satisfying `options.requirement`.
///
/// See the [module docs](self) for the exact order. No network access.
///
/// # Errors
///
/// [`VerifyError::VersionMismatch`] when an explicitly named binary is the
/// wrong version, [`VerifyError::SolcNotFound`] when nothing suitable turned up,
/// or [`VerifyError::Spawn`] when an explicitly named binary cannot be run.
pub fn discover(options: &DiscoveryOptions) -> Result<SolcBinary, VerifyError> {
    let mut searched = Vec::new();

    if let Some(binary) = pinned_binary(options, &mut searched)? {
        return Ok(binary);
    }
    if options.search_path {
        if let Some(binary) = search_path(&options.requirement, &mut searched) {
            return Ok(binary);
        }
    }
    let roots = options.svm_roots.clone().unwrap_or_else(svm_roots);
    if let Some(binary) = search_svm_homes(&options.requirement, &roots, &mut searched) {
        return Ok(binary);
    }

    Err(VerifyError::SolcNotFound {
        requirement: options.requirement.clone(),
        searched,
    })
}

/// Steps 1 and 2: an explicitly named binary, or `FHEC_SOLC`.
///
/// A named binary is an assertion, so a wrong version propagates as an error
/// rather than letting the search continue.
fn pinned_binary(
    options: &DiscoveryOptions,
    searched: &mut Vec<SolcSearchStep>,
) -> Result<Option<SolcBinary>, VerifyError> {
    let pinned = options
        .explicit_path
        .clone()
        .map(|path| (SolcOrigin::Explicit, path))
        .or_else(|| {
            if !options.read_env {
                return None;
            }
            std::env::var_os(SOLC_ENV_VAR)
                .filter(|value| !value.is_empty())
                .map(|value| (SolcOrigin::Env, PathBuf::from(value)))
        });

    if let Some((origin, path)) = pinned {
        log::debug!(
            "solc discovery: using the binary pinned by {origin} at {}",
            path.display()
        );
        let binary = SolcBinary::probe_with_origin(path, origin)?;
        binary.require(&options.requirement)?;
        return Ok(Some(binary));
    }

    if options.explicit_path.is_none() {
        searched.push(SolcSearchStep {
            origin: SolcOrigin::Explicit,
            path: None,
            reason: "no path was supplied".to_owned(),
        });
    }
    if options.read_env {
        searched.push(SolcSearchStep {
            origin: SolcOrigin::Env,
            path: None,
            reason: format!("{SOLC_ENV_VAR} is not set"),
        });
    }
    Ok(None)
}

/// Step 3: a `solc` executable on `PATH`.
fn search_path(requirement: &VersionReq, searched: &mut Vec<SolcSearchStep>) -> Option<SolcBinary> {
    let Some(path) = solc_on_path() else {
        searched.push(SolcSearchStep {
            origin: SolcOrigin::Path,
            path: None,
            reason: "no `solc` executable on PATH".to_owned(),
        });
        return None;
    };
    match SolcBinary::probe_with_origin(path.clone(), SolcOrigin::Path) {
        Ok(binary) if version_matches(&binary.version, requirement) => {
            log::debug!(
                "solc discovery: PATH provided {} at {}",
                binary.version,
                path.display()
            );
            Some(binary)
        }
        Ok(binary) => {
            searched.push(SolcSearchStep {
                origin: SolcOrigin::Path,
                path: Some(path),
                reason: format!("is {}, which does not match", binary.version),
            });
            None
        }
        Err(err) => {
            searched.push(SolcSearchStep {
                origin: SolcOrigin::Path,
                path: Some(path),
                reason: err.to_string(),
            });
            None
        }
    }
}

/// Step 4: version directories under the svm homes, newest match first.
fn search_svm_homes(
    requirement: &VersionReq,
    roots: &[PathBuf],
    searched: &mut Vec<SolcSearchStep>,
) -> Option<SolcBinary> {
    let mut candidates: Vec<(Version, PathBuf)> = Vec::new();
    let mut seen = BTreeSet::new();
    for root in roots {
        let installed = installed_in(root);
        if installed.is_empty() {
            searched.push(SolcSearchStep {
                origin: SolcOrigin::SvmHome,
                path: Some(root.clone()),
                reason: "no <version>/solc-<version> entries here".to_owned(),
            });
            continue;
        }
        for (version, path) in installed {
            if seen.insert(version.clone()) {
                candidates.push((version, path));
            }
        }
    }
    candidates.sort_by(|left, right| right.0.cmp(&left.0));

    for (version, path) in candidates {
        if !version_matches(&version, requirement) {
            searched.push(SolcSearchStep {
                origin: SolcOrigin::SvmHome,
                path: Some(path),
                reason: format!("is {version}, which does not match"),
            });
            continue;
        }
        match SolcBinary::probe_with_origin(path.clone(), SolcOrigin::SvmHome) {
            Ok(binary) if version_matches(&binary.version, requirement) => {
                log::debug!(
                    "solc discovery: an svm home provided {} at {}",
                    binary.version,
                    path.display()
                );
                return Some(binary);
            }
            Ok(binary) => searched.push(SolcSearchStep {
                origin: SolcOrigin::SvmHome,
                path: Some(path),
                reason: format!(
                    "the directory says {version} but the binary reports {}",
                    binary.version
                ),
            }),
            Err(err) => searched.push(SolcSearchStep {
                origin: SolcOrigin::SvmHome,
                path: Some(path),
                reason: err.to_string(),
            }),
        }
    }
    None
}

/// Makes sure an exact `solc` version is on disk, downloading it if it is not.
///
/// **This may access the network.** It is never called by
/// [`crate::SolcRunner::compile`] or by [`discover`]; call it only where a
/// download is acceptable, such as a setup step or an explicit `fhec` install
/// command. Set [`NO_INSTALL_ENV_VAR`] to forbid the download entirely.
///
/// The install is best effort and tries, in order:
///
/// 1. an already-installed copy under any [`svm_roots`] entry;
/// 2. `svm install <version>`, if svm-rs is on `PATH`;
/// 3. a throwaway Foundry project pinned to `<version>`, built with
///    `forge build`, which makes Foundry fetch the compiler into its svm home.
///
/// Every step is logged at info level.
///
/// # Errors
///
/// [`VerifyError::InstallUnavailable`] when no installer exists or downloads are
/// forbidden, and [`VerifyError::InstallFailed`] when one ran without producing
/// a usable binary.
pub fn ensure_solc(version: &Version) -> Result<PathBuf, VerifyError> {
    let allow_download = std::env::var_os(NO_INSTALL_ENV_VAR).is_none();
    ensure_solc_with(version, allow_download)
}

/// [`ensure_solc`] with the download decision made by the caller instead of by
/// [`NO_INSTALL_ENV_VAR`].
///
/// With `allow_download` false this is a pure lookup and touches neither the
/// network nor any installer.
///
/// # Errors
///
/// The same set as [`ensure_solc`].
pub fn ensure_solc_with(version: &Version, allow_download: bool) -> Result<PathBuf, VerifyError> {
    if let Some(path) = find_installed(version) {
        log::info!("solc {version} is already installed at {}", path.display());
        return Ok(path);
    }
    if !allow_download {
        return Err(VerifyError::InstallUnavailable {
            version: Box::new(version.clone()),
            reason: format!(
                "solc {version} is not installed and downloading was not permitted \
                 (set by the caller, or by {NO_INSTALL_ENV_VAR})"
            ),
        });
    }

    let mut attempts = Vec::new();
    if let Some(svm) = which("svm") {
        log::info!(
            "installing solc {version} with `{} install {version}` (network access)",
            svm.display()
        );
        let details = run_installer(Command::new(&svm).arg("install").arg(version.to_string()));
        if let Some(path) = find_installed(version) {
            log::info!("svm installed solc {version} at {}", path.display());
            return Ok(path);
        }
        attempts.push(("svm".to_owned(), details));
    } else {
        log::info!("svm is not on PATH, so it cannot install solc {version}");
    }

    if let Some(forge) = which("forge") {
        log::info!(
            "installing solc {version} by building a throwaway Foundry project (network access)"
        );
        match forge_fetch(&forge, version) {
            Ok(details) => {
                if let Some(path) = find_installed(version) {
                    log::info!("forge installed solc {version} at {}", path.display());
                    return Ok(path);
                }
                attempts.push(("forge".to_owned(), details));
            }
            Err(err) => attempts.push(("forge".to_owned(), err.to_string())),
        }
    } else {
        log::info!("forge is not on PATH, so it cannot install solc {version}");
    }

    match attempts.into_iter().next() {
        Some((installer, details)) => Err(VerifyError::InstallFailed {
            version: Box::new(version.clone()),
            installer,
            details,
        }),
        None => Err(VerifyError::InstallUnavailable {
            version: Box::new(version.clone()),
            reason: "neither `svm` nor `forge` is on PATH".to_owned(),
        }),
    }
}

/// The path of an already-installed `version`, if any svm home holds it.
#[must_use]
pub fn find_installed(version: &Version) -> Option<PathBuf> {
    installed_versions()
        .into_iter()
        .find(|(installed, _)| installed == version)
        .map(|(_, path)| path)
}

/// Finds `name` on `PATH`.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable_file(candidate))
}

/// Runs an installer and renders whatever it reported.
fn run_installer(command: &mut Command) -> String {
    match command.output() {
        Ok(output) => format!(
            "exit {}: {}{}",
            output
                .status
                .code()
                .map_or_else(|| "signal".to_owned(), |code| code.to_string()),
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim(),
        ),
        Err(err) => format!("could not run the installer: {err}"),
    }
}

/// Builds a throwaway Foundry project pinned to `version`, so Foundry downloads
/// that compiler into its svm home.
fn forge_fetch(forge: &Path, version: &Version) -> Result<String, VerifyError> {
    let dir =
        std::env::temp_dir().join(format!("fhec-solc-fetch-{}-{version}", std::process::id()));
    let src = dir.join("src");
    std::fs::create_dir_all(&src).map_err(|source| VerifyError::Spawn {
        path: dir.clone(),
        source,
    })?;
    let config = format!("[profile.default]\nsrc = \"src\"\nout = \"out\"\nlibs = []\nsolc_version = \"{version}\"\n");
    let contract = format!(
        "// SPDX-License-Identifier: MIT\npragma solidity {}.{}.{};\ncontract FhecSolcProbe {{}}\n",
        version.major, version.minor, version.patch
    );
    let write = std::fs::write(dir.join("foundry.toml"), config)
        .and_then(|()| std::fs::write(src.join("FhecSolcProbe.sol"), contract));
    if let Err(source) = write {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(VerifyError::Spawn { path: dir, source });
    }

    let details = run_installer(Command::new(forge).arg("build").current_dir(&dir));
    if let Err(err) = std::fs::remove_dir_all(&dir) {
        log::debug!("could not clean up {}: {err}", dir.display());
    }
    Ok(details)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_requirement_parses() {
        let req = default_requirement();
        assert!(req.matches(&Version::parse("0.8.28").expect("version")));
        assert!(!req.matches(&Version::parse("0.8.24").expect("version")));
        assert!(!req.matches(&Version::parse("0.9.0").expect("version")));
    }

    #[test]
    fn parses_real_solc_version_banners() {
        let text = "solc, the solidity compiler commandline interface\n\
                    Version: 0.8.28+commit.7893614a.Darwin.appleclang\n";
        let version = parse_version_output(text).expect("version parsed");
        assert_eq!((version.major, version.minor, version.patch), (0, 8, 28));
        assert!(version.build.as_str().starts_with("commit."));
        assert!(default_requirement().matches(&version));
    }

    #[test]
    fn build_metadata_does_not_block_matching() {
        let version = Version::parse("0.8.28+commit.7893614a.Darwin.appleclang").expect("version");
        assert!(version_matches(&version, &default_requirement()));
    }

    #[test]
    fn prerelease_builds_do_not_satisfy_a_stable_range() {
        let version = Version::parse("0.8.31-pre.1+commit.b59566f6").expect("version");
        assert!(!version_matches(&version, &default_requirement()));
    }

    #[test]
    fn rejects_unparsable_version_output() {
        assert!(parse_version_output("").is_none());
        assert!(parse_version_output("solc, the solidity compiler").is_none());
    }

    #[test]
    fn bad_requirement_text_is_a_typed_error() {
        let err = parse_requirement("not-a-requirement").expect_err("must reject");
        assert!(matches!(err, VerifyError::InvalidRequirement { .. }));
    }

    #[test]
    fn svm_roots_include_both_layouts() {
        let roots = svm_roots();
        if home_dir().is_some() {
            assert!(roots.iter().any(|root| root.ends_with(".svm")));
            assert!(roots
                .iter()
                .any(|root| root.to_string_lossy().contains("Application Support")));
        }
    }

    #[test]
    fn an_empty_svm_root_yields_nothing() {
        assert!(installed_in(Path::new("/definitely/not/a/real/svm/home")).is_empty());
    }

    #[test]
    fn discovery_with_no_sources_reports_the_trail() {
        let options = DiscoveryOptions {
            requirement: default_requirement(),
            explicit_path: None,
            read_env: false,
            search_path: false,
            svm_roots: Some(vec![PathBuf::from("/definitely/not/a/real/svm/home")]),
        };
        let err = discover(&options).expect_err("nothing can be found");
        let VerifyError::SolcNotFound { searched, .. } = &err else {
            panic!("expected SolcNotFound, got {err}");
        };
        assert!(searched
            .iter()
            .any(|step| step.origin == SolcOrigin::SvmHome));
        assert!(err.to_string().contains("foundryup"));
    }
}
