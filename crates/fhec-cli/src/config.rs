//! `fhec.toml` — project configuration (stage 1, Load).
//!
//! The config is data, not code: a small serde model with strict unknown-key
//! rejection everywhere except the reserved `[strictness]` table, plus a stable
//! content hash for reproducibility stamping.
//!
//! Code note (deviation from the assigned catalog): spec §9 does not yet assign
//! codes for "config file not found" / "config file invalid". FHE1001/FHE1003
//! are already taken (pragma range / import-not-found) and §9 makes codes
//! stable, so this crate uses the next free FHE1xxx numbers as draft additions:
//! FHE1004 config-not-found, FHE1005 config-invalid. They are flagged as draft
//! in the `explain` registry and should be folded into spec §9's next revision.

use crate::diag::{Diagnostic, Severity, Span};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Draft code: no `fhec.toml` found (see module docs).
pub const CODE_CONFIG_NOT_FOUND: &str = "FHE1004";
/// Draft code: `fhec.toml` unreadable or invalid (see module docs).
pub const CODE_CONFIG_INVALID: &str = "FHE1005";

pub const CONFIG_FILE_NAME: &str = "fhec.toml";

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub project: Project,
    pub target: Target,
    pub acl: Acl,
    /// Reserved table: unknown keys inside are accepted and ignored, per the
    /// plan ("strictness levels" arrive later). Excluded from `hash()` because
    /// it cannot affect behavior yet.
    #[serde(skip_serializing)]
    pub strictness: toml::Table,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Project {
    /// Source directory scanned for `.fsol` / `.sol` files.
    pub src: String,
    /// Output mirror directory (spec §1.4, plan "generated tree").
    pub out: String,
    /// Include globs relative to `src`.
    pub include: Vec<String>,
    /// Exclude globs relative to `src`; exclusion wins over inclusion.
    pub exclude: Vec<String>,
}

impl Default for Project {
    fn default() -> Self {
        Project {
            src: "contracts".to_string(),
            out: "generated".to_string(),
            include: vec!["**/*.fsol".to_string(), "**/*.sol".to_string()],
            exclude: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Target {
    /// Target profile name (spec §1.5).
    pub profile: String,
    /// Profile version requirement.
    pub version: String,
    /// solc version requirement for the verify stage (stage 8).
    pub solc: String,
    /// EVM version passed to solc.
    pub evm_version: String,
}

impl Default for Target {
    fn default() -> Self {
        Target {
            profile: "cofhe".to_string(),
            version: "0.1.x".to_string(),
            solc: ">=0.8.25 <0.9.0".to_string(),
            evm_version: "cancun".to_string(),
        }
    }
}

/// ACL pass mode (spec §8): `insert` applies R1–R3; `suggest` downgrades them
/// to fix-it notes (FHE4010–FHE4012).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AclMode {
    #[default]
    Insert,
    Suggest,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Acl {
    pub mode: AclMode,
}

/// A loaded configuration: the parsed model plus where it came from.
#[derive(Clone, Debug)]
pub struct LoadedConfig {
    pub config: Config,
    /// Absolute path of the `fhec.toml` that was read.
    pub path: PathBuf,
    /// Project root = the directory containing `fhec.toml`. `src`/`out` are
    /// resolved against this.
    pub root: PathBuf,
    /// Raw file bytes as text (kept for diagnostic rendering).
    pub text: String,
}

impl Config {
    /// Stable content hash of the *effective* configuration: sha256 over the
    /// canonical JSON serialization (struct field order, defaults filled in).
    /// Two files that normalize to the same effective config hash identically;
    /// the reserved `[strictness]` table is excluded (accept-and-ignore).
    pub fn hash(&self) -> String {
        let canonical = serde_json::to_string(self).expect("config serializes");
        let digest = Sha256::digest(canonical.as_bytes());
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn src_dir(&self, root: &Path) -> PathBuf {
        root.join(&self.project.src)
    }

    pub fn out_dir(&self, root: &Path) -> PathBuf {
        root.join(&self.project.out)
    }
}

/// Searches for `fhec.toml` upward from `start`, returning the first hit.
pub fn find_config(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let candidate = d.join(CONFIG_FILE_NAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = d.parent();
    }
    None
}

/// Loads the configuration: from `explicit` when given (`--config`), otherwise
/// by upward search from `cwd`. Failures come back as catalog diagnostics
/// (boxed: the diagnostic is much larger than the happy path).
pub fn load_config(cwd: &Path, explicit: Option<&Path>) -> Result<LoadedConfig, Box<Diagnostic>> {
    let path = match explicit {
        Some(p) => {
            if p.is_file() {
                p.to_path_buf()
            } else {
                return Err(Box::new(Diagnostic::new(
                    CODE_CONFIG_NOT_FOUND,
                    Severity::Error,
                    Span::file_level(&p.display().to_string()),
                    format!("config file not found: {}", p.display()),
                )));
            }
        }
        None => find_config(cwd).ok_or_else(|| {
            Box::new(Diagnostic::new(
                CODE_CONFIG_NOT_FOUND,
                Severity::Error,
                Span::file_level(CONFIG_FILE_NAME),
                format!(
                    "no {CONFIG_FILE_NAME} found in {} or any parent directory (run `fhec init` to create one)",
                    cwd.display()
                ),
            ))
        })?,
    };
    let text = std::fs::read_to_string(&path).map_err(|e| {
        Box::new(Diagnostic::new(
            CODE_CONFIG_INVALID,
            Severity::Error,
            Span::file_level(&path.display().to_string()),
            format!("cannot read {}: {e}", path.display()),
        ))
    })?;
    let config: Config = toml::from_str(&text).map_err(|e| {
        let file = path.display().to_string();
        let span = match e.span() {
            Some(r) => Span::from_bytes(&file, &text, r.start, r.end),
            None => Span::file_level(&file),
        };
        Box::new(Diagnostic::new(
            CODE_CONFIG_INVALID,
            Severity::Error,
            span,
            format!("invalid {CONFIG_FILE_NAME}: {}", e.message()),
        ))
    })?;
    let root = path
        .parent()
        .expect("config file has a parent directory")
        .to_path_buf();
    Ok(LoadedConfig {
        config,
        path,
        root,
        text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_from_empty_file() {
        let c: Config = toml::from_str("").unwrap();
        assert_eq!(c, Config::default());
        assert_eq!(c.project.src, "contracts");
        assert_eq!(c.target.evm_version, "cancun");
        assert_eq!(c.acl.mode, AclMode::Insert);
    }

    #[test]
    fn unknown_keys_rejected_outside_strictness() {
        let err = toml::from_str::<Config>("[project]\nsrcc = \"x\"\n").unwrap_err();
        assert!(err.message().contains("srcc"));
        let err = toml::from_str::<Config>("[unknown_table]\nx = 1\n").unwrap_err();
        assert!(err.message().contains("unknown_table"));
    }

    #[test]
    fn strictness_accepts_anything() {
        let c: Config =
            toml::from_str("[strictness]\nfuture_knob = \"whatever\"\nlevel = 3\n").unwrap();
        assert_eq!(c.strictness.len(), 2);
    }

    #[test]
    fn hash_is_stable_and_semantic() {
        let a: Config = toml::from_str("").unwrap();
        // Explicitly writing a default value yields the same effective config,
        // hence the same hash.
        let b: Config = toml::from_str("[project]\nsrc = \"contracts\"\n").unwrap();
        let c: Config = toml::from_str("[project]\nsrc = \"other\"\n").unwrap();
        assert_eq!(a.hash(), b.hash());
        assert_ne!(a.hash(), c.hash());
        assert_eq!(a.hash().len(), 64);
        // Strictness contents do not affect the hash.
        let d: Config = toml::from_str("[strictness]\nknob = true\n").unwrap();
        assert_eq!(a.hash(), d.hash());
    }

    #[test]
    fn upward_search_finds_nearest() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join(CONFIG_FILE_NAME), "").unwrap();
        let nested = root.join("a/b/c");
        std::fs::create_dir_all(&nested).unwrap();
        let found = find_config(&nested).unwrap();
        assert_eq!(found, root.join(CONFIG_FILE_NAME));
        // A nearer config shadows the outer one.
        std::fs::write(root.join("a").join(CONFIG_FILE_NAME), "").unwrap();
        let found = find_config(&nested).unwrap();
        assert_eq!(found, root.join("a").join(CONFIG_FILE_NAME));
    }

    #[test]
    fn load_reports_toml_error_with_span() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(CONFIG_FILE_NAME), "[project\n").unwrap();
        let err = load_config(tmp.path(), None).unwrap_err();
        assert_eq!(err.code, CODE_CONFIG_INVALID);
        assert_eq!(err.severity, Severity::Error);
    }

    #[test]
    fn missing_config_is_fhe1004() {
        let tmp = tempfile::tempdir().unwrap();
        // tempdirs live under /tmp which has no fhec.toml ancestor; guard the
        // assumption anyway.
        if find_config(tmp.path()).is_some() {
            return;
        }
        let err = load_config(tmp.path(), None).unwrap_err();
        assert_eq!(err.code, CODE_CONFIG_NOT_FOUND);
    }
}
