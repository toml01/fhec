//! Stage 1 (Load): file discovery and compilation-unit assembly.

use crate::config::{Config, CODE_CONFIG_INVALID};
use crate::diag::{Diagnostic, Severity, Span};
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::path::{Path, PathBuf};

/// Which grammar front-door a file goes through (spec §2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    /// `.fsol` dialect source; lowered by the pipeline.
    Fsol,
    /// Plain `.sol`; passes through byte-identical except import rewriting
    /// (spec §2.6).
    Sol,
}

/// One discovered source file.
#[derive(Clone, Debug)]
pub struct SourceFile {
    /// Path relative to the configured src dir, `/`-separated.
    pub rel_path: String,
    pub abs_path: PathBuf,
    pub content: String,
    pub dialect: Dialect,
}

/// The compilation unit stage 2+ operates on.
#[derive(Clone, Debug, Default)]
pub struct LoadedUnit {
    pub files: Vec<SourceFile>,
}

fn glob_set(patterns: &[String], what: &str) -> Result<GlobSet, Box<Diagnostic>> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        let glob = Glob::new(p).map_err(|e| {
            Box::new(Diagnostic::new(
                CODE_CONFIG_INVALID,
                Severity::Error,
                Span::file_level("fhec.toml"),
                format!("invalid {what} glob {p:?}: {e}"),
            ))
        })?;
        b.add(glob);
    }
    b.build().map_err(|e| {
        Box::new(Diagnostic::new(
            CODE_CONFIG_INVALID,
            Severity::Error,
            Span::file_level("fhec.toml"),
            format!("cannot build {what} glob set: {e}"),
        ))
    })
}

/// Walks the src dir and assembles the [`LoadedUnit`].
///
/// Rules: only `.fsol`/`.sol` files; include globs then exclude globs (both
/// relative to src); `node_modules` and the configured out dir are always
/// skipped; result is sorted by relative path; contents must be UTF-8 (else an
/// FHE1002-family diagnostic is pushed and the file is dropped).
pub fn discover(
    config: &Config,
    root: &Path,
    diags: &mut Vec<Diagnostic>,
) -> Result<LoadedUnit, Box<Diagnostic>> {
    let src = config.src_dir(root);
    if !src.is_dir() {
        return Err(Box::new(Diagnostic::new(
            CODE_CONFIG_INVALID,
            Severity::Error,
            Span::file_level("fhec.toml"),
            format!(
                "src directory does not exist: {} (project.src = {:?})",
                src.display(),
                config.project.src
            ),
        )));
    }
    let include = glob_set(&config.project.include, "include")?;
    let exclude = glob_set(&config.project.exclude, "exclude")?;
    let out_canon = config.out_dir(root).canonicalize().ok();

    let mut paths = Vec::new();
    walk(&src, out_canon.as_deref(), &mut paths);
    paths.sort();

    let mut files = Vec::new();
    for abs in paths {
        let rel = abs
            .strip_prefix(&src)
            .expect("walk yields paths under src")
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        let dialect = match abs.extension().and_then(|e| e.to_str()) {
            Some("fsol") => Dialect::Fsol,
            Some("sol") => Dialect::Sol,
            _ => continue,
        };
        if !include.is_match(&rel) || exclude.is_match(&rel) {
            continue;
        }
        let bytes = match std::fs::read(&abs) {
            Ok(b) => b,
            Err(e) => {
                diags.push(Diagnostic::new(
                    "FHE1002",
                    Severity::Error,
                    Span::file_level(&rel),
                    format!("cannot read file: {e}"),
                ));
                continue;
            }
        };
        let content = match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                diags.push(Diagnostic::new(
                    "FHE1002",
                    Severity::Error,
                    Span::file_level(&rel),
                    "file is not valid UTF-8".to_string(),
                ));
                continue;
            }
        };
        files.push(SourceFile {
            rel_path: rel,
            abs_path: abs,
            content,
            dialect,
        });
    }
    Ok(LoadedUnit { files })
}

fn walk(dir: &Path, out_canon: Option<&Path>, acc: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().map(|e| e.path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "node_modules") {
                continue;
            }
            if let (Some(out), Ok(canon)) = (out_canon, path.canonicalize()) {
                if canon == out {
                    continue;
                }
            }
            walk(&path, out_canon, acc);
        } else if path.is_file() {
            acc.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, content: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    #[test]
    fn discovery_orders_filters_and_skips() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "contracts/b/Two.fsol", "contract Two {}");
        write(root, "contracts/a/One.sol", "contract One {}");
        write(root, "contracts/readme.md", "not a contract");
        write(root, "contracts/node_modules/dep/Dep.sol", "contract D {}");
        write(root, "contracts/skipme/S.fsol", "contract S {}");
        // The out dir nested inside src must be skipped.
        write(root, "contracts/generated/Old.sol", "contract Old {}");

        let mut config = Config::default();
        config.project.out = "contracts/generated".to_string();
        config.project.exclude = vec!["skipme/**".to_string()];

        let mut diags = Vec::new();
        let unit = discover(&config, root, &mut diags).unwrap();
        assert!(diags.is_empty());
        let rels: Vec<_> = unit.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert_eq!(rels, vec!["a/One.sol", "b/Two.fsol"]);
        assert_eq!(unit.files[0].dialect, Dialect::Sol);
        assert_eq!(unit.files[1].dialect, Dialect::Fsol);
    }

    #[test]
    fn non_utf8_is_diagnosed_not_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("contracts")).unwrap();
        std::fs::write(root.join("contracts/Bad.sol"), [0xff, 0xfe, 0x00]).unwrap();
        write(root, "contracts/Good.sol", "contract G {}");

        let config = Config::default();
        let mut diags = Vec::new();
        let unit = discover(&config, root, &mut diags).unwrap();
        assert_eq!(unit.files.len(), 1);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "FHE1002");
        assert!(diags[0].message.contains("UTF-8"));
    }

    #[test]
    fn missing_src_dir_is_config_invalid() {
        let tmp = tempfile::tempdir().unwrap();
        let err = discover(&Config::default(), tmp.path(), &mut Vec::new()).unwrap_err();
        assert_eq!(err.code, CODE_CONFIG_INVALID);
    }
}
