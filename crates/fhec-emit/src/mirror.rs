//! The generated-tree writer: mirrors the source tree 1:1 into the output
//! root, renaming `.fsol` → `.sol` (spec §2.1, PLAN "generated tree").
//! Pass-through content is written byte-exactly; the writer refuses paths
//! that would escape the output root.

use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::error::EmitError;

/// Maps a source-relative path to its output-relative path (`.fsol` → `.sol`).
pub fn output_rel_path(src_rel: &Path) -> PathBuf {
    if src_rel.extension().is_some_and(|e| e == "fsol") {
        src_rel.with_extension("sol")
    } else {
        src_rel.to_path_buf()
    }
}

/// Validates that `rel` stays inside the root: relative, no `..`, no roots.
fn ensure_inside(rel: &Path) -> Result<(), EmitError> {
    let ok = !rel.as_os_str().is_empty()
        && rel
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
    if ok {
        Ok(())
    } else {
        Err(EmitError::PathEscape {
            path: rel.to_path_buf(),
        })
    }
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> EmitError + '_ {
    move |source| EmitError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Writes output files into the mirror tree under `out_root`.
///
/// `files` pairs each *source-relative* path with the complete output
/// content. Content is written byte-exactly (a pass-through file stays
/// byte-identical — the no-op guarantee, spec §1.4). Returns the
/// output-relative paths written, in input order.
pub fn write_mirror(
    out_root: &Path,
    files: &[(PathBuf, String)],
) -> Result<Vec<PathBuf>, EmitError> {
    let mut written = Vec::with_capacity(files.len());
    for (src_rel, content) in files {
        ensure_inside(src_rel)?;
        let out_rel = output_rel_path(src_rel);
        let abs = out_root.join(&out_rel);
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent).map_err(io_err(parent))?;
        }
        fs::write(&abs, content.as_bytes()).map_err(io_err(&abs))?;
        written.push(out_rel);
    }
    Ok(written)
}

/// Removes files under `out_root` that no longer correspond to an input.
///
/// `keep` holds *output-relative* paths (as returned by [`write_mirror`]).
/// The manifest directory `.fhec/` is never touched; symlinks are never
/// followed (a symlink itself may be removed as an orphan, its target is
/// never traversed). Empty directories left behind are removed. Returns the
/// removed output-relative file paths, sorted.
pub fn clean_orphans(out_root: &Path, keep: &HashSet<PathBuf>) -> Result<Vec<PathBuf>, EmitError> {
    let mut removed = Vec::new();
    if out_root.symlink_metadata().is_err() {
        return Ok(removed); // nothing generated yet
    }
    clean_dir(out_root, Path::new(""), keep, &mut removed)?;
    removed.sort();
    Ok(removed)
}

/// Recursively cleans `abs_dir` (= out_root/rel_dir). Returns whether the
/// directory is empty afterwards (so the parent can remove it).
fn clean_dir(
    abs_dir: &Path,
    rel_dir: &Path,
    keep: &HashSet<PathBuf>,
    removed: &mut Vec<PathBuf>,
) -> Result<bool, EmitError> {
    let mut empty = true;
    for entry in fs::read_dir(abs_dir).map_err(io_err(abs_dir))? {
        let entry = entry.map_err(io_err(abs_dir))?;
        let name = entry.file_name();
        let rel = rel_dir.join(&name);
        if rel_dir.as_os_str().is_empty() && name == ".fhec" {
            empty = false; // the manifest directory is ours, never cleaned
            continue;
        }
        let abs = entry.path();
        let meta = abs.symlink_metadata().map_err(io_err(&abs))?;
        if meta.is_dir() {
            let child_empty = clean_dir(&abs, &rel, keep, removed)?;
            if child_empty {
                fs::remove_dir(&abs).map_err(io_err(&abs))?;
            } else {
                empty = false;
            }
        } else if keep.contains(&rel) {
            empty = false;
        } else {
            // Plain file or symlink (not followed) with no matching input.
            fs::remove_file(&abs).map_err(io_err(&abs))?;
            removed.push(rel);
        }
    }
    Ok(empty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renames_fsol_and_passes_sol_through() {
        let dir = tempfile::tempdir().unwrap();
        let files = vec![
            (PathBuf::from("a/Counter.fsol"), "contract A {}".to_string()),
            (
                PathBuf::from("b/Plain.sol"),
                "contract B {}\r\n".to_string(),
            ),
        ];
        let written = write_mirror(dir.path(), &files).unwrap();
        assert_eq!(
            written,
            vec![PathBuf::from("a/Counter.sol"), PathBuf::from("b/Plain.sol")]
        );
        // Byte-identical pass-through (CRLF preserved).
        let bytes = fs::read(dir.path().join("b/Plain.sol")).unwrap();
        assert_eq!(bytes, b"contract B {}\r\n");
        assert!(dir.path().join("a/Counter.sol").exists());
        assert!(!dir.path().join("a/Counter.fsol").exists());
    }

    #[test]
    fn refuses_path_escape() {
        let dir = tempfile::tempdir().unwrap();
        for bad in ["../evil.sol", "/abs/evil.sol", "a/../../evil.sol"] {
            let files = vec![(PathBuf::from(bad), String::new())];
            let err = write_mirror(dir.path(), &files).unwrap_err();
            assert!(matches!(err, EmitError::PathEscape { .. }), "{bad}");
            assert_eq!(err.code(), "FHE9001");
        }
    }

    #[test]
    fn cleans_orphans_but_keeps_manifest_dir() {
        let dir = tempfile::tempdir().unwrap();
        let files = vec![
            (PathBuf::from("keep/K.fsol"), "k".to_string()),
            (PathBuf::from("gone/G.fsol"), "g".to_string()),
        ];
        let written = write_mirror(dir.path(), &files).unwrap();
        fs::create_dir_all(dir.path().join(".fhec")).unwrap();
        fs::write(dir.path().join(".fhec/manifest.json"), "{}").unwrap();

        // Second run no longer produces gone/G.sol.
        let keep: HashSet<PathBuf> = written.into_iter().take(1).collect();
        let removed = clean_orphans(dir.path(), &keep).unwrap();
        assert_eq!(removed, vec![PathBuf::from("gone/G.sol")]);
        assert!(!dir.path().join("gone").exists(), "empty dir pruned");
        assert!(dir.path().join("keep/K.sol").exists());
        assert!(dir.path().join(".fhec/manifest.json").exists());
    }

    #[test]
    fn clean_on_missing_root_is_noop() {
        let removed = clean_orphans(Path::new("/nonexistent/fhec-test-xyz"), &HashSet::new());
        assert_eq!(removed.unwrap(), Vec::<PathBuf>::new());
    }
}
