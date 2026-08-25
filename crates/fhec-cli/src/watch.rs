//! `--watch` loop for `build` and `check`.
//!
//! The one-shot commands stay one-shot. This module runs them immediately,
//! then rebuilds when `fhec.toml` or a dialect source under `src` changes.

use crate::commands::{load_project, GlobalArgs};
use crate::config::LoadedConfig;
use notify_debouncer_mini::{new_debouncer, notify::RecursiveMode, DebounceEventResult};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

/// Debounce window for coalescing editor save storms.
const DEBOUNCE: Duration = Duration::from_millis(250);

/// Run `run` once, then again whenever a watched dialect source or `fhec.toml`
/// changes. Returns the last command exit code on Ctrl-C or watcher shutdown.
pub fn cmd_watch(g: &GlobalArgs, run: fn(&GlobalArgs) -> i32) -> i32 {
    let loaded = match load_project(g) {
        Ok(l) => l,
        Err(_) => return run(g),
    };
    if let Err(code) = refuse_unsafe_watch(&loaded) {
        return code;
    }

    let last = run(g);
    watch_loop(g, &loaded, run, last)
}

fn refuse_unsafe_watch(loaded: &LoadedConfig) -> Result<(), i32> {
    let Ok(root) = loaded.root.canonicalize() else {
        eprintln!("fhec: --watch cannot resolve project root");
        return Err(2);
    };
    let src = resolve_for_compare(&loaded.config.src_dir(&loaded.root));
    let out = resolve_for_compare(&loaded.config.out_dir(&loaded.root));
    if out == src {
        eprintln!(
            "fhec: --watch refusing — out dir equals src dir ({})",
            out.display()
        );
        return Err(2);
    }
    if !out.starts_with(&root) || out == root {
        eprintln!(
            "fhec: --watch refusing — out dir {} is not inside the project root {}",
            out.display(),
            root.display()
        );
        return Err(2);
    }
    Ok(())
}

fn resolve_for_compare(path: &Path) -> PathBuf {
    path.canonicalize()
        .unwrap_or_else(|_| std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()))
}

fn watch_loop(
    g: &GlobalArgs,
    loaded: &LoadedConfig,
    run: fn(&GlobalArgs) -> i32,
    mut last: i32,
) -> i32 {
    let src = resolve_for_compare(&loaded.config.src_dir(&loaded.root));
    let out = resolve_for_compare(&loaded.config.out_dir(&loaded.root));
    let config_path = resolve_for_compare(&loaded.path);

    let (tx, rx) = mpsc::channel();
    let mut debouncer = match new_debouncer(DEBOUNCE, move |res: DebounceEventResult| {
        let _ = tx.send(res);
    }) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("fhec: --watch cannot start file watcher: {e}");
            return 2;
        }
    };

    // Never watch `out`. Recursive `src` may still deliver events from a nested
    // out dir; `should_rebuild` drops those.
    if src.exists() {
        if let Err(e) = debouncer.watcher().watch(&src, RecursiveMode::Recursive) {
            eprintln!("fhec: --watch cannot watch {}: {e}", src.display());
            return 2;
        }
    }
    if let Err(e) = debouncer
        .watcher()
        .watch(&config_path, RecursiveMode::NonRecursive)
    {
        eprintln!("fhec: --watch cannot watch {}: {e}", config_path.display());
        return 2;
    }

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop);
        if let Err(e) = ctrlc::set_handler(move || {
            stop.store(true, Ordering::SeqCst);
        }) {
            // Still watch; a later SIGINT will use the default terminate.
            eprintln!("fhec: --watch cannot install Ctrl-C handler: {e}");
        }
    }

    loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(Ok(events)) => {
                let rebuild = events
                    .iter()
                    .any(|event| should_rebuild(&event.path, &src, &out, &config_path));
                if rebuild {
                    eprintln!("fhec: rebuilding (source changed)");
                    last = run(g);
                }
            }
            Ok(Err(_)) => {
                // Transient watcher errors: keep the loop alive.
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if stop.load(Ordering::SeqCst) {
                    return last;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return last,
        }
    }
}

/// Whether a filesystem event should trigger another `build`/`check`.
///
/// Ignores the out directory, editor junk, and anything that is not `fhec.toml`
/// or a `.fsol`/`.sol` file.
pub(crate) fn should_rebuild(path: &Path, src: &Path, out: &Path, config_path: &Path) -> bool {
    if is_under(path, out) {
        return false;
    }
    if is_editor_junk(path) {
        return false;
    }
    if path == config_path || file_name_eq(path, "fhec.toml") {
        return true;
    }
    if !is_under(path, src) {
        return false;
    }
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("fsol") | Some("sol")
    )
}

fn is_under(path: &Path, dir: &Path) -> bool {
    path == dir || path.starts_with(dir)
}

fn is_editor_junk(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.starts_with('.') || name.ends_with('~') || name.ends_with(".swp") || name.ends_with(".swo")
}

fn file_name_eq(path: &Path, expected: &str) -> bool {
    path.file_name().and_then(|n| n.to_str()) == Some(expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn p(s: &str) -> &Path {
        Path::new(s)
    }

    fn check(path: &str) -> bool {
        should_rebuild(
            p(path),
            p("/proj/contracts"),
            p("/proj/generated"),
            p("/proj/fhec.toml"),
        )
    }

    #[test]
    fn rebuilds_on_dialect_sources() {
        assert!(check("/proj/contracts/A.fsol"));
        assert!(check("/proj/contracts/nested/B.sol"));
    }

    #[test]
    fn rebuilds_on_config() {
        assert!(check("/proj/fhec.toml"));
    }

    #[test]
    fn ignores_out_dir_even_for_sol() {
        assert!(!check("/proj/generated/A.sol"));
        assert!(!check("/proj/generated/nested/B.fsol"));
        assert!(!check("/proj/generated"));
    }

    #[test]
    fn ignores_out_nested_inside_src() {
        assert!(!should_rebuild(
            p("/proj/contracts/generated/A.sol"),
            p("/proj/contracts"),
            p("/proj/contracts/generated"),
            p("/proj/fhec.toml"),
        ));
        assert!(should_rebuild(
            p("/proj/contracts/A.fsol"),
            p("/proj/contracts"),
            p("/proj/contracts/generated"),
            p("/proj/fhec.toml"),
        ));
    }

    #[test]
    fn ignores_editor_junk() {
        assert!(!check("/proj/contracts/A.fsol~"));
        assert!(!check("/proj/contracts/.A.fsol"));
        assert!(!check("/proj/contracts/A.fsol.swp"));
        assert!(!check("/proj/contracts/A.fsol.swo"));
        assert!(!check("/proj/.fhec.toml"));
    }

    #[test]
    fn ignores_unrelated_paths() {
        assert!(!check("/proj/contracts/README.md"));
        assert!(!check("/proj/contracts/subdir"));
        assert!(!check("/proj/README.md"));
    }
}
