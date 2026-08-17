//! Corpus test: every `.sol` file in the CoFHE reference checkouts must parse cleanly.
//!
//! Corpus location: the `FHEC_CORPUS_DIRS` env var (colon-separated directories),
//! falling back to the sibling checkouts used during development. When none of the
//! directories exist the test SKIPS (passes with a message) so CI without the sibling
//! repos stays green.

use std::path::{Path, PathBuf};

const DEFAULT_DIRS: &[&str] = &[
    "/Users/toml/dev/cofhe-contracts/contracts",
    "/Users/toml/dev/cofhesdk/packages/mock-contracts/contracts",
    "/Users/toml/dev/cofhesdk/packages/site/snippets",
];

fn corpus_dirs() -> Vec<PathBuf> {
    let dirs: Vec<PathBuf> = match std::env::var("FHEC_CORPUS_DIRS") {
        Ok(v) => v
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect(),
        Err(_) => DEFAULT_DIRS.iter().map(PathBuf::from).collect(),
    };
    dirs.into_iter().filter(|d| d.is_dir()).collect()
}

fn collect_sol_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Skip dependency trees; we only want the corpus sources themselves.
            if path
                .file_name()
                .is_some_and(|n| n == "node_modules" || n == "lib")
            {
                continue;
            }
            collect_sol_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "sol") {
            out.push(path);
        }
    }
}

#[test]
fn cofhe_corpus_parses_cleanly() {
    let dirs = corpus_dirs();
    if dirs.is_empty() {
        eprintln!(
            "SKIP: no corpus directories found; set FHEC_CORPUS_DIRS (colon-separated) \
             or provide the sibling checkouts"
        );
        return;
    }

    let mut files = Vec::new();
    for dir in &dirs {
        collect_sol_files(dir, &mut files);
    }
    files.sort();
    assert!(
        !files.is_empty(),
        "corpus dirs {dirs:?} exist but contain no .sol files"
    );

    let mut failures = Vec::new();
    for file in &files {
        match fhec_syntax::parse_path(file) {
            Ok(()) => eprintln!("ok    {} (0 errors)", file.display()),
            Err(diags) => {
                eprintln!(
                    "ERROR {} ({} diagnostic lines)",
                    file.display(),
                    diags.len()
                );
                failures.push((file.clone(), diags));
            }
        }
    }

    if !failures.is_empty() {
        for (file, diags) in &failures {
            eprintln!("--- {}", file.display());
            for line in diags.iter().take(20) {
                eprintln!("{line}");
            }
        }
        panic!(
            "{} of {} corpus files failed to parse",
            failures.len(),
            files.len()
        );
    }
    eprintln!("corpus: {} files parsed cleanly", files.len());
}
