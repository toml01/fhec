//! The §1.4 no-op guarantee at check level: parse + bind + check over the
//! real CoFHE corpus must produce ZERO diagnostics and ZERO rewrite sites
//! (pure plain-Solidity/CoFHE code is never touched). ACL *facts* are
//! allowed — the ACL pass's §8.6 dedupe makes them no-ops on
//! already-annotated code.
//!
//! Corpus location: `FHEC_CORPUS_DIRS` (colon-separated directories), falling
//! back to the sibling checkouts. SKIPS (does not fail) when absent.

use fhec_check::check;
use fhec_targets::CofheProfile;
use solar_parse::{
    ast,
    interface::{source_map::FileName, ColorChoice, Session},
    Parser,
};
use std::path::{Path, PathBuf};

const DEFAULT_DIRS: &[&str] = &[
    "/Users/toml/dev/cofhe-contracts/contracts",
    "/Users/toml/dev/cofhesdk/packages/mock-contracts/contracts",
    "/Users/toml/dev/cofhesdk/packages/site/snippets",
];

fn corpus_dirs() -> Vec<PathBuf> {
    match std::env::var("FHEC_CORPUS_DIRS") {
        Ok(v) => v.split(':').map(PathBuf::from).collect(),
        Err(_) => DEFAULT_DIRS.iter().map(PathBuf::from).collect(),
    }
}

fn collect_sol_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || name == "node_modules" || name == "lib" {
            continue;
        }
        if path.is_dir() {
            collect_sol_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "sol") {
            out.push(path);
        }
    }
    out.sort();
}

#[test]
fn corpus_is_a_no_op_at_check_level() {
    let dirs: Vec<PathBuf> = corpus_dirs().into_iter().filter(|d| d.is_dir()).collect();
    if dirs.is_empty() {
        eprintln!("corpus_noop: SKIP — no corpus directories found (set FHEC_CORPUS_DIRS)");
        return;
    }

    for dir in dirs {
        let mut paths = Vec::new();
        collect_sol_files(&dir, &mut paths);
        if paths.is_empty() {
            eprintln!("corpus_noop: SKIP {} (no .sol files)", dir.display());
            continue;
        }

        let sess = Session::builder()
            .with_buffer_emitter(ColorChoice::Never)
            .build();
        sess.enter(|| {
            let arena = ast::Arena::new();
            let mut files = Vec::new();
            for path in &paths {
                let src = std::fs::read_to_string(path).expect("corpus file must read");
                let mut parser = Parser::from_source_code(
                    &sess,
                    &arena,
                    FileName::Custom(path.to_string_lossy().into_owned()),
                    src,
                )
                .expect("corpus source registration");
                let unit = match parser.parse_file() {
                    Ok(u) => u,
                    Err(e) => {
                        e.emit();
                        panic!("corpus file {} must parse", path.display());
                    }
                };
                let unit: &ast::SourceUnit<'_> = arena.alloc(unit);
                files.push(fhec_bind::SourceFile {
                    name: path.to_string_lossy().into_owned(),
                    ast: unit,
                });
            }
            let bound = fhec_bind::bind(
                files
                    .iter()
                    .map(|f| fhec_bind::SourceFile {
                        name: f.name.clone(),
                        ast: f.ast,
                    })
                    .collect(),
            );
            let profile = CofheProfile::v0_2();
            let checked = check(&files, &bound, &profile, sess.source_map());

            for d in &checked.diagnostics {
                let loc = sess
                    .source_map()
                    .span_to_diagnostic_string(d.span);
                eprintln!("corpus_noop: {} {} at {} — {}", d.code, dir.display(), loc, d.message);
            }
            assert!(
                checked.diagnostics.is_empty(),
                "corpus unit {} must check clean ({} diagnostics)",
                dir.display(),
                checked.diagnostics.len()
            );
            assert_eq!(
                checked.rewrite_site_count(),
                0,
                "corpus unit {} must have zero rewrite sites",
                dir.display()
            );
            eprintln!(
                "corpus_noop: OK {} — {} files, 0 sites, 0 diagnostics, facts: {} writes / {} ext-args / {} returns",
                dir.display(),
                paths.len(),
                checked.acl.storage_writes.len(),
                checked.acl.external_args.len(),
                checked.acl.returns.len()
            );
        });
    }
}
