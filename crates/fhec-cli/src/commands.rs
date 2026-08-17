//! Command implementations. Each returns the process exit code:
//! 0 = ok, 1 = error diagnostics were produced, 2 = usage/internal problem.

use crate::config::{load_config, LoadedConfig, CONFIG_FILE_NAME};
use crate::diag::{has_errors, render_human, render_json, Diagnostic};
use crate::load::discover;
use crate::pipeline::{Pipeline, StageOutcome};
use std::path::{Path, PathBuf};

/// Global CLI options shared by all commands.
#[derive(Clone, Debug, Default)]
pub struct GlobalArgs {
    pub config: Option<PathBuf>,
    pub json: bool,
    pub verbose: bool,
}

/// Renders diagnostics to the right stream: `--json` prints the spec §10.2
/// array on stdout; human format goes to stderr.
fn report(diags: &[Diagnostic], json: bool, lookup: impl Fn(&str) -> Option<String>) {
    if diags.is_empty() {
        return;
    }
    if json {
        println!("{}", render_json(diags));
    } else {
        for d in diags {
            eprint!("{}", render_human(d, lookup(&d.span.file).as_deref()));
        }
    }
}

fn load_project(g: &GlobalArgs) -> Result<LoadedConfig, Box<Diagnostic>> {
    let cwd = std::env::current_dir().expect("cwd is accessible");
    load_config(&cwd, g.config.as_deref())
}

/// Shared front half of `check` and `build`: load → discover → parse → the
/// stage seams up to `lower`. Returns the pipeline (with diagnostics) or an
/// exit code when even loading failed.
fn front_half(g: &GlobalArgs) -> Result<(Pipeline, LoadedConfig), i32> {
    let loaded = match load_project(g) {
        Ok(l) => l,
        Err(d) => {
            let text = std::fs::read_to_string(&d.span.file).ok();
            report(&[*d.clone()], g.json, |_| text.clone());
            return Err(1);
        }
    };
    let mut pre_diags = Vec::new();
    let unit = match discover(&loaded.config, &loaded.root, &mut pre_diags) {
        Ok(u) => u,
        Err(d) => {
            pre_diags.push(*d);
            report(&pre_diags, g.json, |f| {
                (f == CONFIG_FILE_NAME).then(|| loaded.text.clone())
            });
            return Err(1);
        }
    };
    let mut pipeline = Pipeline::new(loaded.config.clone(), loaded.root.clone(), unit);
    pipeline.diags = pre_diags;
    pipeline.parse();
    for outcome in [pipeline.bind(), pipeline.check()] {
        if let (StageOutcome::Skipped(what), true) = (outcome, g.verbose) {
            eprintln!("fhec: skipped {what} (not wired yet)");
        }
    }
    Ok((pipeline, loaded))
}

fn finish(pipeline: &Pipeline, loaded: &LoadedConfig, g: &GlobalArgs) -> i32 {
    report(&pipeline.diags, g.json, |f| {
        if f == CONFIG_FILE_NAME || Path::new(f) == loaded.path {
            Some(loaded.text.clone())
        } else {
            pipeline.content_of(f).map(str::to_string)
        }
    });
    if has_errors(&pipeline.diags) {
        1
    } else {
        0
    }
}

pub fn cmd_check(g: &GlobalArgs) -> i32 {
    match front_half(g) {
        Ok((pipeline, loaded)) => {
            let code = finish(&pipeline, &loaded, g);
            if code == 0 && g.verbose {
                eprintln!(
                    "fhec: {} file(s) parsed clean (config hash {})",
                    pipeline.unit.files.len(),
                    &loaded.config.hash()[..12]
                );
            }
            code
        }
        Err(code) => code,
    }
}

pub fn cmd_build(g: &GlobalArgs) -> i32 {
    match front_half(g) {
        Ok((mut pipeline, loaded)) => {
            for outcome in [pipeline.lower(), pipeline.emit(), pipeline.verify()] {
                if let (StageOutcome::Skipped(what), true) = (outcome, g.verbose) {
                    eprintln!("fhec: skipped {what}");
                }
            }
            finish(&pipeline, &loaded, g)
        }
        Err(code) => code,
    }
}

const CONFIG_TEMPLATE: &str = r#"# fhec project configuration.
# Every key shown commented-out is at its default value.

[project]
# Directory scanned for .fsol / .sol sources.
src = "contracts"
# Output mirror for transpiled Solidity (committed to git by convention).
out = "generated"
# Include/exclude globs, relative to `src`. Exclusion wins.
# include = ["**/*.fsol", "**/*.sol"]
# exclude = []

[target]
# Target library profile and pinned profile version.
profile = "cofhe"
version = "0.1.x"
# solc requirement used by the verify stage.
# solc = ">=0.8.25 <0.9.0"
# evm_version = "cancun"

[acl]
# "insert" applies ACL rules R1-R3 automatically; "suggest" only reports fix-its.
mode = "insert"
"#;

const SAMPLE_CONTRACT: &str = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

/// Sample fhec dialect contract.
///
/// `fhec build` lowers the `in` parameter sugar, the `+` operator, the
/// encrypted comparison, and the encrypted `if` into CoFHE library calls,
/// and inserts the required ACL grants after the storage write.
contract Counter {
    euint32 public count;
    euint32 private max;

    constructor(uint32 initial, uint32 maximum) {
        count = FHE.asEuint32(initial);
        max = FHE.asEuint32(maximum);
        FHE.allowThis(count);
        FHE.allowSender(count);
    }

    function increment(in euint32 amount) external {
        euint32 next = count + amount;
        if (next <= max) {
            count = next;
        }
    }
}
"#;

pub fn cmd_init() -> i32 {
    let cwd = std::env::current_dir().expect("cwd is accessible");
    let config_path = cwd.join(CONFIG_FILE_NAME);
    let contracts = cwd.join("contracts");
    let sample = contracts.join("Counter.fsol");
    for existing in [&config_path, &sample] {
        if existing.exists() {
            eprintln!(
                "fhec init: refusing to overwrite existing {}",
                existing.display()
            );
            return 2;
        }
    }
    if let Err(e) = std::fs::create_dir_all(&contracts) {
        eprintln!("fhec init: cannot create {}: {e}", contracts.display());
        return 2;
    }
    if let Err(e) = std::fs::write(&config_path, CONFIG_TEMPLATE) {
        eprintln!("fhec init: cannot write {}: {e}", config_path.display());
        return 2;
    }
    if let Err(e) = std::fs::write(&sample, SAMPLE_CONTRACT) {
        eprintln!("fhec init: cannot write {}: {e}", sample.display());
        return 2;
    }
    println!("created {CONFIG_FILE_NAME}");
    println!("created contracts/Counter.fsol");
    println!("next: run `fhec check`");
    0
}

pub fn cmd_explain(code: &str) -> i32 {
    match crate::explain::lookup(code) {
        Some(entry) => {
            print!("{}", crate::explain::render(entry));
            0
        }
        None => {
            eprintln!("fhec explain: unknown diagnostic code {code:?} (expected e.g. FHE2007)");
            2
        }
    }
}

pub fn cmd_clean(g: &GlobalArgs) -> i32 {
    let loaded = match load_project(g) {
        Ok(l) => l,
        Err(d) => {
            report(&[*d], g.json, |_| None);
            return 1;
        }
    };
    let out = loaded.config.out_dir(&loaded.root);
    if !out.exists() {
        if g.verbose {
            eprintln!("fhec clean: nothing to clean ({} absent)", out.display());
        }
        return 0;
    }
    // Refuse dangerous configurations: out == src, or out escaping the project.
    let src = loaded.config.src_dir(&loaded.root);
    let (Ok(out_c), Ok(root_c)) = (out.canonicalize(), loaded.root.canonicalize()) else {
        eprintln!("fhec clean: cannot resolve paths");
        return 2;
    };
    if let Ok(src_c) = src.canonicalize() {
        if out_c == src_c {
            eprintln!(
                "fhec clean: refusing — out dir equals src dir ({})",
                out_c.display()
            );
            return 2;
        }
    }
    if !out_c.starts_with(&root_c) || out_c == root_c {
        eprintln!(
            "fhec clean: refusing — out dir {} is not inside the project root {}",
            out_c.display(),
            root_c.display()
        );
        return 2;
    }
    match std::fs::remove_dir_all(&out_c) {
        Ok(()) => {
            println!("removed {}", out.display());
            0
        }
        Err(e) => {
            eprintln!("fhec clean: cannot remove {}: {e}", out_c.display());
            2
        }
    }
}
