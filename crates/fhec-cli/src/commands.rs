//! Command implementations. Each returns the process exit code:
//! 0 = ok, 1 = error diagnostics were produced, 2 = usage/internal problem.

use crate::config::{load_config, AclMode as ConfigAclMode, LoadedConfig, CONFIG_FILE_NAME};
use crate::diag::{has_errors, render_human, render_json, Diagnostic, Severity, Span};
use crate::load::{discover, LoadedUnit};
use crate::stages::{self, FileOutput, StageOptions};
use fhec_emit::{Manifest, ManifestFile};
use fhec_lower::AclMode;
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Global CLI options shared by all commands.
#[derive(Clone, Debug, Default)]
pub struct GlobalArgs {
    pub config: Option<PathBuf>,
    pub json: bool,
    pub verbose: bool,
    /// CI mode: write nothing, fail when regeneration differs (spec §1.4).
    pub frozen: bool,
    /// Apply safe fix-its to the original sources, then re-check.
    pub fix: bool,
    /// ACL mode override (`--acl=insert|suggest`), else the config decides.
    pub acl: Option<ConfigAclMode>,
    /// Skip the stage-8 solc gate.
    pub no_verify: bool,
    /// Hidden: re-transpile the generated output and assert byte identity.
    pub self_check: bool,
    /// Rebuild or recheck when dialect sources or `fhec.toml` change.
    pub watch: bool,
}

impl GlobalArgs {
    fn acl_mode(&self, loaded: &LoadedConfig) -> AclMode {
        match self.acl.unwrap_or(loaded.config.acl.mode) {
            ConfigAclMode::Insert => AclMode::Insert,
            ConfigAclMode::Suggest => AclMode::Suggest,
        }
    }
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

/// Load `fhec.toml` the same way every command does (`--config` or upward search).
pub(crate) fn load_project(g: &GlobalArgs) -> Result<LoadedConfig, Box<Diagnostic>> {
    let cwd = std::env::current_dir().expect("cwd is accessible");
    load_config(&cwd, g.config.as_deref())
}

/// Stage 1: config + discovery. Returns the loaded project or an exit code.
fn load_front(g: &GlobalArgs) -> Result<(LoadedConfig, LoadedUnit, Vec<Diagnostic>), i32> {
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
    Ok((loaded, unit, pre_diags))
}

/// Renders all collected diagnostics with source-text lookup, returning the
/// exit code.
fn finish(diags: &[Diagnostic], loaded: &LoadedConfig, unit: &LoadedUnit, g: &GlobalArgs) -> i32 {
    report(diags, g.json, |f| {
        if f == CONFIG_FILE_NAME || Path::new(f) == loaded.path {
            Some(loaded.text.clone())
        } else {
            unit.files
                .iter()
                .find(|sf| sf.rel_path == f)
                .map(|sf| sf.content.clone())
        }
    });
    if has_errors(diags) {
        1
    } else {
        0
    }
}

pub fn cmd_check(g: &GlobalArgs) -> i32 {
    let (loaded, unit, pre_diags) = match load_front(g) {
        Ok(t) => t,
        Err(code) => return code,
    };
    let acl_mode = g.acl_mode(&loaded);

    if g.fix {
        return check_with_fix(g, &loaded, unit, pre_diags);
    }

    // `check` runs the lowerer too (discarding outputs): every §7 reject
    // rule and §8 warning must fire on `check` exactly as on `build`.
    let opts = StageOptions {
        acl_mode,
        lower: true,
        discard_outputs: true,
    };
    let result = stages::run(&unit, &loaded.config, &opts);
    let mut diags = pre_diags;
    diags.extend(result.diagnostics);
    let code = finish(&diags, &loaded, &unit, g);
    if code == 0 && g.verbose {
        eprintln!(
            "fhec: {} file(s) checked clean, {} rewrite site(s) (config hash {})",
            unit.files.len(),
            result.rewrite_sites,
            &loaded.config.hash()[..12]
        );
    }
    code
}

/// `check --fix`: collect safe fix-its (running the ACL pass in suggest mode
/// so its insertions surface as fix-its), apply them to the original files,
/// then re-check and report what remains.
fn check_with_fix(
    g: &GlobalArgs,
    loaded: &LoadedConfig,
    unit: LoadedUnit,
    pre_diags: Vec<Diagnostic>,
) -> i32 {
    let opts = StageOptions {
        acl_mode: AclMode::Suggest,
        lower: true,
        discard_outputs: true,
    };
    let result = stages::run(&unit, &loaded.config, &opts);

    if result.safe_fixits.is_empty() {
        eprintln!("fhec: no safe fix-its to apply");
        let mut diags = pre_diags;
        diags.extend(result.diagnostics);
        return finish(&diags, loaded, &unit, g);
    }

    // Group fix-its per file and apply them with the splice discipline.
    let mut by_file: std::collections::BTreeMap<String, Vec<(fhec_ir::ByteRange, String)>> =
        std::collections::BTreeMap::new();
    for (file, range, replacement) in &result.safe_fixits {
        by_file
            .entry(file.clone())
            .or_default()
            .push((*range, replacement.clone()));
    }
    let mut applied_count = 0usize;
    for (file, fixes) in &by_file {
        let Some(sf) = unit.files.iter().find(|f| &f.rel_path == file) else {
            continue;
        };
        let mut plan = fhec_ir::FilePlan::new(file.clone());
        for (range, replacement) in fixes {
            plan.push(fhec_ir::Patch::replace(
                *range,
                replacement.clone(),
                fhec_ir::Provenance::new("--fix", *range),
            ));
        }
        match fhec_emit::splice(&sf.content, &plan) {
            Ok(spliced) => {
                if let Err(e) = std::fs::write(&sf.abs_path, &spliced.text) {
                    eprintln!("fhec: cannot write {}: {e}", sf.abs_path.display());
                    return 2;
                }
                applied_count += fixes.len();
                eprintln!("fhec: applied {} fix-it(s) to {file}", fixes.len());
            }
            Err(e) => {
                eprintln!("fhec: cannot apply fix-its to {file}: {e}");
                return 2;
            }
        }
    }
    eprintln!("fhec: {applied_count} fix-it(s) applied; re-checking");

    // Re-run stage 1 discovery + the checks on the fixed sources.
    let mut rerun_diags = Vec::new();
    let unit = match discover(&loaded.config, &loaded.root, &mut rerun_diags) {
        Ok(u) => u,
        Err(d) => {
            rerun_diags.push(*d);
            report(&rerun_diags, g.json, |_| None);
            return 1;
        }
    };
    let opts = StageOptions {
        acl_mode: g.acl_mode(loaded),
        lower: true,
        discard_outputs: true,
    };
    let result = stages::run(&unit, &loaded.config, &opts);
    rerun_diags.extend(result.diagnostics);
    finish(&rerun_diags, loaded, &unit, g)
}

pub fn cmd_build(g: &GlobalArgs) -> i32 {
    let (loaded, unit, pre_diags) = match load_front(g) {
        Ok(t) => t,
        Err(code) => return code,
    };
    let acl_mode = g.acl_mode(&loaded);
    let opts = StageOptions {
        acl_mode,
        lower: true,
        discard_outputs: false,
    };
    let result = stages::run(&unit, &loaded.config, &opts);
    let mut diags = pre_diags;
    diags.extend(result.diagnostics.iter().cloned());
    if has_errors(&diags) || (result.outputs.is_empty() && !unit.files.is_empty()) {
        if !has_errors(&diags) {
            diags.push(Diagnostic::new(
                "FHE9001",
                Severity::Error,
                Span::file_level(""),
                "lowering produced no outputs without reporting an error (internal)".to_string(),
            ));
        }
        return finish(&diags, &loaded, &unit, g);
    }

    let out_root = loaded.config.out_dir(&loaded.root);
    let manifest = build_manifest(&result.outputs);

    if g.frozen {
        let frozen_diags = frozen_compare(&out_root, &result.outputs, &manifest);
        diags.extend(frozen_diags);
        if !g.no_verify {
            diags.extend(crate::gate::run_gate(
                &loaded.root,
                &loaded.config.project.out,
                &result.outputs,
                &manifest,
                &unit,
                &loaded.config.target,
            ));
        }
        return finish(&diags, &loaded, &unit, g);
    }

    // Stage 7: write the mirror + manifest, clean orphans.
    let files_to_write: Vec<(PathBuf, String)> = result
        .outputs
        .iter()
        .map(|o| (PathBuf::from(&o.source_rel), o.text.clone()))
        .collect();
    let written = match fhec_emit::write_mirror(&out_root, &files_to_write) {
        Ok(w) => w,
        Err(e) => {
            diags.push(Diagnostic::new(
                e.code(),
                Severity::Error,
                Span::file_level(""),
                format!("cannot write the generated tree: {e}"),
            ));
            return finish(&diags, &loaded, &unit, g);
        }
    };
    if let Err(e) = fhec_emit::write_manifest(&out_root, &manifest) {
        diags.push(Diagnostic::new(
            e.code(),
            Severity::Error,
            Span::file_level(""),
            format!("cannot write the manifest: {e}"),
        ));
        return finish(&diags, &loaded, &unit, g);
    }
    let keep: HashSet<PathBuf> = written.iter().cloned().collect();
    if let Err(e) = fhec_emit::clean_orphans(&out_root, &keep) {
        diags.push(Diagnostic::new(
            e.code(),
            Severity::Error,
            Span::file_level(""),
            format!("cannot clean orphans: {e}"),
        ));
        return finish(&diags, &loaded, &unit, g);
    }
    if g.verbose {
        let no_ops = result
            .outputs
            .iter()
            .filter(|o| o.applied.is_empty())
            .count();
        eprintln!(
            "fhec: wrote {} file(s) to {} ({} pass-through), {} rewrite site(s)",
            written.len(),
            out_root.display(),
            no_ops,
            result.rewrite_sites,
        );
    }

    // Stage 8: the solc gate.
    if !g.no_verify {
        let gate_diags = crate::gate::run_gate(
            &loaded.root,
            &loaded.config.project.out,
            &result.outputs,
            &manifest,
            &unit,
            &loaded.config.target,
        );
        diags.extend(gate_diags);
    } else if g.verbose {
        eprintln!("fhec: solc gate skipped (--no-verify)");
    }

    // Hidden: §1.4 idempotence self-check.
    if g.self_check && !has_errors(&diags) {
        diags.extend(stages::self_check(
            &result.outputs,
            &loaded.config,
            acl_mode,
        ));
    }

    finish(&diags, &loaded, &unit, g)
}

fn build_manifest(outputs: &[FileOutput]) -> Manifest {
    let mut manifest = Manifest::new("fhec", env!("CARGO_PKG_VERSION"));
    for o in outputs {
        manifest.files.push(ManifestFile::from_applied(
            o.output_rel.to_string_lossy().replace('\\', "/"),
            o.source_rel.clone(),
            &o.applied,
        ));
    }
    manifest
}

/// `--frozen`: compare every would-be output byte-for-byte against the out
/// dir without writing anything.
fn frozen_compare(out_root: &Path, outputs: &[FileOutput], manifest: &Manifest) -> Vec<Diagnostic> {
    let mut problems = Vec::new();
    let mut expected: HashSet<PathBuf> = HashSet::new();
    for o in outputs {
        expected.insert(o.output_rel.clone());
        let on_disk = out_root.join(&o.output_rel);
        match std::fs::read_to_string(&on_disk) {
            Ok(existing) if existing == o.text => {}
            Ok(_) => problems.push(format!(
                "{} differs from regeneration",
                o.output_rel.display()
            )),
            Err(_) => problems.push(format!("{} is missing", o.output_rel.display())),
        }
    }
    let manifest_path = out_root.join(".fhec/manifest.json");
    match std::fs::read_to_string(&manifest_path) {
        Ok(existing) if existing == fhec_emit::manifest_json(manifest) => {}
        Ok(_) => problems.push(".fhec/manifest.json differs from regeneration".to_string()),
        Err(_) => problems.push(".fhec/manifest.json is missing".to_string()),
    }
    // Orphans: files on disk that regeneration would not produce.
    let mut on_disk = Vec::new();
    collect_files(out_root, Path::new(""), &mut on_disk);
    for rel in on_disk {
        if rel.starts_with(".fhec") {
            continue;
        }
        if !expected.contains(&rel) {
            problems.push(format!(
                "{} is an orphan (not produced by regeneration)",
                rel.display()
            ));
        }
    }
    if problems.is_empty() {
        Vec::new()
    } else {
        // Draft code (like FHE1004/FHE1005): spec §9 has no row for frozen
        // drift yet; FHE1006 is the next free load-range number.
        vec![Diagnostic::new(
            "FHE1006",
            Severity::Error,
            Span::file_level(""),
            format!(
                "--frozen: the generated tree is stale; run `fhec build` and commit the result:\n  {}",
                problems.join("\n  ")
            ),
        )]
    }
}

fn collect_files(root: &Path, rel: &Path, acc: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root.join(rel)) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let child = rel.join(&name);
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &child, acc);
        } else {
            acc.push(child);
        }
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
version = "0.2.x"
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

/// Effective configuration printed by `fhec config`. `strictness` and the raw
/// file text are intentionally omitted; `Config` already skips `strictness`.
#[derive(Serialize)]
struct EffectiveConfig<'a> {
    root: String,
    path: String,
    hash: String,
    #[serde(flatten)]
    config: &'a crate::config::Config,
}

fn abs_display(path: &Path) -> String {
    std::path::absolute(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

/// Print the effective loaded configuration as JSON on stdout.
pub fn cmd_config(g: &GlobalArgs) -> i32 {
    let loaded = match load_project(g) {
        Ok(l) => l,
        Err(d) => {
            let text = std::fs::read_to_string(&d.span.file).ok();
            report(&[*d], g.json, |_| text.clone());
            return 1;
        }
    };
    let payload = EffectiveConfig {
        root: abs_display(&loaded.root),
        path: abs_display(&loaded.path),
        hash: loaded.config.hash(),
        config: &loaded.config,
    };
    match serde_json::to_string_pretty(&payload) {
        Ok(json) => {
            println!("{json}");
            0
        }
        Err(e) => {
            eprintln!("fhec: cannot serialize config: {e}");
            2
        }
    }
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
