//! Stages 2–6, run inside one solar session.
//!
//! [`run`] parses every discovered file in a single session, then binds
//! (stage 3), checks (stages 4–5), and — for `build` — lowers (stage 6) and
//! splices (stage 7's pure half). Everything span-bearing is converted to
//! owned [`Diagnostic`]s before the session ends; the spliced outputs come
//! out as owned [`FileOutput`]s ready for the mirror writer and the solc
//! gate.
//!
//! The parse gate runs first in throwaway sessions (one per file) so that
//! FHE1002 diagnostics attribute cleanly per file; the shared session then
//! re-parses, which cannot fail. The double parse is cheap at project scale
//! and keeps error attribution exact.

use crate::config::Config;
use crate::diag::{has_errors, Diagnostic, FixIt, Severity, Span};
use crate::load::{Dialect, LoadedUnit};
use fhec_emit::AppliedPatch;
use fhec_ir::ByteRange;
use fhec_lower::{AclMode, LowerOptions};
use fhec_syntax::parse::{
    ast,
    interface::{
        source_map::{FileName, SourceMap},
        ColorChoice, Session,
    },
    Parser,
};
use std::path::PathBuf;

/// Options for a stages run.
#[derive(Clone, Copy, Debug)]
pub struct StageOptions {
    /// ACL pass mode (config `[acl] mode`, overridable by `--acl`).
    pub acl_mode: AclMode,
    /// Whether to run stage 6 (lower) and produce outputs. `check` sets this
    /// only when the ACL mode is `suggest` (to surface FHE4010–FHE4012
    /// notes); `build` always sets it.
    pub lower: bool,
    /// Discard the plan even when lowering ran (`check --acl=suggest`).
    pub discard_outputs: bool,
}

/// One transpiled file, spliced and re-parse-validated.
pub struct FileOutput {
    /// Source path relative to the src dir (`a/B.fsol`).
    pub source_rel: String,
    /// Output path relative to the out dir (`a/B.sol`).
    pub output_rel: PathBuf,
    /// Complete output text (byte-identical to the input for no-op files).
    pub text: String,
    /// Offset map for the manifest.
    pub applied: Vec<AppliedPatch>,
}

/// The owned result of stages 2–6 (+ splice).
#[derive(Default)]
pub struct StagesResult {
    /// All diagnostics, in stage order.
    pub diagnostics: Vec<Diagnostic>,
    /// Spliced outputs, one per input file in unit order. Empty when
    /// lowering did not run or any error aborted it.
    pub outputs: Vec<FileOutput>,
    /// Rewrite-site count from the checker (for `--verbose`).
    pub rewrite_sites: usize,
    /// Safe fix-its harvested from all stage diagnostics, for `--fix`.
    pub safe_fixits: Vec<(String, ByteRange, String)>,
}

impl StagesResult {
    pub fn has_errors(&self) -> bool {
        has_errors(&self.diagnostics)
    }
}

/// Runs stages 2–6 over a loaded unit.
pub fn run(unit: &LoadedUnit, config: &Config, opts: &StageOptions) -> StagesResult {
    let mut result = StagesResult::default();

    // §2.1: .fsol files must carry a pragma within the supported range.
    pragma_gate(unit, &mut result.diagnostics);

    // Stage 2 parse gate, per file for clean attribution.
    for file in &unit.files {
        if let Err(lines) = fhec_syntax::parse_source(&file.rel_path, &file.content) {
            let mut d = Diagnostic::new(
                "FHE1002",
                Severity::Error,
                Span::file_level(&file.rel_path),
                lines.join("\n"),
            );
            d.rule = Some("§2.2".to_string());
            result.diagnostics.push(d);
        }
    }
    if result.has_errors() {
        return result;
    }

    // Target profile (stage 1's pinning decision, needed by stages 4–6).
    let registry = fhec_targets::ProfileRegistry::builtin();
    let spec = format!("{}@{}", config.target.profile, config.target.version);
    let profile = match registry
        .resolve(&spec)
        .or_else(|_| registry.resolve(&config.target.profile))
    {
        Ok(p) => p,
        Err(e) => {
            let mut d = Diagnostic::new(
                "FHE5002",
                Severity::Error,
                Span::file_level("fhec.toml"),
                format!("unknown target profile: {e}"),
            );
            d.rule = Some("§1.5".to_string());
            result.diagnostics.push(d);
            return result;
        }
    };

    // Stages 3–6 inside one session.
    let sess = Session::builder()
        .with_buffer_emitter(ColorChoice::Never)
        .build();
    let plan: Option<fhec_ir::RewritePlan> = sess.enter(|| {
        let arena = ast::Arena::new();
        let mut files: Vec<fhec_bind::SourceFile<'_>> = Vec::new();
        for file in &unit.files {
            let mut parser = match Parser::from_source_code(
                &sess,
                &arena,
                FileName::Custom(file.rel_path.clone()),
                file.content.clone(),
            ) {
                Ok(p) => p,
                Err(_guaranteed) => {
                    push_internal(
                        &mut result.diagnostics,
                        &file.rel_path,
                        "source registration",
                    );
                    return None;
                }
            };
            let parsed = match parser.parse_file() {
                Ok(u) => u,
                Err(e) => {
                    e.emit();
                    // The gate above accepted this file; a failure here is an
                    // internal inconsistency, never silent.
                    push_internal(&mut result.diagnostics, &file.rel_path, "re-parse");
                    return None;
                }
            };
            let parsed: &ast::SourceUnit<'_> = arena.alloc(parsed);
            files.push(fhec_bind::SourceFile {
                name: file.rel_path.clone(),
                ast: parsed,
            });
        }

        let sm = sess.source_map();

        // Stage 3: bind.
        let bound = fhec_bind::bind(
            files
                .iter()
                .map(|f| fhec_bind::SourceFile {
                    name: f.name.clone(),
                    ast: f.ast,
                })
                .collect(),
        );
        for d in bound.diagnostics() {
            let mut diag = Diagnostic::new(
                d.code,
                Severity::Error,
                to_span(sm, unit, d.span),
                d.message.clone(),
            );
            diag.rule = Some("§2.2".to_string());
            result.diagnostics.push(diag);
        }

        // Stages 4–5: check + legality.
        let checked = fhec_check::check(&files, &bound, profile.as_ref(), sm);
        result.rewrite_sites = checked.rewrite_site_count();
        for d in &checked.diagnostics {
            result
                .diagnostics
                .push(convert_check_diag(sm, unit, d, &mut result.safe_fixits));
        }

        if !opts.lower || has_errors(&result.diagnostics) {
            return None;
        }

        // Stage 6: lower.
        let lowered = fhec_lower::lower(
            &files,
            &bound,
            &checked,
            profile.as_ref(),
            sm,
            &LowerOptions {
                acl_mode: opts.acl_mode,
            },
        );
        for d in &lowered.diagnostics {
            result
                .diagnostics
                .push(convert_check_diag(sm, unit, d, &mut result.safe_fixits));
        }
        if !lowered.failed_files.is_empty() || has_errors(&result.diagnostics) {
            return None;
        }
        Some(lowered.plan)
    });

    // Stage 7 (pure half): splice + re-parse guard, outside the session.
    let Some(plan) = plan else {
        return result;
    };
    if opts.discard_outputs {
        return result;
    }
    for (file, file_plan) in unit.files.iter().zip(plan.files.iter()) {
        debug_assert_eq!(file.rel_path, file_plan.source_path);
        let spliced = match fhec_emit::splice(&file.content, file_plan) {
            Ok(s) => s,
            Err(e) => {
                result.diagnostics.push(emit_error_diag(&file.rel_path, &e));
                continue;
            }
        };
        let output_rel = fhec_emit::output_rel_path(std::path::Path::new(&file.rel_path));
        if !spliced.is_no_op() {
            let out_name = output_rel.to_string_lossy().replace('\\', "/");
            if let Err(e) = fhec_emit::validate_output(&out_name, &spliced.text) {
                result.diagnostics.push(emit_error_diag(&file.rel_path, &e));
                continue;
            }
        }
        result.outputs.push(FileOutput {
            source_rel: file.rel_path.clone(),
            output_rel,
            text: spliced.text,
            applied: spliced.applied,
        });
    }
    if result.has_errors() {
        result.outputs.clear();
    }
    result
}

/// Re-runs the pipeline over the generated outputs and checks byte identity
/// (`T(T(x)) == T(x)`, spec §1.4). Intra-unit import specifiers are rewritten
/// back to `.fsol` in memory so the generated text is checked as dialect
/// input; the re-run's §2.6 rewrite restores them, so byte identity is exact.
pub fn self_check(outputs: &[FileOutput], config: &Config, acl_mode: AclMode) -> Vec<Diagnostic> {
    use crate::load::SourceFile;

    let unit_outputs: std::collections::BTreeSet<String> = outputs
        .iter()
        .map(|o| o.output_rel.to_string_lossy().replace('\\', "/"))
        .collect();

    let files = outputs
        .iter()
        .map(|o| SourceFile {
            rel_path: o.source_rel.clone(),
            abs_path: PathBuf::from(&o.source_rel),
            content: unrewrite_imports(&o.source_rel, &o.text, &unit_outputs),
            dialect: if o.source_rel.ends_with(".fsol") {
                Dialect::Fsol
            } else {
                Dialect::Sol
            },
        })
        .collect();
    let unit = LoadedUnit { files };

    let opts = StageOptions {
        acl_mode,
        lower: true,
        discard_outputs: false,
    };
    let second = run(&unit, config, &opts);
    let mut diags = second.diagnostics;
    if has_errors(&diags) {
        return diags;
    }
    for (first, again) in outputs.iter().zip(second.outputs.iter()) {
        if first.text != again.text {
            diags.push(Diagnostic::new(
                "FHE9001",
                Severity::Error,
                Span::file_level(&first.source_rel),
                format!(
                    "self-check failed: transpiling the generated output of {} again \
                     changed it (T(T(x)) != T(x), spec §1.4)",
                    first.source_rel
                ),
            ));
        }
    }
    diags
}

/// Rewrites intra-unit import specifiers of a generated text back to `.fsol`.
///
/// Only specifiers that resolve (relative to `importer`) to another generated
/// unit file are touched; external and unresolved specifiers stay as-is.
fn unrewrite_imports(
    importer: &str,
    text: &str,
    unit_outputs: &std::collections::BTreeSet<String>,
) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let is_import = trimmed
            .strip_prefix("import")
            .is_some_and(|rest| rest.starts_with(|c: char| c.is_whitespace() || c == '"'));
        if !is_import {
            out.push_str(line);
            continue;
        }
        let Some((head, rest)) = line.split_once('"') else {
            out.push_str(line);
            continue;
        };
        let Some((spec, tail)) = rest.split_once('"') else {
            out.push_str(line);
            continue;
        };
        let resolved = resolve_relative(importer, spec);
        if spec.ends_with(".sol") && unit_outputs.contains(&resolved) {
            let unrewritten = format!("{}.fsol", &spec[..spec.len() - ".sol".len()]);
            out.push_str(head);
            out.push('"');
            out.push_str(&unrewritten);
            out.push('"');
            out.push_str(tail);
        } else {
            out.push_str(line);
        }
    }
    out
}

/// Resolves a possibly-relative import specifier against the importer's
/// unit-relative path. Bare specifiers come back unchanged.
pub fn resolve_relative(importer: &str, spec: &str) -> String {
    if !spec.starts_with('.') {
        return spec.to_owned();
    }
    let mut segments: Vec<&str> = importer
        .rsplit_once('/')
        .map_or_else(Vec::new, |(dir, _)| dir.split('/').collect());
    for part in spec.split('/') {
        match part {
            "." | "" => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    segments.join("/")
}

/// §2.1 clause 2: every `.fsol` file must carry a `pragma solidity`
/// constraint whose satisfiable range lies within `>=0.8.25 <0.9.0`.
///
/// The check is best-effort sound: a pragma the semver grammar cannot parse
/// is skipped (solc re-checks in stage 8) — never a false FHE1001.
fn pragma_gate(unit: &LoadedUnit, diags: &mut Vec<Diagnostic>) {
    const OUTSIDE: &[&str] = &[
        "0.4.11", "0.5.17", "0.6.12", "0.7.6", "0.8.0", "0.8.24", "0.9.0", "0.9.99", "1.0.0",
    ];
    const INSIDE: &[&str] = &["0.8.25", "0.8.28", "0.8.33", "0.8.99"];

    for file in &unit.files {
        if file.dialect != Dialect::Fsol {
            continue;
        }
        let Some((offset, expr)) = find_pragma(&file.content) else {
            let mut d = Diagnostic::new(
                "FHE1001",
                Severity::Error,
                Span::file_level(&file.rel_path),
                "a .fsol file must carry a `pragma solidity` constraint within >=0.8.25 <0.9.0"
                    .to_string(),
            );
            d.rule = Some("§2.1".to_string());
            diags.push(d);
            continue;
        };
        let normalized = expr.split_whitespace().collect::<Vec<_>>().join(", ");
        let Ok(req) = semver::VersionReq::parse(&normalized) else {
            continue; // unparsable → leave it to solc (stage 8)
        };
        let sat = |v: &str| req.matches(&semver::Version::parse(v).expect("test versions parse"));
        let any_outside = OUTSIDE.iter().any(|v| sat(v));
        let any_inside = INSIDE.iter().any(|v| sat(v));
        if any_outside || !any_inside {
            let mut d = Diagnostic::new(
                "FHE1001",
                Severity::Error,
                Span::from_bytes(&file.rel_path, &file.content, offset, offset + expr.len()),
                format!("pragma range `{expr}` is not within the supported range >=0.8.25 <0.9.0"),
            );
            d.rule = Some("§2.1".to_string());
            diags.push(d);
        }
    }
}

/// Finds the first `pragma solidity <expr>;`, returning the byte offset and
/// text of `<expr>`.
fn find_pragma(content: &str) -> Option<(usize, &str)> {
    let mut search_from = 0usize;
    while let Some(rel) = content[search_from..].find("pragma") {
        let at = search_from + rel;
        let rest = &content[at + "pragma".len()..];
        let rest_trim = rest.trim_start();
        if let Some(after) = rest_trim.strip_prefix("solidity") {
            let expr_all = after.trim_start();
            let end = expr_all.find(';')?;
            let expr = expr_all[..end].trim_end();
            let offset = content.len() - expr_all.len();
            return Some((offset, expr));
        }
        search_from = at + "pragma".len();
    }
    None
}

/// Converts a checker/lowerer diagnostic (they share the shape) and harvests
/// its safe fix-its.
fn convert_check_diag(
    sm: &SourceMap,
    unit: &LoadedUnit,
    d: &fhec_check::Diagnostic,
    safe_fixits: &mut Vec<(String, ByteRange, String)>,
) -> Diagnostic {
    let severity = match d.severity {
        fhec_check::Severity::Error => Severity::Error,
        fhec_check::Severity::Warning => Severity::Warning,
        fhec_check::Severity::Note => Severity::Note,
    };
    let span = to_span(sm, unit, d.span);
    let mut diag = Diagnostic::new(d.code, severity, span, d.message.clone());
    diag.rule = d.rule.map(str::to_string);
    for f in &d.fixits {
        let fspan = to_span(sm, unit, f.span);
        if f.safe {
            safe_fixits.push((
                fspan.file.clone(),
                ByteRange::new(fspan.start_byte, fspan.end_byte),
                f.replacement.clone(),
            ));
        }
        diag.fixits.push(FixIt {
            span: fspan,
            replacement: f.replacement.clone(),
            safe: f.safe,
        });
    }
    diag
}

/// Converts a solar span to the spec §10.2 shape.
fn to_span(sm: &SourceMap, unit: &LoadedUnit, span: fhec_syntax::interface::Span) -> Span {
    let lo = sm.lookup_byte_offset(span.lo());
    let hi = sm.lookup_byte_offset(span.hi());
    let file = match &lo.sf.name {
        FileName::Custom(s) => s.clone(),
        FileName::Real(p) => p.to_string_lossy().replace('\\', "/"),
        _ => String::new(),
    };
    let content = unit
        .files
        .iter()
        .find(|f| f.rel_path == file)
        .map(|f| f.content.as_str())
        .unwrap_or("");
    Span::from_bytes(&file, content, lo.pos.to_usize(), hi.pos.to_usize())
}

fn emit_error_diag(file: &str, e: &fhec_emit::EmitError) -> Diagnostic {
    Diagnostic::new(
        e.code(),
        Severity::Error,
        Span::file_level(file),
        format!("emit failed: {e}"),
    )
}

fn push_internal(diags: &mut Vec<Diagnostic>, file: &str, what: &str) {
    diags.push(Diagnostic::new(
        "FHE9001",
        Severity::Error,
        Span::file_level(file),
        format!("{what} failed after the parse gate accepted the file (internal)"),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_pragma_basics() {
        let (off, expr) = find_pragma("// hi\npragma solidity ^0.8.25;\n").unwrap();
        assert_eq!(expr, "^0.8.25");
        assert_eq!(off, 22);
        let (_, expr) = find_pragma("pragma solidity >=0.8.25 <0.9.0;").unwrap();
        assert_eq!(expr, ">=0.8.25 <0.9.0");
        assert!(find_pragma("contract C {}").is_none());
    }

    fn fsol_unit(content: &str) -> LoadedUnit {
        LoadedUnit {
            files: vec![crate::load::SourceFile {
                rel_path: "A.fsol".into(),
                abs_path: PathBuf::from("/x/A.fsol"),
                content: content.into(),
                dialect: Dialect::Fsol,
            }],
        }
    }

    #[test]
    fn pragma_gate_rules() {
        let mut diags = Vec::new();
        pragma_gate(
            &fsol_unit("pragma solidity ^0.8.25;\ncontract C {}\n"),
            &mut diags,
        );
        assert!(diags.is_empty(), "{diags:?}");

        // ^0.8.0 admits 0.8.0 (< 0.8.25): outside.
        let mut diags = Vec::new();
        pragma_gate(
            &fsol_unit("pragma solidity ^0.8.0;\ncontract C {}\n"),
            &mut diags,
        );
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "FHE1001");

        // Missing pragma entirely.
        let mut diags = Vec::new();
        pragma_gate(&fsol_unit("contract C {}\n"), &mut diags);
        assert_eq!(diags.len(), 1);

        // Exact supported range.
        let mut diags = Vec::new();
        pragma_gate(
            &fsol_unit("pragma solidity >=0.8.25 <0.9.0;\ncontract C {}\n"),
            &mut diags,
        );
        assert!(diags.is_empty(), "{diags:?}");
    }

    #[test]
    fn resolve_relative_specs() {
        assert_eq!(resolve_relative("a/B.fsol", "./C.sol"), "a/C.sol");
        assert_eq!(resolve_relative("a/B.fsol", "../C.sol"), "C.sol");
        assert_eq!(resolve_relative("B.fsol", "./sub/C.sol"), "sub/C.sol");
        assert_eq!(
            resolve_relative("a/B.fsol", "@scope/pkg/C.sol"),
            "@scope/pkg/C.sol"
        );
    }

    #[test]
    fn unrewrite_only_unit_imports() {
        let mut set = std::collections::BTreeSet::new();
        set.insert("a/Other.sol".to_string());
        let text = "import \"./Other.sol\";\nimport \"@x/y/Z.sol\";\n";
        let out = unrewrite_imports("a/B.fsol", text, &set);
        assert_eq!(out, "import \"./Other.fsol\";\nimport \"@x/y/Z.sol\";\n");
    }
}
