//! Stage 8: the solc verification gate.
//!
//! Assembles the full source closure (generated files + external imports
//! resolved through node_modules, node-style: walk up from the importer),
//! compiles with `solc --standard-json`, and forwards diagnostics as FHE6000
//! with spans remapped through the manifest onto the original `.fsol`
//! positions.

use crate::config::Target;
use crate::diag::{Diagnostic, Severity, Span};
use crate::load::LoadedUnit;
use crate::stages::{resolve_relative, FileOutput};
use fhec_emit::{Manifest, ManifestFile};
use fhec_verify::{CompileInput, CompileSettings, SolcRunner};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The advisory produced when an import cannot be resolved on disk.
const INSTALL_HINT: &str =
    "install the library packages (e.g. `npm install @fhenixprotocol/cofhe-contracts` or \
     `pnpm add @fhenixprotocol/cofhe-contracts`), or pass --no-verify to skip the solc gate";

/// Runs the gate over the emitted outputs. Returns diagnostics; an empty
/// list means the gate passed.
pub fn run_gate(
    root: &Path,
    out_dir_name: &str,
    outputs: &[FileOutput],
    manifest: &Manifest,
    unit: &LoadedUnit,
    target: &Target,
) -> Vec<Diagnostic> {
    let mut diags = Vec::new();

    // 1. Source closure.
    let sources = match closure(root, out_dir_name, outputs) {
        Ok(s) => s,
        Err(msg) => {
            let mut d = Diagnostic::new(
                "FHE6000",
                Severity::Error,
                Span::file_level(out_dir_name),
                format!("cannot assemble the solc source closure: {msg}; {INSTALL_HINT}"),
            );
            d.rule = Some("§10.3".to_string());
            diags.push(d);
            return diags;
        }
    };

    // 2. Compiler.
    let requirement = target
        .solc
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(", ");
    let runner = match SolcRunner::for_requirement(&requirement) {
        Ok(r) => r,
        Err(e) => {
            let mut d = Diagnostic::new(
                "FHE6000",
                Severity::Error,
                Span::file_level(""),
                format!(
                    "no usable solc for requirement `{}`: {e}; {INSTALL_HINT}",
                    target.solc
                ),
            );
            d.rule = Some("§10.3".to_string());
            diags.push(d);
            return diags;
        }
    };

    // 3. Compile.
    let input = CompileInput {
        sources,
        settings: CompileSettings {
            evm_version: Some(target.evm_version.clone()),
            ..CompileSettings::default()
        },
    };
    let compiled = match runner.compile(&input) {
        Ok(c) => c,
        Err(e) => {
            diags.push(Diagnostic::new(
                "FHE6000",
                Severity::Error,
                Span::file_level(""),
                format!("solc failed to run: {e}"),
            ));
            return diags;
        }
    };

    // 4. Forward + remap.
    let out_prefix = format!("{out_dir_name}/");
    for vd in compiled.fhe_diagnostics() {
        let severity = match vd.severity {
            fhec_verify::Severity::Error => Severity::Error,
            fhec_verify::Severity::Warning => Severity::Warning,
            fhec_verify::Severity::Note => Severity::Note,
        };
        let span = remap_span(&vd.span, &out_prefix, manifest, unit);
        let mut d = Diagnostic::new(&vd.code, severity, span.0, vd.message.clone());
        if span.1 {
            d.message
                .push_str(" (position is inside code fhec generated from this construct)");
        }
        d.rule = vd.rule.clone();
        diags.push(d);
    }
    diags
}

/// Remaps a solc span (virtual output coordinates) onto the original source
/// through the manifest. Returns the span and whether the position fell
/// inside generated (inserted/replaced) text.
fn remap_span(
    vspan: &fhec_verify::Span,
    out_prefix: &str,
    manifest: &Manifest,
    unit: &LoadedUnit,
) -> (Span, bool) {
    let Some(out_rel) = vspan.file.strip_prefix(out_prefix) else {
        // A library file (or no location): pass the span through as-is.
        return (
            Span {
                file: vspan.file.clone(),
                start_byte: vspan.start_byte,
                end_byte: vspan.end_byte,
                start_line: vspan.start_line,
                start_col: vspan.start_col,
                end_line: vspan.end_line,
                end_col: vspan.end_col,
            },
            false,
        );
    };
    let Some(mf) = manifest.files.iter().find(|f| f.output == out_rel) else {
        return (Span::file_level(&vspan.file), false);
    };
    let (start, end, inside) = remap_range(mf, vspan.start_byte, vspan.end_byte);
    let content = unit
        .files
        .iter()
        .find(|f| f.rel_path == mf.source)
        .map(|f| f.content.as_str())
        .unwrap_or("");
    (Span::from_bytes(&mf.source, content, start, end), inside)
}

/// Maps `[start, end)` in output coordinates onto source coordinates using a
/// manifest file's mappings (sorted by output range).
///
/// A position inside a mapping's output range blames the whole source range
/// of that mapping; a position between mappings shifts by the accumulated
/// length delta of the mappings before it.
pub fn remap_range(mf: &ManifestFile, start: usize, end: usize) -> (usize, usize, bool) {
    for m in &mf.mappings {
        if start >= m.output_range[0] && start < m.output_range[1].max(m.output_range[0] + 1) {
            return (m.source_range[0], m.source_range[1], true);
        }
    }
    let mut delta: i64 = 0;
    for m in &mf.mappings {
        if m.output_range[1] <= start {
            delta = m.output_range[1] as i64 - m.source_range[1] as i64;
        } else {
            break;
        }
    }
    let shift = |v: usize| -> usize { (v as i64 - delta).max(0) as usize };
    (shift(start), shift(end), false)
}

/// Builds the full standard-JSON source map: generated outputs keyed as
/// `<out_dir>/<out_rel>`, plus every transitively imported external file.
///
/// Bare specifiers resolve node-style: `node_modules/<spec>` walking up from
/// the importer's directory (for generated files: the project root).
fn closure(
    root: &Path,
    out_dir_name: &str,
    outputs: &[FileOutput],
) -> Result<BTreeMap<String, String>, String> {
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    // virtual path → disk dir the import came from (for node-style walk-up).
    let mut queue: Vec<(String, PathBuf)> = Vec::new();

    for out in outputs {
        let out_rel = out.output_rel.to_string_lossy().replace('\\', "/");
        let virtual_path = format!("{out_dir_name}/{out_rel}");
        for spec in import_specs(&out.text) {
            let resolved = resolve_relative(&virtual_path, &spec);
            queue.push((resolved, root.to_path_buf()));
        }
        sources.insert(virtual_path, out.text.clone());
    }

    while let Some((virtual_path, from_dir)) = queue.pop() {
        if sources.contains_key(&virtual_path) {
            continue;
        }
        // A relative import between generated files resolves inside the
        // in-memory set; reaching here means it is missing from the unit.
        if virtual_path.starts_with(&format!("{out_dir_name}/")) {
            return Err(format!(
                "generated file imports `{virtual_path}`, which is not part of the project"
            ));
        }
        let disk = resolve_bare(&from_dir, &virtual_path).ok_or_else(|| {
            format!(
                "cannot resolve import `{virtual_path}` through node_modules (searched upward \
                 from {})",
                from_dir.display()
            )
        })?;
        let content = std::fs::read_to_string(&disk)
            .map_err(|e| format!("cannot read {}: {e}", disk.display()))?;
        let disk_dir = disk.parent().unwrap_or(Path::new("/")).to_path_buf();
        for spec in import_specs(&content) {
            let resolved = resolve_relative(&virtual_path, &spec);
            queue.push((resolved, disk_dir.clone()));
        }
        sources.insert(virtual_path, content);
    }
    Ok(sources)
}

/// Node-style resolution of a bare specifier: `<dir>/node_modules/<spec>`
/// walking up from `from_dir`.
fn resolve_bare(from_dir: &Path, spec: &str) -> Option<PathBuf> {
    let mut dir = Some(from_dir);
    while let Some(d) = dir {
        let candidate = d.join("node_modules").join(spec);
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = d.parent();
    }
    None
}

/// Extracts the string literal of every import directive, line-based.
///
/// The generated output re-parsed cleanly (stage 7 guard), so imports are
/// well-formed; a line-based scan is sufficient and cheap. Solidity string
/// literals accept both quote styles, so `import '...'` counts too.
fn import_specs(source: &str) -> Vec<String> {
    let mut specs = Vec::new();
    for line in source.lines() {
        if let Some(spec) = import_spec_of_line(line) {
            specs.push(spec.to_owned());
        }
    }
    specs
}

/// Returns the first string literal of a line iff the line is an import
/// directive, handling both `"` and `'` quote styles.
pub(crate) fn import_spec_of_line(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    trimmed
        .strip_prefix("import")
        .filter(|rest| rest.starts_with(|c: char| c.is_whitespace() || c == '"' || c == '\''))?;
    let pos = trimmed.find(['"', '\''])?;
    let quote = trimmed.as_bytes()[pos] as char;
    let rest = &trimmed[pos + 1..];
    rest.split_once(quote).map(|(inner, _)| inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhec_emit::Mapping;

    fn mf(mappings: Vec<Mapping>) -> ManifestFile {
        ManifestFile {
            output: "A.sol".into(),
            source: "A.fsol".into(),
            no_op: mappings.is_empty(),
            mappings,
        }
    }

    fn mapping(out: [usize; 2], src: [usize; 2]) -> Mapping {
        Mapping {
            output_range: out,
            source_range: src,
            rule: "test".into(),
            code: None,
        }
    }

    #[test]
    fn remap_identity_before_first_mapping() {
        let m = mf(vec![mapping([100, 120], [100, 105])]);
        assert_eq!(remap_range(&m, 10, 20), (10, 20, false));
    }

    #[test]
    fn remap_inside_mapping_blames_source_range() {
        let m = mf(vec![mapping([100, 120], [100, 105])]);
        assert_eq!(remap_range(&m, 110, 115), (100, 105, true));
    }

    #[test]
    fn remap_after_mapping_shifts_by_delta() {
        // Output grew by 15 bytes at the patch.
        let m = mf(vec![mapping([100, 120], [100, 105])]);
        assert_eq!(remap_range(&m, 130, 140), (115, 125, false));
    }

    #[test]
    fn remap_after_two_mappings_uses_last_delta() {
        let m = mf(vec![
            mapping([100, 120], [100, 105]), // +15
            mapping([200, 210], [190, 195]), // cumulative +15
        ]);
        assert_eq!(remap_range(&m, 250, 260), (235, 245, false));
    }

    #[test]
    fn remap_pure_insertion_position() {
        // An insertion: empty source range, non-empty output range.
        let m = mf(vec![mapping([50, 90], [50, 50])]);
        assert_eq!(remap_range(&m, 60, 70), (50, 50, true));
        assert_eq!(remap_range(&m, 95, 99), (55, 59, false));
    }

    #[test]
    fn bare_resolution_walks_up() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let pkg = root.join("node_modules/@scope/pkg");
        std::fs::create_dir_all(pkg.join("sub")).unwrap();
        std::fs::write(pkg.join("sub/X.sol"), "contract X {}").unwrap();
        let nested = root.join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        let found = resolve_bare(&nested, "@scope/pkg/sub/X.sol").unwrap();
        assert!(found.ends_with("node_modules/@scope/pkg/sub/X.sol"));
        assert!(resolve_bare(&nested, "@scope/pkg/missing.sol").is_none());
    }

    #[test]
    fn import_specs_scan() {
        let src = "// import \"fake\"\nimport \"./A.sol\";\nimport {X} from \"@p/q/B.sol\";\n";
        // Note: `import {X} from "..."` — the first string literal is the spec.
        assert_eq!(
            import_specs(src),
            vec!["./A.sol".to_string(), "@p/q/B.sol".to_string()]
        );
    }

    #[test]
    fn import_specs_single_quoted() {
        // The real EncryptedCounter snippet imports with single quotes.
        let src = "import '@fhenixprotocol/cofhe-contracts/FHE.sol';\nimport {Y} from './C.sol';\nimportant();\n";
        assert_eq!(
            import_specs(src),
            vec![
                "@fhenixprotocol/cofhe-contracts/FHE.sol".to_string(),
                "./C.sol".to_string()
            ]
        );
    }
}
