//! The eight-stage pipeline shell (plan: Load → Parse → Bind → Check →
//! Legality → Lower → Emit → Verify).
//!
//! Stage 1 lives in [`crate::config`]/[`crate::load`]; stage 2 is wired to
//! fhec-syntax below. Stages 3–8 are typed seams: each returns
//! [`StageOutcome::Skipped`] until its crate lands, so `build`/`check` gain
//! stages by replacing one method body each, without reshuffling the drivers.

use crate::config::Config;
use crate::diag::{Diagnostic, Severity, Span};
use crate::load::LoadedUnit;
use std::path::PathBuf;

/// What a pipeline stage did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageOutcome {
    /// The stage executed (its findings are in [`Pipeline::diags`]).
    Ran,
    /// The stage is not wired yet; the payload names it for `--verbose`.
    Skipped(&'static str),
}

/// Pipeline state threaded through the stages.
pub struct Pipeline {
    pub config: Config,
    pub root: PathBuf,
    pub unit: LoadedUnit,
    pub diags: Vec<Diagnostic>,
}

impl Pipeline {
    pub fn new(config: Config, root: PathBuf, unit: LoadedUnit) -> Self {
        Pipeline {
            config,
            root,
            unit,
            diags: Vec::new(),
        }
    }

    /// Stage 2 (Parse): every file must parse under the dialect grammar.
    ///
    /// Parse failures surface as FHE1002 with a file-level span carrying the
    /// parser's rendered output.
    // SEAM(stage-2+): fhec-syntax currently renders diagnostics to strings; once
    // it exposes structured diagnostics (span + message), map them to precise
    // spans here instead of file-level ones.
    pub fn parse(&mut self) -> StageOutcome {
        for file in &self.unit.files {
            if let Err(lines) = fhec_syntax::parse_source(&file.rel_path, &file.content) {
                let mut d = Diagnostic::new(
                    "FHE1002",
                    Severity::Error,
                    Span::file_level(&file.rel_path),
                    lines.join("\n"),
                );
                d.rule = Some("§2.2".to_string());
                self.diags.push(d);
            }
        }
        StageOutcome::Ran
    }

    /// Stage 3 (Bind).
    // SEAM(stage-3): call fhec-bind over the parsed unit.
    pub fn bind(&mut self) -> StageOutcome {
        StageOutcome::Skipped("bind (stage 3)")
    }

    /// Stage 4 (Check) + stage 5 (Legality).
    // SEAM(stage-4/5): call fhec-check (typing, definite assignment, legality).
    pub fn check(&mut self) -> StageOutcome {
        StageOutcome::Skipped("check/legality (stages 4-5)")
    }

    /// Stage 6 (Lower).
    // SEAM(stage-6): call fhec-lower to produce the RewritePlan.
    pub fn lower(&mut self) -> StageOutcome {
        StageOutcome::Skipped("lower (stage 6)")
    }

    /// Stage 7 (Emit).
    // SEAM(stage-7): call fhec-emit to splice patches and write the mirror tree
    // + manifest under the configured out dir.
    pub fn emit(&mut self) -> StageOutcome {
        StageOutcome::Skipped("emit (stage 7) — nothing to emit yet")
    }

    /// Stage 8 (Verify).
    // SEAM(stage-8): call fhec-verify (solc gate) on the emitted tree.
    pub fn verify(&mut self) -> StageOutcome {
        StageOutcome::Skipped("verify (stage 8)")
    }

    pub fn has_errors(&self) -> bool {
        crate::diag::has_errors(&self.diags)
    }

    /// Source-content lookup for the human diagnostic renderer.
    pub fn content_of(&self, file: &str) -> Option<&str> {
        self.unit
            .files
            .iter()
            .find(|f| f.rel_path == file)
            .map(|f| f.content.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load::{Dialect, SourceFile};

    fn unit_with(content: &str) -> LoadedUnit {
        LoadedUnit {
            files: vec![SourceFile {
                rel_path: "A.fsol".to_string(),
                abs_path: PathBuf::from("/x/A.fsol"),
                content: content.to_string(),
                dialect: Dialect::Fsol,
            }],
        }
    }

    #[test]
    fn parse_stage_accepts_dialect_source() {
        let src =
            "pragma solidity ^0.8.25;\ncontract C {\n  function f(in euint32 x) external {}\n}\n";
        let mut p = Pipeline::new(Config::default(), PathBuf::from("/x"), unit_with(src));
        assert_eq!(p.parse(), StageOutcome::Ran);
        assert!(p.diags.is_empty());
    }

    #[test]
    fn parse_stage_reports_fhe1002() {
        let mut p = Pipeline::new(
            Config::default(),
            PathBuf::from("/x"),
            unit_with("contract {"),
        );
        p.parse();
        assert_eq!(p.diags.len(), 1);
        assert_eq!(p.diags[0].code, "FHE1002");
        assert!(p.has_errors());
    }

    #[test]
    fn later_stages_are_skipped_seams() {
        let mut p = Pipeline::new(
            Config::default(),
            PathBuf::from("/x"),
            LoadedUnit::default(),
        );
        assert!(matches!(p.bind(), StageOutcome::Skipped(_)));
        assert!(matches!(p.check(), StageOutcome::Skipped(_)));
        assert!(matches!(p.lower(), StageOutcome::Skipped(_)));
        assert!(matches!(p.emit(), StageOutcome::Skipped(_)));
        assert!(matches!(p.verify(), StageOutcome::Skipped(_)));
    }
}
