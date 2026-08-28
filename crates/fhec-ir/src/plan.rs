//! Rewrite plans: dumb-data byte-patch lists.
//!
//! Lowering (pipeline stage 6) produces a [`RewritePlan`]; the emitter
//! (stage 7, crate `fhec-emit`) validates and splices it into the original
//! source bytes (spec §2.5).
//!
//! # Invariants
//!
//! A [`FilePlan`] is valid when, after normalization to the canonical patch
//! order (by `range.start`; insertions before replacements at the same
//! offset; [`InsertOrder`] next; plan order as the final tiebreaker):
//!
//! 1. every patch range is in bounds of the original file and lies on UTF-8
//!    character boundaries,
//! 2. no two patch ranges overlap (touching at a boundary is allowed; a pure
//!    insertion may sit at the edge of a replacement, never strictly inside
//!    one).
//!
//! These invariants are *validated by the emitter*, which reports violations
//! as internal errors (FHE9001, spec §9) — this module only carries the data.

use crate::fragment::ByteRange;

/// Where a patch came from: the lowering rule and its source anchor.
///
/// `source_range` is the span of the original construct that *triggered* the
/// patch. It can differ from the patch's own range — e.g. an ACL insertion
/// (spec §8.1) has an empty patch range after the write statement, while its
/// provenance points at the triggering write.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Provenance {
    /// The rule that produced the patch (e.g. `"operator-lowering"`, `"§8.1 R1"`).
    pub rule: String,
    /// The related diagnostic code, when the rule has one (e.g. `"FHE4001"`).
    pub code: Option<String>,
    /// Span of the original construct this patch derives from.
    pub source_range: ByteRange,
}

impl Provenance {
    /// Provenance for `rule` anchored at `source_range`, with no diagnostic code.
    pub fn new(rule: impl Into<String>, source_range: ByteRange) -> Self {
        Provenance {
            rule: rule.into(),
            code: None,
            source_range,
        }
    }

    /// Attaches a diagnostic code.
    #[must_use]
    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }
}

/// Relative order of two patches that land on the *same* byte offset.
///
/// Plan order cannot decide this: the lowering passes run in a fixed order
/// (operators → if/select → ACL, plus per-file sugar expansion), and that
/// order is not the order the output statements must appear in. When a
/// materializer that *declares* a name and a patch that *reads* that name
/// both anchor at one offset — which happens whenever there is no whitespace
/// between the two source constructs — the declaration must come first or the
/// output names an undeclared identifier.
///
/// Ordering is by declaration order: [`InsertOrder::Declaration`] sorts first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum InsertOrder {
    /// The patch introduces declarations later patches at this offset may
    /// name (spec §2.3 encrypted-input materializers, spec §2.7 when a
    /// `precondition` block moves them).
    Declaration,
    /// Everything else. Plan order breaks the remaining ties.
    #[default]
    Normal,
}

/// A single byte-range patch: replace `range` in the original file with
/// `replacement`.
///
/// An empty `range` (`start == end`) is a pure insertion at that offset.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Patch {
    /// The replaced range of the original file (empty = insertion point).
    pub range: ByteRange,
    /// The final rendered replacement text.
    pub replacement: String,
    /// Rule provenance, kept for the source-map manifest.
    pub provenance: Provenance,
    /// Tiebreaker against other patches at the same offset.
    pub order: InsertOrder,
}

impl Patch {
    /// A replacement patch over a non-degenerate range.
    pub fn replace(
        range: ByteRange,
        replacement: impl Into<String>,
        provenance: Provenance,
    ) -> Self {
        Patch {
            range,
            replacement: replacement.into(),
            provenance,
            order: InsertOrder::Normal,
        }
    }

    /// A pure insertion at byte offset `at`.
    pub fn insert(at: usize, text: impl Into<String>, provenance: Provenance) -> Self {
        Patch {
            range: ByteRange::new(at, at),
            replacement: text.into(),
            provenance,
            order: InsertOrder::Normal,
        }
    }

    /// Marks this patch as introducing declarations later patches at the same
    /// offset may name; see [`InsertOrder`].
    #[must_use]
    pub fn declaration(mut self) -> Self {
        self.order = InsertOrder::Declaration;
        self
    }

    /// Whether this patch inserts without replacing any original bytes.
    pub fn is_insertion(&self) -> bool {
        self.range.is_empty()
    }

    /// The canonical sort key against other patches of the same file.
    ///
    /// Ties on this key are broken by plan order (the sort is stable).
    pub fn sort_key(&self) -> (usize, u8, InsertOrder) {
        (self.range.start, u8::from(!self.is_insertion()), self.order)
    }
}

/// All patches for one source file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FilePlan {
    /// Project-relative path of the source file the patches apply to.
    pub source_path: String,
    /// The patches, in production order (the emitter normalizes; see module docs).
    pub patches: Vec<Patch>,
}

impl FilePlan {
    /// An empty plan for `source_path` (a no-op file, spec §1.4).
    pub fn new(source_path: impl Into<String>) -> Self {
        FilePlan {
            source_path: source_path.into(),
            patches: Vec::new(),
        }
    }

    /// Appends a patch.
    pub fn push(&mut self, patch: Patch) {
        self.patches.push(patch);
    }

    /// Whether the plan changes nothing (the no-op guarantee case).
    pub fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }
}

/// The rewrite plan for a whole compilation unit.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RewritePlan {
    /// One plan per file, in compilation-unit order.
    pub files: Vec<FilePlan>,
}

impl RewritePlan {
    /// An empty plan.
    pub fn new() -> Self {
        RewritePlan::default()
    }

    /// Appends a file plan.
    pub fn push(&mut self, file: FilePlan) {
        self.files.push(file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors() {
        let prov = Provenance::new("§8.1 R1", ByteRange::new(10, 30)).with_code("FHE4001");
        assert_eq!(prov.code.as_deref(), Some("FHE4001"));

        let ins = Patch::insert(30, "FHE.allowThis(count);", prov.clone());
        assert!(ins.is_insertion());
        assert_eq!(ins.range, ByteRange::new(30, 30));

        let rep = Patch::replace(ByteRange::new(10, 20), "FHE.add(a, b)", prov);
        assert!(!rep.is_insertion());

        let mut plan = FilePlan::new("contracts/Counter.fsol");
        assert!(plan.is_empty());
        plan.push(ins);
        plan.push(rep);
        assert_eq!(plan.patches.len(), 2);

        let mut unit = RewritePlan::new();
        unit.push(plan);
        assert_eq!(unit.files.len(), 1);
    }
}
