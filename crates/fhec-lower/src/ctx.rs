//! Shared lowering context: site indexes, span→byte-range conversion, source
//! text access, and small text utilities used by all three passes.

use fhec_bind::{BoundUnit, FileId, SourceFile};
use fhec_check::CheckedUnit;
use fhec_ir::ByteRange;
use fhec_targets::TargetProfile;
use solar_data_structures::map::FxHashMap;
use solar_interface::source_map::SourceMap;
use solar_interface::Span;

/// Everything the passes read; nothing here mutates.
pub(crate) struct Ctx<'a, 'ast> {
    pub files: &'a [SourceFile<'ast>],
    pub unit: &'a BoundUnit<'ast>,
    pub checked: &'a CheckedUnit,
    pub profile: &'a dyn TargetProfile,
    pub sm: &'a SourceMap,
    /// Per-file source text, aligned with `files` (and thus with `FileId`).
    pub texts: Vec<String>,
    /// Operator sites indexed by their whole-expression span.
    pub ops_by_span: FxHashMap<Span, usize>,
    /// Ternary sites indexed by their whole-expression span.
    pub terns_by_span: FxHashMap<Span, usize>,
    /// Compound-assignment sites indexed by their `L op= R` span.
    pub compounds_by_span: FxHashMap<Span, usize>,
    /// Inc/dec sites indexed by their span (statement or expression).
    pub incdecs_by_span: FxHashMap<Span, usize>,
    /// Encrypted-if sites indexed by their statement span.
    pub ifs_by_span: FxHashMap<Span, usize>,
}

impl<'a, 'ast> Ctx<'a, 'ast> {
    pub fn new(
        files: &'a [SourceFile<'ast>],
        unit: &'a BoundUnit<'ast>,
        checked: &'a CheckedUnit,
        profile: &'a dyn TargetProfile,
        sm: &'a SourceMap,
    ) -> Self {
        let mut ops_by_span = FxHashMap::default();
        for (i, s) in checked.operator_sites.iter().enumerate() {
            ops_by_span.insert(s.span, i);
        }
        let mut terns_by_span = FxHashMap::default();
        for (i, s) in checked.ternary_sites.iter().enumerate() {
            terns_by_span.insert(s.span, i);
        }
        let mut compounds_by_span = FxHashMap::default();
        for (i, s) in checked.compound_sites.iter().enumerate() {
            compounds_by_span.insert(s.span, i);
        }
        let mut incdecs_by_span = FxHashMap::default();
        for (i, s) in checked.incdec_sites.iter().enumerate() {
            incdecs_by_span.insert(s.span, i);
            incdecs_by_span.insert(s.target_span, i);
        }
        let mut ifs_by_span = FxHashMap::default();
        for (i, s) in checked.if_sites.iter().enumerate() {
            ifs_by_span.insert(s.span, i);
        }
        let texts = files
            .iter()
            .map(|f| {
                let file = sm
                    .get_file(solar_interface::source_map::FileName::Custom(
                        f.name.clone(),
                    ))
                    .or_else(|| {
                        sm.get_file(solar_interface::source_map::FileName::Real(
                            std::path::PathBuf::from(&f.name),
                        ))
                    });
                match file {
                    Some(sf) => sf.src.to_string(),
                    // Fall back through the AST span: every parsed file has items
                    // or at least a span-carrying node; an empty file is fine too.
                    None => String::new(),
                }
            })
            .collect();
        Ctx {
            files,
            unit,
            checked,
            profile,
            sm,
            texts,
            ops_by_span,
            terns_by_span,
            compounds_by_span,
            incdecs_by_span,
            ifs_by_span,
        }
    }

    /// File-relative byte range of a span.
    pub fn range(&self, span: Span) -> ByteRange {
        let lo = self.sm.lookup_byte_offset(span.lo());
        let hi = self.sm.lookup_byte_offset(span.hi());
        ByteRange::new(lo.pos.to_usize(), hi.pos.to_usize())
    }

    /// The source text a span covers.
    pub fn snippet(&self, span: Span) -> String {
        self.sm
            .span_to_snippet(span)
            .unwrap_or_else(|_| String::new())
    }

    /// The full text of a file.
    pub fn text(&self, file: FileId) -> &str {
        &self.texts[file.index()]
    }

    /// Whether `inner` lies within `outer` (same file assumed by callers).
    pub fn contains(&self, outer: Span, inner: Span) -> bool {
        outer.lo() <= inner.lo() && inner.hi() <= outer.hi()
    }

    /// The indentation (leading whitespace) of the line containing byte
    /// offset `at` in `file`.
    pub fn line_indent(&self, file: FileId, at: usize) -> String {
        let text = self.text(file);
        let line_start = text[..at].rfind('\n').map_or(0, |i| i + 1);
        text[line_start..]
            .chars()
            .take_while(|c| *c == ' ' || *c == '\t')
            .collect()
    }

    /// Whether the file is a dialect file (spec §2.1: only `.fsol` files are
    /// patched, except the §2.6 import rewrite which applies everywhere).
    pub fn is_dialect(&self, file: FileId) -> bool {
        self.files[file.index()].name.ends_with(".fsol")
    }
}

/// Strips one or more balanced outer parenthesis layers from a text.
pub(crate) fn strip_parens(s: &str) -> &str {
    let mut t = s.trim();
    while t.starts_with('(') && t.ends_with(')') {
        // Only strip when the parens actually match each other.
        let inner = &t[1..t.len() - 1];
        let mut depth = 0i32;
        let mut balanced = true;
        for c in inner.chars() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth < 0 {
                        balanced = false;
                        break;
                    }
                }
                _ => {}
            }
        }
        if balanced && depth == 0 {
            t = inner.trim();
        } else {
            break;
        }
    }
    t
}

/// Applies a set of non-overlapping file-relative substitutions to the slice
/// of `text` covered by `range`, returning the rewritten slice text.
pub(crate) fn splice_within(
    text: &str,
    range: ByteRange,
    subs: &mut [(ByteRange, String)],
) -> String {
    subs.sort_by_key(|(r, _)| r.start);
    let mut out = String::new();
    let mut cursor = range.start;
    for (r, replacement) in subs.iter() {
        debug_assert!(
            r.start >= cursor && r.end <= range.end,
            "substitution out of range"
        );
        out.push_str(&text[cursor..r.start]);
        out.push_str(replacement);
        cursor = r.end;
    }
    out.push_str(&text[cursor..range.end]);
    out
}
