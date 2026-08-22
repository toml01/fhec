//! The splicer: applies a [`FilePlan`] to the original file bytes.
//!
//! # Canonical patch order
//!
//! Patches are normalized with a *stable* sort before application:
//!
//! 1. ascending `range.start`;
//! 2. at the same start offset, pure insertions before replacements;
//! 3. remaining ties keep plan order.
//!
//! Rule 3 is what makes multi-statement insertions at one offset (e.g.
//! `FHE.allowThis(x);` then `FHE.allowSender(x);`, spec §8.1) come out in the
//! order the lowering pass produced them. The splicer normalizes rather than
//! requiring pre-sorted input because the three lowering passes (operators →
//! if/select → ACL) each append patches in their own walk order; only
//! *overlap* indicates a genuine invariant violation upstream.

use fhec_ir::{ByteRange, FilePlan, Provenance};

use crate::error::EmitError;

/// One applied patch, with its final position in the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedPatch {
    /// Range of the replacement text in the *output* bytes.
    pub output_range: ByteRange,
    /// The original range the patch replaced (empty for insertions).
    pub source_range: ByteRange,
    /// Rule provenance carried through for the manifest.
    pub provenance: Provenance,
}

/// The result of splicing one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplicedFile {
    /// The complete output text.
    pub text: String,
    /// Every applied patch in canonical order, with final output ranges.
    pub applied: Vec<AppliedPatch>,
}

impl SplicedFile {
    /// Whether the file came through untouched (spec §1.4 no-op guarantee).
    pub fn is_no_op(&self) -> bool {
        self.applied.is_empty()
    }
}

/// Applies `plan` to `original`, returning the output text and the offset map.
///
/// Validates the plan invariants (bounds, UTF-8 boundaries, no overlap after
/// normalization — see module docs); a violation is an internal error in the
/// FHE9001 range, never a panic. An empty plan returns the input byte-exactly.
pub fn splice(original: &str, plan: &FilePlan) -> Result<SplicedFile, EmitError> {
    let path = plan.source_path.as_str();

    // Canonical order (stable: plan order breaks remaining ties).
    let mut order: Vec<usize> = (0..plan.patches.len()).collect();
    order.sort_by_key(|&i| {
        let p = &plan.patches[i];
        (p.range.start, u8::from(!p.is_insertion()))
    });

    let mut out = String::with_capacity(original.len());
    let mut applied = Vec::with_capacity(order.len());
    let mut cursor = 0usize; // input bytes consumed so far
    let mut prev_range = ByteRange::new(0, 0);

    for &i in &order {
        let patch = &plan.patches[i];
        let range = patch.range;

        if range.start > range.end || range.end > original.len() {
            return Err(EmitError::PatchOutOfBounds {
                path: path.to_string(),
                range,
                file_len: original.len(),
            });
        }
        if !original.is_char_boundary(range.start) || !original.is_char_boundary(range.end) {
            return Err(EmitError::PatchSplitsUtf8 {
                path: path.to_string(),
                range,
            });
        }
        if range.start < cursor {
            return Err(EmitError::PatchOverlap {
                path: path.to_string(),
                first: prev_range,
                second: range,
            });
        }

        out.push_str(&original[cursor..range.start]);
        let out_start = out.len();
        out.push_str(&patch.replacement);
        applied.push(AppliedPatch {
            output_range: ByteRange::new(out_start, out.len()),
            source_range: range,
            provenance: patch.provenance.clone(),
        });
        cursor = range.end;
        prev_range = range;
    }

    out.push_str(&original[cursor..]);
    Ok(SplicedFile { text: out, applied })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhec_ir::Patch;

    fn prov() -> Provenance {
        Provenance::new("test", ByteRange::new(0, 0))
    }

    fn plan(patches: Vec<Patch>) -> FilePlan {
        FilePlan {
            source_path: "t.fsol".into(),
            patches,
        }
    }

    #[test]
    fn empty_plan_is_byte_identical() {
        // Tricky content: CRLF mix, comments, unicode, no trailing newline.
        let src = "pragma solidity ^0.8.25;\r\n// naïve — comment\ncontract C { /* € */ }";
        let out = splice(src, &plan(vec![])).unwrap();
        assert!(out.is_no_op());
        assert_eq!(out.text, src);
    }

    #[test]
    fn replaces_and_inserts() {
        let src = "abcdefghij";
        let p = plan(vec![
            Patch::replace(ByteRange::new(2, 4), "XY", prov()),
            Patch::insert(6, "+", prov()),
            Patch::replace(ByteRange::new(8, 10), "", prov()),
        ]);
        let out = splice(src, &p).unwrap();
        assert_eq!(out.text, "abXYef+gh");
        // Offset map points at each replacement in the output.
        assert_eq!(&out.text[2..4], "XY");
        assert_eq!(out.applied[0].output_range, ByteRange::new(2, 4));
        assert_eq!(out.applied[1].output_range, ByteRange::new(6, 7));
        assert_eq!(out.applied[2].output_range, ByteRange::new(9, 9));
    }

    #[test]
    fn normalizes_unsorted_input() {
        let src = "0123456789";
        let p = plan(vec![
            Patch::insert(8, "B", prov()),
            Patch::replace(ByteRange::new(0, 2), "A", prov()),
        ]);
        let out = splice(src, &p).unwrap();
        assert_eq!(out.text, "A234567B89");
    }

    #[test]
    fn same_offset_insertions_keep_plan_order() {
        let src = "xy";
        let p = plan(vec![
            Patch::insert(1, "1", prov()),
            Patch::insert(1, "2", prov()),
            Patch::insert(1, "3", prov()),
        ]);
        let out = splice(src, &p).unwrap();
        assert_eq!(out.text, "x123y");
    }

    #[test]
    fn insertion_precedes_replacement_at_same_offset() {
        let src = "abcdef";
        // Plan order deliberately reversed: replacement first, insertion second.
        let p = plan(vec![
            Patch::replace(ByteRange::new(2, 4), "REP", prov()),
            Patch::insert(2, "INS", prov()),
        ]);
        let out = splice(src, &p).unwrap();
        assert_eq!(out.text, "abINSREPef");
    }

    #[test]
    fn insertion_at_replacement_end_is_allowed() {
        let src = "abcdef";
        let p = plan(vec![
            Patch::replace(ByteRange::new(1, 3), "R", prov()),
            Patch::insert(3, "I", prov()),
        ]);
        let out = splice(src, &p).unwrap();
        assert_eq!(out.text, "aRIdef");
    }

    #[test]
    fn rejects_overlap() {
        let src = "abcdefgh";
        let p = plan(vec![
            Patch::replace(ByteRange::new(1, 5), "X", prov()),
            Patch::replace(ByteRange::new(4, 6), "Y", prov()),
        ]);
        let err = splice(src, &p).unwrap_err();
        assert!(matches!(err, EmitError::PatchOverlap { .. }));
        assert_eq!(err.code(), "FHE9001");
    }

    #[test]
    fn rejects_insertion_inside_replacement() {
        let src = "abcdefgh";
        let p = plan(vec![
            Patch::replace(ByteRange::new(1, 5), "X", prov()),
            Patch::insert(3, "Y", prov()),
        ]);
        assert!(matches!(
            splice(src, &p).unwrap_err(),
            EmitError::PatchOverlap { .. }
        ));
    }

    #[test]
    fn rejects_same_start_replacements() {
        let src = "abcdefgh";
        let p = plan(vec![
            Patch::replace(ByteRange::new(2, 4), "X", prov()),
            Patch::replace(ByteRange::new(2, 5), "Y", prov()),
        ]);
        assert!(matches!(
            splice(src, &p).unwrap_err(),
            EmitError::PatchOverlap { .. }
        ));
    }

    #[test]
    fn rejects_out_of_bounds() {
        let src = "short";
        let p = plan(vec![Patch::replace(ByteRange::new(3, 9), "X", prov())]);
        let err = splice(src, &p).unwrap_err();
        assert!(matches!(err, EmitError::PatchOutOfBounds { .. }));
        assert_eq!(err.code(), "FHE9001");
    }

    #[test]
    fn rejects_utf8_split() {
        let src = "aé b"; // 'é' occupies bytes 1..3
        let p = plan(vec![Patch::replace(ByteRange::new(1, 2), "X", prov())]);
        assert!(matches!(
            splice(src, &p).unwrap_err(),
            EmitError::PatchSplitsUtf8 { .. }
        ));
    }

    /// Fixed-seed xorshift64 — deterministic, no external dep.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// Round-trip property: applying the inverse patches (computed from the
    /// offset map) to the output restores the original input byte-exactly.
    #[test]
    fn random_patch_sets_round_trip() {
        let base: String = ('a'..='z').cycle().take(200).collect();
        let mut rng = Rng(0x5eed_cafe_d00d_f00d);

        for _case in 0..50 {
            // Build up to 6 non-overlapping patches from sorted cut points.
            let n = rng.below(6) + 1;
            let mut cuts: Vec<usize> = (0..n * 2).map(|_| rng.below(base.len() + 1)).collect();
            cuts.sort_unstable();
            cuts.dedup();
            let mut patches = Vec::new();
            let (pairs, _rest) = cuts.as_chunks::<2>();
            for pair in pairs {
                let (s, e) = (pair[0], pair[1]);
                let text = match rng.below(3) {
                    0 => String::new(), // deletion
                    1 => "R".repeat(rng.below(5) + 1),
                    _ => "insert!".to_string(),
                };
                patches.push(Patch::replace(ByteRange::new(s, e), text, prov()));
            }
            let p = FilePlan {
                source_path: "prop.fsol".into(),
                patches,
            };
            let out = splice(&base, &p).unwrap();

            // Each output range holds exactly the replacement text.
            let mut sorted = p.patches.clone();
            sorted.sort_by_key(|pt| (pt.range.start, u8::from(!pt.is_insertion())));
            for (ap, pt) in out.applied.iter().zip(&sorted) {
                assert_eq!(
                    &out.text[ap.output_range.start..ap.output_range.end],
                    pt.replacement
                );
            }

            // Inverse: replace every output range with its original bytes.
            let inverse = FilePlan {
                source_path: "prop-inverse.fsol".into(),
                patches: out
                    .applied
                    .iter()
                    .map(|ap| {
                        Patch::replace(
                            ap.output_range,
                            &base[ap.source_range.start..ap.source_range.end],
                            prov(),
                        )
                    })
                    .collect(),
            };
            let restored = splice(&out.text, &inverse).unwrap();
            assert_eq!(restored.text, base, "round trip failed");
        }
    }
}
