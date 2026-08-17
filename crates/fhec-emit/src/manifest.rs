//! The sidecar source-map manifest (`generated/.fhec/manifest.json`).
//!
//! Maps output byte ranges back to original source ranges with rule
//! provenance, so solc diagnostics on the generated tree can be remapped to
//! `.fsol` positions (spec §9 FHE6000, PLAN "Emission"). Serialization is
//! byte-deterministic: stable field order (struct order), two-space pretty
//! printing, trailing newline.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::EmitError;
use crate::splice::AppliedPatch;

/// Relative path of the manifest inside the output root.
pub const MANIFEST_REL_PATH: &str = ".fhec/manifest.json";

/// The whole-run manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Producing tool name (`"fhec"`).
    pub tool: String,
    /// Producing tool version.
    pub version: String,
    /// One entry per emitted file, in emission order.
    pub files: Vec<ManifestFile>,
}

/// Source-map data for one emitted file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFile {
    /// Output path, relative to the output root.
    pub output: String,
    /// Source path, relative to the source root.
    pub source: String,
    /// Whether the file passed through byte-identical (spec §1.4).
    pub no_op: bool,
    /// Output-range → source-range mappings, in output order.
    pub mappings: Vec<Mapping>,
}

/// One output-range → source-range mapping with rule provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mapping {
    /// `[start, end)` byte range in the output file.
    pub output_range: [usize; 2],
    /// `[start, end)` byte range in the source file.
    pub source_range: [usize; 2],
    /// The rule that produced the patch.
    pub rule: String,
    /// Related diagnostic code, when the rule has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl Manifest {
    /// An empty manifest for this tool version.
    pub fn new(tool: impl Into<String>, version: impl Into<String>) -> Self {
        Manifest {
            tool: tool.into(),
            version: version.into(),
            files: Vec::new(),
        }
    }
}

impl ManifestFile {
    /// Builds a file entry from the splicer's applied-patch list.
    pub fn from_applied(
        output: impl Into<String>,
        source: impl Into<String>,
        applied: &[AppliedPatch],
    ) -> Self {
        ManifestFile {
            output: output.into(),
            source: source.into(),
            no_op: applied.is_empty(),
            mappings: applied
                .iter()
                .map(|ap| Mapping {
                    output_range: [ap.output_range.start, ap.output_range.end],
                    source_range: [ap.source_range.start, ap.source_range.end],
                    rule: ap.provenance.rule.clone(),
                    code: ap.provenance.code.clone(),
                })
                .collect(),
        }
    }
}

/// Renders the manifest to its canonical byte-deterministic JSON form.
pub fn manifest_json(manifest: &Manifest) -> String {
    let mut json =
        serde_json::to_string_pretty(manifest).expect("manifest model always serializes");
    json.push('\n');
    json
}

/// Writes the manifest to `<out_root>/.fhec/manifest.json`, returning the path.
pub fn write_manifest(out_root: &Path, manifest: &Manifest) -> Result<PathBuf, EmitError> {
    let path = out_root.join(MANIFEST_REL_PATH);
    let parent = path.parent().expect("manifest path has a parent");
    fs::create_dir_all(parent).map_err(|source| EmitError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    fs::write(&path, manifest_json(manifest)).map_err(|source| EmitError::Io {
        path: path.clone(),
        source,
    })?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhec_ir::{ByteRange, Provenance};

    fn sample() -> Manifest {
        let applied = vec![
            AppliedPatch {
                output_range: ByteRange::new(120, 155),
                source_range: ByteRange::new(120, 131),
                provenance: Provenance::new("operator-lowering", ByteRange::new(120, 131)),
            },
            AppliedPatch {
                output_range: ByteRange::new(200, 245),
                source_range: ByteRange::new(180, 180),
                provenance: Provenance::new("§8.1 R1", ByteRange::new(160, 180))
                    .with_code("FHE4001"),
            },
        ];
        let mut m = Manifest::new("fhec", "0.0.0");
        m.files
            .push(ManifestFile::from_applied("A.sol", "A.fsol", &applied));
        m.files
            .push(ManifestFile::from_applied("B.sol", "B.sol", &[]));
        m
    }

    #[test]
    fn golden_json() {
        let expected = r#"{
  "tool": "fhec",
  "version": "0.0.0",
  "files": [
    {
      "output": "A.sol",
      "source": "A.fsol",
      "no_op": false,
      "mappings": [
        {
          "output_range": [
            120,
            155
          ],
          "source_range": [
            120,
            131
          ],
          "rule": "operator-lowering"
        },
        {
          "output_range": [
            200,
            245
          ],
          "source_range": [
            180,
            180
          ],
          "rule": "§8.1 R1",
          "code": "FHE4001"
        }
      ]
    },
    {
      "output": "B.sol",
      "source": "B.sol",
      "no_op": true,
      "mappings": []
    }
  ]
}
"#;
        assert_eq!(manifest_json(&sample()), expected);
    }

    #[test]
    fn deterministic_across_runs() {
        assert_eq!(manifest_json(&sample()), manifest_json(&sample()));
    }

    #[test]
    fn write_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_manifest(dir.path(), &sample()).unwrap();
        assert!(path.ends_with(".fhec/manifest.json"));
        let read: Manifest =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(read, sample());
    }
}
