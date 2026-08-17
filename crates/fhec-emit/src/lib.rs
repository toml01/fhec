//! Pipeline stage 7 (Emit): byte-range patching, deterministic temp naming,
//! re-parse guards, mirror-tree writing, and the source-map manifest.
//!
//! Output = input bytes, except inside patch spans (spec §2.5). Minimal
//! diffs, preserved comments/formatting, and idempotence are structural:
//! an empty plan reproduces the input byte-exactly (spec §1.4).
//!
//! Flow for one file: lowering produces a [`FilePlan`] (from `fhec-ir`);
//! every rendered fragment is checked with [`validate_fragment`] before it
//! enters a patch; [`splice`] applies the plan and yields the output text
//! plus the offset map; [`validate_output`] re-parses the whole result;
//! [`write_mirror`] writes the generated tree (`.fsol` → `.sol`); and
//! [`write_manifest`] records output-range → source-range provenance for
//! solc error remapping (FHE6000).

#![warn(missing_docs)]

mod error;
mod guard;
mod manifest;
mod mirror;
mod namer;
mod splice;

pub use error::EmitError;
pub use guard::{validate_fragment, validate_output, FragmentKind};
pub use manifest::{
    manifest_json, write_manifest, Manifest, ManifestFile, Mapping, MANIFEST_REL_PATH,
};
pub use mirror::{clean_orphans, output_rel_path, write_mirror};
pub use namer::{TempHint, TempNamer};
pub use splice::{splice, AppliedPatch, SplicedFile};
