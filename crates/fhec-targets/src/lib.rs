//! Target profiles: the mapping from abstract FHE-IR to a concrete FHE
//! library (spec §1.5).
//!
//! Lowering emits [`fhec_ir::FheOp`]s; a [`TargetProfile`] supplies the
//! library spelling, the signature table, the cast matrix, ACL primitive
//! names, and required imports for one pinned library release. The checker
//! consults the profile so that an operation absent from the pinned version
//! is rejected (FHE5001) instead of emitted.

#![warn(missing_docs)]

mod cofhe;
mod profile;
mod registry;

pub use cofhe::CofheProfile;
pub use profile::{Capabilities, ProfileError, TargetProfile};
pub use registry::{ProfileHandle, ProfileRegistry, UnknownProfileError};
