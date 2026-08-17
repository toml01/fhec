//! `fhec` binary: build/check/init/explain/clean.
//!
//! Library layout (the binary in `main.rs` is a thin clap shell):
//! - [`config`] — stage 1: `fhec.toml` model, upward search, content hash
//! - [`load`] — stage 1: file discovery / compilation-unit assembly
//! - [`stages`] — stages 2–6 (+ splice) inside one solar session
//! - [`gate`] — stage 8: source closure, solc gate, FHE6000 remapping
//! - [`diag`] — spec §10.2 diagnostic model, human + JSON renderers
//! - [`explain`] — static spec §9 catalog for `fhec explain`
//! - [`commands`] — command drivers returning exit codes

pub mod commands;
pub mod config;
pub mod diag;
pub mod explain;
pub mod gate;
pub mod load;
pub mod stages;
