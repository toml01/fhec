//! `fhec` binary: build/check/init/explain/clean.
//!
//! Library layout (the binary in `main.rs` is a thin clap shell):
//! - [`config`] — stage 1: `fhec.toml` model, upward search, content hash
//! - [`load`] — stage 1: file discovery / compilation-unit assembly
//! - [`pipeline`] — stages 2–8 shell; 3–8 are typed seams awaiting their crates
//! - [`diag`] — spec §10.2 diagnostic model, human + JSON renderers
//! - [`explain`] — static spec §9 catalog for `fhec explain`
//! - [`commands`] — command drivers returning exit codes

pub mod commands;
pub mod config;
pub mod diag;
pub mod explain;
pub mod load;
pub mod pipeline;
