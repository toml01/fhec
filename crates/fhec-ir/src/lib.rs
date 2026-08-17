//! Abstract FHE-IR: the target-independent intermediate representation that
//! lowering passes emit and target profiles render into library calls.
//!
//! This is a *rendering* IR, not an optimizer IR. Fragments reference the
//! original source by byte range, generated temporaries by name, or literal
//! replacement text; the emitter splices rendered fragments into the input
//! byte stream (spec §2.5).

#![warn(missing_docs)]

mod etype;
mod fragment;
mod op;
mod plan;

pub use etype::{EType, EWidth};
pub use fragment::{ByteRange, Expr, Operand, Stmt, TempType};
pub use op::FheOp;
pub use plan::{FilePlan, Patch, Provenance, RewritePlan};
