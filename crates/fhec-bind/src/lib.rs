//! Symbols, scopes, imports, inheritance — pipeline stage 3 (Bind).
//!
//! [`bind`] turns parsed solar ASTs into a [`BoundUnit`]: flat side tables of
//! declarations plus a span-keyed map from every identifier *use* to a
//! [`Resolution`].
//!
//! # Design
//!
//! - **Borrowed, session-scoped.** The solar AST is arena-allocated, so `BoundUnit<'ast>`
//!   borrows AST nodes rather than copying them. The intended shape is one scope that
//!   enters a solar `Session`, parses all files into one `Arena`, binds, and then runs
//!   the checker and lowering over the same borrows. Identifier uses are keyed by
//!   [`Span`](solar_interface::Span), which is unique across a session's source map, so
//!   downstream passes can query resolutions from any AST node they encounter.
//! - **Facts, not guesses.** Binding serves the checker's *positive fragment*
//!   (spec §3.1): whatever cannot be established is an explicit
//!   [`Resolution::Unresolved`] with a [`UnresolvedReason`], never a fallback to "assume
//!   file scope" or "assume plaintext". The checker maps these to its `Unknown` type.
//!   Concretely:
//!   - Imports that leave the unit resolve to [`Resolution::External`] (aliased/glob:
//!     we know the specifier) or make unknown names degrade to
//!     [`UnresolvedReason::MaybeExternal`] (plain imports: unknown symbol set).
//!   - A contract with a base outside the unit has an *incomplete inherited surface*:
//!     names that miss its own members degrade to
//!     [`UnresolvedReason::IncompleteInheritance`] instead of falling through to file
//!     scope (they might be members of the unseen base).
//! - **Hard errors are rare.** Only structural facts produce FHE1xxx diagnostics:
//!   duplicate definitions in one scope and unresolvable imports. Everything else is a
//!   resolution state; solc remains the authority on plain-Solidity legality.
//!
//! Name lookup order (spec-relevant): block scopes (innermost first) → parameters/named
//! returns → contract own members → inherited members through the C3 linearization
//! (private base members excluded) → file-level declarations → import bindings →
//! builtins → conservative fallback.
//!
//! # Encrypted-input sugar
//!
//! TODO(fhec-syntax): once the `in eT name` parameter sugar lands in the vendored
//! grammar with a dedicated AST marker, [`FunctionInfo`] will expose the flag per
//! parameter. The binder walks parameters generically, so no structural change is
//! expected — only surfacing the marker.

mod binder;
mod ids;
mod inherit;
mod model;
mod unit;

pub use binder::bind;
pub use ids::{ContractId, ErrorId, EventId, FileId, FunctionId, TypeDeclId, VarId};
pub use model::{
    BaseRef, BindDiagnostic, Builtin, ContractInfo, ErrorInfo, EventInfo, FunctionInfo,
    IncompleteReason, Linearization, MethodResolution, Resolution, TypeDeclInfo, TypeDeclKind,
    UnresolvedReason, UsingEntry, UsingFunction, UsingListResolution, UsingTarget, VarInfo,
    VarOwner, CODE_DUPLICATE_DEFINITION, CODE_UNRESOLVED_IMPORT,
};
pub use unit::{BoundUnit, SourceFile};
