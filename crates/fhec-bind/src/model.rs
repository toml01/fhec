//! The data model of a bound compilation unit: declarations, resolutions, diagnostics.

use crate::ids::{ContractId, ErrorId, EventId, FileId, FunctionId, TypeDeclId, VarId};
use solar_ast as ast;
use solar_interface::{Ident, Span, Symbol};

/// What a name refers to, as decided by the binder.
///
/// Resolution is a *fact*, not a guess: whenever the binder cannot establish where a name
/// comes from, it returns [`Resolution::Unresolved`] with a reason. The checker maps
/// `Unresolved` to its `Unknown` type; it must never treat it as plaintext or encrypted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// A local variable (including named return variables, which behave as locals).
    Local(VarId),
    /// A function or constructor parameter.
    Param(VarId),
    /// A state variable, possibly inherited.
    StateVar(VarId),
    /// A function, modifier, or free function; overloads are collected into one group.
    Function(Vec<FunctionId>),
    /// A contract, interface, library, or abstract contract declared in the unit.
    Contract(ContractId),
    /// A struct, enum, or user-defined value type declared in the unit.
    TypeName(TypeDeclId),
    /// An event declared in the unit.
    Event(EventId),
    /// An error declared in the unit.
    Error(ErrorId),
    /// A file constant declared in the unit.
    FileConst(VarId),
    /// A Solidity builtin (`msg`, `block`, `require`, ...).
    Builtin(Builtin),
    /// A name known to come from outside the compilation unit.
    ///
    /// `member` is the original (pre-alias) name for `import {A as B}` bindings.
    External {
        /// The import specifier the name comes from (e.g. `@scope/pkg/File.sol`).
        specifier: String,
        /// The original exported name, when known.
        member: Option<Symbol>,
    },
    /// A namespace created by `import * as NS from "./in-unit.sol"` or
    /// `import "./in-unit.sol" as NS`. Members resolve via
    /// [`BoundUnit::namespace_member`](crate::BoundUnit::namespace_member).
    Namespace(FileId),
    /// The binder cannot establish what this name refers to.
    Unresolved(UnresolvedReason),
}

/// Why a name could not be resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnresolvedReason {
    /// Not found in any scope, and the file has no unknown import surface.
    NotFound,
    /// Not found in the unit, but the file (transitively) plain-imports external files;
    /// the name may come from any of these specifiers.
    MaybeExternal {
        /// The external plain-import specifiers in the file's import closure.
        specifiers: Vec<String>,
    },
    /// The name missed the contract's own members and the contract has an inherited
    /// surface the binder cannot see completely (external or unresolved base). The
    /// name MAY be a member of an unseen base — resolving past it would be a guess.
    IncompleteInheritance {
        /// The contract whose inherited surface is incomplete.
        contract: ContractId,
        /// What file-scope lookup would have answered, positive or not.
        ///
        /// It is NOT the resolution: an inherited member shadows a file-scope
        /// name, so using it as one would be a guess. Only an explicit policy
        /// may inspect it — trusting exposure from a profile-pinned import
        /// ([`crate`] users: `fhec-check`'s `trust` and `precondition`).
        fallback: Box<Resolution>,
    },
    /// The name was bound by an import the binder could not resolve.
    ImportFailed {
        /// The offending import specifier.
        specifier: String,
    },
    /// A named import from an in-unit file whose visible symbols do not provably
    /// contain the name (the target file itself has external imports).
    MaybeReExport {
        /// The import specifier of the target file.
        specifier: String,
    },
    /// Two different imported files provide the same name; using it would be ambiguous.
    Ambiguous,
}

/// A Solidity builtin name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Builtin(pub &'static str);

/// Names treated as Solidity builtins (outermost scope).
pub(crate) const BUILTINS: &[&str] = &[
    "msg",
    "block",
    "tx",
    "abi",
    "this",
    "super",
    "require",
    "assert",
    "revert",
    "keccak256",
    "sha256",
    "ripemd160",
    "ecrecover",
    "addmod",
    "mulmod",
    "selfdestruct",
    "blockhash",
    "blobhash",
    "gasleft",
    "type",
];

/// Where a variable declaration lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VarOwner {
    /// Contract state variable.
    State(ContractId),
    /// Function/constructor/modifier parameter.
    Param(FunctionId),
    /// Return parameter, named or unnamed.
    Return(FunctionId),
    /// Local variable in a function body.
    Local(FunctionId),
    /// File-level constant.
    FileConst(FileId),
    /// Struct field.
    StructField(TypeDeclId),
}

/// A variable declaration and its context.
#[derive(Debug)]
pub struct VarInfo<'ast> {
    /// The declaring AST node.
    pub decl: &'ast ast::VariableDefinition<'ast>,
    /// Name, if the declaration is named.
    pub name: Option<Ident>,
    /// The file containing the declaration.
    pub file: FileId,
    /// Where the variable lives.
    pub owner: VarOwner,
    /// Raw `@custom:fhe-*` NatSpec items attached to this declaration (spec
    /// §8.8). Only ever non-empty for a state variable: a struct field or a
    /// function parameter is a bare `VariableDefinition` with no doc
    /// comments of its own.
    pub policy_docs: Vec<PolicyDoc>,
}

/// One raw `@custom:fhe-<key>` NatSpec item, carried unparsed from the
/// binder to the checker's policy module (spec §8.8). `key` is the text
/// after `fhe-`, so `@custom:fhe-allow` yields `key == "allow"`.
#[derive(Clone, Debug)]
pub struct PolicyDoc {
    /// The part of the custom tag name after `fhe-`.
    pub key: String,
    /// The natspec item's content, trimmed.
    pub content: String,
    /// The span of the tag (the `@` is not included).
    pub span: Span,
}

/// Extracts every `@custom:fhe-*` item from a declaration's doc comments,
/// in source order. A policy written in an ordinary (non-doc) comment is
/// invisible here by construction — trivia collection already discarded it
/// before binding — which is exactly the gap spec §8.8 restriction 1's raw
/// source scan (in `fhec-check`) exists to close.
pub(crate) fn extract_policy_docs(docs: &ast::DocComments<'_>) -> Vec<PolicyDoc> {
    let mut out = Vec::new();
    for doc in docs.iter() {
        for item in doc.natspec.iter() {
            if let ast::NatSpecKind::Custom { name } = &item.kind {
                if let Some(key) = name.as_str().strip_prefix("fhe-") {
                    out.push(PolicyDoc {
                        key: key.to_string(),
                        content: item.content().trim().to_string(),
                        span: item.span,
                    });
                }
            }
        }
    }
    out
}

/// A function-like declaration (function, constructor, modifier, fallback, receive).
#[derive(Debug)]
pub struct FunctionInfo<'ast> {
    /// The declaring AST node.
    pub ast: &'ast ast::ItemFunction<'ast>,
    /// The span of the whole item.
    pub span: Span,
    /// Name, if any (constructors/fallback/receive have none).
    pub name: Option<Ident>,
    /// Owned copy of the name for session-free access.
    pub name_str: Option<String>,
    /// The file containing the declaration.
    pub file: FileId,
    /// The contract the function belongs to; `None` for free functions.
    pub contract: Option<ContractId>,
    /// Parameter variable ids, in declaration order.
    pub params: Vec<VarId>,
    /// Return parameter variable ids, in declaration order.
    pub returns: Vec<VarId>,
}

/// How a base contract reference resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BaseRef {
    /// The base is a contract in this unit.
    InUnit(ContractId),
    /// The base is known to come from outside the unit.
    External {
        /// The base name as written.
        name: String,
        /// The import specifier, when known.
        specifier: Option<String>,
    },
    /// The binder cannot establish what the base refers to.
    Unknown {
        /// The base name as written.
        name: String,
    },
}

/// Why a contract's inherited surface is incomplete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IncompleteReason {
    /// At least one base is external to the unit.
    ExternalBase,
    /// At least one base could not be resolved at all.
    UnresolvedBase,
    /// A base in the unit is itself incomplete.
    BaseIncomplete,
    /// C3 linearization failed (inconsistent hierarchy or cycle).
    LinearizationFailed,
}

/// The linearized inheritance of a contract.
#[derive(Clone, Debug)]
pub struct Linearization {
    /// Most-derived-first (starts with the contract itself). When `complete` is false this
    /// holds only the in-unit prefix the binder could establish (always at least `self`).
    pub order: Vec<ContractId>,
    /// True when every base (transitively) is in the unit and C3 succeeded.
    pub complete: bool,
    /// Why the linearization is incomplete, when it is.
    pub reason: Option<IncompleteReason>,
}

/// A contract, interface, library, or abstract contract.
#[derive(Debug)]
pub struct ContractInfo<'ast> {
    /// The declaring AST node.
    pub ast: &'ast ast::ItemContract<'ast>,
    /// The span of the whole item.
    pub span: Span,
    /// The contract name.
    pub name: Ident,
    /// Owned copy of the name for session-free access.
    pub name_str: String,
    /// The kind (contract/abstract/interface/library).
    pub kind: ast::ContractKind,
    /// The file containing the declaration.
    pub file: FileId,
    /// Base references in declaration order.
    pub bases: Vec<BaseRef>,
    /// Linearized inheritance (computed after all contracts are collected).
    pub linearization: Linearization,
    /// State variable ids in declaration order.
    pub state_vars: Vec<VarId>,
    /// Function ids in declaration order (all kinds).
    pub functions: Vec<FunctionId>,
    /// Own (non-inherited) member table.
    pub(crate) members: crate::binder::NameTable,
}

/// A struct, enum, or user-defined value type declaration.
#[derive(Debug)]
pub struct TypeDeclInfo<'ast> {
    /// The declaring AST node.
    pub kind: TypeDeclKind<'ast>,
    /// The file containing the declaration.
    pub file: FileId,
    /// The contract scope, if declared inside a contract.
    pub contract: Option<ContractId>,
    /// The declared name.
    pub name: Ident,
    /// Raw `@custom:fhe-*` NatSpec items attached to this declaration (spec
    /// §8.8). Only meaningful for a `struct`; always empty for an enum or a
    /// user-defined value type.
    pub policy_docs: Vec<PolicyDoc>,
}

/// The AST node behind a [`TypeDeclInfo`].
#[derive(Debug)]
pub enum TypeDeclKind<'ast> {
    /// A struct definition.
    Struct(&'ast ast::ItemStruct<'ast>),
    /// An enum definition.
    Enum(&'ast ast::ItemEnum<'ast>),
    /// A user-defined value type definition.
    Udvt(&'ast ast::ItemUdvt<'ast>),
}

/// An event declaration.
#[derive(Debug)]
pub struct EventInfo<'ast> {
    /// The declaring AST node.
    pub ast: &'ast ast::ItemEvent<'ast>,
    /// The file containing the declaration.
    pub file: FileId,
    /// The contract scope, if declared inside a contract.
    pub contract: Option<ContractId>,
    /// Raw `@custom:fhe-*` NatSpec items attached to this declaration (spec
    /// §8.8).
    pub policy_docs: Vec<PolicyDoc>,
}

/// An error declaration.
#[derive(Debug)]
pub struct ErrorInfo<'ast> {
    /// The declaring AST node.
    pub ast: &'ast ast::ItemError<'ast>,
    /// The file containing the declaration.
    pub file: FileId,
    /// The contract scope, if declared inside a contract.
    pub contract: Option<ContractId>,
}

/// A structural problem found while binding.
///
/// Codes are in the FHE1xxx range per spec §9. `FHE1003` covers unresolvable imports.
/// `FHE1020` (duplicate definition) is used by the binder and still needs a spec §9 row.
#[derive(Clone, Debug)]
pub struct BindDiagnostic {
    /// Stable diagnostic code (`FHE1003`, `FHE1020`).
    pub code: &'static str,
    /// Human-readable message.
    pub message: String,
    /// The source span the diagnostic points at.
    pub span: Span,
    /// The file the diagnostic belongs to.
    pub file: FileId,
}

/// Unresolvable import (spec §9).
pub const CODE_UNRESOLVED_IMPORT: &str = "FHE1003";
/// Duplicate definition in the same scope (binder-assigned; pending spec §9 row).
pub const CODE_DUPLICATE_DEFINITION: &str = "FHE1020";

/// The type pattern a `using` directive applies to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UsingTarget {
    /// `using ... for T` where `T` is a single-identifier custom type or an elementary
    /// type; matched by its textual name (e.g. `euint32`, `uint256`).
    Name(String),
    /// `using ... for *`.
    Wildcard,
    /// A target the binder does not model (qualified path, array, mapping, function).
    Complex,
}

/// What the function list of a `using` directive resolved to.
#[derive(Clone, Debug)]
pub enum UsingListResolution {
    /// `using L for T`: the library path resolution.
    Library(Resolution),
    /// `using {a, L.b as +, c} for T`: per entry, the method name (last path segment),
    /// the resolution of the attached function, and whether the entry binds an operator
    /// (operator entries do not participate in method-call syntax).
    Functions(Vec<UsingFunction>),
}

/// One entry of a `using { ... } for T` list.
#[derive(Clone, Debug)]
pub struct UsingFunction {
    /// The method name this entry would attach (last path segment).
    pub method: Symbol,
    /// The resolution of the referenced function (through libraries/namespaces).
    pub resolution: Resolution,
    /// True when the entry has `as <op>` (binds an operator, not a method name).
    pub is_operator: bool,
}

/// A collected `using` directive.
#[derive(Clone, Debug)]
pub struct UsingEntry {
    /// The file the directive appears in.
    pub file: FileId,
    /// The contract scope, when the directive is inside a contract.
    pub contract: Option<ContractId>,
    /// True for `using ... for T global`.
    pub global: bool,
    /// The target type pattern.
    pub target: UsingTarget,
    /// The resolved function list.
    pub list: UsingListResolution,
}

/// Result of a method-syntax lookup (`a.add(b)`) through `using` directives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MethodResolution {
    /// In-unit candidate functions for the method.
    Functions(Vec<FunctionId>),
    /// A `using` directive for this type/method points outside the unit.
    External {
        /// The import specifier, when known.
        specifier: Option<String>,
    },
    /// No applicable `using` directive binds this method for this type in the unit.
    ///
    /// Note: bindings living in *external* files (e.g. CoFHE's `using BindingsEuint32
    /// for euint32 global;` inside FHE.sol) are invisible to the binder; the checker
    /// must consult the target profile for those.
    NoBinding,
}
