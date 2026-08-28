//! The lowerer's worklist: typed rewrite sites and ACL facts.
//!
//! Everything here is owned data — no arena borrows — so the lowering pass can
//! consume it freely. All spans are raw solar [`Span`]s into the session's
//! source map. The Rust types enforce the spec §3.2 discipline structurally:
//! an operand reaches the lowerer only as an [`OperandPlan`], which cannot
//! express "unknown".

use fhec_bind::{FileId, FunctionId};
use fhec_ir::{EType, EWidth, FheOp};
use solar_data_structures::map::FxHashMap;
use solar_interface::Span;

use crate::diag::Diagnostic;
use crate::ty::Ty;

/// Span-keyed expression/declaration types.
#[derive(Default)]
pub struct TypeTable {
    map: FxHashMap<Span, Ty>,
}

impl TypeTable {
    /// Records a type for an expression span.
    pub(crate) fn record(&mut self, span: Span, ty: Ty) {
        self.map.insert(span, ty);
    }

    /// The recorded type for a span, when the positive fragment covered it.
    pub fn get(&self, span: Span) -> Option<&Ty> {
        self.map.get(&span)
    }

    /// Number of typed spans (test/diagnostic aid).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// How one operand of a rewrite site becomes an encrypted value of the site's
/// operand type (spec §3.2, §3.3). `Unknown` is unrepresentable here by
/// construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperandKind {
    /// Already encrypted at exactly the needed type: splice as-is.
    AlreadyEncrypted(EType),
    /// A plaintext expression to wrap in the profile's trivial encrypt
    /// (spec §3.3 rule 1).
    TrivialEncrypt {
        /// The encrypted type to produce.
        to: EType,
    },
    /// An encrypted operand to widen (spec §3.3 rule 3).
    WidenEncrypted {
        /// The operand's width.
        from: EWidth,
        /// The (wider) target width.
        to: EWidth,
    },
    /// A number literal to wrap in the trivial encrypt (range already
    /// checked, spec §3.3 rule 2).
    LiteralEncrypt {
        /// The encrypted type to produce.
        to: EType,
    },
}

/// One operand of a rewrite site: its source span plus its conversion plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperandPlan {
    /// The operand expression's exact span (splice source).
    pub span: Span,
    /// How the operand becomes the site's operand type.
    pub kind: OperandKind,
}

/// An operator application over encrypted operands to rewrite (spec §4.1).
/// Boolean `&&`/`||`/`!` over `ebool` are operator sites too (spec §5.5).
#[derive(Clone, Debug)]
pub struct OperatorSite {
    /// The whole expression's span (the patch range).
    pub span: Span,
    /// The abstract operation.
    pub op: FheOp,
    /// The encrypted result type.
    pub result: EType,
    /// Operands in evaluation order.
    pub operands: Vec<OperandPlan>,
    /// Whether this came from `&&`/`||` (both sides always execute, §5.5).
    pub no_short_circuit: bool,
    /// The enclosing function.
    pub function: FunctionId,
    /// The file containing the site.
    pub file: FileId,
}

/// A ternary over an encrypted condition to rewrite to `select` (spec §5.4).
#[derive(Clone, Debug)]
pub struct TernarySite {
    /// The whole `c ? a : b` span (the patch range).
    pub span: Span,
    /// The condition span (already `ebool`).
    pub cond_span: Span,
    /// The two arms in source order.
    pub arms: [OperandPlan; 2],
    /// The common encrypted result type of the arms.
    pub result: EType,
    /// The enclosing function.
    pub function: FunctionId,
    /// The file containing the site.
    pub file: FileId,
}

/// An `if`/`else` on an encrypted condition (spec §5.1–§5.3). The checker has
/// verified both branches against §7.1; the branch-versioning analysis
/// (write sets, aliasing, merges) is the lowering pass's job.
#[derive(Clone, Debug)]
pub struct EncryptedIfSite {
    /// The whole statement's span.
    pub span: Span,
    /// The condition expression's span (type `ebool`).
    pub cond_span: Span,
    /// The then-branch statement span.
    pub then_span: Span,
    /// The else-branch statement span, when present.
    pub else_span: Option<Span>,
    /// Nesting depth: 0 for a top-level encrypted `if`, +1 per enclosing
    /// encrypted branch (lowering is innermost-first, spec §5.3).
    pub depth: u32,
    /// The enclosing function.
    pub function: FunctionId,
    /// The file containing the site.
    pub file: FileId,
}

/// A compound assignment on an encrypted left-hand side (spec §4.2).
#[derive(Clone, Debug)]
pub struct CompoundAssignSite {
    /// The whole `L op= R` span.
    pub span: Span,
    /// The left-hand side span.
    pub lhs_span: Span,
    /// The left-hand side's encrypted type (also the result type).
    pub lhs: EType,
    /// The abstract operation of the operator part.
    pub op: FheOp,
    /// The right-hand side's conversion plan.
    pub rhs: OperandPlan,
    /// The enclosing function.
    pub function: FunctionId,
    /// The file containing the site.
    pub file: FileId,
}

/// A statement-position `++`/`--` on an encrypted target (spec §4.2).
#[derive(Clone, Debug)]
pub struct IncDecSite {
    /// The whole expression-statement span.
    pub span: Span,
    /// The target lvalue span.
    pub target_span: Span,
    /// The target's encrypted type.
    pub ty: EType,
    /// `true` for `++`, `false` for `--`.
    pub is_increment: bool,
    /// The enclosing function.
    pub function: FunctionId,
    /// The file containing the site.
    pub file: FileId,
}

/// One `in eT name` or `in(proof) eT name` parameter to expand (spec §2.3).
#[derive(Clone, Debug)]
pub struct InSugarSite {
    /// Span of the whole parameter declaration (starts at `in`).
    pub param_span: Span,
    /// Span of the function's full parameter list, parens included (the
    /// shared `inputProof` parameter is appended before its closing `)`).
    pub params_span: Span,
    /// Span of the `in` keyword.
    pub in_span: Span,
    /// The proof parameter this input verifies against.
    ///
    /// `None` is the implicit form `in eT name`: the expansion appends one
    /// `bytes memory inputProof` parameter and converts against that name.
    /// `Some(name)` is the explicit binder `in(name) eT name`: `name` is an
    /// author-declared `bytes memory|calldata` parameter of the same list,
    /// which keeps its position, name, and data location, and no proof
    /// parameter is appended. The checker guarantees that every site of one
    /// function carries the same value (FHE1014).
    pub proof: Option<String>,
    /// The declared encrypted type.
    pub ty: EType,
    /// The parameter name.
    pub name: String,
    /// Whether the function has a body (bodiless: signature rewrite only,
    /// spec §2.3 restriction 3).
    pub has_body: bool,
    /// Span of the function body's opening `{` block, when present (the
    /// conversion statement is inserted at its start).
    pub body_span: Option<Span>,
    /// The enclosing function.
    pub function: FunctionId,
    /// The file containing the site.
    pub file: FileId,
}

/// The one legal `precondition { ... }` block of a function (spec §2.7).
///
/// Only *legal* blocks become sites: the block is the first statement of a
/// function or constructor body whose parameter list declares at least one
/// dialect-managed encrypted input. Every other occurrence is FHE1017 and no
/// site is stated, so the lowerer never sees one it must not act on.
#[derive(Clone, Debug)]
pub struct PreconditionSite {
    /// Span of the whole statement, `precondition` through the closing `}`.
    pub stmt_span: Span,
    /// Span the lowerer deletes to leave a plain nested block behind: the
    /// keyword plus the trivia up to the block's `{`.
    pub marker_span: Span,
    /// Span of the nested block, `{` through `}`. Input materializers are
    /// inserted immediately after its end.
    pub block_span: Span,
    /// The enclosing function.
    pub function: FunctionId,
    /// The file containing the site.
    pub file: FileId,
}

/// What kind of storage slot an encrypted write targets (spec §8.1).
#[derive(Clone, Debug)]
pub enum SlotKind {
    /// A simple state variable.
    SimpleVar,
    /// A mapping slot.
    Mapping {
        /// The key expression's span.
        key_span: Span,
        /// Whether the key expression is exactly `msg.sender`.
        key_is_msg_sender: bool,
        /// Whether the key types as a plaintext address.
        key_is_address: bool,
    },
    /// An array element.
    ArrayIndex {
        /// The index expression's span.
        index_span: Span,
    },
    /// A struct field (possibly nested).
    StructField,
}

/// An encrypted write to storage, outside any encrypted branch (rule R1
/// input, spec §8.1). Writes inside encrypted branches belong to the
/// enclosing [`EncryptedIfSite`]'s merge lowering instead.
#[derive(Clone, Debug)]
pub struct EncryptedStorageWrite {
    /// The whole assignment statement's span (insertion point is after it).
    pub stmt_span: Span,
    /// The written lvalue's span.
    pub lvalue_span: Span,
    /// The slot kind.
    pub slot: SlotKind,
    /// The written value's encrypted type.
    pub value_ty: EType,
    /// Whether the enclosing function is `view`/`pure`.
    pub in_view_or_pure: bool,
    /// The enclosing function.
    pub function: FunctionId,
    /// The file containing the write.
    pub file: FileId,
}

/// An external call passing encrypted arguments (rule R2 input, spec §8.2).
#[derive(Clone, Debug)]
pub struct EncryptedArgCall {
    /// The whole call expression's span.
    pub call_span: Span,
    /// The span of the statement containing the call (insertion point is
    /// before it).
    pub stmt_span: Span,
    /// The callee *object* expression's span (`token` in `token.transfer(x)`)
    /// — the address expression `allowTransient` needs.
    pub callee_span: Span,
    /// Whether the callee object is a plain identifier (no hoisting needed,
    /// spec §8.2 draft decision).
    pub callee_is_ident: bool,
    /// The encrypted arguments: span and type each.
    pub args: Vec<(Span, EType)>,
    /// The enclosing function.
    pub function: FunctionId,
    /// The file containing the call.
    pub file: FileId,
}

/// A `return` of an encrypted value (rule R3 input, spec §8.3–§8.4).
#[derive(Clone, Debug)]
pub struct EncryptedReturn {
    /// The whole `return ...;` statement span.
    pub stmt_span: Span,
    /// The returned expression's span.
    pub expr_span: Span,
    /// The returned encrypted type.
    pub value_ty: EType,
    /// Whether the function is `public`/`external` (R3 applies only then).
    pub is_public_or_external: bool,
    /// Whether the function is `view` (no insertion; warning FHE4002).
    pub is_view: bool,
    /// The enclosing function.
    pub function: FunctionId,
    /// The file containing the return.
    pub file: FileId,
}

/// The ACL-relevant typed facts (spec §8). The checker states facts; the ACL
/// lowering pass decides insertions, dedupe, and warnings.
#[derive(Default)]
pub struct AclFacts {
    /// R1 inputs: encrypted storage writes.
    pub storage_writes: Vec<EncryptedStorageWrite>,
    /// R2 inputs: external calls with encrypted arguments.
    pub external_args: Vec<EncryptedArgCall>,
    /// R3 inputs: encrypted returns.
    pub returns: Vec<EncryptedReturn>,
}

/// The result of stages 4–5: types, rewrite sites, ACL facts, diagnostics.
#[derive(Default)]
pub struct CheckedUnit {
    /// Span-keyed positive-fragment types.
    pub types: TypeTable,
    /// Operator rewrite sites (spec §4).
    pub operator_sites: Vec<OperatorSite>,
    /// Ternary→select sites (spec §5.4).
    pub ternary_sites: Vec<TernarySite>,
    /// Encrypted `if` sites (spec §5.1).
    pub if_sites: Vec<EncryptedIfSite>,
    /// Compound-assignment sites (spec §4.2).
    pub compound_sites: Vec<CompoundAssignSite>,
    /// Statement `++`/`--` sites (spec §4.2).
    pub incdec_sites: Vec<IncDecSite>,
    /// `in` parameter sugar expansions (spec §2.3).
    pub sugar_sites: Vec<InSugarSite>,
    /// Legal `precondition` blocks, at most one per function (spec §2.7).
    pub precondition_sites: Vec<PreconditionSite>,
    /// ACL facts (spec §8).
    pub acl: AclFacts,
    /// Diagnostics (spec §9). Any `Severity::Error` entry MUST abort
    /// lowering for the affected contract (spec §1.3).
    pub diagnostics: Vec<Diagnostic>,
}

impl CheckedUnit {
    /// Whether any diagnostic is an error.
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity == crate::diag::Severity::Error)
    }

    /// Total number of rewrite sites (excludes ACL facts, which are inputs
    /// to a policy, not rewrites by themselves).
    pub fn rewrite_site_count(&self) -> usize {
        self.operator_sites.len()
            + self.ternary_sites.len()
            + self.if_sites.len()
            + self.compound_sites.len()
            + self.incdec_sites.len()
            + self.sugar_sites.len()
            + self.precondition_sites.len()
    }
}
