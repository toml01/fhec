//! Reader policies: `@custom:fhe-allow` parsing, validation, and resolution
//! (spec §8.8).
//!
//! [`collect`] turns the raw [`fhec_bind::PolicyDoc`] items the binder
//! carried through into a [`PolicyTable`] of fully resolved [`Policy`]
//! values, or refuses with FHE4005. Rules R4/R5 (`fhec-lower`) transcribe
//! what a `Policy` says; nothing here decides an insertion, and nothing
//! here guesses — a reader path that cannot be resolved by the five
//! resolution rules is refused, never silently dropped (spec §1.3).

use std::collections::HashMap;

use fhec_bind::{
    BoundUnit, ContractId, EventId, FileId, Resolution, TypeDeclId, TypeDeclKind, VarId,
};
use solar_ast as ast;
use solar_interface::{
    source_map::{FileName, SourceMap},
    BytePos, Span, Symbol,
};

use crate::decl::{declared_ty, nesting, Nesting};
use crate::diag::{codes, Diagnostic, Severity};
use crate::sites::CheckedUnit;
use crate::trust::Trust;
use crate::ty::{PlainTy, Ty};

// ---------------------------------------------------------------------------
// Resolved policy model
// ---------------------------------------------------------------------------

/// One key/index binder available at a policy's write sites, derived from
/// the target's own declared mapping/array nesting (spec §8.8 "Key
/// binding"): `mapping(address account => euint64)` yields one binder at
/// position 0 aliased `account`; a bare `mapping(uint256 => X)` yields one
/// binder with no alias; an array yields one binder with `is_array: true`
/// (spec's `index`).
#[derive(Clone, Debug)]
pub struct KeyBinder {
    /// 0-based position in the target's own mapping/array chain.
    pub position: usize,
    /// The Solidity-declared key name, when the mapping names one.
    pub alias: Option<String>,
    /// True for an array index binder (`index`); false for a mapping key
    /// (`key`/`key0`/`key1`/...).
    pub is_array: bool,
}

/// Where a policy's `target` lives (spec §8.8 "Placement").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PolicyOwner {
    /// Attached to a state variable; `target` names that variable itself.
    StateVar(VarId),
    /// Attached to a struct; `target` names one of its fields.
    Struct(TypeDeclId),
    /// Attached to an event; `target` names one of its parameters.
    Event(EventId),
}

/// A validated, resolved `@custom:fhe-allow` policy (spec §8.8).
#[derive(Clone, Debug)]
pub struct Policy {
    /// Where the target lives.
    pub owner: PolicyOwner,
    /// The declared target name (a variable, struct field, or event param).
    pub target: String,
    /// The key/index binders available at this policy's write sites, in
    /// position order; empty when the target's own declared type is not
    /// itself a mapping or array.
    pub keys: Vec<KeyBinder>,
    /// The reader list, or a gated/ungated `public`.
    pub readers: PolicyReaders,
    /// The encrypted type of the target itself, when its *own* declared
    /// type is directly encrypted (not reached through a mapping, array,
    /// or struct). `None` for every other shape — spec §8.11
    /// re-application needs this to know the target is nameable by its own
    /// bare name alone, with no key or field access to add.
    pub direct_value_ty: Option<fhec_ir::EType>,
    /// Anchor span for diagnostics and for R4/R5 fix-it/note placement (the
    /// doc-comment tag).
    pub span: Span,
}

/// A policy's reader list (spec §8.8 grammar `readers`).
#[derive(Clone, Debug)]
pub enum PolicyReaders {
    /// `public`, optionally gated (spec §8.11).
    Public {
        /// The `if <condition>` guard, when present.
        condition: Option<ReaderPath>,
    },
    /// An explicit reader list (`this`/paths), each rendered independently
    /// (spec §8.9).
    List(Vec<PolicyReader>),
}

/// One entry of an explicit (non-`public`) reader list.
#[derive(Clone, Debug)]
pub enum PolicyReader {
    /// `this` — the contract. R4/R5 always emit the unconditional
    /// `allowThis` first regardless (spec §8.9); a policy naming `this`
    /// explicitly produces no *second* call for it.
    This,
    /// A resolved path.
    Path(ReaderPath),
}

/// A resolved, typed reader path (spec §8.8 "Reader resolution").
#[derive(Clone, Debug)]
pub struct ReaderPath {
    /// What the path's first name resolved to.
    pub root: ReaderRoot,
    /// `.field` segments beyond the root, rendered verbatim: only the root
    /// is resolved against the five rules, and an invalid trailing field
    /// fails loudly at the solc gate rather than here.
    pub tail: Vec<String>,
    /// Anchor span for diagnostics.
    pub span: Span,
}

/// What a reader path's root name resolved to (spec §8.8 resolution rules
/// 1, 4, 5; rules 2–3 are the `this`/`public` literals handled before a
/// path is even parsed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReaderRoot {
    /// A positional binder: index into the owning [`Policy::keys`].
    Key(usize),
    /// `self` — the target location the write addresses.
    SelfRef,
    /// A sibling field of the struct the policy is attached to.
    SiblingField(String),
    /// A state variable elsewhere in the unit.
    StateVar(VarId),
    /// An event parameter (only for an event-attached policy).
    EventParam(String),
}

/// Every resolved policy in the unit, keyed for the lowerer's write-site and
/// emit-site lookups.
#[derive(Default)]
pub struct PolicyTable {
    /// Policies attached directly to a state variable.
    pub by_state_var: HashMap<VarId, Policy>,
    /// Policies attached to a struct, keyed by (struct, field name).
    pub by_struct_field: HashMap<(TypeDeclId, String), Policy>,
    /// Policies attached to an event, keyed by (event, parameter name).
    pub by_event_param: HashMap<(EventId, String), Policy>,
}

impl PolicyTable {
    /// Every policy declared on a given struct (spec §8.11 re-application:
    /// a write to any field a policy names may need to walk every policy of
    /// the same struct).
    pub fn struct_policies(&self, id: TypeDeclId) -> impl Iterator<Item = &Policy> {
        self.by_struct_field
            .iter()
            .filter(move |((t, _), _)| *t == id)
            .map(|(_, p)| p)
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Parses, validates, and resolves every `@custom:fhe-allow` policy in the
/// unit, pushing FHE4005 diagnostics for anything invalid and populating
/// `out.policies`.
pub(crate) fn collect(unit: &BoundUnit<'_>, trust: &Trust, sm: &SourceMap, out: &mut CheckedUnit) {
    let mut ctx = Ctx {
        unit,
        trust,
        diags: Vec::new(),
    };
    let mut accounted: Vec<u32> = Vec::new();

    for (_, contract) in unit.contracts() {
        for &vid in &contract.state_vars {
            let var = unit.var(vid);
            for doc in &var.policy_docs {
                accounted.push(doc.span.lo().0);
            }
            if var.policy_docs.is_empty() {
                continue;
            }
            if !refuse_if_not_dialect(&mut ctx, unit, var.file, &var.policy_docs) {
                continue;
            }
            let Some(name) = var.name else { continue };
            let tc = TargetCtx {
                owner: PolicyOwner::StateVar(vid),
                contract: Some(match unit.var(vid).owner {
                    fhec_bind::VarOwner::State(c) => c,
                    _ => continue,
                }),
                file: var.file,
                target_name: name.as_str().to_string(),
                keys: key_chain(&var.decl.ty),
                struct_ast: None,
                event_ast: None,
            };
            let target_ty = declared_ty(unit, trust, &var.decl.ty);
            let mut seen: Vec<String> = Vec::new();
            for doc in &var.policy_docs {
                if doc.key != "allow" {
                    ctx.refuse(
                        doc.span,
                        format!(
                            "unrecognized `@custom:fhe-{}` tag (spec §8.8 restriction 3): only \
                             `@custom:fhe-allow` is defined",
                            doc.key
                        ),
                    );
                    continue;
                }
                if let Some(policy) = build_policy(&mut ctx, &tc, &target_ty, doc, &mut seen) {
                    out.policies.by_state_var.insert(vid, policy);
                }
            }
        }
    }

    for (tid, td) in unit.type_decls() {
        for doc in &td.policy_docs {
            accounted.push(doc.span.lo().0);
        }
        if td.policy_docs.is_empty() {
            continue;
        }
        let TypeDeclKind::Struct(s) = &td.kind else {
            for doc in &td.policy_docs {
                ctx.refuse(
                    doc.span,
                    "a reader policy may only be attached to a state variable, a struct, or an \
                     event declaration (spec §8.8)"
                        .to_string(),
                );
            }
            continue;
        };
        if !refuse_if_not_dialect(&mut ctx, unit, td.file, &td.policy_docs) {
            continue;
        }
        let mut seen: Vec<String> = Vec::new();
        for doc in &td.policy_docs {
            if doc.key != "allow" {
                ctx.refuse(
                    doc.span,
                    format!(
                        "unrecognized `@custom:fhe-{}` tag (spec §8.8 restriction 3): only \
                         `@custom:fhe-allow` is defined",
                        doc.key
                    ),
                );
                continue;
            }
            let Some((target_name, readers_text)) = split_target_readers(&doc.content) else {
                ctx.refuse(
                    doc.span,
                    "malformed policy: expected `<target>: <readers>` (spec §8.8 grammar)"
                        .to_string(),
                );
                continue;
            };
            let Some(field) = s
                .fields
                .iter()
                .find(|f| f.name.is_some_and(|n| n.as_str() == target_name))
            else {
                ctx.refuse(
                    doc.span,
                    format!(
                        "target `{target_name}` does not name a field of this struct (spec §8.8 \
                         restriction 4)"
                    ),
                );
                continue;
            };
            if seen.iter().any(|s| s == target_name) {
                ctx.refuse(
                    doc.span,
                    format!(
                        "duplicate policy target `{target_name}`: two policies on one \
                         declaration must not name the same target (spec §8.8 restriction 4)"
                    ),
                );
                continue;
            }
            let target_ty = declared_ty(unit, trust, &field.ty);
            match nesting(unit, trust, &target_ty) {
                Nesting::Encrypted(_) => {}
                _ => {
                    ctx.refuse(
                        doc.span,
                        format!(
                            "target `{target_name}`'s type contains no encrypted type, \
                             directly or through a mapping, array, or struct (spec §8.8 \
                             restriction 5)"
                        ),
                    );
                    continue;
                }
            }
            let tc = TargetCtx {
                owner: PolicyOwner::Struct(tid),
                contract: td.contract,
                file: td.file,
                target_name: target_name.to_string(),
                keys: key_chain(&field.ty),
                struct_ast: Some(s),
                event_ast: None,
            };
            let Some(readers) = parse_readers(&mut ctx, &tc, doc.span, readers_text) else {
                continue;
            };
            if !check_reapplication(&mut ctx, &tc, &readers, doc.span) {
                continue;
            }
            seen.push(target_name.to_string());
            out.policies.by_struct_field.insert(
                (tid, target_name.to_string()),
                Policy {
                    owner: tc.owner,
                    target: target_name.to_string(),
                    keys: tc.keys,
                    readers,
                    direct_value_ty: match &target_ty {
                        Ty::Encrypted(e) => Some(*e),
                        _ => None,
                    },
                    span: doc.span,
                },
            );
        }
    }

    for (eid, ev) in unit.events() {
        for doc in &ev.policy_docs {
            accounted.push(doc.span.lo().0);
        }
        if ev.policy_docs.is_empty() {
            continue;
        }
        if !refuse_if_not_dialect(&mut ctx, unit, ev.file, &ev.policy_docs) {
            continue;
        }
        let mut seen: Vec<String> = Vec::new();
        for doc in &ev.policy_docs {
            if doc.key != "allow" {
                ctx.refuse(
                    doc.span,
                    format!(
                        "unrecognized `@custom:fhe-{}` tag (spec §8.8 restriction 3): only \
                         `@custom:fhe-allow` is defined",
                        doc.key
                    ),
                );
                continue;
            }
            let Some((target_name, readers_text)) = split_target_readers(&doc.content) else {
                ctx.refuse(
                    doc.span,
                    "malformed policy: expected `<target>: <readers>` (spec §8.8 grammar)"
                        .to_string(),
                );
                continue;
            };
            let Some(param) = ev
                .ast
                .parameters
                .vars
                .iter()
                .find(|p| p.name.is_some_and(|n| n.as_str() == target_name))
            else {
                ctx.refuse(
                    doc.span,
                    format!(
                        "target `{target_name}` does not name a parameter of this event (spec \
                         §8.8 restriction 4)"
                    ),
                );
                continue;
            };
            if seen.iter().any(|s| s == target_name) {
                ctx.refuse(
                    doc.span,
                    format!(
                        "duplicate policy target `{target_name}`: two policies on one \
                         declaration must not name the same target (spec §8.8 restriction 4)"
                    ),
                );
                continue;
            }
            let target_ty = declared_ty(unit, trust, &param.ty);
            match nesting(unit, trust, &target_ty) {
                Nesting::Encrypted(_) => {}
                _ => {
                    ctx.refuse(
                        doc.span,
                        format!(
                            "target `{target_name}`'s type contains no encrypted type (spec \
                             §8.8 restriction 5)"
                        ),
                    );
                    continue;
                }
            }
            let tc = TargetCtx {
                owner: PolicyOwner::Event(eid),
                contract: ev.contract,
                file: ev.file,
                target_name: target_name.to_string(),
                keys: key_chain(&param.ty),
                struct_ast: None,
                event_ast: Some(ev.ast),
            };
            let Some(readers) = parse_readers(&mut ctx, &tc, doc.span, readers_text) else {
                continue;
            };
            if !check_reapplication(&mut ctx, &tc, &readers, doc.span) {
                continue;
            }
            seen.push(target_name.to_string());
            out.policies.by_event_param.insert(
                (eid, target_name.to_string()),
                Policy {
                    owner: tc.owner,
                    target: target_name.to_string(),
                    keys: tc.keys,
                    readers,
                    direct_value_ty: match &target_ty {
                        Ty::Encrypted(e) => Some(*e),
                        _ => None,
                    },
                    span: doc.span,
                },
            );
        }
    }

    accounted.sort_unstable();
    scan_for_orphaned_tags(unit, sm, &accounted, &mut ctx.diags);

    out.diagnostics.append(&mut ctx.diags);
}

/// Refuses (restriction 2) every doc on a declaration outside a `.fsol`
/// file. Returns whether collection should continue for this declaration.
fn refuse_if_not_dialect(
    ctx: &mut Ctx,
    unit: &BoundUnit<'_>,
    file: FileId,
    docs: &[fhec_bind::PolicyDoc],
) -> bool {
    if is_dialect_file(unit, file) {
        return true;
    }
    for doc in docs {
        ctx.refuse(
            doc.span,
            "a reader policy in a `.sol` file can never take effect: `.sol` files are never \
             rewritten (spec §1.4, §8.8 restriction 2), so the grants it states would never be \
             emitted"
                .to_string(),
        );
    }
    false
}

fn is_dialect_file(unit: &BoundUnit<'_>, file: FileId) -> bool {
    unit.files()
        .find(|(id, _)| *id == file)
        .is_some_and(|(_, name)| name.ends_with(".fsol"))
}

// ---------------------------------------------------------------------------
// Shared validation context
// ---------------------------------------------------------------------------

struct Ctx<'a, 'ast> {
    unit: &'a BoundUnit<'ast>,
    trust: &'a Trust,
    diags: Vec<Diagnostic>,
}

impl Ctx<'_, '_> {
    fn refuse(&mut self, span: Span, message: String) {
        self.diags.push(Diagnostic {
            code: codes::ACL_POLICY_INVALID,
            severity: Severity::Error,
            span,
            message,
            fixits: Vec::new(),
            rule: Some("§8.8"),
        });
    }
}

/// Everything about the declaration a policy is attached to, needed to
/// resolve its readers.
struct TargetCtx<'ast> {
    owner: PolicyOwner,
    contract: Option<ContractId>,
    file: FileId,
    target_name: String,
    keys: Vec<KeyBinder>,
    struct_ast: Option<&'ast ast::ItemStruct<'ast>>,
    event_ast: Option<&'ast ast::ItemEvent<'ast>>,
}

impl<'ast> TargetCtx<'ast> {
    fn sibling_field(&self, name: &str) -> Option<&'ast ast::VariableDefinition<'ast>> {
        self.struct_ast?
            .fields
            .iter()
            .find(|f| f.name.is_some_and(|n| n.as_str() == name))
    }

    fn event_param(&self, name: &str) -> Option<&'ast ast::VariableDefinition<'ast>> {
        self.event_ast?
            .parameters
            .vars
            .iter()
            .find(|p| p.name.is_some_and(|n| n.as_str() == name))
    }

    fn is_self_reference(&self, root: &ReaderRoot) -> bool {
        match (self.owner, root) {
            (PolicyOwner::StateVar(vid), ReaderRoot::StateVar(v2)) => vid == *v2,
            (PolicyOwner::Struct(_), ReaderRoot::SiblingField(name)) => *name == self.target_name,
            (PolicyOwner::Event(_), ReaderRoot::EventParam(name)) => *name == self.target_name,
            _ => false,
        }
    }
}

/// Builds and validates one state-variable-attached policy from a doc item.
/// State-variable placement is the one case where `target` has only one
/// legal spelling (the variable's own name), so this handles both restriction
/// 4's "kind" check and its "no duplicate target" check via `seen`.
fn build_policy<'ast>(
    ctx: &mut Ctx<'_, 'ast>,
    tc: &TargetCtx<'ast>,
    target_ty: &Ty,
    doc: &fhec_bind::PolicyDoc,
    seen: &mut Vec<String>,
) -> Option<Policy> {
    let Some((target_name, readers_text)) = split_target_readers(&doc.content) else {
        ctx.refuse(
            doc.span,
            "malformed policy: expected `<target>: <readers>` (spec §8.8 grammar)".to_string(),
        );
        return None;
    };
    if target_name != tc.target_name {
        ctx.refuse(
            doc.span,
            format!(
                "target `{target_name}` must name the state variable this policy is attached \
                 to (`{}`) (spec §8.8 restriction 4)",
                tc.target_name
            ),
        );
        return None;
    }
    if seen.iter().any(|s| s == target_name) {
        ctx.refuse(
            doc.span,
            format!(
                "duplicate policy target `{target_name}`: two policies on one declaration must \
                 not name the same target (spec §8.8 restriction 4)"
            ),
        );
        return None;
    }
    match nesting(ctx.unit, ctx.trust, target_ty) {
        Nesting::Encrypted(_) => {}
        _ => {
            ctx.refuse(
                doc.span,
                format!(
                    "target `{target_name}`'s type contains no encrypted type, directly or \
                     through a mapping, array, or struct (spec §8.8 restriction 5)"
                ),
            );
            return None;
        }
    }
    let readers = parse_readers(ctx, tc, doc.span, readers_text)?;
    if !check_reapplication(ctx, tc, &readers, doc.span) {
        return None;
    }
    seen.push(target_name.to_string());
    Some(Policy {
        owner: tc.owner,
        target: target_name.to_string(),
        keys: tc.keys.clone(),
        readers,
        direct_value_ty: match target_ty {
            Ty::Encrypted(e) => Some(*e),
            _ => None,
        },
        span: doc.span,
    })
}

// ---------------------------------------------------------------------------
// Grammar parsing
// ---------------------------------------------------------------------------

fn split_target_readers(content: &str) -> Option<(&str, &str)> {
    let idx = content.find(':')?;
    let target = content[..idx].trim();
    let readers = content[idx + 1..].trim();
    if target.is_empty() || readers.is_empty() || !is_ident(target) {
        return None;
    }
    Some((target, readers))
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

fn is_ident_char(c: char, first: bool) -> bool {
    if first {
        c.is_ascii_alphabetic() || c == '_' || c == '$'
    } else {
        c.is_ascii_alphanumeric() || c == '_' || c == '$'
    }
}

/// One segment of a `path` beyond its root name.
enum PathSeg {
    Field(String),
    /// `[subscript]` — accepted syntactically so a malformed one gets a
    /// clear diagnostic, but always refused during resolution: no spec
    /// example needs a bracketed reader-path segment, and guessing what it
    /// should bind to would not be a transcription (spec §1.3, documented
    /// scope decision).
    Index(#[allow(dead_code)] String),
}

/// Parses `path := name ( '.' name | '[' subscript ']' )*`.
fn parse_path(s: &str) -> Option<(String, Vec<PathSeg>)> {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    if bytes.is_empty() || !is_ident_char(s.chars().next()?, true) {
        return None;
    }
    while i < bytes.len() && is_ident_char(bytes[i] as char, i == 0) {
        i += 1;
    }
    let root = s[..i].to_string();
    let mut segs = Vec::new();
    while i < bytes.len() {
        match bytes[i] {
            b'.' => {
                i += 1;
                let start = i;
                while i < bytes.len() && is_ident_char(bytes[i] as char, i == start) {
                    i += 1;
                }
                if i == start {
                    return None;
                }
                segs.push(PathSeg::Field(s[start..i].to_string()));
            }
            b'[' => {
                i += 1;
                let start = i;
                while i < bytes.len() && is_ident_char(bytes[i] as char, i == start) {
                    i += 1;
                }
                if i == start || i >= bytes.len() || bytes[i] != b']' {
                    return None;
                }
                segs.push(PathSeg::Index(s[start..i].to_string()));
                i += 1;
            }
            _ => return None,
        }
    }
    Some((root, segs))
}

fn parse_readers<'ast>(
    ctx: &mut Ctx<'_, 'ast>,
    tc: &TargetCtx<'ast>,
    span: Span,
    readers_text: &str,
) -> Option<PolicyReaders> {
    let parts: Vec<&str> = readers_text.split(',').map(str::trim).collect();
    if parts.iter().any(|p| p.is_empty()) {
        ctx.refuse(
            span,
            "empty reader in a comma-separated reader list (spec §8.8 grammar)".to_string(),
        );
        return None;
    }
    let is_public =
        |p: &str| p == "public" || p.starts_with("public ") || p.starts_with("public\t");
    if parts.iter().any(|p| is_public(p)) {
        if parts.len() != 1 {
            ctx.refuse(
                span,
                "`public` must be the only reader in its list (spec §8.8 restriction 7)"
                    .to_string(),
            );
            return None;
        }
        let p = parts[0];
        if p == "public" {
            return Some(PolicyReaders::Public { condition: None });
        }
        let rest = p["public".len()..].trim_start();
        let Some(cond_text) = rest.strip_prefix("if") else {
            ctx.refuse(
                span,
                format!(
                    "malformed `public` reader `{p}` (spec §8.8 grammar: `public [ 'if' \
                     condition ]`)"
                ),
            );
            return None;
        };
        let cond_text = cond_text.trim();
        if cond_text.is_empty() {
            ctx.refuse(
                span,
                "`public if` requires a condition path (spec §8.8)".to_string(),
            );
            return None;
        }
        let cond = resolve_condition(ctx, tc, span, cond_text)?;
        return Some(PolicyReaders::Public {
            condition: Some(cond),
        });
    }

    let mut readers = Vec::new();
    for p in parts {
        if p == "this" {
            readers.push(PolicyReader::This);
            continue;
        }
        let path = resolve_reader_path(ctx, tc, span, p)?;
        readers.push(PolicyReader::Path(path));
    }
    Some(PolicyReaders::List(readers))
}

fn resolve_reader_path<'ast>(
    ctx: &mut Ctx<'_, 'ast>,
    tc: &TargetCtx<'ast>,
    span: Span,
    text: &str,
) -> Option<ReaderPath> {
    let Some((root_text, segs)) = parse_path(text) else {
        ctx.refuse(
            span,
            format!("malformed reader path `{text}` (spec §8.8 grammar)"),
        );
        return None;
    };
    if segs.iter().any(|s| matches!(s, PathSeg::Index(_))) {
        ctx.refuse(
            span,
            format!(
                "reader path `{text}` uses a bracketed subscript, which this revision does not \
                 support (spec §8.8); write the reader as a plain name or `name.field` chain"
            ),
        );
        return None;
    }
    let tail: Vec<String> = segs
        .into_iter()
        .map(|s| match s {
            PathSeg::Field(f) => f,
            PathSeg::Index(_) => unreachable!("refused above"),
        })
        .collect();
    let root = resolve_root(ctx, tc, span, &root_text)?;
    let path = ReaderPath { root, tail, span };
    if tc.is_self_reference(&path.root) && path.tail.is_empty() {
        ctx.refuse(
            span,
            format!("reader path `{text}` names the target itself (spec §8.8 restriction 8)"),
        );
        return None;
    }
    Some(path)
}

fn resolve_condition<'ast>(
    ctx: &mut Ctx<'_, 'ast>,
    tc: &TargetCtx<'ast>,
    span: Span,
    text: &str,
) -> Option<ReaderPath> {
    let path = resolve_reader_path(ctx, tc, span, text)?;
    match &path.root {
        ReaderRoot::Key(_) | ReaderRoot::SelfRef => {
            ctx.refuse(
                span,
                "a `public if` condition must resolve to an event parameter, a state variable, \
                 or a struct sibling field of type `bool` — a bound key or `self` cannot (spec \
                 §8.8, §8.11)"
                    .to_string(),
            );
            return None;
        }
        _ => {}
    }
    if path.tail.is_empty() {
        let declared = match &path.root {
            ReaderRoot::StateVar(vid) => Some(declared_ty(
                ctx.unit,
                ctx.trust,
                &ctx.unit.var(*vid).decl.ty,
            )),
            ReaderRoot::SiblingField(name) => tc
                .sibling_field(name)
                .map(|f| declared_ty(ctx.unit, ctx.trust, &f.ty)),
            ReaderRoot::EventParam(name) => tc
                .event_param(name)
                .map(|p| declared_ty(ctx.unit, ctx.trust, &p.ty)),
            _ => None,
        };
        if let Some(ty) = declared {
            if ty != Ty::Plain(PlainTy::Bool) {
                ctx.refuse(
                    span,
                    "a `public if` condition must type as `bool` (spec §8.8, §8.11)".to_string(),
                );
                return None;
            }
        }
    }
    Some(path)
}

/// Resolves a reader path's root name (spec §8.8 "Reader resolution" rules
/// 1, 4, 5; restriction 6).
fn resolve_root<'ast>(
    ctx: &mut Ctx<'_, 'ast>,
    tc: &TargetCtx<'ast>,
    span: Span,
    root_text: &str,
) -> Option<ReaderRoot> {
    if root_text == "self" {
        return Some(ReaderRoot::SelfRef);
    }
    if let Some(pos) = resolve_key_binder(tc, root_text) {
        return Some(ReaderRoot::Key(pos));
    }
    if matches!(tc.owner, PolicyOwner::Event(_)) && tc.event_param(root_text).is_some() {
        return Some(ReaderRoot::EventParam(root_text.to_string()));
    }
    if matches!(tc.owner, PolicyOwner::Struct(_)) && tc.sibling_field(root_text).is_some() {
        return Some(ReaderRoot::SiblingField(root_text.to_string()));
    }
    let sym = Symbol::intern(root_text);
    let res = ctx
        .unit
        .resolve_name_in_scope(None, tc.contract, tc.file, sym, root_text);
    if let Resolution::StateVar(vid) = res {
        return Some(ReaderRoot::StateVar(vid));
    }
    if matches!(root_text, "msg" | "tx" | "block") {
        let is_builtin = matches!(&res, Resolution::Builtin(b) if b.0 == root_text)
            || matches!(
                Trust::unwrap_fallback(&res),
                Resolution::Builtin(b) if b.0 == root_text
            );
        if is_builtin {
            ctx.refuse(
                span,
                format!(
                    "reader path root `{root_text}` is the `{root_text}` builtin, refused \
                     inside a reader list (spec §8.8 restriction 6): a policy naming the caller \
                     would apply to every write of the target, including one made on another \
                     account's behalf"
                ),
            );
            return None;
        }
    }
    ctx.refuse(
        span,
        format!(
            "reader path root `{root_text}` does not resolve to a bound key/index, `self`, a \
             sibling field, an event parameter, or a state variable (spec §8.8)"
        ),
    );
    None
}

/// Spec §8.11: a mapping/array target has no key to re-apply with, so a
/// reader naming mutable state on one is forward-only. Returns `false` when
/// the policy must be refused (a gated `public if` on such a target — a
/// disclosure that could never actually re-fire); pushes the FHE4007
/// warning and returns `true` otherwise (the policy stays legal).
fn check_reapplication(
    ctx: &mut Ctx,
    tc: &TargetCtx<'_>,
    readers: &PolicyReaders,
    span: Span,
) -> bool {
    if tc.keys.is_empty() {
        return true; // not a mapping/array target: re-application has a key to bind, always
    }
    match readers {
        PolicyReaders::Public {
            condition: Some(cond),
        } => {
            let Some(name) = mutable_state_name(ctx.unit, &cond.root) else {
                return true;
            };
            ctx.diags.push(Diagnostic {
                code: codes::ACL_POLICY_NOT_REAPPLICABLE,
                severity: Severity::Error,
                span,
                message: format!(
                    "a `public if {name}` gate on a mapping/array target can never re-apply: \
                     re-application requires a key this policy's own writes do not carry, so \
                     the write that flips `{name}` would be the only site that ever publishes \
                     — and it is not a site of this policy at all (spec §8.11)"
                ),
                fixits: Vec::new(),
                rule: Some("§8.11"),
            });
            false
        }
        PolicyReaders::Public { condition: None } => true,
        PolicyReaders::List(list) => {
            for reader in list {
                let PolicyReader::Path(p) = reader else {
                    continue;
                };
                if let Some(name) = mutable_state_name(ctx.unit, &p.root) {
                    ctx.diags.push(Diagnostic {
                        code: codes::ACL_POLICY_NOT_REAPPLICABLE,
                        severity: Severity::Warning,
                        span,
                        message: format!(
                            "reader `{name}` names mutable state, but this policy's target is \
                             a mapping/array: the transpiler cannot enumerate its keys, so a \
                             write to `{name}` cannot re-apply the grant to handles already \
                             written. The policy is forward-only — it grants on handles \
                             written from now on; backfilling past handles is only possible \
                             off-chain (spec §8.11)"
                        ),
                        fixits: Vec::new(),
                        rule: Some("§8.11"),
                    });
                }
            }
            true
        }
    }
}

/// The name of the mutable state `root` names, when re-application would
/// need to reach it: a non-`constant`/`immutable` state variable, or any
/// struct sibling field (Solidity has no constant/immutable struct field).
/// A bound key, `self`, and an event parameter are not "state" in the
/// re-application sense — nothing writes them independently of the policy's
/// own write sites.
fn mutable_state_name(unit: &BoundUnit<'_>, root: &ReaderRoot) -> Option<String> {
    match root {
        ReaderRoot::StateVar(vid) => {
            let var = unit.var(*vid);
            (var.decl.mutability.is_none())
                .then(|| var.name.map(|n| n.as_str().to_string()))
                .flatten()
        }
        ReaderRoot::SiblingField(name) => Some(name.clone()),
        ReaderRoot::Key(_) | ReaderRoot::SelfRef | ReaderRoot::EventParam(_) => None,
    }
}

fn resolve_key_binder(tc: &TargetCtx<'_>, root_text: &str) -> Option<usize> {
    if root_text == "key" {
        return tc
            .keys
            .iter()
            .find(|k| k.position == 0 && !k.is_array)
            .map(|k| k.position);
    }
    if root_text == "index" {
        return tc.keys.iter().find(|k| k.is_array).map(|k| k.position);
    }
    if let Some(n) = root_text.strip_prefix("key") {
        if let Ok(pos) = n.parse::<usize>() {
            return tc
                .keys
                .iter()
                .find(|k| k.position == pos && !k.is_array)
                .map(|k| k.position);
        }
    }
    tc.keys
        .iter()
        .find(|k| k.alias.as_deref() == Some(root_text))
        .map(|k| k.position)
}

/// Peels a declared type's mapping/array layers into key binders (spec
/// §8.8 "Key binding"), stopping at the first non-container type (an
/// encrypted leaf or a struct — either way, further access is via `self`).
fn key_chain(ty: &ast::Type<'_>) -> Vec<KeyBinder> {
    let mut out = Vec::new();
    let mut cur = ty;
    loop {
        match &cur.kind {
            ast::TypeKind::Mapping(m) => {
                out.push(KeyBinder {
                    position: out.len(),
                    alias: m.key_name.map(|n| n.as_str().to_string()),
                    is_array: false,
                });
                cur = &m.value;
            }
            ast::TypeKind::Array(a) => {
                out.push(KeyBinder {
                    position: out.len(),
                    alias: None,
                    is_array: true,
                });
                cur = &a.element;
            }
            _ => break,
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Restriction 1: raw-source scan for an orphaned `@custom:fhe-*` tag
// ---------------------------------------------------------------------------

/// Scans every file's raw source for `custom:fhe-` occurrences (the `@` is
/// excluded to match [`solar_ast::NatSpecKind::Custom`]'s span convention)
/// that no collected [`fhec_bind::PolicyDoc`] accounts for: a policy
/// written in an ordinary (non-doc) comment, or a genuine doc comment
/// attached to a declaration kind §8.8 does not cover (spec §8.8
/// restriction 1). `accounted` is sorted.
fn scan_for_orphaned_tags(
    unit: &BoundUnit<'_>,
    sm: &SourceMap,
    accounted: &[u32],
    diags: &mut Vec<Diagnostic>,
) {
    const NEEDLE: &str = "custom:fhe-";
    for (_, name) in unit.files() {
        let Some(sf) = sm
            .get_file(FileName::Custom(name.to_string()))
            .or_else(|| sm.get_file(FileName::Real(std::path::PathBuf::from(name))))
        else {
            continue;
        };
        let text = sf.src.as_str();
        let mut cursor = 0usize;
        while let Some(rel) = text[cursor..].find(NEEDLE) {
            let pos = cursor + rel;
            let global = sf.start_pos.0 + pos as u32;
            if accounted.binary_search(&global).is_err() {
                let word_end = text[pos..]
                    .find(|c: char| c.is_whitespace() || c == '*' || c == '/')
                    .map(|o| pos + o)
                    .unwrap_or(text.len());
                let span = Span::new(BytePos(global), BytePos(sf.start_pos.0 + word_end as u32));
                diags.push(Diagnostic {
                    code: codes::ACL_POLICY_INVALID,
                    severity: Severity::Error,
                    span,
                    message: "a `@custom:fhe-*` tag here has no effect: it must be a doc \
                              comment (`///` or `/** */`) attached directly to a state \
                              variable, a struct, or an event declaration — not an ordinary \
                              comment, and not a doc comment on another kind of declaration \
                              (spec §8.8 restriction 1)"
                        .to_string(),
                    fixits: Vec::new(),
                    rule: Some("§8.8"),
                });
            }
            cursor = pos + NEEDLE.len();
        }
    }
}
