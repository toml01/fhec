//! Binding a reader policy to a concrete write or emit site (spec §8.9,
//! §8.10): matching a decomposed lvalue/argument against a policy's target
//! and rendering its readers to concrete Solidity text at that site.
//!
//! This module never guesses: a shape it cannot decompose, or a reader
//! whose current-scope resolution the emit-time twin of source-name
//! resolution cannot confirm, is refused with FHE4006 rather than rendered
//! on faith (spec §1.3).

use fhec_bind::{FunctionId, Resolution, TypeDeclId, VarId, VarOwner};
use fhec_check::{Policy, PolicyReader, PolicyReaders, ReaderRoot};
use solar_ast as ast;
use solar_interface::Span;

use crate::ctx::{strip_parens, Ctx};
use crate::expr::{call_arg_exprs, fail_coded, LowerFailure, Result};
use crate::pass_acl::{writes_to, WriteTarget};

/// One step of a decomposed lvalue path, in source (outer-to-inner) order.
enum Step {
    Field(String),
    Key(String),
}

/// A write's lvalue, decomposed to a root declaration plus an ordered step
/// list (spec §8.9 "Binding at the write site").
struct Decomposed {
    /// The state variable, or the storage-pointer local/param, the path is
    /// rooted at.
    root_var: VarId,
    /// The root's own rendered text (its declared name).
    root_text: String,
    is_pointer: bool,
    steps: Vec<Step>,
}

/// What [`bind_write`] found for one encrypted storage write.
pub(crate) struct BoundWrite<'p> {
    pub policy: &'p Policy,
    pub self_text: String,
    /// Rendered text for each of the policy's own key/index binders, in
    /// position order.
    pub key_texts: Vec<String>,
}

/// Decomposes `lvalue`'s AST and matches it against the unit's policies
/// (spec §8.9). Returns:
/// - `Ok(Some(bound))` when a policy governs this write and was bound;
/// - `Ok(None)` when no policy applies (the ordinary R1 path continues
///   unchanged);
/// - `Err` (FHE4006) when a policy is known to target the struct this
///   write's root local's *declared type* names, but the local cannot be
///   proven to be the single, unconditionally-bound ERC-7201 pointer spec
///   §8.9 requires to bind through it safely.
pub(crate) fn bind_write<'p, 'ast>(
    ctx: &Ctx<'_, 'ast>,
    checked_policies: &'p fhec_check::PolicyTable,
    function: FunctionId,
    lvalue: &'ast ast::Expr<'ast>,
) -> Result<Option<BoundWrite<'p>>> {
    let Some(decomposed) = decompose(ctx, function, lvalue) else {
        return Ok(None);
    };
    bind_decomposed(ctx, checked_policies, function, lvalue.span, &decomposed)
}

fn bind_decomposed<'p, 'ast>(
    ctx: &Ctx<'_, 'ast>,
    checked_policies: &'p fhec_check::PolicyTable,
    function: FunctionId,
    site_span: Span,
    decomposed: &Decomposed,
) -> Result<Option<BoundWrite<'p>>> {
    if !decomposed.is_pointer {
        let Some(policy) = checked_policies.by_state_var.get(&decomposed.root_var) else {
            return Ok(None);
        };
        let (self_text, key_texts) =
            render_self_and_keys(&decomposed.root_text, &decomposed.steps, policy)?;
        return Ok(Some(BoundWrite {
            policy,
            self_text,
            key_texts,
        }));
    }

    // A storage-pointer root: policies attach to *fields* of the struct it
    // points to, so the first step must be exactly `Field(name)`.
    let Some(struct_ty) = declared_struct(ctx, ctx.unit.var(decomposed.root_var)) else {
        return Ok(None);
    };
    let Some(Step::Field(field)) = decomposed.steps.first() else {
        return Ok(None);
    };
    let Some(policy) = checked_policies
        .by_struct_field
        .get(&(struct_ty, field.clone()))
    else {
        return Ok(None);
    };
    // A policy targets this struct's field: the pointer MUST be provably
    // bindable, or a fault this write reaches is silently left unreadable.
    if !is_bindable_storage_pointer(ctx, function, decomposed.root_var) {
        return fail_coded(
            site_span,
            format!(
                "`{}` carries a reader policy on field `{field}`, but the storage pointer \
                 `{}` cannot be proven to resolve to it: it must be assigned exactly once, \
                 from a call to a parameterless function or from a state variable, and never \
                 reassigned or conditionally bound (spec §8.9)",
                ctx.unit.type_decl(struct_ty).name,
                decomposed.root_text
            ),
            "FHE4006",
            Some("§8.9"),
        );
    }
    let self_root = format!("{}.{field}", decomposed.root_text);
    let (self_text, key_texts) = render_self_and_keys(&self_root, &decomposed.steps[1..], policy)?;
    Ok(Some(BoundWrite {
        policy,
        self_text,
        key_texts,
    }))
}

/// Splits `steps` into the policy's own leading key binders (rendered onto
/// `root_text` to produce `self`) and consumes exactly that many: the
/// target's own mapping/array nesting is a prefix of every write beneath it
/// (spec §8.8 "Key binding").
fn render_self_and_keys(
    root_text: &str,
    steps: &[Step],
    policy: &Policy,
) -> Result<(String, Vec<String>)> {
    let mut self_text = root_text.to_string();
    let mut key_texts = Vec::new();
    for (i, step) in steps.iter().enumerate() {
        if i >= policy.keys.len() {
            break;
        }
        match step {
            Step::Key(text) => {
                self_text.push('[');
                self_text.push_str(text);
                self_text.push(']');
                key_texts.push(text.clone());
            }
            Step::Field(_) => {
                // The target's own type has fewer container layers than a
                // policy's `keys` implies a struct member reached this
                // write before all its own keys were consumed — impossible
                // given `keys` is derived from the same declared type
                // (`key_chain`), so this branch never runs in practice; the
                // safe answer is still to stop rather than guess.
                break;
            }
        }
    }
    Ok((self_text, key_texts))
}

// ---------------------------------------------------------------------------
// Decomposition
// ---------------------------------------------------------------------------

fn decompose<'ast>(
    ctx: &Ctx<'_, 'ast>,
    function: FunctionId,
    e: &'ast ast::Expr<'ast>,
) -> Option<Decomposed> {
    match &e.peel_parens().kind {
        ast::ExprKind::Ident(id) => match ctx.unit.resolve(*id) {
            Some(Resolution::StateVar(v)) => Some(Decomposed {
                root_var: *v,
                root_text: strip_parens(&ctx.snippet(e.span)).to_string(),
                is_pointer: false,
                steps: Vec::new(),
            }),
            Some(Resolution::Local(v)) | Some(Resolution::Param(v)) => {
                if ctx.unit.var(*v).decl.data_location != Some(ast::DataLocation::Storage) {
                    return None;
                }
                let _ = function;
                Some(Decomposed {
                    root_var: *v,
                    root_text: strip_parens(&ctx.snippet(e.span)).to_string(),
                    is_pointer: true,
                    steps: Vec::new(),
                })
            }
            _ => None,
        },
        ast::ExprKind::Member(base, name) => {
            let mut d = decompose(ctx, function, base)?;
            d.steps.push(Step::Field(name.to_string()));
            Some(d)
        }
        ast::ExprKind::Index(base, ast::IndexKind::Index(Some(k))) => {
            let mut d = decompose(ctx, function, base)?;
            d.steps
                .push(Step::Key(strip_parens(&ctx.snippet(k.span)).to_string()));
            Some(d)
        }
        _ => None,
    }
}

/// The struct type declaration a variable's own declared type names
/// (`Storage storage $` → `Storage`), when it is a single-identifier custom
/// type resolving to a struct.
fn declared_struct(ctx: &Ctx<'_, '_>, var: &fhec_bind::VarInfo<'_>) -> Option<TypeDeclId> {
    struct_of(ctx, &var.decl.ty)
}

fn struct_of(ctx: &Ctx<'_, '_>, ty: &ast::Type<'_>) -> Option<TypeDeclId> {
    let ast::TypeKind::Custom(path) = &ty.kind else {
        return None;
    };
    let first = path.segments().first()?;
    match ctx.unit.resolve_span(first.span)? {
        Resolution::TypeName(id) => match &ctx.unit.type_decl(*id).kind {
            fhec_bind::TypeDeclKind::Struct(_) => Some(*id),
            _ => None,
        },
        _ => None,
    }
}

/// Spec §8.9 "Binding at the write site": a storage-pointer local assigned
/// exactly once in the function, from a call to a parameterless function or
/// from a state variable, unconditionally (a direct element of the
/// function's top-level statement list), and never reassigned.
fn is_bindable_storage_pointer(ctx: &Ctx<'_, '_>, function: FunctionId, var: VarId) -> bool {
    let info = ctx.unit.var(var);
    if !matches!(info.owner, VarOwner::Local(_)) {
        return false; // a `... storage` function parameter has no single-assignment proof
    }
    let Some(init) = &info.decl.initializer else {
        return false;
    };
    let ok_source = match &init.peel_parens().kind {
        ast::ExprKind::Ident(id) => {
            matches!(ctx.unit.resolve(*id), Some(Resolution::StateVar(_)))
        }
        ast::ExprKind::Call(callee, args) => {
            call_arg_exprs(args).is_empty()
                && match &callee.peel_parens().kind {
                    ast::ExprKind::Ident(id) => matches!(
                        ctx.unit.resolve(*id),
                        Some(Resolution::Function(fids))
                            if fids.len() == 1 && ctx.unit.function(fids[0]).params.is_empty()
                    ),
                    _ => false,
                }
        }
        _ => false,
    };
    if !ok_source {
        return false;
    }
    let Some(body) = ctx.unit.function(function).ast.body.as_ref() else {
        return false;
    };
    let declared_at_top_level = body
        .iter()
        .any(|s| matches!(&s.kind, ast::StmtKind::DeclSingle(v) if v.span == info.decl.span));
    if !declared_at_top_level {
        return false; // declared inside a nested block/branch: conditionally bound
    }
    !body
        .iter()
        .any(|s| writes_to(ctx, s, WriteTarget::Var { name: "", id: var }))
}

// ---------------------------------------------------------------------------
// Rendering a resolved reader to concrete text (spec §8.9)
// ---------------------------------------------------------------------------

/// One reader ready to render: `None` for `this` (R4/R5 emit its
/// unconditional `allowThis` separately and unconditionally).
pub(crate) enum RenderedReader {
    Named {
        text: String,
        is_const_nonzero: bool,
    },
}

/// Renders every reader of a policy at a bound write/emit site to concrete
/// address-expression text, re-confirming a bare state-variable reader's
/// name resolution at the *insertion* site (the emit-time twin of
/// source-name resolution, spec §1.3) so a shadowing local cannot silently
/// retarget the grant.
pub(crate) fn render_readers(
    ctx: &Ctx<'_, '_>,
    function: FunctionId,
    policy: &Policy,
    self_text: &str,
    key_texts: &[String],
) -> Result<PolicyRendering> {
    match &policy.readers {
        PolicyReaders::Public { condition } => {
            let cond = condition
                .as_ref()
                .map(|c| render_path(ctx, function, self_text, key_texts, c))
                .transpose()?;
            Ok(PolicyRendering::Public {
                condition: cond.map(|(text, _)| text),
            })
        }
        PolicyReaders::List(list) => {
            let mut out = Vec::new();
            for reader in list {
                match reader {
                    PolicyReader::This => {}
                    PolicyReader::Path(path) => {
                        let (text, is_const) =
                            render_path(ctx, function, self_text, key_texts, path)?;
                        out.push(RenderedReader::Named {
                            text,
                            is_const_nonzero: is_const,
                        });
                    }
                }
            }
            Ok(PolicyRendering::List(out))
        }
    }
}

pub(crate) enum PolicyRendering {
    Public { condition: Option<String> },
    List(Vec<RenderedReader>),
}

/// One R4/R5 grant, ready to splice as a statement (spec §8.9): `allowThis`
/// first and unconditionally, then every reader in policy order. Also used
/// for §8.6 dedupe matching (`fn_name`/`arg0`/`arg1` describe the *inner*
/// call, independent of any zero-address guard wrapping it).
pub(crate) struct CallLine {
    pub fn_name: String,
    pub arg0: String,
    pub arg1: Option<String>,
    /// The full statement text, guard included when the reader is not
    /// proven non-zero.
    pub text: String,
}

/// Renders the full R4/R5 grant sequence for one target handle: `allowThis`
/// unconditionally first, then the resolved readers. A `public` reader
/// renders `allowPublic` and replaces the whole list (spec §8.9).
pub(crate) fn render_call_lines(
    ctx: &Ctx<'_, '_>,
    target_span: Span,
    value_ty: fhec_ir::EType,
    target_text: &str,
    rendering: &PolicyRendering,
) -> Result<Vec<CallLine>> {
    let allow_this = ctx
        .profile
        .acl_fn_name(fhec_ir::FheOp::AllowThis)
        .unwrap_or_default();
    let this_call = ctx
        .profile
        .render_call(fhec_ir::FheOp::AllowThis, &[value_ty], &[target_text])
        .map_err(|e| internal(target_span, e))?;
    let mut out = vec![CallLine {
        fn_name: allow_this,
        arg0: target_text.to_string(),
        arg1: None,
        text: format!("{this_call};"),
    }];

    match rendering {
        PolicyRendering::Public { condition } => {
            let name = ctx
                .profile
                .acl_fn_name(fhec_ir::FheOp::AllowPublic)
                .unwrap_or_default();
            let call = ctx
                .profile
                .render_call(fhec_ir::FheOp::AllowPublic, &[value_ty], &[target_text])
                .map_err(|e| internal(target_span, e))?;
            let text = match condition {
                Some(cond) => format!("if ({cond}) {call};"),
                None => format!("{call};"),
            };
            out.push(CallLine {
                fn_name: name,
                arg0: target_text.to_string(),
                arg1: None,
                text,
            });
        }
        PolicyRendering::List(readers) => {
            let name = ctx
                .profile
                .acl_fn_name(fhec_ir::FheOp::Allow)
                .unwrap_or_default();
            for r in readers {
                let RenderedReader::Named {
                    text: reader_text,
                    is_const_nonzero,
                } = r;
                let call = ctx
                    .profile
                    .render_call(
                        fhec_ir::FheOp::Allow,
                        &[value_ty],
                        &[target_text, reader_text],
                    )
                    .map_err(|e| internal(target_span, e))?;
                let text = if *is_const_nonzero {
                    format!("{call};")
                } else {
                    format!("if ({reader_text} != address(0)) {call};")
                };
                out.push(CallLine {
                    fn_name: name.clone(),
                    arg0: target_text.to_string(),
                    arg1: Some(reader_text.clone()),
                    text,
                });
            }
        }
    }
    Ok(out)
}

fn internal(span: Span, err: fhec_targets::ProfileError) -> LowerFailure {
    LowerFailure {
        span,
        message: format!("profile refused a checked ACL call: {err} (internal)"),
        code: None,
    }
}

/// Renders one reader path, returning its text and whether it is provably a
/// non-zero constant (spec §8.9 "Zero-address guard" draft decision).
fn render_path(
    ctx: &Ctx<'_, '_>,
    function: FunctionId,
    self_text: &str,
    key_texts: &[String],
    path: &fhec_check::ReaderPath,
) -> Result<(String, bool)> {
    let (mut text, is_const) = match &path.root {
        ReaderRoot::SelfRef => (self_text.to_string(), false),
        ReaderRoot::Key(i) => (
            key_texts
                .get(*i)
                .cloned()
                .ok_or_else(|| lost(path.span, "policy key binder"))?,
            false,
        ),
        ReaderRoot::SiblingField(name) => {
            // `self_text` up to (not including) the field this write
            // reaches is the same struct instance; splice in the sibling
            // field name in its place. `self_text` for a struct-pointer
            // write already ends in `.{written-field}[...]`; a sibling
            // reads the same pointer prefix with a different tail.
            let base = strip_written_field(self_text);
            (format!("{base}.{name}"), false)
        }
        ReaderRoot::StateVar(vid) => {
            let name = ctx
                .unit
                .var(*vid)
                .name
                .map(|n| n.as_str().to_string())
                .ok_or_else(|| lost(path.span, "policy state-variable reader"))?;
            confirm_state_var_in_scope(ctx, function, *vid, &name, path.span)?;
            (name, false)
        }
        ReaderRoot::EventParam(_) => {
            return fail_coded(
                path.span,
                "an event parameter reader is only meaningful at an emit site (internal)"
                    .to_string(),
                "FHE9001",
                None,
            );
        }
    };
    for seg in &path.tail {
        text.push('.');
        text.push_str(seg);
    }
    Ok((text, is_const))
}

/// `self_text` for a struct-pointer write is `<ptr>.<field>[k0][k1]...`; a
/// sibling field reads the same pointer with a different field, so this
/// strips back to `<ptr>` (everything before the first `.`).
fn strip_written_field(self_text: &str) -> &str {
    self_text.split('.').next().unwrap_or(self_text)
}

/// Confirms a bare state-variable reader's name still resolves, at the
/// insertion site's scope, to the same declaration the policy resolved at
/// its declaration site (spec §1.3: a shadowing local/param in *this*
/// function must not silently retarget the grant).
fn confirm_state_var_in_scope(
    ctx: &Ctx<'_, '_>,
    function: FunctionId,
    expected: VarId,
    name: &str,
    span: Span,
) -> Result<()> {
    let info = ctx.unit.function(function);
    let sym = solar_interface::Symbol::intern(name);
    let res = ctx
        .unit
        .resolve_name_in_scope(Some(function), info.contract, info.file, sym, name);
    if matches!(res, Resolution::StateVar(v) if v == expected) {
        return Ok(());
    }
    fail_coded(
        span,
        format!(
            "reader `{name}` is shadowed by a local or parameter in this function, so the \
             grant cannot be written safely here (spec §8.9)"
        ),
        "FHE4006",
        Some("§8.9"),
    )
}

fn lost(span: Span, what: &str) -> LowerFailure {
    LowerFailure {
        span,
        message: format!("{what} not found (internal)"),
        code: None,
    }
}
