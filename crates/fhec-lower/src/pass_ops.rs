//! Pass 1 — expression-level lowering (spec §4): operators, comparisons,
//! boolean operators, ternary→select, compound assignment, statement
//! `++`/`--`, and the `in` parameter sugar expansion (spec §2.3).
//!
//! The pass walks statements of every function in a dialect file, skipping
//! spans owned by other passes (encrypted `if` statements → pass 2; hoisted
//! R2/R3 expressions → pass 3), and emits one replacement patch per outermost
//! rewritten expression.

use fhec_bind::FunctionId;
use fhec_ir::{FheOp, FilePlan, Patch, Provenance};
use solar_ast as ast;
use solar_interface::Span;

use crate::ctx::Ctx;
use crate::expr::{fail, LowerFailure, Renderer, Result};

/// Spans that other passes own; pass 1 must not patch inside them.
pub(crate) struct SkipSpans {
    pub spans: Vec<Span>,
}

impl SkipSpans {
    fn owns(&self, ctx: &Ctx<'_, '_>, span: Span) -> bool {
        self.spans.iter().any(|s| ctx.contains(*s, span))
    }
}

/// Runs pass 1 over one function's body, appending patches to `plan`.
pub(crate) fn run_function<'ast>(
    ctx: &Ctx<'_, 'ast>,
    function: FunctionId,
    skips: &SkipSpans,
    plan: &mut FilePlan,
) -> Result<()> {
    let info = ctx.unit.function(function);
    let Some(body) = &info.ast.body else {
        return Ok(());
    };
    for stmt in body.iter() {
        walk_stmt(ctx, stmt, skips, plan)?;
    }
    Ok(())
}

fn walk_stmt<'ast>(
    ctx: &Ctx<'_, 'ast>,
    stmt: &'ast ast::Stmt<'ast>,
    skips: &SkipSpans,
    plan: &mut FilePlan,
) -> Result<()> {
    if skips.owns(ctx, stmt.span) {
        return Ok(());
    }
    match &stmt.kind {
        ast::StmtKind::Block(b)
        | ast::StmtKind::UncheckedBlock(b)
        | ast::StmtKind::Precondition(b) => {
            for s in b.iter() {
                walk_stmt(ctx, s, skips, plan)?;
            }
        }
        ast::StmtKind::If(cond, then_s, else_s) => {
            if ctx.ifs_by_span.contains_key(&stmt.span) {
                // Encrypted if: pass 2 owns the whole statement.
                return Ok(());
            }
            patch_expr(ctx, cond, skips, plan)?;
            walk_stmt(ctx, then_s, skips, plan)?;
            if let Some(e) = else_s {
                walk_stmt(ctx, e, skips, plan)?;
            }
        }
        ast::StmtKind::While(cond, body) => {
            patch_expr(ctx, cond, skips, plan)?;
            walk_stmt(ctx, body, skips, plan)?;
        }
        ast::StmtKind::DoWhile(body, cond) => {
            walk_stmt(ctx, body, skips, plan)?;
            patch_expr(ctx, cond, skips, plan)?;
        }
        ast::StmtKind::For {
            init,
            cond,
            next,
            body,
        } => {
            if let Some(s) = init {
                walk_stmt(ctx, s, skips, plan)?;
            }
            if let Some(c) = cond {
                patch_expr(ctx, c, skips, plan)?;
            }
            if let Some(n) = next {
                patch_expr(ctx, n, skips, plan)?;
            }
            walk_stmt(ctx, body, skips, plan)?;
        }
        ast::StmtKind::DeclSingle(v) => {
            if let Some(init) = &v.initializer {
                patch_expr(ctx, init, skips, plan)?;
            }
        }
        ast::StmtKind::DeclMulti(_, rhs) => {
            patch_expr(ctx, rhs, skips, plan)?;
        }
        ast::StmtKind::Return(Some(e)) => {
            patch_expr(ctx, e, skips, plan)?;
        }
        ast::StmtKind::Expr(e) => {
            // Statement-position `++`/`--` on an encrypted target lowers to a
            // whole-statement replacement (spec §4.2).
            if let Some(&i) = ctx
                .incdecs_by_span
                .get(&stmt.span)
                .or_else(|| ctx.incdecs_by_span.get(&e.span))
            {
                let site = &ctx.checked.incdec_sites[i];
                let target = ctx.snippet(site.target_span);
                let one = ctx
                    .profile
                    .render_call(FheOp::TrivialEncrypt { to: site.ty }, &[], &["1"])
                    .map_err(|err| internal(stmt.span, err))?;
                let op = if site.is_increment {
                    FheOp::Add
                } else {
                    FheOp::Sub
                };
                let call = ctx
                    .profile
                    .render_call(op, &[site.ty, site.ty], &[&target, &one])
                    .map_err(|err| internal(stmt.span, err))?;
                // The site span covers the whole expression statement
                // (including `;`); the expression span does not.
                let (range, replacement) = if site.span == stmt.span {
                    (ctx.range(stmt.span), format!("{target} = {call};"))
                } else {
                    (ctx.range(e.span), format!("{target} = {call}"))
                };
                plan.push(Patch::replace(
                    range,
                    replacement,
                    Provenance::new("§4.2 inc-dec", ctx.range(stmt.span)),
                ));
                return Ok(());
            }
            // Compound assignment on an encrypted left-hand side (spec §4.2).
            if let Some(&i) = ctx.compounds_by_span.get(&e.span) {
                let site = &ctx.checked.compound_sites[i];
                let ast::ExprKind::Assign(_, _, rhs) = &e.kind else {
                    return fail(e.span, "compound site is not an assignment (internal)");
                };
                let renderer = Renderer::new(ctx);
                let lhs_text = ctx.snippet(site.lhs_span);
                let raw = renderer.render_expr(rhs)?;
                let (rhs_ty, rhs_text) = renderer.wrap_operand(&site.rhs, raw, e.span)?;
                let call = ctx
                    .profile
                    .render_call(site.op, &[site.lhs, rhs_ty], &[&lhs_text, &rhs_text])
                    .map_err(|err| internal(e.span, err))?;
                plan.push(Patch::replace(
                    ctx.range(e.span),
                    format!("{lhs_text} = {call}"),
                    Provenance::new("§4.2 compound-assign", ctx.range(e.span)),
                ));
                return Ok(());
            }
            patch_expr(ctx, e, skips, plan)?;
        }
        ast::StmtKind::Emit(_, args) | ast::StmtKind::Revert(_, args) => {
            for a in crate::expr::call_arg_exprs(args) {
                patch_expr(ctx, a, skips, plan)?;
            }
        }
        ast::StmtKind::Try(t) => {
            patch_expr(ctx, t.expr, skips, plan)?;
            for clause in t.clauses.iter() {
                for s in clause.block.iter() {
                    walk_stmt(ctx, s, skips, plan)?;
                }
            }
        }
        ast::StmtKind::Assembly(_)
        | ast::StmtKind::Break
        | ast::StmtKind::Continue
        | ast::StmtKind::Placeholder
        | ast::StmtKind::Return(None) => {}
    }
    Ok(())
}

/// Renders an expression; when the rendering differs from the source text,
/// emits one replacement patch covering the whole expression.
fn patch_expr<'ast>(
    ctx: &Ctx<'_, 'ast>,
    e: &'ast ast::Expr<'ast>,
    skips: &SkipSpans,
    plan: &mut FilePlan,
) -> Result<()> {
    if skips.owns(ctx, e.span) {
        return Ok(());
    }
    let rendered = Renderer::new(ctx).render_expr(e)?;
    if rendered != ctx.snippet(e.span) {
        plan.push(Patch::replace(
            ctx.range(e.span),
            rendered,
            Provenance::new("§4.1 operator-lowering", ctx.range(e.span)),
        ));
    }
    Ok(())
}

fn internal(span: Span, err: fhec_targets::ProfileError) -> LowerFailure {
    LowerFailure {
        span,
        message: format!("profile refused a checked operation: {err} (internal)"),
        code: None,
    }
}

// ---------------------------------------------------------------------------
// `in` parameter sugar (spec §2.3)
// ---------------------------------------------------------------------------

/// The fixed name of the shared proof parameter appended to a function whose
/// `in` sugar uses the implicit form (spec §2.3; the checker guarantees it is
/// collision-free). The explicit binder `in(proof)` uses the author's own
/// parameter name instead and appends nothing.
const INPUT_PROOF: &str = "inputProof";

/// Expands every sugar site of one file. Per function with sugar: each `in`
/// parameter is replaced by its external-input handle declaration, one shared
/// `bytes memory inputProof` parameter is appended to the parameter list
/// (implicit form only), and the verified conversion prelude is inserted at
/// the start of the body — a direct conversion call for one parameter, a
/// single batch verification for several (one signature covers the whole
/// batch; per-parameter conversion calls would not verify).
pub(crate) fn expand_sugar(ctx: &Ctx<'_, '_>, file_idx: usize, plan: &mut FilePlan) -> Result<()> {
    // The `precondition` marker (spec §2.7) is stripped so a plain nested
    // block survives. The block's own bytes are untouched, and the
    // conversions below are inserted after its closing `}` — the marker patch
    // and the conversion insertion never overlap.
    for site in ctx
        .checked
        .precondition_sites
        .iter()
        .filter(|s| s.file.index() == file_idx)
    {
        plan.push(Patch::replace(
            ctx.range(site.marker_span),
            String::new(),
            Provenance::new("§2.7 precondition-marker", ctx.range(site.marker_span)),
        ));
    }

    // Explicit cast sugar (spec §2.9) is rewritten by the shared recursive
    // renderer (`Renderer::render_expr`, indexed via `ctx.cast_sugar_by_span`)
    // reached through `patch_expr`'s per-statement call, alongside operator
    // and ternary sites — not a bespoke flat patch here — so a cast-sugar
    // call nested inside another rewritten construct composes instead of
    // colliding (spec §2.5).

    let mut sites: Vec<&fhec_check::InSugarSite> = ctx
        .checked
        .sugar_sites
        .iter()
        .filter(|s| s.file.index() == file_idx)
        .collect();
    sites.sort_by_key(|s| ctx.range(s.param_span).start);

    // Parameter lists never interleave, so sorting by parameter position
    // makes each function's sites contiguous.
    let mut groups: Vec<Vec<&fhec_check::InSugarSite>> = Vec::new();
    for site in sites {
        match groups.last_mut() {
            Some(group) if group[0].function == site.function => group.push(site),
            _ => groups.push(vec![site]),
        }
    }

    for group in groups {
        expand_function_sugar(ctx, &group, plan)?;
    }
    Ok(())
}

/// Expands the sugar sites of one function (all of `sites` share it).
fn expand_function_sugar(
    ctx: &Ctx<'_, '_>,
    sites: &[&fhec_check::InSugarSite],
    plan: &mut FilePlan,
) -> Result<()> {
    let first = sites[0];

    // The checker resolves the proof for the whole parameter list, so every
    // site of one function carries the same binding (FHE1014). Refuse rather
    // than pick one if that ever stops holding (§1.3).
    if sites.iter().any(|s| s.proof != first.proof) {
        return fail(
            first.param_span,
            "sugar sites of one function disagree on the input proof (internal)",
        );
    }
    let proof = first.proof.as_deref().unwrap_or(INPUT_PROOF);

    // 1. Each `in eT name` parameter becomes `externalET name_input`. A
    //    bodiless declaration generates no local, so nothing needs the
    //    author's name and the parameter keeps it: that name is ABI-visible
    //    and, on a published interface, is what integrators and
    //    named-argument call sites bind to (spec §2.3).
    for site in sites {
        let external_ty = ctx.profile.external_input_type(site.ty);
        let wire_name = if first.has_body {
            format!("{}_input", site.name)
        } else {
            site.name.clone()
        };
        plan.push(Patch::replace(
            ctx.range(site.param_span),
            format!("{external_ty} {wire_name}"),
            Provenance::new("§2.3 in-sugar-param", ctx.range(site.param_span)),
        ));
    }

    // 2. The implicit form appends one shared proof parameter at the end of
    //    the list. A single-line list keeps `, bytes memory inputProof`
    //    immediately before `)`. A multiline list (any newline inside the
    //    parens) attaches the comma to the last existing parameter and puts
    //    the new one on its own line at that parameter's indentation, so `)`
    //    stays on its original line. The explicit binder names a parameter
    //    the author already declared, which keeps its position, name, and
    //    data location, so nothing is appended and the ABI gains no extra
    //    proof.
    let file_text = ctx.text(first.file);
    if first.proof.is_none() {
        let params_range = ctx.range(first.params_span);
        debug_assert_eq!(&file_text[params_range.end - 1..params_range.end], ")");
        let proof_param = ctx.profile.input_proof_param();
        let list = &file_text[params_range.start..params_range.end];
        let (at, inserted) = if list.contains('\n') {
            let at = trailing_ws_start(file_text, params_range.start, params_range.end - 1);
            let indent = ctx.line_indent(first.file, at.saturating_sub(1));
            let nl = if list.contains("\r\n") { "\r\n" } else { "\n" };
            (at, format!(",{nl}{indent}{proof_param}"))
        } else {
            (params_range.end - 1, format!(", {proof_param}"))
        };
        plan.push(Patch::insert(
            at,
            inserted,
            Provenance::new("§2.3 in-sugar-proof-param", ctx.range(first.params_span)),
        ));
    }

    // 3. The conversion prelude (bodiless functions: signature rewrite only).
    if !first.has_body {
        return Ok(());
    }
    let Some(body_span) = first.body_span else {
        return fail(
            first.param_span,
            "sugar site has a body but no body span (internal)",
        );
    };
    let (at, indent) = materialization_point(ctx, first.function, first.file, body_span);

    let statements: Vec<String> = if let [site] = sites {
        let input = format!("{}_input", site.name);
        let call = ctx
            .profile
            .render_call(FheOp::FromExternal { ty: site.ty }, &[], &[&input, proof])
            .map_err(|e| internal(site.param_span, e))?;
        vec![format!(
            "{} {} = {};",
            site.ty.solidity_name(),
            site.name,
            call
        )]
    } else {
        let mut namer = fhec_emit::TempNamer::new(crate::idents::file_idents(
            ctx.files[first.file.index()].ast,
        ));
        let inputs_tmp = namer.fresh(fhec_emit::TempHint::Inputs);
        let hashes_tmp = namer.fresh(fhec_emit::TempHint::Hashes);
        let inputs: Vec<(fhec_ir::EType, String, String)> = sites
            .iter()
            .map(|s| (s.ty, format!("{}_input", s.name), s.name.clone()))
            .collect();
        let params: Vec<(fhec_ir::EType, &str, &str)> = inputs
            .iter()
            .map(|(t, i, n)| (*t, i.as_str(), n.as_str()))
            .collect();
        ctx.profile
            .batch_input_statements(&params, proof, &inputs_tmp, &hashes_tmp)
    };

    let mut prelude = String::new();
    for stmt in &statements {
        prelude.push('\n');
        prelude.push_str(&indent);
        prelude.push_str(stmt);
    }
    // Tagged as a declaration: the prelude declares the handles, and a patch
    // that reads one (an ACL grant on the next statement) can anchor at the
    // very same offset when the source has no whitespace there.
    plan.push(
        Patch::insert(
            at,
            prelude,
            Provenance::new("§2.3 in-sugar-conversion", ctx.range(first.param_span)),
        )
        .declaration(),
    );
    Ok(())
}

/// Where a function's generated encrypted-input materializers go, and the
/// indentation they take (spec §2.3 *materialization point*, §2.7).
///
/// The point is right after the body's opening `{`, unless the body opens with
/// a `precondition` block: then it moves after that block's closing `}`, so
/// the author's plaintext guard runs before any generated conversion. The
/// indent is unchanged either way — the block is the body's first statement,
/// so it sets that indent.
fn materialization_point(
    ctx: &Ctx<'_, '_>,
    function: FunctionId,
    file: fhec_bind::FileId,
    body_span: Span,
) -> (usize, String) {
    let file_text = ctx.text(file);
    let body_range = ctx.range(body_span);
    let brace = body_range.start;
    debug_assert_eq!(&file_text[brace..brace + 1], "{");
    let indent = body_indent(file_text, body_range.start, body_range.end);
    let at = match ctx.preconditions_by_fn.get(&function) {
        Some(&i) => {
            let site = &ctx.checked.precondition_sites[i];
            let block = ctx.range(site.block_span);
            debug_assert_eq!(&file_text[block.end - 1..block.end], "}");
            block.end
        }
        None => brace + 1,
    };
    (at, indent)
}

// ---------------------------------------------------------------------------
// The shared boundary (spec §2.8)
// ---------------------------------------------------------------------------

/// The fixed generated wire-parameter suffix of a shared input. The checker
/// guarantees it is collision-free (FHE1016).
const WIRE_SUFFIX: &str = "_shared";

/// Expands every shared-boundary site of one file (spec §2.8).
///
/// Two rewrites, both driven purely by checker-approved sites:
///
/// 1. **Shared inputs.** Each `in shared eT name` parameter becomes
///    `sharedT name_shared`, and one `eT name = FHE.receiveTParam(name_shared);`
///    per parameter — in source parameter order — is inserted at the
///    materialization point. Unlike external inputs these do not batch: each
///    receive stands alone, because a shared handle carries no input proof.
///
/// 2. **Shared returns.** The `returns (shared(msg.sender) eT)` declaration
///    becomes `sharedT`, and every returned expression is bracketed with
///    `FHE.shareT(` … `, msg.sender)`.
///
/// The return wrap is deliberately **two zero-width insertions at the
/// expression's own boundaries**, never a replacement of the statement or of
/// the expression. That is what makes it compose with everything else without
/// claiming statement ownership:
///
/// - the expression appears exactly once in the output, so single evaluation
///   holds by construction and no hoist is needed;
/// - ordinary operator lowering (pass 1) still replaces the expression span or
///   spans inside it — a replacement at `[start, end)` sorts *after* an
///   insertion at `start` and *before* an insertion at `end`, so the wrap ends
///   up around the lowered form;
/// - an R2 `allowTransient` grant for an external call inside the expression
///   is inserted before the whole statement and its argument hoists replace
///   spans strictly inside the expression, so no grant is displaced or lost;
/// - no statement is inserted or moved, so a `return` cannot be pushed out of
///   the conditional it belongs to.
///
/// The checker additionally refuses a shared `return` that is a braceless
/// branch body or that assigns inside its expression, which keeps the
/// construct clear of the two known composition defects in the ACL pass.
pub(crate) fn expand_shared(ctx: &Ctx<'_, '_>, file_idx: usize, plan: &mut FilePlan) -> Result<()> {
    expand_shared_inputs(ctx, file_idx, plan)?;
    expand_shared_returns(ctx, file_idx, plan)
}

fn expand_shared_inputs(ctx: &Ctx<'_, '_>, file_idx: usize, plan: &mut FilePlan) -> Result<()> {
    let mut sites: Vec<&fhec_check::SharedInputSite> = ctx
        .checked
        .shared_input_sites
        .iter()
        .filter(|s| s.file.index() == file_idx)
        .collect();
    sites.sort_by_key(|s| ctx.range(s.param_span).start);

    // Parameter lists never interleave, so sorting by parameter position makes
    // each function's sites contiguous and keeps them in source order.
    let mut groups: Vec<Vec<&fhec_check::SharedInputSite>> = Vec::new();
    for site in sites {
        match groups.last_mut() {
            Some(group) if group[0].function == site.function => group.push(site),
            _ => groups.push(vec![site]),
        }
    }

    for group in groups {
        let first = group[0];
        let mut receives: Vec<String> = Vec::with_capacity(group.len());
        for site in &group {
            let wire = ctx
                .profile
                .shared_wire_type(site.ty)
                .map_err(|e| internal(site.param_span, e))?;
            // A bodiless declaration generates no local, so nothing needs
            // the author's name and the parameter keeps it. That name is
            // ABI-visible and, on a published interface, is what integrators
            // and named-argument call sites bind to (spec §2.8).
            let wire_name = if first.has_body {
                format!("{}{WIRE_SUFFIX}", site.name)
            } else {
                site.name.clone()
            };
            plan.push(Patch::replace(
                ctx.range(site.param_span),
                format!("{wire} {wire_name}"),
                Provenance::new("§2.8 shared-input-param", ctx.range(site.param_span)),
            ));
            let call = ctx
                .profile
                .render_receive_param(site.ty, &wire_name)
                .map_err(|e| internal(site.param_span, e))?;
            receives.push(format!(
                "{} {} = {call};",
                site.ty.solidity_name(),
                site.name
            ));
        }

        // A bodiless declaration rewrites its signature only (§2.3 rule 3).
        if !first.has_body {
            continue;
        }
        let Some(body_span) = first.body_span else {
            return fail(
                first.param_span,
                "shared-input site has a body but no body span (internal)",
            );
        };
        let (at, indent) = materialization_point(ctx, first.function, first.file, body_span);
        let mut prelude = String::new();
        for stmt in &receives {
            prelude.push('\n');
            prelude.push_str(&indent);
            prelude.push_str(stmt);
        }
        // Tagged as a declaration for the same reason the §2.3 prelude is: a
        // patch that reads one of these handles may anchor at this very offset.
        plan.push(
            Patch::insert(
                at,
                prelude,
                Provenance::new("§2.8 shared-input-receive", ctx.range(first.param_span)),
            )
            .declaration(),
        );
    }
    Ok(())
}

fn expand_shared_returns(ctx: &Ctx<'_, '_>, file_idx: usize, plan: &mut FilePlan) -> Result<()> {
    for site in ctx
        .checked
        .shared_return_sites
        .iter()
        .filter(|s| s.file.index() == file_idx)
    {
        let wire = ctx
            .profile
            .shared_wire_type(site.ty)
            .map_err(|e| internal(site.decl_span, e))?;
        plan.push(Patch::replace(
            ctx.range(site.decl_span),
            wire,
            Provenance::new("§2.8 shared-return-type", ctx.range(site.decl_span)),
        ));

        let share = ctx
            .profile
            .share_fn(site.ty)
            .map_err(|e| internal(site.decl_span, e))?;
        for expr_span in &site.return_exprs {
            let range = ctx.range(*expr_span);
            plan.push(Patch::insert(
                range.start,
                format!("{share}("),
                Provenance::new("§2.8 shared-return-share", range),
            ));
            plan.push(Patch::insert(
                range.end,
                format!(", {})", site.recipient),
                Provenance::new("§2.8 shared-return-share", range),
            ));
        }
    }
    Ok(())
}

/// Byte offset of the first trailing ASCII whitespace before `close`, or
/// `close` itself when the bytes immediately before it are not whitespace.
///
/// Used to attach a comma to the last existing parameter of a multiline
/// list: the insert sits after that parameter (and after any trailing
/// comment text) so the original newline and closing `)` stay put.
fn trailing_ws_start(text: &str, open: usize, close: usize) -> usize {
    let bytes = text.as_bytes();
    let mut i = close;
    while i > open {
        match bytes[i - 1] {
            b' ' | b'\t' | b'\n' | b'\r' => i -= 1,
            _ => break,
        }
    }
    i
}

/// The indentation for a statement inserted at the start of a body block.
fn body_indent(text: &str, open: usize, close: usize) -> String {
    // First non-empty line after the `{` that is still inside the block.
    let after = &text[open + 1..close];
    for line in after.lines() {
        if line.trim().is_empty() {
            continue;
        }
        return line
            .chars()
            .take_while(|c| *c == ' ' || *c == '\t')
            .collect();
    }
    // Empty body: indent of the `{` line plus one level.
    let line_start = text[..open].rfind('\n').map_or(0, |i| i + 1);
    let base: String = text[line_start..]
        .chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect();
    format!("{base}    ")
}
