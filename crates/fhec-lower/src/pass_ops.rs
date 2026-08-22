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
        ast::StmtKind::Block(b) | ast::StmtKind::UncheckedBlock(b) => {
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

/// The fixed name of the shared proof parameter appended to a function with
/// `in` sugar (spec §2.3; the checker guarantees it is collision-free).
const INPUT_PROOF: &str = "inputProof";

/// Expands every sugar site of one file. Per function with sugar: each `in`
/// parameter is replaced by its external-input handle declaration, one shared
/// `bytes memory inputProof` parameter is appended to the parameter list, and
/// the verified conversion prelude is inserted at the start of the body — a
/// direct conversion call for one parameter, a single batch verification for
/// several (one signature covers the whole batch; per-parameter conversion
/// calls would not verify).
pub(crate) fn expand_sugar(ctx: &Ctx<'_, '_>, file_idx: usize, plan: &mut FilePlan) -> Result<()> {
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

    // 1. Each `in eT name` parameter becomes `externalET name_input`.
    for site in sites {
        let external_ty = ctx.profile.external_input_type(site.ty);
        plan.push(Patch::replace(
            ctx.range(site.param_span),
            format!("{external_ty} {}_input", site.name),
            Provenance::new("§2.3 in-sugar-param", ctx.range(site.param_span)),
        ));
    }

    // 2. One shared proof parameter, appended before the list's closing `)`.
    let params_range = ctx.range(first.params_span);
    let file_text = ctx.text(first.file);
    debug_assert_eq!(&file_text[params_range.end - 1..params_range.end], ")");
    plan.push(Patch::insert(
        params_range.end - 1,
        format!(", {}", ctx.profile.input_proof_param()),
        Provenance::new("§2.3 in-sugar-proof-param", ctx.range(first.params_span)),
    ));

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
    let body_range = ctx.range(body_span);
    // Insert right after the opening `{`, indented like the first body
    // line (or the body's line + 4 when the body is empty).
    let brace = body_range.start;
    debug_assert_eq!(&file_text[brace..brace + 1], "{");
    let indent = body_indent(file_text, body_range.start, body_range.end);

    let statements: Vec<String> = if let [site] = sites {
        let input = format!("{}_input", site.name);
        let call = ctx
            .profile
            .render_call(
                FheOp::FromExternal { ty: site.ty },
                &[],
                &[&input, INPUT_PROOF],
            )
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
            .batch_input_statements(&params, INPUT_PROOF, &inputs_tmp, &hashes_tmp)
    };

    let mut prelude = String::new();
    for stmt in &statements {
        prelude.push('\n');
        prelude.push_str(&indent);
        prelude.push_str(stmt);
    }
    plan.push(Patch::insert(
        brace + 1,
        prelude,
        Provenance::new("§2.3 in-sugar-conversion", ctx.range(first.param_span)),
    ));
    Ok(())
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
