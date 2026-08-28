//! Pass 3 — ACL insertion (spec §8): R1 after encrypted storage writes,
//! R2 before external calls with encrypted arguments, R3 before encrypted
//! returns. Never `FHE.allow`, `allowGlobal`, or `allowPublic` (spec §8.5).
//!
//! A trigger statement that is the lone, braceless body of an `if`, `else`,
//! `while`, `do` or `for` is wrapped in a block as part of the insertion: a
//! grant emitted next to it would otherwise become the branch body and push
//! the guarded statement out of the branch (R2), or fire unconditionally
//! (R1). The braces are ordinary patches at the statement's own boundaries,
//! ordered by [`fhec_ir::InsertOrder`], so they compose with every other
//! patch inside the statement.
//!
//! Dedupe (spec §8.6): an equivalent existing call suppresses the insertion —
//! same ACL function, syntactically identical argument after parenthesis
//! stripping; method syntax counts as library syntax. R1 scans forward from
//! the trigger to the next write of the same location or the end of the
//! block; R2/R3 insert *before* their trigger, so their window scans backward
//! from the trigger to the start of the block (a §8.6 refinement — the
//! spec's forward window is written for R1).

use std::cell::RefCell;

use fhec_check::{EncryptedArgCall, EncryptedReturn, EncryptedStorageWrite, Severity, SlotKind};
use fhec_emit::{TempHint, TempNamer};
use fhec_ir::{EType, FheOp, FilePlan, Patch, Provenance};
use solar_ast as ast;
use solar_interface::Span;

use crate::codes;
use crate::ctx::{strip_parens, Ctx};
use crate::expr::{fail_coded, LowerFailure, Renderer, Result};

pub(crate) struct AclOutcome {
    /// Statement spans whose inner rendering pass 3 took over (pass 1 skips).
    pub owned_stmts: Vec<Span>,
    /// Statement spans this pass already wrapped in braces (spec §8.0); a
    /// statement carrying two ACL facts is wrapped once.
    braced: Vec<Span>,
    /// R1 grants for a write that shares its statement with an R3 return
    /// (`return slot = value;`). R3 owns the whole statement, so R1 hands its
    /// calls over instead of inserting after the `return` it cannot see.
    pending_r1: Vec<(Span, fhec_bind::FileId, fhec_bind::FunctionId, Vec<String>)>,
}

/// Runs R1/R2/R3 for one function, in source order.
pub(crate) fn run_function<'ast>(
    ctx: &Ctx<'_, 'ast>,
    function: fhec_bind::FunctionId,
    namer: &RefCell<TempNamer>,
    acl_insert: bool,
    diags: &RefCell<Vec<fhec_check::Diagnostic>>,
    if_spans: &[Span],
    plan: &mut FilePlan,
) -> Result<AclOutcome> {
    let mut outcome = AclOutcome {
        owned_stmts: Vec::new(),
        braced: Vec::new(),
        pending_r1: Vec::new(),
    };
    let inside_if = |span: Span| if_spans.iter().any(|s| ctx.contains(*s, span));

    // Deterministic source order across the three rules.
    enum Fact<'f> {
        W(&'f EncryptedStorageWrite),
        C(&'f EncryptedArgCall),
        R(&'f EncryptedReturn),
    }
    let mut facts: Vec<(usize, Fact<'_>)> = Vec::new();
    for w in &ctx.checked.acl.storage_writes {
        if w.function == function && !inside_if(w.stmt_span) {
            facts.push((ctx.range(w.stmt_span).start, Fact::W(w)));
        }
    }
    for c in &ctx.checked.acl.external_args {
        if c.function == function && !inside_if(c.stmt_span) {
            facts.push((ctx.range(c.stmt_span).start, Fact::C(c)));
        }
    }
    for r in &ctx.checked.acl.returns {
        if r.function == function && !inside_if(r.stmt_span) {
            facts.push((ctx.range(r.stmt_span).start, Fact::R(r)));
        }
    }
    facts.sort_by_key(|(k, _)| *k);

    for (_, fact) in facts {
        match fact {
            Fact::W(w) => rule_r1(ctx, w, acl_insert, diags, plan, &mut outcome)?,
            Fact::C(c) => rule_r2(ctx, c, namer, acl_insert, diags, plan, &mut outcome)?,
            Fact::R(r) => rule_r3(ctx, r, namer, acl_insert, diags, plan, &mut outcome)?,
        }
    }
    // Defensive: a grant handed to an R3 fact that never ran (its statement
    // was filtered out) is still owed to the contract (spec §1.3).
    while let Some(&(span, _, _, _)) = outcome.pending_r1.first() {
        refuse_pending_r1(ctx, span, &mut outcome)?;
    }
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// R1 — storage writes (spec §8.1)
// ---------------------------------------------------------------------------

fn rule_r1(
    ctx: &Ctx<'_, '_>,
    w: &EncryptedStorageWrite,
    acl_insert: bool,
    diags: &RefCell<Vec<fhec_check::Diagnostic>>,
    plan: &mut FilePlan,
    outcome: &mut AclOutcome,
) -> Result<()> {
    if w.in_view_or_pure {
        // A storage write in view/pure is already a checker/solc error.
        return Ok(());
    }
    let lvalue = strip_parens(&ctx.snippet(w.lvalue_span)).to_string();

    if let SlotKind::Mapping {
        key_is_msg_sender,
        key_is_address,
        ..
    } = &w.slot
    {
        if *key_is_address && !*key_is_msg_sender {
            diags.borrow_mut().push(fhec_check::Diagnostic {
                code: "FHE4001",
                severity: Severity::Warning,
                span: w.lvalue_span,
                message: format!(
                    "encrypted write to `{lvalue}` is keyed by an address that is not \
                     `msg.sender`; the transaction sender gains read access to a ciphertext \
                     filed under another address"
                ),
                fixits: Vec::new(),
                rule: Some("§8.1"),
            });
        }
    }

    let window = forward_window(ctx, w.function, w.stmt_span, &lvalue);
    let mut missing: Vec<FheOp> = Vec::new();
    for op in [FheOp::AllowThis, FheOp::AllowSender] {
        let name = ctx.profile.acl_fn_name(op).unwrap_or_default();
        if !window
            .iter()
            .any(|s| acl_call_matches(ctx, s, &name, &lvalue, None))
        {
            missing.push(op);
        }
    }
    if missing.is_empty() {
        return Ok(());
    }

    let indent = ctx.line_indent(w.file, ctx.range(w.stmt_span).start);
    let at = after_stmt_offset(ctx.text(w.file), ctx.range(w.stmt_span).end);
    if acl_insert {
        let calls: Vec<String> = missing
            .iter()
            .map(|op| {
                ctx.profile
                    .render_call(*op, &[w.value_ty], &[&lvalue])
                    .map(|c| format!("{c};"))
            })
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| internal(w.stmt_span, e))?;
        // `return slot = value;` states both an R1 write and an R3 return on
        // one statement. R1's insertion point is R3's replacement end, so the
        // grants would land after the `return` and never run (spec §8.0).
        // R3 owns the statement: hand the calls over.
        if is_return_site(ctx, w.function, w.stmt_span) {
            outcome
                .pending_r1
                .push((w.stmt_span, w.file, w.function, calls));
            return Ok(());
        }
        brace_lone_stmt(ctx, w.function, w.stmt_span, plan, outcome)?;
        for call in calls {
            plan.push(Patch::insert(
                at,
                format!("\n{indent}{call}"),
                Provenance::new("§8.1 R1", ctx.range(w.stmt_span)).with_code("FHE4010"),
            ));
        }
    } else {
        let calls: Vec<String> = missing
            .iter()
            .map(|op| {
                ctx.profile
                    .render_call(*op, &[w.value_ty], &[&lvalue])
                    .map(|c| format!("{c};"))
            })
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| internal(w.stmt_span, e))?;
        let insertion: String = calls.iter().map(|c| format!("\n{indent}{c}")).collect();
        diags.borrow_mut().push(fhec_check::Diagnostic {
            code: "FHE4010",
            severity: Severity::Note,
            span: w.stmt_span,
            message: format!(
                "ACL suggestion: after this write, add `{}`",
                calls.join(" ")
            ),
            fixits: vec![fhec_check::FixIt {
                span: zero_width_at(w.stmt_span),
                replacement: insertion,
                safe: true,
            }],
            rule: Some("§8.1"),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// R2 — encrypted arguments to external calls (spec §8.2)
// ---------------------------------------------------------------------------

fn rule_r2<'ast>(
    ctx: &Ctx<'_, 'ast>,
    c: &EncryptedArgCall,
    namer: &RefCell<TempNamer>,
    acl_insert: bool,
    diags: &RefCell<Vec<fhec_check::Diagnostic>>,
    plan: &mut FilePlan,
    outcome: &mut AclOutcome,
) -> Result<()> {
    let callee_text = strip_parens(&ctx.snippet(c.callee_span)).to_string();
    let window = backward_window(ctx, c.function, c.stmt_span);
    let transient = ctx
        .profile
        .acl_fn_name(FheOp::AllowTransient)
        .unwrap_or_default();

    // Render every encrypted argument first: lowering inside the argument is
    // this rule's responsibility once it owns the statement.
    struct ArgPlan<'ast2> {
        span: Span,
        ty: EType,
        rendered: String,
        original: String,
        deduped: bool,
        node: &'ast2 ast::Expr<'ast2>,
    }
    // The grant's account operand is always an `address`; a contract-typed
    // callee must be wrapped (`FHE.allowTransient(x, address(vault))`).
    // Dedupe compares modulo that wrapper.
    let callee_key = strip_address_cast(&callee_text).to_string();
    let mut args: Vec<ArgPlan<'ast>> = Vec::new();
    for (span, ty) in &c.args {
        let node = find_expr(ctx, c.function, *span)
            .ok_or_else(|| lost(*span, "R2 argument expression"))?;
        let rendered = Renderer::new(ctx).render_expr(node)?;
        let original = ctx.snippet(*span);
        let arg_key = strip_parens(&original).to_string();
        let deduped = window
            .iter()
            .any(|s| acl_call_matches_normalized(ctx, s, &transient, &arg_key, &callee_key));
        args.push(ArgPlan {
            span: *span,
            ty: *ty,
            rendered,
            original,
            deduped,
            node,
        });
    }

    let needs_insert = args.iter().any(|a| !a.deduped);
    if !needs_insert {
        // Everything is already granted; only apply expression lowering.
        for a in &args {
            if a.rendered != a.original {
                plan.push(Patch::replace(
                    ctx.range(a.span),
                    a.rendered.clone(),
                    Provenance::new("§4.1 operator-lowering", ctx.range(a.span)),
                ));
            }
        }
        return Ok(());
    }

    if !acl_insert {
        let list = args
            .iter()
            .filter(|a| !a.deduped)
            .map(|a| {
                format!(
                    "FHE.allowTransient({}, address({callee_key}));",
                    strip_parens(&a.original)
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        diags.borrow_mut().push(fhec_check::Diagnostic {
            code: "FHE4011",
            severity: Severity::Note,
            span: c.call_span,
            message: format!("ACL suggestion: before this call, add `{list}`"),
            fixits: Vec::new(),
            rule: Some("§8.2"),
        });
        // Expression lowering still happens (pass 1 keeps the statement).
        return Ok(());
    }

    let indent = ctx.line_indent(c.file, ctx.range(c.stmt_span).start);
    brace_lone_stmt(ctx, c.function, c.stmt_span, plan, outcome)?;
    let mut lines: Vec<String> = Vec::new();

    // Callee handling (spec §8.2 draft decision — single evaluation):
    // a simple name is read in place; anything else is hoisted to a temp of
    // its *declared* type so the call still dispatches through it. When the
    // lowerer cannot establish that type, it refuses (spec §1.3) with
    // FHE4003 and a workaround suggestion in the message.
    let callee_node = find_expr(ctx, c.function, c.callee_span)
        .ok_or_else(|| lost(c.callee_span, "R2 callee expression"))?;
    let account = if c.callee_is_ident || is_simple_path(&callee_text) {
        format!("address({callee_text})")
    } else {
        let Some(ty_text) = callee_type_text(ctx, callee_node) else {
            return fail_coded(
                c.callee_span,
                format!(
                    "cannot determine the callee's declared type for single-evaluation \
                     hoisting (spec §8.2); assign `{callee_text}` to a local variable and \
                     call through it"
                ),
                "FHE4003",
                Some("§8.2"),
            );
        };
        let temp = namer.borrow_mut().fresh(TempHint::Callee);
        lines.push(format!("{ty_text} {temp} = {callee_text};"));
        plan.push(Patch::replace(
            ctx.range(c.callee_span),
            temp.clone(),
            Provenance::new("§8.2 R2 callee-hoist", ctx.range(c.callee_span)),
        ));
        format!("address({temp})")
    };

    for a in &args {
        if a.deduped {
            if a.rendered != a.original {
                plan.push(Patch::replace(
                    ctx.range(a.span),
                    a.rendered.clone(),
                    Provenance::new("§4.1 operator-lowering", ctx.range(a.span)),
                ));
            }
            continue;
        }
        let handle = if is_ident_text(strip_parens(&a.original)) {
            strip_parens(&a.original).to_string()
        } else {
            // Hoist for single evaluation: the call and the grant must see
            // the same handle.
            let temp = namer.borrow_mut().fresh(TempHint::Val);
            lines.push(format!(
                "{} {} = {};",
                a.ty.solidity_name(),
                temp,
                a.rendered
            ));
            plan.push(Patch::replace(
                ctx.range(a.span),
                temp.clone(),
                Provenance::new("§8.2 R2 arg-hoist", ctx.range(a.span)),
            ));
            temp
        };
        let call = ctx
            .profile
            .render_call(FheOp::AllowTransient, &[a.ty], &[&handle, &account])
            .map_err(|e| internal(c.stmt_span, e))?;
        lines.push(format!("{call};"));
        let _ = a.node; // arg AST currently only needed for rendering above
    }

    let insertion: String = lines.iter().map(|l| format!("{l}\n{indent}")).collect();
    plan.push(Patch::insert(
        ctx.range(c.stmt_span).start,
        insertion,
        Provenance::new("§8.2 R2", ctx.range(c.call_span)).with_code("FHE4011"),
    ));
    outcome.owned_stmts.push(c.stmt_span);
    Ok(())
}

// ---------------------------------------------------------------------------
// R3 — encrypted returns (spec §8.3–§8.4)
// ---------------------------------------------------------------------------

fn rule_r3<'ast>(
    ctx: &Ctx<'_, 'ast>,
    r: &EncryptedReturn,
    namer: &RefCell<TempNamer>,
    acl_insert: bool,
    diags: &RefCell<Vec<fhec_check::Diagnostic>>,
    plan: &mut FilePlan,
    outcome: &mut AclOutcome,
) -> Result<()> {
    if !r.is_public_or_external {
        return refuse_pending_r1(ctx, r.stmt_span, outcome);
    }
    if r.is_view {
        diags.borrow_mut().push(fhec_check::Diagnostic {
            code: "FHE4002",
            severity: Severity::Warning,
            span: r.stmt_span,
            message: "a `view` function cannot grant ACL access to its encrypted return value; \
                      the caller must have been granted access elsewhere"
                .to_string(),
            fixits: Vec::new(),
            rule: Some("§8.4"),
        });
        return refuse_pending_r1(ctx, r.stmt_span, outcome);
    }

    let transient = ctx
        .profile
        .acl_fn_name(FheOp::AllowTransient)
        .unwrap_or_default();
    let expr_key = strip_parens(&ctx.snippet(r.expr_span)).to_string();
    let window = backward_window(ctx, r.function, r.stmt_span);
    if window
        .iter()
        .any(|s| acl_call_matches(ctx, s, &transient, &expr_key, Some("msg.sender")))
    {
        // Already granted (also the idempotence path, §8.6).
        return refuse_pending_r1(ctx, r.stmt_span, outcome);
    }

    let node = find_expr(ctx, r.function, r.expr_span)
        .ok_or_else(|| lost(r.expr_span, "R3 return expression"))?;
    let rendered = Renderer::new(ctx).render_expr(node)?;

    if !acl_insert {
        diags.borrow_mut().push(fhec_check::Diagnostic {
            code: "FHE4012",
            severity: Severity::Note,
            span: r.stmt_span,
            message: format!(
                "ACL suggestion: hoist the return value and add \
                 `FHE.allowTransient(<ret>, msg.sender);` before returning `{expr_key}`"
            ),
            fixits: Vec::new(),
            rule: Some("§8.3"),
        });
        return refuse_pending_r1(ctx, r.stmt_span, outcome);
    }

    brace_lone_stmt(ctx, r.function, r.stmt_span, plan, outcome)?;
    let temp = namer.borrow_mut().fresh(TempHint::Ret);
    let call = ctx
        .profile
        .render_call(FheOp::AllowTransient, &[r.value_ty], &[&temp, "msg.sender"])
        .map_err(|e| internal(r.stmt_span, e))?;
    let indent = ctx.line_indent(r.file, ctx.range(r.stmt_span).start);
    let stmt_range = ctx.range(r.stmt_span);
    // Cover the trailing `;` when the statement span excludes it.
    let end = after_stmt_offset(ctx.text(r.file), stmt_range.end);
    // Grants handed over by R1 for a `return slot = value;` statement: they
    // must run before the `return`, inside the text R3 owns.
    let storage_grants: String = take_pending_r1(outcome, r.stmt_span)
        .iter()
        .map(|c| format!("{c}\n{indent}"))
        .collect();
    plan.push(Patch::replace(
        fhec_ir::ByteRange::new(stmt_range.start, end),
        format!(
            "{} {} = {};\n{indent}{storage_grants}{call};\n{indent}return {temp};",
            r.value_ty.solidity_name(),
            temp,
            rendered,
        ),
        Provenance::new("§8.3 R3", ctx.range(r.stmt_span)).with_code("FHE4012"),
    ));
    outcome.owned_stmts.push(r.stmt_span);
    Ok(())
}

// ---------------------------------------------------------------------------
// R1/R3 composition on one statement
// ---------------------------------------------------------------------------

/// Whether an R3 return fact is stated on exactly this statement.
fn is_return_site(ctx: &Ctx<'_, '_>, function: fhec_bind::FunctionId, stmt_span: Span) -> bool {
    ctx.checked
        .acl
        .returns
        .iter()
        .any(|r| r.function == function && r.stmt_span == stmt_span)
}

/// Removes and returns the R1 grants handed over for `stmt_span`.
fn take_pending_r1(outcome: &mut AclOutcome, stmt_span: Span) -> Vec<String> {
    let mut out = Vec::new();
    outcome.pending_r1.retain(|(span, _, _, calls)| {
        if *span == stmt_span {
            out.extend(calls.iter().cloned());
            false
        } else {
            true
        }
    });
    out
}

/// Refuses when R3 did not claim a statement whose R1 grants it was handed.
///
/// The write sits inside a `return`, so there is no position left where the
/// grants would run: before the statement the slot does not hold the value
/// yet, and after it the function has returned. Spec §1.3 — refuse rather
/// than emit a grant that silently never runs.
fn refuse_pending_r1(ctx: &Ctx<'_, '_>, stmt_span: Span, outcome: &mut AclOutcome) -> Result<()> {
    if take_pending_r1(outcome, stmt_span).is_empty() {
        return Ok(());
    }
    let lvalue = strip_parens(&ctx.snippet(stmt_span)).to_string();
    fail_coded(
        stmt_span,
        format!(
            "the encrypted storage write in `{lvalue}` cannot receive its ACL grants: \
             inserted before the statement the slot does not hold the value yet, and \
             inserted after it the function has already returned (spec §8.0); split the \
             statement into a write and a `return`"
        ),
        codes::ACL_POSITION_ILLEGAL,
        Some("§8.1"),
    )
}

// ---------------------------------------------------------------------------
// Braceless branch bodies
// ---------------------------------------------------------------------------

/// Where a trigger statement sits when it is not an element of a `{ }` block.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LoneStmt {
    /// The lone body of an `if`, `else`, `while`, `do` or `for`. A grant
    /// inserted beside it would land outside the branch, so the rule braces
    /// the pair.
    BranchBody,
    /// The initializer of a `for` header. A block is not legal there and the
    /// header holds no statement list, so the rule refuses (spec §1.3).
    ForInit,
}

/// Wraps `stmt_span` in braces when it is a braceless branch body, so that a
/// grant inserted at either of its boundaries stays inside the branch.
///
/// Idempotent per statement: a statement that carries two ACL facts is
/// wrapped once. Refuses with FHE4004 where no block may be written.
fn brace_lone_stmt(
    ctx: &Ctx<'_, '_>,
    function: fhec_bind::FunctionId,
    stmt_span: Span,
    plan: &mut FilePlan,
    outcome: &mut AclOutcome,
) -> Result<()> {
    if outcome.braced.contains(&stmt_span) {
        return Ok(());
    }
    match lone_stmt_position(ctx, function, stmt_span) {
        None => return Ok(()),
        Some(LoneStmt::ForInit) => {
            return fail_coded(
                stmt_span,
                "an ACL grant for this statement cannot be inserted in a `for` header (spec §8); \
                 move the statement above the loop"
                    .to_string(),
                codes::ACL_POSITION_ILLEGAL,
                Some("§8"),
            );
        }
        Some(LoneStmt::BranchBody) => {}
    }
    let file = ctx.unit.function(function).file;
    let range = ctx.range(stmt_span);
    let indent = ctx.line_indent(file, range.start);
    let end = after_stmt_offset(ctx.text(file), range.end);
    plan.push(
        Patch::insert(
            range.start,
            "{ ",
            Provenance::new("§8 brace-wrap", ctx.range(stmt_span)),
        )
        .block_open(),
    );
    plan.push(
        Patch::insert(
            end,
            format!("\n{indent}}}"),
            Provenance::new("§8 brace-wrap", ctx.range(stmt_span)),
        )
        .block_close(),
    );
    outcome.braced.push(stmt_span);
    Ok(())
}

/// Classifies the position of the statement with span `target`, or `None`
/// when it is an ordinary element of a statement list.
fn lone_stmt_position(
    ctx: &Ctx<'_, '_>,
    function: fhec_bind::FunctionId,
    target: Span,
) -> Option<LoneStmt> {
    let body = ctx.unit.function(function).ast.body.as_ref()?;
    scan_block(body, target)
}

fn scan_block<'ast>(block: &'ast [ast::Stmt<'ast>], target: Span) -> Option<LoneStmt> {
    block.iter().find_map(|s| scan_stmt(s, target))
}

fn scan_stmt<'ast>(stmt: &'ast ast::Stmt<'ast>, target: Span) -> Option<LoneStmt> {
    if !(stmt.span.lo() <= target.lo() && target.hi() <= stmt.span.hi()) {
        return None;
    }
    match &stmt.kind {
        ast::StmtKind::Block(b)
        | ast::StmtKind::UncheckedBlock(b)
        | ast::StmtKind::Precondition(b) => scan_block(b, target),
        ast::StmtKind::If(_, t, e) => {
            scan_branch(t, target).or_else(|| e.as_ref().and_then(|e| scan_branch(e, target)))
        }
        ast::StmtKind::While(_, b) | ast::StmtKind::DoWhile(b, _) => scan_branch(b, target),
        ast::StmtKind::For { body, init, .. } => scan_branch(body, target).or_else(|| {
            init.as_ref().and_then(|i| {
                if i.span == target {
                    Some(LoneStmt::ForInit)
                } else {
                    scan_stmt(i, target)
                }
            })
        }),
        ast::StmtKind::Try(t) => t.clauses.iter().find_map(|c| scan_block(&c.block, target)),
        _ => None,
    }
}

/// The direct body of a branching statement: a `Block` holds an ordinary
/// statement list, anything else is the braceless form this module braces.
fn scan_branch<'ast>(body: &'ast ast::Stmt<'ast>, target: Span) -> Option<LoneStmt> {
    match &body.kind {
        ast::StmtKind::Block(b) => scan_block(b, target),
        _ if body.span == target => Some(LoneStmt::BranchBody),
        _ => scan_stmt(body, target),
    }
}

// ---------------------------------------------------------------------------
// Dedupe windows and call matching (spec §8.6)
// ---------------------------------------------------------------------------

/// Statements after the trigger in its enclosing block, up to the next write
/// of `lvalue` or the end of the block.
fn forward_window<'ast>(
    ctx: &Ctx<'_, 'ast>,
    function: fhec_bind::FunctionId,
    trigger: Span,
    lvalue: &str,
) -> Vec<&'ast ast::Stmt<'ast>> {
    let Some((stmts, idx)) = enclosing_block(ctx, function, trigger) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for s in stmts.iter().skip(idx + 1) {
        if writes_to(ctx, s, lvalue) {
            break;
        }
        out.push(s);
    }
    out
}

/// Statements before the trigger in its enclosing block (nearest first).
fn backward_window<'ast>(
    ctx: &Ctx<'_, 'ast>,
    function: fhec_bind::FunctionId,
    trigger: Span,
) -> Vec<&'ast ast::Stmt<'ast>> {
    let Some((stmts, idx)) = enclosing_block(ctx, function, trigger) else {
        return Vec::new();
    };
    stmts.iter().take(idx).rev().collect()
}

/// Finds the enclosing statement list of the statement with span `target`,
/// returning the list plus the statement's index.
fn enclosing_block<'ast>(
    ctx: &Ctx<'_, 'ast>,
    function: fhec_bind::FunctionId,
    target: Span,
) -> Option<(&'ast [ast::Stmt<'ast>], usize)> {
    let body = ctx.unit.function(function).ast.body.as_ref()?;
    search_block(body, target)
}

fn search_block<'ast>(
    block: &'ast [ast::Stmt<'ast>],
    target: Span,
) -> Option<(&'ast [ast::Stmt<'ast>], usize)> {
    for (i, s) in block.iter().enumerate() {
        if s.span == target {
            return Some((block, i));
        }
        if !(s.span.lo() <= target.lo() && target.hi() <= s.span.hi()) {
            continue;
        }
        let found = match &s.kind {
            ast::StmtKind::Block(b)
            | ast::StmtKind::UncheckedBlock(b)
            | ast::StmtKind::Precondition(b) => search_block(b, target),
            ast::StmtKind::If(_, t, e) => {
                search_stmt(t, target).or_else(|| e.as_ref().and_then(|e| search_stmt(e, target)))
            }
            ast::StmtKind::While(_, b) | ast::StmtKind::DoWhile(b, _) => search_stmt(b, target),
            ast::StmtKind::For { body, init, .. } => search_stmt(body, target)
                .or_else(|| init.as_ref().and_then(|s| search_stmt(s, target))),
            ast::StmtKind::Try(t) => t
                .clauses
                .iter()
                .find_map(|c| search_block(&c.block, target)),
            _ => None,
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

fn search_stmt<'ast>(
    stmt: &'ast ast::Stmt<'ast>,
    target: Span,
) -> Option<(&'ast [ast::Stmt<'ast>], usize)> {
    match &stmt.kind {
        ast::StmtKind::Block(b) => search_block(b, target),
        _ => {
            // A braceless branch: treat the single statement as a one-element
            // block when it is the target itself.
            if stmt.span == target {
                Some((std::slice::from_ref(stmt), 0))
            } else {
                search_block(std::slice::from_ref(stmt), target)
            }
        }
    }
}

/// Whether a statement is an assignment to (or inc/dec of) `lvalue`.
fn writes_to<'ast>(ctx: &Ctx<'_, 'ast>, stmt: &'ast ast::Stmt<'ast>, lvalue: &str) -> bool {
    let ast::StmtKind::Expr(e) = &stmt.kind else {
        return false;
    };
    match &e.kind {
        ast::ExprKind::Assign(lhs, _, _) => strip_parens(&ctx.snippet(lhs.span)) == lvalue,
        ast::ExprKind::Unary(op, x)
            if matches!(
                op.kind,
                ast::UnOpKind::PreInc
                    | ast::UnOpKind::PreDec
                    | ast::UnOpKind::PostInc
                    | ast::UnOpKind::PostDec
            ) =>
        {
            strip_parens(&ctx.snippet(x.span)) == lvalue
        }
        _ => false,
    }
}

/// Strips one `address(...)` wrapper, then parentheses.
fn strip_address_cast(s: &str) -> &str {
    let t = strip_parens(s);
    if let Some(rest) = t.strip_prefix("address(") {
        if let Some(inner) = rest.strip_suffix(')') {
            return strip_parens(inner);
        }
    }
    t
}

/// [`acl_call_matches`] with the account operand compared modulo an
/// `address(...)` wrapper (the inserted grant always wraps, spec §8.2).
fn acl_call_matches_normalized<'ast>(
    ctx: &Ctx<'_, 'ast>,
    stmt: &'ast ast::Stmt<'ast>,
    name: &str,
    arg0: &str,
    account_key: &str,
) -> bool {
    let ast::StmtKind::Expr(e) = &stmt.kind else {
        return false;
    };
    let ast::ExprKind::Call(callee, args) = &e.kind else {
        return false;
    };
    let ast::ExprKind::Member(base, method) = &callee.kind else {
        return false;
    };
    if method.to_string() != name {
        return false;
    }
    let arg_texts: Vec<String> = crate::expr::call_arg_exprs(args)
        .iter()
        .map(|a| strip_parens(&ctx.snippet(a.span)).to_string())
        .collect();
    let base_text = strip_parens(&ctx.snippet(base.span)).to_string();
    let account_matches = |t: &str| strip_address_cast(t) == account_key;
    // Library syntax: FHE.name(handle, account).
    let lib = arg_texts.len() == 2 && arg_texts[0] == arg0 && account_matches(&arg_texts[1]);
    // Method syntax: handle.name(account).
    let method_syn = base_text == arg0 && arg_texts.len() == 1 && account_matches(&arg_texts[0]);
    lib || method_syn
}

/// The declared type text of a callee expression, when derivable: a contract
/// cast (`IVault(x)` → `IVault`) or an identifier-rooted mapping/array path
/// (`vaults[i]` → the mapping's value type).
fn callee_type_text<'ast>(ctx: &Ctx<'_, 'ast>, e: &'ast ast::Expr<'ast>) -> Option<String> {
    match &e.kind {
        // A cast: `IVault(addr)` — the head names the type.
        ast::ExprKind::Call(head, _) => match &head.kind {
            ast::ExprKind::Ident(ident) => match ctx.unit.resolve(*ident) {
                Some(fhec_bind::Resolution::Contract(_)) => Some(ctx.snippet(head.span)),
                _ => None,
            },
            ast::ExprKind::Type(_) => Some(ctx.snippet(head.span)),
            _ => None,
        },
        // An identifier-rooted indexed path: walk the declared type.
        ast::ExprKind::Index(..) => {
            let mut steps = 0usize;
            let mut cur = e;
            let vid = loop {
                match &cur.kind {
                    ast::ExprKind::Index(base, ast::IndexKind::Index(Some(_))) => {
                        steps += 1;
                        cur = base;
                    }
                    ast::ExprKind::Ident(ident) => match ctx.unit.resolve(*ident) {
                        Some(fhec_bind::Resolution::StateVar(v))
                        | Some(fhec_bind::Resolution::Local(v))
                        | Some(fhec_bind::Resolution::Param(v)) => break *v,
                        _ => return None,
                    },
                    _ => return None,
                }
            };
            let mut ty = &ctx.unit.var(vid).decl.ty;
            for _ in 0..steps {
                match &ty.kind {
                    ast::TypeKind::Mapping(m) => ty = &m.value,
                    ast::TypeKind::Array(a) => ty = &a.element,
                    _ => return None,
                }
            }
            Some(ctx.snippet(ty.span))
        }
        _ => None,
    }
}

/// Whether a statement is an ACL call `FHE.<name>(arg0[, arg1])` or
/// `arg0.<name>([arg1])` with the given argument texts (spec §8.6).
fn acl_call_matches<'ast>(
    ctx: &Ctx<'_, 'ast>,
    stmt: &'ast ast::Stmt<'ast>,
    name: &str,
    arg0: &str,
    arg1: Option<&str>,
) -> bool {
    let ast::StmtKind::Expr(e) = &stmt.kind else {
        return false;
    };
    let ast::ExprKind::Call(callee, args) = &e.kind else {
        return false;
    };
    let ast::ExprKind::Member(base, method) = &callee.kind else {
        return false;
    };
    if method.to_string() != name {
        return false;
    }
    let arg_texts: Vec<String> = crate::expr::call_arg_exprs(args)
        .iter()
        .map(|a| strip_parens(&ctx.snippet(a.span)).to_string())
        .collect();
    let base_text = strip_parens(&ctx.snippet(base.span)).to_string();

    // Library syntax: FHE.name(handle[, account]) — the base is the library.
    let lib_match = match (arg_texts.first(), arg1) {
        (Some(a0), None) => a0 == arg0 && arg_texts.len() == 1,
        (Some(a0), Some(a1)) => {
            a0 == arg0 && arg_texts.get(1).map(String::as_str) == Some(a1) && arg_texts.len() == 2
        }
        (None, _) => false,
    };
    // Method syntax: handle.name([account]) — the base is the handle.
    let method_match = base_text == arg0
        && match arg1 {
            None => arg_texts.is_empty(),
            Some(a1) => arg_texts.len() == 1 && arg_texts[0] == a1,
        };
    lib_match || method_match
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Finds the expression node with exactly this span in a function body.
fn find_expr<'ast>(
    ctx: &Ctx<'_, 'ast>,
    function: fhec_bind::FunctionId,
    span: Span,
) -> Option<&'ast ast::Expr<'ast>> {
    use solar_ast::visit::Visit;
    use std::ops::ControlFlow;

    struct Finder<'ast> {
        span: Span,
        found: Option<&'ast ast::Expr<'ast>>,
    }
    impl<'ast> Visit<'ast> for Finder<'ast> {
        type BreakValue = ();
        fn visit_expr(&mut self, e: &'ast ast::Expr<'ast>) -> ControlFlow<()> {
            if e.span == self.span {
                self.found = Some(e);
                return ControlFlow::Break(());
            }
            self.walk_expr(e)
        }
    }

    let info = ctx.unit.function(function);
    let body = info.ast.body.as_ref()?;
    let mut f = Finder { span, found: None };
    for s in body.iter() {
        if f.visit_stmt(s).is_break() {
            break;
        }
    }
    f.found
}

fn is_ident_text(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// `a.b.c` chains and bare identifiers do not need callee hoisting.
fn is_simple_path(s: &str) -> bool {
    !s.is_empty() && s.split('.').all(is_ident_text)
}

/// The offset just past the statement's trailing `;`, when the span excludes
/// it.
fn after_stmt_offset(text: &str, stmt_end: usize) -> usize {
    let bytes = text.as_bytes();
    let mut i = stmt_end;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b';' {
        i + 1
    } else {
        stmt_end
    }
}

fn zero_width_at(span: Span) -> Span {
    span.with_lo(span.hi())
}

fn internal(span: Span, err: fhec_targets::ProfileError) -> LowerFailure {
    LowerFailure {
        span,
        message: format!("profile refused a checked operation: {err} (internal)"),
        code: None,
    }
}

fn lost(span: Span, what: &str) -> LowerFailure {
    LowerFailure {
        span,
        message: format!("{what} not found in the function body (internal)"),
        code: None,
    }
}
