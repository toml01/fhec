//! Pass 2 — `if`/`else` on encrypted conditions → straight-line `FHE.select`
//! code, per the normative SSA-lite branch-versioning algorithm (spec §5.2):
//!
//! 1. legality is the checker's (already done);
//! 2. hoist the condition into `__fhe_cond_n`, evaluated once;
//! 3. compute the write set of both branches; hoist non-literal index keys;
//!    undecidable aliasing rejects with FHE3011;
//! 4. read a pre-value temp only where a branch or merge needs it;
//! 5. walk each branch with its own environment seeded from those pre-values;
//!    every assignment makes a fresh temp;
//! 6. merge per location, in first-write order:
//!    `L = FHE.select(cond, thenVal-or-pre, elseVal-or-pre);`.
//!
//! When both arms exist, each is a single assignment of the same identifier,
//! and the condition and both right-hand sides are free of side effects, step
//! 6 MAY render as `L = FHE.select(cond, thenRhs, elseRhs)` with no
//! temporaries. Other shapes keep the algorithm above.
//!
//! Nested encrypted `if`s recurse (innermost renders first as part of its
//! enclosing branch walk, spec §5.3); conjunction composes through the merges
//! alone — no condition conjunction is ever synthesized.
//!
//! # Aliasing (spec §5.2 step 3, §7.2 FHE3011)
//!
//! Locations are keyed by their *resolved root declaration* plus an access
//! path, so a shadowing local can never be confused with a state variable.
//! Two indexed paths denote the same location iff their keys are the same
//! hoisted temp (identical source text) or equal literals; distinct literals
//! are distinct locations; every other combination — including reads that may
//! alias a written location — is undecidable and rejects with FHE3011.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use fhec_bind::{Resolution, VarId};
use fhec_check::{PlainTy, Severity, Ty};
use fhec_emit::{TempHint, TempNamer};
use fhec_ir::{EType, FheOp};
use solar_ast as ast;
use solar_interface::Span;

use crate::ctx::{strip_parens, Ctx};
use crate::expr::{call_arg_exprs, fail, fail_coded, LowerFailure, Renderer, Result};

/// The identity of an index key inside a location path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum KeyId {
    /// A literal key: distinct literals are distinct locations.
    Lit(String),
    /// A hoisted non-literal key: identical source text shares one temp.
    Tmp(String),
    /// A non-literal key that was never hoisted (read-side only).
    Raw(String),
}

/// One segment of a location path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Seg {
    Field(String),
    Key(KeyId),
}

/// A written location's identity: resolved root + path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct LocKey {
    root: String,
    segs: Vec<Seg>,
}

/// How two path components relate for aliasing purposes.
enum Rel {
    Same,
    Distinct,
    Unknown,
}

fn seg_rel(a: &Seg, b: &Seg) -> Rel {
    match (a, b) {
        (Seg::Field(x), Seg::Field(y)) => {
            if x == y {
                Rel::Same
            } else {
                Rel::Distinct
            }
        }
        (Seg::Key(x), Seg::Key(y)) => match (x, y) {
            (KeyId::Lit(a), KeyId::Lit(b)) => {
                if a == b {
                    Rel::Same
                } else {
                    Rel::Distinct
                }
            }
            (KeyId::Tmp(a), KeyId::Tmp(b)) => {
                if a == b {
                    Rel::Same
                } else {
                    Rel::Unknown
                }
            }
            _ => Rel::Unknown,
        },
        _ => Rel::Unknown,
    }
}

/// Whether two paths on the same root may denote the same location without
/// being provably equal (spec §5.2 step 3). Equal paths are handled by the
/// caller before this check.
fn may_alias(a: &LocKey, b: &LocKey) -> bool {
    if a.root != b.root {
        return false;
    }
    for (x, y) in a.segs.iter().zip(b.segs.iter()) {
        match seg_rel(x, y) {
            Rel::Distinct => return false,
            Rel::Same => continue,
            Rel::Unknown => return true,
        }
    }
    // One path is a (possibly equal-length) prefix of the other: a write to
    // `s.f` vs a read of `s`, or vice versa — undecidable unless equal.
    a.segs.len() != b.segs.len() || a == b
}

/// One written location (spec §5.2 step 3).
#[derive(Clone, Debug)]
struct Loc {
    key: LocKey,
    /// The text the merge assignment writes (hoisted key temps included).
    display: String,
    ty: EType,
    is_storage: bool,
    /// Why this location's owner is not provably `msg.sender` (spec §8.1,
    /// issue #70), or `None` when it is a mapping keyed by exactly
    /// `msg.sender` and the sender grant is sound. Computed independently of
    /// the `key`/aliasing classification above — this is about ownership,
    /// never about write-set identity.
    sender_unproven: Option<&'static str>,
    /// First write (diagnostics anchor + first-write merge order).
    first_write: Span,
}

/// Per-frame hoisted-key table.
struct KeyTable {
    /// `(canonical source text, temp name, declared key type text)`.
    rows: Vec<(String, String, String)>,
}

impl KeyTable {
    fn lookup(&self, canon: &str) -> Option<&str> {
        self.rows
            .iter()
            .find(|(c, _, _)| c == canon)
            .map(|(_, t, _)| t.as_str())
    }
}

/// The mutable state of one branch walk (spec §5.2 step 5).
struct Env<'f> {
    versions: HashMap<LocKey, String>,
    /// Pre-value temp names. A branch read of one is recorded so unused
    /// incoming values can be omitted safely after rendering.
    pre_of: &'f HashMap<LocKey, String>,
    pre_used: &'f RefCell<HashSet<LocKey>>,
    writes: &'f [Loc],
    keys: &'f KeyTable,
    hint: TempHint,
    /// Fresh version temps this branch allocated (declared by the frame).
    decls: Vec<(EType, String)>,
}

impl Env<'_> {
    fn has(&self, key: &LocKey) -> bool {
        self.writes.iter().any(|l| &l.key == key)
    }

    fn read(&self, key: &LocKey, display: &str) -> String {
        let value = self
            .versions
            .get(key)
            .cloned()
            .unwrap_or_else(|| display.to_string());
        if self.pre_of.get(key) == Some(&value) {
            self.pre_used.borrow_mut().insert(key.clone());
        }
        value
    }
}

/// Frame-independent lowering context for one function's encrypted ifs.
pub(crate) struct IfCtx<'r, 'a, 'ast> {
    pub ctx: &'r Ctx<'a, 'ast>,
    pub namer: &'r RefCell<TempNamer>,
    /// The enclosing function (spec §8.9 policy binding needs it to prove a
    /// storage-pointer local's single-assignment shape).
    pub function: fhec_bind::FunctionId,
    /// The top-level `if` statement span (branch-local detection boundary).
    pub if_span: Span,
    /// Insert vs suggest (spec §8).
    pub acl_insert: bool,
    /// Non-fatal diagnostics sink (FHE4001 warnings, FHE4010 notes).
    pub diags: &'r RefCell<Vec<fhec_check::Diagnostic>>,
    /// Fatal-failure sink for contexts that cannot return `Err` directly
    /// (the substitution hook).
    pub errors: &'r RefCell<Vec<LowerFailure>>,
}

/// Lowers one top-level encrypted `if` statement to its replacement text,
/// positioned at a line whose indentation is `base_indent`.
pub(crate) fn lower_top_if<'ast>(
    ictx: &IfCtx<'_, '_, 'ast>,
    stmt: &'ast ast::Stmt<'ast>,
    base_indent: &str,
) -> Result<String> {
    let text = render_frame(ictx, stmt, base_indent, None)?;
    if let Some(first) = ictx.errors.borrow_mut().drain(..).next() {
        return Err(first);
    }
    Ok(text)
}

fn render_frame<'ast>(
    ictx: &IfCtx<'_, '_, 'ast>,
    stmt: &'ast ast::Stmt<'ast>,
    base_indent: &str,
    outer: Option<&RefCell<Env<'_>>>,
) -> Result<String> {
    let ast::StmtKind::If(cond, then_s, else_s) = &stmt.kind else {
        return fail(stmt.span, "if-site span is not an if statement (internal)");
    };
    let ctx = ictx.ctx;
    let i1 = format!("{base_indent}    ");
    let i2 = format!("{base_indent}        ");

    if let Some(text) = try_direct_select(ictx, stmt, outer, base_indent)? {
        return Ok(text);
    }

    // Step 2: hoist the condition, evaluated once in the enclosing env.
    let cond_text = render_expr_in(ictx, outer, cond)?;
    let cond_temp = ictx.namer.borrow_mut().fresh(TempHint::Cond);

    // Step 3: write set + key hoisting.
    let mut keys = KeyTable { rows: Vec::new() };
    let mut writes: Vec<Loc> = Vec::new();
    scan_branch(ictx, then_s, &mut writes, &mut keys)?;
    if let Some(e) = else_s {
        scan_branch(ictx, e, &mut writes, &mut keys)?;
    }

    // Step 4: allocate candidate pre-values. Branch rendering records which
    // ones are actually read; merge fallbacks do the same below, so a value
    // assigned independently on both arms never reads an uninitialized
    // handle just to feed a select.
    let mut pre_of: HashMap<LocKey, String> = HashMap::new();
    let mut pre_decls: Vec<String> = Vec::new();
    for loc in &writes {
        let init = match outer {
            Some(o) => o.borrow().read(&loc.key, &loc.display),
            None => loc.display.clone(),
        };
        let temp = ictx.namer.borrow_mut().fresh(TempHint::Pre);
        pre_decls.push(format!("{} {} = {};", loc.ty.solidity_name(), temp, init));
        pre_of.insert(loc.key.clone(), temp);
    }
    let pre_used = RefCell::new(HashSet::new());

    // Step 5: branch walks with separate environments.
    let then_env = RefCell::new(Env {
        versions: pre_of.clone(),
        pre_of: &pre_of,
        pre_used: &pre_used,
        writes: &writes,
        keys: &keys,
        hint: TempHint::Then,
        decls: Vec::new(),
    });
    let then_lines = render_branch(ictx, then_s, &then_env, &i2)?;
    let then_env = then_env.into_inner();

    let (else_lines, else_env) = match else_s {
        Some(e) => {
            let env = RefCell::new(Env {
                versions: pre_of.clone(),
                pre_of: &pre_of,
                pre_used: &pre_used,
                writes: &writes,
                keys: &keys,
                hint: TempHint::Else,
                decls: Vec::new(),
            });
            let lines = render_branch(ictx, e, &env, &i2)?;
            (lines, Some(env.into_inner()))
        }
        None => (Vec::new(), None),
    };

    // Step 6: merges in first-write order, then R1 for merged storage writes.
    let mut merge_lines: Vec<String> = Vec::new();
    for loc in &writes {
        let pre = &pre_of[&loc.key];
        let then_v = then_env
            .versions
            .get(&loc.key)
            .cloned()
            .unwrap_or_else(|| pre.clone());
        if then_v == *pre {
            pre_used.borrow_mut().insert(loc.key.clone());
        }
        let else_v = else_env.as_ref().map_or_else(
            || {
                pre_used.borrow_mut().insert(loc.key.clone());
                pre.clone()
            },
            |e| {
                let value = e
                    .versions
                    .get(&loc.key)
                    .cloned()
                    .unwrap_or_else(|| pre.clone());
                if value == *pre {
                    pre_used.borrow_mut().insert(loc.key.clone());
                }
                value
            },
        );
        let select = ctx
            .profile
            .render_call(
                FheOp::Select,
                &[EType::Ebool, loc.ty, loc.ty],
                &[&cond_temp, &then_v, &else_v],
            )
            .map_err(|e| LowerFailure {
                span: stmt.span,
                message: format!("profile refused a checked select: {e} (internal)"),
                code: None,
            })?;
        let target = match outer {
            Some(o) => {
                let mut o = o.borrow_mut();
                if o.has(&loc.key) {
                    let t = ictx.namer.borrow_mut().fresh(o.hint);
                    o.decls.push((loc.ty, t.clone()));
                    o.versions.insert(loc.key.clone(), t.clone());
                    t
                } else {
                    // A location of the enclosing scope the enclosing frame
                    // does not version (e.g. an outer-branch local): direct.
                    loc.display.clone()
                }
            }
            None => loc.display.clone(),
        };
        let is_direct = target == loc.display;
        merge_lines.push(format!("{target} = {select};"));
        if loc.is_storage && is_direct {
            let key_text = |k: &'ast ast::Expr<'ast>| -> String {
                let canon = strip_parens(&ctx.snippet(k.span)).to_string();
                keys.lookup(&canon).map(|t| t.to_string()).unwrap_or(canon)
            };
            append_storage_acl(ictx, loc, stmt.span, &mut merge_lines, &key_text)?;
        }
    }

    let then_decls = then_env.decls;
    let else_decls = else_env.map(|env| env.decls);

    // Assemble the replacement block.
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("{i1}ebool {cond_temp} = {cond_text};\n"));
    for (canon, temp, ty_text) in &keys.rows {
        out.push_str(&format!("{i1}{ty_text} {temp} = {canon};\n"));
    }
    let pre_used = pre_used.into_inner();
    for (loc, d) in writes.iter().zip(&pre_decls) {
        if pre_used.contains(&loc.key) {
            out.push_str(&format!("{i1}{d}\n"));
        }
    }
    for (ty, name) in &then_decls {
        out.push_str(&format!("{i1}{} {name};\n", ty.solidity_name()));
    }
    out.push_str(&format!("{i1}{{\n"));
    for l in &then_lines {
        out.push_str(&format!("{i2}{l}\n"));
    }
    out.push_str(&format!("{i1}}}\n"));
    if let Some(decls) = &else_decls {
        for (ty, name) in decls {
            out.push_str(&format!("{i1}{} {name};\n", ty.solidity_name()));
        }
        out.push_str(&format!("{i1}{{\n"));
        for l in &else_lines {
            out.push_str(&format!("{i2}{l}\n"));
        }
        out.push_str(&format!("{i1}}}\n"));
    }
    for l in &merge_lines {
        out.push_str(&format!("{i1}{l}\n"));
    }
    out.push_str(&format!("{base_indent}}}"));
    Ok(out)
}

/// Direct `L = FHE.select(cond, thenRhs, elseRhs)` when each arm is one
/// assignment of the same identifier and the operands have no side effects.
///
/// Indexed / field lvalues, a missing else, extra statements, nested `if`s,
/// and effectful operands keep the general SSA-lite rendering.
fn try_direct_select<'ast>(
    ictx: &IfCtx<'_, '_, 'ast>,
    stmt: &'ast ast::Stmt<'ast>,
    outer: Option<&RefCell<Env<'_>>>,
    base_indent: &str,
) -> Result<Option<String>> {
    let ast::StmtKind::If(cond, then_s, else_s) = &stmt.kind else {
        return Ok(None);
    };
    let Some(else_s) = else_s.as_deref() else {
        return Ok(None);
    };
    let i1 = format!("{base_indent}    ");
    let Some((then_e, then_lhs, then_rhs)) = single_plain_assign(then_s) else {
        return Ok(None);
    };
    let Some((else_e, else_lhs, else_rhs)) = single_plain_assign(else_s) else {
        return Ok(None);
    };
    if !expr_is_select_safe(ictx, cond)
        || !expr_is_select_safe(ictx, then_rhs)
        || !expr_is_select_safe(ictx, else_rhs)
    {
        return Ok(None);
    }

    let mut keys = KeyTable { rows: Vec::new() };
    let then_canon = classify(ictx, then_lhs, &mut keys, false)?;
    let else_canon = classify(ictx, else_lhs, &mut keys, false)?;
    let (key, display, is_storage) = match (then_canon, else_canon) {
        (
            Canon::Path(then_key, then_disp, then_storage),
            Canon::Path(else_key, else_disp, else_storage),
        ) if then_key == else_key
            && then_key.segs.is_empty()
            && then_disp == else_disp
            && then_storage == else_storage =>
        {
            (then_key, then_disp, then_storage)
        }
        _ => return Ok(None),
    };
    if !keys.rows.is_empty() {
        return Ok(None);
    }
    // Both arms write the same identifier (`then_disp == else_disp`), so the
    // ownership shape (spec §8.1, issue #70) is the same regardless of which
    // arm's lvalue is inspected.
    let sender_unproven = sender_unproven_reason(ictx, then_lhs);

    let then_ty = write_type(ictx, then_s, then_e, then_lhs)?;
    let else_ty = write_type(ictx, else_s, else_e, else_lhs)?;
    if then_ty != else_ty {
        return Ok(None);
    }

    let cond_text = render_expr_in(ictx, outer, cond)?;
    let then_text = render_expr_in(ictx, outer, then_rhs)?;
    let else_text = render_expr_in(ictx, outer, else_rhs)?;
    let select = ictx
        .ctx
        .profile
        .render_call(
            FheOp::Select,
            &[EType::Ebool, then_ty, else_ty],
            &[&cond_text, &then_text, &else_text],
        )
        .map_err(|e| LowerFailure {
            span: stmt.span,
            message: format!("profile refused a checked select: {e} (internal)"),
            code: None,
        })?;

    let loc = Loc {
        key,
        display,
        ty: then_ty,
        is_storage,
        sender_unproven,
        first_write: then_lhs.span,
    };
    let target = match outer {
        Some(o) => {
            let mut o = o.borrow_mut();
            if o.has(&loc.key) {
                let t = ictx.namer.borrow_mut().fresh(o.hint);
                o.decls.push((loc.ty, t.clone()));
                o.versions.insert(loc.key.clone(), t.clone());
                t
            } else {
                loc.display.clone()
            }
        }
        None => loc.display.clone(),
    };
    let is_direct = target == loc.display;
    let mut lines = vec![format!("{target} = {select};")];
    if loc.is_storage && is_direct {
        // No key was ever hoisted on this path (`keys.rows` is empty — the
        // guard above already refused otherwise), so the source snippet is
        // the only text a key could need.
        let key_text =
            |k: &'ast ast::Expr<'ast>| strip_parens(&ictx.ctx.snippet(k.span)).to_string();
        append_storage_acl(ictx, &loc, stmt.span, &mut lines, &key_text)?;
    }
    if lines.len() == 1 {
        return Ok(Some(lines.pop().expect("one merge line")));
    }
    let mut out = String::from("{\n");
    for l in &lines {
        out.push_str(&format!("{i1}{l}\n"));
    }
    out.push_str(&format!("{base_indent}}}"));
    Ok(Some(out))
}

/// One plain `L = R;` statement, possibly wrapped in a single-statement block.
fn single_plain_assign<'ast>(
    stmt: &'ast ast::Stmt<'ast>,
) -> Option<(
    &'ast ast::Expr<'ast>,
    &'ast ast::Expr<'ast>,
    &'ast ast::Expr<'ast>,
)> {
    match &stmt.kind {
        ast::StmtKind::Block(b) => {
            let mut it = b.iter();
            let only = it.next()?;
            if it.next().is_some() {
                return None;
            }
            single_plain_assign(only)
        }
        ast::StmtKind::Expr(e) => match &e.kind {
            ast::ExprKind::Assign(lhs, None, rhs) => Some((e, lhs, rhs)),
            _ => None,
        },
        _ => None,
    }
}

/// Whether `e` is safe to splice as a `FHE.select` operand (spec §5.5).
fn expr_is_select_safe<'ast>(ictx: &IfCtx<'_, '_, 'ast>, e: &'ast ast::Expr<'ast>) -> bool {
    use ast::ExprKind::*;
    match &e.kind {
        Assign(..) | Delete(_) | New(_) | CallOptions(..) | Payable(_) | TypeCall(_) => false,
        Unary(op, x) => !op.kind.has_side_effects() && expr_is_select_safe(ictx, x),
        Call(callee, args) => {
            call_callee_is_select_safe(ictx, e, callee)
                && call_arg_exprs(args)
                    .into_iter()
                    .all(|a| expr_is_select_safe(ictx, a))
        }
        Binary(l, _, r) => expr_is_select_safe(ictx, l) && expr_is_select_safe(ictx, r),
        Ternary(c, a, b) => {
            expr_is_select_safe(ictx, c)
                && expr_is_select_safe(ictx, a)
                && expr_is_select_safe(ictx, b)
        }
        Tuple(els) => els.iter().all(|el| {
            el.as_deref()
                .unspan()
                .is_none_or(|inner| expr_is_select_safe(ictx, inner))
        }),
        Array(els) => els.iter().all(|el| expr_is_select_safe(ictx, el)),
        Index(base, kind) => {
            expr_is_select_safe(ictx, base)
                && match kind {
                    ast::IndexKind::Index(i) => {
                        i.as_deref().is_none_or(|k| expr_is_select_safe(ictx, k))
                    }
                    ast::IndexKind::Range(a, b) => {
                        a.as_deref().is_none_or(|e| expr_is_select_safe(ictx, e))
                            && b.as_deref().is_none_or(|e| expr_is_select_safe(ictx, e))
                    }
                }
        }
        Member(obj, _) => expr_is_select_safe(ictx, obj),
        Lit(..) | Ident(_) | Type(_) | Err(_) => true,
    }
}

fn call_callee_is_select_safe<'ast>(
    ictx: &IfCtx<'_, '_, 'ast>,
    call: &'ast ast::Expr<'ast>,
    callee: &'ast ast::Expr<'ast>,
) -> bool {
    if ictx.ctx.cast_sugar_by_span.contains_key(&call.span) {
        return true;
    }
    let callee_p = callee.peel_parens();
    match &callee_p.kind {
        ast::ExprKind::Member(obj, mname) => match ictx.ctx.checked.types.get(obj.span) {
            Some(Ty::Plain(PlainTy::FheLib)) => true,
            Some(Ty::Encrypted(_)) => true,
            Some(Ty::Plain(PlainTy::EncTypeRef(_))) => {
                matches!(mname.as_str(), "wrap" | "unwrap")
            }
            _ => false,
        },
        ast::ExprKind::Ident(id) => match ictx.ctx.unit.resolve(*id) {
            Some(Resolution::Builtin(b)) => matches!(
                b.0,
                "keccak256"
                    | "sha256"
                    | "ripemd160"
                    | "ecrecover"
                    | "addmod"
                    | "mulmod"
                    | "gasleft"
                    | "blockhash"
                    | "blobhash"
            ),
            Some(Resolution::Contract(_) | Resolution::TypeName(_)) => true,
            _ => matches!(
                ictx.ctx.checked.types.get(callee_p.span),
                Some(Ty::Plain(PlainTy::EncTypeRef(_) | PlainTy::FheFn(_)))
            ),
        },
        ast::ExprKind::Type(_) => true,
        _ => false,
    }
}

fn append_storage_acl<'ast>(
    ictx: &IfCtx<'_, '_, 'ast>,
    loc: &Loc,
    stmt_span: Span,
    lines: &mut Vec<String>,
    key_text: &dyn Fn(&'ast ast::Expr<'ast>) -> String,
) -> Result<()> {
    // R4 (spec §8.9): a policy on the written slot replaces this rule's
    // ownership decision entirely, exactly as it does at a direct write —
    // this is the merge path where issue #81 found a live disclosure.
    if let Some(node) = crate::pass_acl::find_expr(ictx.ctx, ictx.function, loc.first_write) {
        if let Some(bound) = crate::policy_bind::bind_write_with_keys(
            ictx.ctx,
            &ictx.ctx.checked.policies,
            ictx.function,
            node,
            key_text,
        )? {
            return append_policy_grants(ictx, loc, &bound, lines);
        }
    }
    append_ownership_grants(ictx, loc, stmt_span, lines)
}

fn append_policy_grants(
    ictx: &IfCtx<'_, '_, '_>,
    loc: &Loc,
    bound: &crate::policy_bind::BoundWrite<'_>,
    lines: &mut Vec<String>,
) -> Result<()> {
    let rendering = crate::policy_bind::render_readers(
        ictx.ctx,
        ictx.function,
        bound.policy,
        &bound.self_text,
        &bound.key_texts,
    )?;
    let calls = crate::policy_bind::render_call_lines(
        ictx.ctx,
        loc.first_write,
        loc.ty,
        &loc.display,
        &rendering,
    )?;
    if ictx.acl_insert {
        for call in calls {
            lines.push(call.text);
        }
    } else {
        let joined: String = calls.iter().map(|c| format!("{} ", c.text)).collect();
        ictx.diags.borrow_mut().push(fhec_check::Diagnostic {
            code: "FHE4013",
            severity: Severity::Note,
            span: loc.first_write,
            message: format!(
                "ACL suggestion: after the merged write, add `{}`",
                joined.trim_end()
            ),
            fixits: Vec::new(),
            rule: Some("§8.9"),
        });
    }
    Ok(())
}

fn append_ownership_grants(
    ictx: &IfCtx<'_, '_, '_>,
    loc: &Loc,
    stmt_span: Span,
    lines: &mut Vec<String>,
) -> Result<()> {
    // `allowThis` is always sound; `allowSender` is only sound for a slot
    // provably owned by `msg.sender` (spec §8.1, issue #70) — a mapping
    // keyed by exactly `msg.sender`. Everything else (no key at all, or a
    // key that is not provably `msg.sender`) withholds the sender grant and
    // warns, the same as `pass_acl::rule_r1`.
    let ops: &[FheOp] = if let Some(reason) = loc.sender_unproven {
        ictx.diags.borrow_mut().push(fhec_check::Diagnostic {
            code: "FHE4001",
            severity: Severity::Warning,
            span: loc.first_write,
            message: format!(
                "encrypted write to `{}` {reason}, so its owner is not provably \
                 `msg.sender`; the sender grant is withheld here, so the transaction \
                 sender does not gain read access to a ciphertext that is not provably \
                 its own. Add an explicit grant if that is what you intend",
                loc.display
            ),
            fixits: Vec::new(),
            rule: Some("§8.1"),
        });
        &[FheOp::AllowThis]
    } else {
        &[FheOp::AllowThis, FheOp::AllowSender]
    };
    if ictx.acl_insert {
        for &op in ops {
            let call = ictx
                .ctx
                .profile
                .render_call(op, &[loc.ty], &[&loc.display])
                .map_err(|e| LowerFailure {
                    span: stmt_span,
                    message: format!("profile refused an ACL call: {e} (internal)"),
                    code: None,
                })?;
            lines.push(format!("{call};"));
        }
    } else {
        let calls: String = ops
            .iter()
            .map(|op| {
                ictx.ctx
                    .profile
                    .render_call(*op, &[loc.ty], &[&loc.display])
                    .map(|c| format!("{c}; "))
            })
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| LowerFailure {
                span: stmt_span,
                message: format!("profile refused an ACL call: {e} (internal)"),
                code: None,
            })?;
        ictx.diags.borrow_mut().push(fhec_check::Diagnostic {
            code: "FHE4010",
            severity: Severity::Note,
            span: loc.first_write,
            message: format!(
                "ACL suggestion: after the merged write, add `{}`",
                calls.trim_end()
            ),
            fixits: Vec::new(),
            rule: Some("§8.1"),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Location classification
// ---------------------------------------------------------------------------

enum Canon {
    Path(LocKey, String, bool), // key, display, is_storage
    BranchLocal,
    Undecidable(Span, String),
}

/// Classifies an lvalue or read path. `hoist` is `Some` during the write-set
/// scan (non-literal keys get hoisted) and `None` during branch rendering
/// (keys resolve through the already-built table; unknown non-literal keys
/// become [`KeyId::Raw`], which only matters if the path may alias a write).
fn classify<'ast>(
    ictx: &IfCtx<'_, '_, 'ast>,
    e: &'ast ast::Expr<'ast>,
    keys: &mut KeyTable,
    hoist: bool,
) -> Result<Canon> {
    let ctx = ictx.ctx;
    match &e.kind {
        ast::ExprKind::Ident(ident) => {
            let name = ctx.snippet(e.span);
            match ctx.unit.resolve(*ident) {
                Some(Resolution::StateVar(v)) => Ok(Canon::Path(
                    LocKey {
                        root: format!("s{}", v.index()),
                        segs: Vec::new(),
                    },
                    name,
                    true,
                )),
                Some(Resolution::Local(v)) | Some(Resolution::Param(v)) => {
                    let decl_span = ctx.unit.var(*v).decl.span;
                    if ctx.contains(ictx.if_span, decl_span) {
                        return Ok(Canon::BranchLocal);
                    }
                    // A storage-pointer local writes through to storage.
                    let is_storage = matches!(
                        ctx.unit.var(*v).decl.data_location,
                        Some(ast::DataLocation::Storage)
                    );
                    Ok(Canon::Path(
                        LocKey {
                            root: format!("l{}", v.index()),
                            segs: Vec::new(),
                        },
                        name,
                        is_storage,
                    ))
                }
                _ => Ok(Canon::Undecidable(
                    e.span,
                    format!("cannot classify `{name}` as a writable location"),
                )),
            }
        }
        ast::ExprKind::Member(base, field) => match classify(ictx, base, keys, hoist)? {
            Canon::Path(mut key, display, is_storage) => {
                key.segs.push(Seg::Field(field.to_string()));
                Ok(Canon::Path(key, format!("{display}.{field}"), is_storage))
            }
            other => Ok(other),
        },
        ast::ExprKind::Index(base, ast::IndexKind::Index(Some(k))) => {
            match classify(ictx, base, keys, hoist)? {
                Canon::Path(mut key, display, is_storage) => {
                    let (key_id, key_text, _is_addr_key) =
                        classify_key(ictx, base, k, keys, hoist)?;
                    key.segs.push(Seg::Key(key_id));
                    Ok(Canon::Path(
                        key,
                        format!("{display}[{key_text}]"),
                        is_storage,
                    ))
                }
                other => Ok(other),
            }
        }
        // A parenthesized lvalue.
        ast::ExprKind::Tuple(items) if items.len() == 1 => match items[0].as_deref().unspan() {
            Some(inner) => classify(ictx, inner, keys, hoist),
            None => Ok(Canon::Undecidable(e.span, "empty tuple lvalue".into())),
        },
        _ => Ok(Canon::Undecidable(
            e.span,
            "unsupported lvalue shape inside an encrypted branch".into(),
        )),
    }
}

/// Classifies one index key (spec §5.2 step 3): literals stay inline;
/// non-literals hoist to a shared temp during the scan.
fn classify_key<'ast>(
    ictx: &IfCtx<'_, '_, 'ast>,
    base: &'ast ast::Expr<'ast>,
    k: &'ast ast::Expr<'ast>,
    keys: &mut KeyTable,
    hoist: bool,
) -> Result<(KeyId, String, bool)> {
    let ctx = ictx.ctx;
    let canon = strip_parens(&ctx.snippet(k.span)).to_string();
    let is_addr_key = base_key_type(ictx, base).is_some_and(|t| t == "address");
    if matches!(k.kind, ast::ExprKind::Lit(..)) {
        return Ok((KeyId::Lit(canon.clone()), canon, is_addr_key));
    }
    if let Some(temp) = keys.lookup(&canon) {
        return Ok((KeyId::Tmp(temp.to_string()), temp.to_string(), is_addr_key));
    }
    if hoist {
        let ty_text = base_key_type(ictx, base).ok_or_else(|| LowerFailure {
            span: k.span,
            message:
                "cannot determine the index key type for hoisting; the write set is undecidable"
                    .to_string(),
            code: None,
        })?;
        let temp = ictx.namer.borrow_mut().fresh(TempHint::Key);
        keys.rows.push((canon, temp.clone(), ty_text));
        Ok((KeyId::Tmp(temp.clone()), temp, is_addr_key))
    } else {
        Ok((KeyId::Raw(canon.clone()), canon, is_addr_key))
    }
}

/// The declared key type text of the mapping/array being indexed, when the
/// base is a state variable or local with a directly-declared type.
fn base_key_type<'ast>(ictx: &IfCtx<'_, '_, 'ast>, base: &'ast ast::Expr<'ast>) -> Option<String> {
    let ctx = ictx.ctx;
    let vid = root_var(ictx, base)?;
    // Walk the declared type along the base's path below the root.
    let mut ty: &ast::Type<'ast> = &ctx.unit.var(vid).decl.ty;
    let mut path: Vec<&'ast ast::Expr<'ast>> = Vec::new();
    let mut cur = base;
    loop {
        match &cur.kind {
            ast::ExprKind::Ident(_) => break,
            ast::ExprKind::Member(b, _) | ast::ExprKind::Index(b, _) => {
                path.push(cur);
                cur = b;
            }
            ast::ExprKind::Tuple(items) if items.len() == 1 => {
                cur = items[0].as_deref().unspan()?;
            }
            _ => return None,
        }
    }
    for step in path.iter().rev() {
        match (&step.kind, &ty.kind) {
            (ast::ExprKind::Index(..), ast::TypeKind::Mapping(m)) => ty = &m.value,
            (ast::ExprKind::Index(..), ast::TypeKind::Array(a)) => ty = &a.element,
            // Struct fields would need a struct-table walk; unsupported here.
            _ => return None,
        }
    }
    match &ty.kind {
        ast::TypeKind::Mapping(m) => Some(ctx.snippet(m.key.span)),
        ast::TypeKind::Array(_) => Some("uint256".to_string()),
        _ => None,
    }
}

/// Why a merged write's owner is not provably `msg.sender` (spec §8.1, issue
/// #70), or `None` when it is: mirrors `pass_acl::rule_r1`'s slot-kind check
/// — only a mapping keyed by exactly `msg.sender` at the write's own top
/// level earns the sender grant. Everything else (no key at all, a struct
/// field, an array element, or a mapping keyed by anything else) withholds
/// it. This looks only at the top-level shape of `lhs`, independent of the
/// `LocKey` path classification above, which exists for aliasing, not
/// ownership.
///
/// The `msg.sender` proof itself goes through [`fhec_check::is_msg_sender`]
/// (name resolution: `msg` must resolve to the builtin), not a text
/// comparison — a parameter or local named `msg` shadows the builtin, and a
/// spelling check would wrongly treat `msg.sender` under that shadow as
/// proof of ownership. The same helper backs R1's direct-write proof
/// (`SlotKind::Mapping::key_is_msg_sender` in `fhec-check`), so both paths
/// agree on every input, including a parenthesized `(msg).sender`.
fn sender_unproven_reason<'ast>(
    ictx: &IfCtx<'_, '_, 'ast>,
    lhs: &'ast ast::Expr<'ast>,
) -> Option<&'static str> {
    match &lhs.kind {
        ast::ExprKind::Tuple(items) if items.len() == 1 => match items[0].as_deref().unspan() {
            Some(inner) => sender_unproven_reason(ictx, inner),
            None => Some("targets a location that carries no owner key"),
        },
        ast::ExprKind::Index(base, ast::IndexKind::Index(Some(k))) => {
            let is_addr_key = base_key_type(ictx, base).as_deref() == Some("address");
            let is_sender = fhec_check::is_msg_sender(ictx.ctx.unit, k);
            match (is_addr_key, is_sender) {
                (true, true) => None,
                (true, false) => Some("is keyed by an address that is not `msg.sender`"),
                (false, _) => Some("targets a location that carries no owner key"),
            }
        }
        _ => Some("targets a location that carries no owner key"),
    }
}

fn root_var<'ast>(ictx: &IfCtx<'_, '_, 'ast>, e: &'ast ast::Expr<'ast>) -> Option<VarId> {
    match &e.kind {
        ast::ExprKind::Ident(ident) => match ictx.ctx.unit.resolve(*ident) {
            Some(Resolution::StateVar(v))
            | Some(Resolution::Local(v))
            | Some(Resolution::Param(v)) => Some(*v),
            _ => None,
        },
        ast::ExprKind::Member(b, _) | ast::ExprKind::Index(b, _) => root_var(ictx, b),
        ast::ExprKind::Tuple(items) if items.len() == 1 => {
            items[0].as_deref().unspan().and_then(|i| root_var(ictx, i))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Write-set scan (spec §5.2 step 3)
// ---------------------------------------------------------------------------

fn scan_branch<'ast>(
    ictx: &IfCtx<'_, '_, 'ast>,
    stmt: &'ast ast::Stmt<'ast>,
    writes: &mut Vec<Loc>,
    keys: &mut KeyTable,
) -> Result<()> {
    match &stmt.kind {
        ast::StmtKind::Block(b) | ast::StmtKind::UncheckedBlock(b) => {
            for s in b.iter() {
                scan_branch(ictx, s, writes, keys)?;
            }
            Ok(())
        }
        ast::StmtKind::DeclSingle(_) => Ok(()),
        ast::StmtKind::Expr(e) => match &e.kind {
            ast::ExprKind::Assign(lhs, _, _) => {
                let ty = write_type(ictx, stmt, e, lhs)?;
                record_write(ictx, lhs, ty, writes, keys)
            }
            ast::ExprKind::Unary(op, x)
                if matches!(
                    op.kind,
                    ast::UnOpKind::PreInc
                        | ast::UnOpKind::PreDec
                        | ast::UnOpKind::PostInc
                        | ast::UnOpKind::PostDec
                ) =>
            {
                let ty = write_type(ictx, stmt, e, x)?;
                record_write(ictx, x, ty, writes, keys)
            }
            _ => Ok(()),
        },
        ast::StmtKind::If(_, t, e) => {
            // Only encrypted ifs are legal here (checker FHE3007); their merge
            // writes count as writes of this branch too (spec §5.2 step 3).
            if !ictx.ctx.ifs_by_span.contains_key(&stmt.span) {
                return fail(
                    stmt.span,
                    "plaintext control flow inside an encrypted branch survived checking (internal)",
                );
            }
            scan_branch(ictx, t, writes, keys)?;
            if let Some(e) = e {
                scan_branch(ictx, e, writes, keys)?;
            }
            Ok(())
        }
        // A statement form the spec does not enumerate for encrypted branches
        // (e.g. a tuple declaration): rejected rather than lowered by
        // guesswork (spec §5.2).
        _ => fail_coded(
            stmt.span,
            "this statement form is not one of the forms this specification enumerates for an \
             encrypted branch (e.g. a tuple declaration); rejecting rather than lowering by \
             guesswork",
            "FHE3013",
            Some("§5.2"),
        ),
    }
}

/// The encrypted type of a branch write: from the lvalue's recorded type,
/// the compound/inc-dec site, or the right-hand side's type — whichever the
/// checker recorded.
fn write_type<'ast>(
    ictx: &IfCtx<'_, '_, 'ast>,
    _stmt: &'ast ast::Stmt<'ast>,
    e: &'ast ast::Expr<'ast>,
    lhs: &'ast ast::Expr<'ast>,
) -> Result<EType> {
    let ctx = ictx.ctx;
    if let Some(Ty::Encrypted(t)) = ctx.checked.types.get(lhs.span) {
        return Ok(*t);
    }
    if let Some(&i) = ctx.compounds_by_span.get(&e.span) {
        return Ok(ctx.checked.compound_sites[i].lhs);
    }
    if let Some(&i) = ctx
        .incdecs_by_span
        .get(&e.span)
        .or_else(|| ctx.incdecs_by_span.get(&_stmt.span))
    {
        return Ok(ctx.checked.incdec_sites[i].ty);
    }
    if let ast::ExprKind::Assign(_, None, rhs) = &e.kind {
        if let Some(Ty::Encrypted(t)) = ctx.checked.types.get(peel(rhs).span) {
            return Ok(*t);
        }
        // The right-hand side may itself be a rewrite site whose result type
        // is known even when the type table has no entry for its span.
        if let Some(&i) = ctx.ops_by_span.get(&peel(rhs).span) {
            return Ok(ctx.checked.operator_sites[i].result);
        }
        if let Some(&i) = ctx.terns_by_span.get(&peel(rhs).span) {
            return Ok(ctx.checked.ternary_sites[i].result);
        }
    }
    fail(
        lhs.span,
        "cannot establish the encrypted type of a write inside an encrypted branch; \
         refusing to lower",
    )
}

fn peel<'ast>(e: &'ast ast::Expr<'ast>) -> &'ast ast::Expr<'ast> {
    let mut cur = e;
    loop {
        match &cur.kind {
            ast::ExprKind::Tuple(items) if items.len() == 1 => match items[0].as_deref().unspan() {
                Some(inner) => cur = inner,
                None => return cur,
            },
            _ => return cur,
        }
    }
}

fn record_write<'ast>(
    ictx: &IfCtx<'_, '_, 'ast>,
    lhs: &'ast ast::Expr<'ast>,
    ty: EType,
    writes: &mut Vec<Loc>,
    keys: &mut KeyTable,
) -> Result<()> {
    match classify(ictx, lhs, keys, true)? {
        Canon::BranchLocal => Ok(()),
        Canon::Undecidable(span, msg) => Err(LowerFailure {
            span,
            message: msg,
            code: None,
        }),
        Canon::Path(key, display, is_storage) => {
            if writes.iter().any(|l| l.key == key) {
                return Ok(());
            }
            for existing in writes.iter() {
                if may_alias(&existing.key, &key) {
                    return fail(
                        lhs.span,
                        format!(
                            "cannot decide whether `{display}` and `{}` are the same location \
                             (spec §5.2 step 3)",
                            existing.display
                        ),
                    );
                }
            }
            writes.push(Loc {
                key,
                display,
                ty,
                is_storage,
                sender_unproven: sender_unproven_reason(ictx, lhs),
                first_write: lhs.span,
            });
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Branch rendering (spec §5.2 step 5)
// ---------------------------------------------------------------------------

/// Renders an expression with reads substituted from `env` (when given).
fn render_expr_in<'ast>(
    ictx: &IfCtx<'_, '_, 'ast>,
    env: Option<&RefCell<Env<'_>>>,
    e: &'ast ast::Expr<'ast>,
) -> Result<String> {
    match env {
        None => Renderer::new(ictx.ctx).render_expr(e),
        Some(env) => {
            let subst = make_subst(ictx, env);
            Renderer::with_subst(ictx.ctx, &*subst).render_expr(e)
        }
    }
}

/// The substitution hook for one environment: reads of versioned locations
/// become their current version temps; possible-alias reads and expression-
/// position writes are recorded as failures (never guessed around).
fn make_subst<'r, 'f, 'a, 'ast>(
    ictx: &'r IfCtx<'r, 'a, 'ast>,
    env: &'r RefCell<Env<'f>>,
) -> Box<dyn Fn(&'ast ast::Expr<'ast>) -> Option<String> + 'r> {
    Box::new(move |e: &'ast ast::Expr<'ast>| {
        match &e.kind {
            ast::ExprKind::Assign(..) => {
                ictx.errors.borrow_mut().push(LowerFailure {
                    span: e.span,
                    message: "assignment in expression position inside an encrypted branch"
                        .to_string(),
                    code: None,
                });
                return None;
            }
            ast::ExprKind::Unary(op, _)
                if matches!(
                    op.kind,
                    ast::UnOpKind::PreInc
                        | ast::UnOpKind::PreDec
                        | ast::UnOpKind::PostInc
                        | ast::UnOpKind::PostDec
                ) =>
            {
                ictx.errors.borrow_mut().push(LowerFailure {
                    span: e.span,
                    message: "increment/decrement in expression position inside an encrypted \
                              branch"
                        .to_string(),
                    code: None,
                });
                return None;
            }
            ast::ExprKind::Ident(_) | ast::ExprKind::Member(..) | ast::ExprKind::Index(..) => {}
            _ => return None,
        }
        // Read-path classification against this env's frame tables.
        let mut scratch = KeyTable { rows: Vec::new() };
        // The env's keys are read-only here; classification uses a scratch
        // table seeded by lookup through the closure below.
        let canon = {
            let borrowed = env.borrow();
            // Temporarily construct a lookup-preferring classification by
            // copying the frame's key rows into the scratch table.
            scratch.rows = borrowed.keys.rows.clone();
            drop(borrowed);
            classify(ictx, e, &mut scratch, false)
        };
        match canon {
            Ok(Canon::Path(key, display, _)) => {
                let env = env.borrow();
                if env.has(&key) {
                    return Some(env.read(&key, &display));
                }
                for w in env.writes {
                    if may_alias(&w.key, &key) {
                        ictx.errors.borrow_mut().push(LowerFailure {
                            span: e.span,
                            message: format!(
                                "cannot decide whether the read of `{display}` aliases the \
                                 written location `{}` (spec §5.2 step 3)",
                                w.display
                            ),
                            code: None,
                        });
                        return None;
                    }
                }
                None
            }
            Ok(Canon::BranchLocal) | Ok(Canon::Undecidable(..)) => {
                // Unclassifiable reads are only a problem when they share a
                // root with a written location; roots we cannot resolve are
                // not lvalue roots the scan accepted, so they cannot alias.
                None
            }
            Err(f) => {
                ictx.errors.borrow_mut().push(f);
                None
            }
        }
    })
}

/// Renders one branch into statement lines (without leading indentation;
/// multi-line entries carry their own inner indentation based on `indent`).
fn render_branch<'ast>(
    ictx: &IfCtx<'_, '_, 'ast>,
    stmt: &'ast ast::Stmt<'ast>,
    env: &RefCell<Env<'_>>,
    indent: &str,
) -> Result<Vec<String>> {
    let mut out = Vec::new();
    match &stmt.kind {
        ast::StmtKind::Block(b) => {
            for s in b.iter() {
                render_stmt(ictx, s, env, indent, &mut out)?;
            }
        }
        _ => render_stmt(ictx, stmt, env, indent, &mut out)?,
    }
    Ok(out)
}

fn render_stmt<'ast>(
    ictx: &IfCtx<'_, '_, 'ast>,
    stmt: &'ast ast::Stmt<'ast>,
    env: &RefCell<Env<'_>>,
    indent: &str,
    out: &mut Vec<String>,
) -> Result<()> {
    let ctx = ictx.ctx;
    match &stmt.kind {
        ast::StmtKind::Block(b) => {
            let inner = format!("{indent}    ");
            let mut lines = Vec::new();
            for s in b.iter() {
                render_stmt(ictx, s, env, &inner, &mut lines)?;
            }
            out.push(assemble_block("{", &lines, indent, &inner));
        }
        ast::StmtKind::UncheckedBlock(b) => {
            let inner = format!("{indent}    ");
            let mut lines = Vec::new();
            for s in b.iter() {
                render_stmt(ictx, s, env, &inner, &mut lines)?;
            }
            out.push(assemble_block("unchecked {", &lines, indent, &inner));
        }
        ast::StmtKind::If(..) => {
            if !ctx.ifs_by_span.contains_key(&stmt.span) {
                return fail(
                    stmt.span,
                    "plaintext control flow inside an encrypted branch survived checking \
                     (internal)",
                );
            }
            let text = render_frame(ictx, stmt, indent, Some(env))?;
            out.push(text);
        }
        ast::StmtKind::DeclSingle(v) => {
            // A branch-local declaration stays a real declaration; only its
            // initializer is rendered (reads substituted, sites lowered).
            match &v.initializer {
                Some(init) => {
                    let rendered = render_expr_in(ictx, Some(env), init)?;
                    out.push(stmt_text_with(ctx, stmt.span, init.span, &rendered));
                }
                None => out.push(ctx.snippet(stmt.span)),
            }
        }
        ast::StmtKind::Expr(e) => match &e.kind {
            ast::ExprKind::Assign(lhs, None, rhs) => {
                let rendered = render_expr_in(ictx, Some(env), rhs)?;
                write_versioned(ictx, env, lhs, rendered, out)?;
            }
            ast::ExprKind::Assign(lhs, Some(_), _rhs) => {
                let Some(&i) = ctx.compounds_by_span.get(&e.span) else {
                    return fail(
                        e.span,
                        "compound assignment inside an encrypted branch has no rewrite site \
                         (internal)",
                    );
                };
                let site = &ctx.checked.compound_sites[i];
                let ast::ExprKind::Assign(_, _, rhs) = &e.kind else {
                    unreachable!()
                };
                let current = read_lvalue(ictx, env, lhs)?;
                let raw = render_expr_in(ictx, Some(env), rhs)?;
                let renderer = Renderer::new(ctx);
                let (rhs_ty, rhs_text) = renderer.wrap_operand(&site.rhs, raw, e.span)?;
                let call = ctx
                    .profile
                    .render_call(site.op, &[site.lhs, rhs_ty], &[&current, &rhs_text])
                    .map_err(|err| LowerFailure {
                        span: e.span,
                        message: format!("profile refused a checked operation: {err} (internal)"),
                        code: None,
                    })?;
                write_versioned(ictx, env, lhs, call, out)?;
            }
            ast::ExprKind::Unary(op, x)
                if matches!(
                    op.kind,
                    ast::UnOpKind::PreInc
                        | ast::UnOpKind::PreDec
                        | ast::UnOpKind::PostInc
                        | ast::UnOpKind::PostDec
                ) =>
            {
                let Some(&i) = ctx
                    .incdecs_by_span
                    .get(&stmt.span)
                    .or_else(|| ctx.incdecs_by_span.get(&e.span))
                else {
                    return fail(
                        e.span,
                        "increment/decrement inside an encrypted branch has no rewrite site \
                         (internal)",
                    );
                };
                let site = &ctx.checked.incdec_sites[i];
                let current = read_lvalue(ictx, env, x)?;
                let one = ctx
                    .profile
                    .render_call(FheOp::TrivialEncrypt { to: site.ty }, &[], &["1"])
                    .map_err(|err| LowerFailure {
                        span: e.span,
                        message: format!("profile refused a trivial encrypt: {err} (internal)"),
                        code: None,
                    })?;
                let op = if site.is_increment {
                    FheOp::Add
                } else {
                    FheOp::Sub
                };
                let call = ctx
                    .profile
                    .render_call(op, &[site.ty, site.ty], &[&current, &one])
                    .map_err(|err| LowerFailure {
                        span: e.span,
                        message: format!("profile refused a checked operation: {err} (internal)"),
                        code: None,
                    })?;
                write_versioned(ictx, env, x, call, out)?;
            }
            _ => {
                let rendered = render_expr_in(ictx, Some(env), e)?;
                out.push(stmt_text_with(ctx, stmt.span, e.span, &rendered));
            }
        },
        _ => {
            return fail(
                stmt.span,
                "statement kind inside an encrypted branch survived checking (internal)",
            )
        }
    }
    Ok(())
}

/// The current-read text of an lvalue inside a branch (versioned when the
/// location is in the write set).
fn read_lvalue<'ast>(
    ictx: &IfCtx<'_, '_, 'ast>,
    env: &RefCell<Env<'_>>,
    lhs: &'ast ast::Expr<'ast>,
) -> Result<String> {
    let mut scratch = KeyTable {
        rows: env.borrow().keys.rows.clone(),
    };
    match classify(ictx, lhs, &mut scratch, false)? {
        Canon::Path(key, display, _) => Ok(env.borrow().read(&key, &display)),
        Canon::BranchLocal => Ok(ictx.ctx.snippet(lhs.span)),
        Canon::Undecidable(span, msg) => Err(LowerFailure {
            span,
            message: msg,
            code: None,
        }),
    }
}

/// Emits `\<fresh-version-temp\> = value;` for a write-set location, a direct
/// assignment for branch locals.
fn write_versioned<'ast>(
    ictx: &IfCtx<'_, '_, 'ast>,
    env: &RefCell<Env<'_>>,
    lhs: &'ast ast::Expr<'ast>,
    value: String,
    out: &mut Vec<String>,
) -> Result<()> {
    let mut scratch = KeyTable {
        rows: env.borrow().keys.rows.clone(),
    };
    match classify(ictx, lhs, &mut scratch, false)? {
        Canon::BranchLocal => {
            out.push(format!("{} = {};", ictx.ctx.snippet(lhs.span), value));
            Ok(())
        }
        Canon::Undecidable(span, msg) => Err(LowerFailure {
            span,
            message: msg,
            code: None,
        }),
        Canon::Path(key, display, _) => {
            let mut env = env.borrow_mut();
            if !env.has(&key) {
                return fail(
                    lhs.span,
                    format!("write to `{display}` missed the write-set scan (internal)"),
                );
            }
            let ty = env
                .writes
                .iter()
                .find(|l| l.key == key)
                .map(|l| l.ty)
                .expect("checked by has()");
            let hint = env.hint;
            let temp = ictx.namer.borrow_mut().fresh(hint);
            env.decls.push((ty, temp.clone()));
            env.versions.insert(key, temp.clone());
            out.push(format!("{temp} = {value};"));
            Ok(())
        }
    }
}

/// The statement's source text with one expression replaced by its rendering.
fn stmt_text_with(ctx: &Ctx<'_, '_>, stmt_span: Span, expr_span: Span, rendered: &str) -> String {
    let stmt_range = ctx.range(stmt_span);
    let expr_range = ctx.range(expr_span);
    let text = ctx.snippet(stmt_span);
    let start = expr_range.start - stmt_range.start;
    let end = expr_range.end - stmt_range.start;
    format!("{}{}{}", &text[..start], rendered, &text[end..])
}

fn assemble_block(open: &str, lines: &[String], indent: &str, inner: &str) -> String {
    let mut s = String::new();
    s.push_str(open);
    s.push('\n');
    for l in lines {
        s.push_str(&format!("{inner}{l}\n"));
    }
    s.push_str(&format!("{indent}}}"));
    s
}
