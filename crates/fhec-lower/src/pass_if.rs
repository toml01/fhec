//! Pass 2 — `if`/`else` on encrypted conditions → straight-line `FHE.select`
//! code, per the normative SSA-lite branch-versioning algorithm (spec §5.2):
//!
//! 1. legality is the checker's (already done);
//! 2. hoist the condition into `__fhe_cond_n`, evaluated once;
//! 3. compute the write set of both branches; hoist non-literal index keys;
//!    undecidable aliasing rejects with FHE3011;
//! 4. read a pre-value temp per written location;
//! 5. walk each branch with its own environment seeded from the pre-values;
//!    every assignment makes a fresh temp;
//! 6. merge per location, in first-write order:
//!    `L = FHE.select(cond, thenVal-or-pre, elseVal-or-pre);`.
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
use std::collections::HashMap;

use fhec_bind::{Resolution, VarId};
use fhec_check::{Severity, Ty};
use fhec_emit::{TempHint, TempNamer};
use fhec_ir::{EType, FheOp};
use solar_ast as ast;
use solar_interface::Span;

use crate::ctx::{strip_parens, Ctx};
use crate::expr::{fail, fail_coded, LowerFailure, Renderer, Result};

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
    /// Mapping slot keyed by a plaintext address other than `msg.sender`.
    addr_key_not_sender: bool,
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
        self.versions
            .get(key)
            .cloned()
            .unwrap_or_else(|| display.to_string())
    }
}

/// Frame-independent lowering context for one function's encrypted ifs.
pub(crate) struct IfCtx<'r, 'a, 'ast> {
    pub ctx: &'r Ctx<'a, 'ast>,
    pub namer: &'r RefCell<TempNamer>,
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

    // Step 4: pre-values, read in the enclosing environment.
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

    // Step 5: branch walks with separate environments.
    let then_env = RefCell::new(Env {
        versions: pre_of.clone(),
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
        let then_v = then_env.read(&loc.key, pre);
        let else_v = else_env
            .as_ref()
            .map_or_else(|| pre.clone(), |e| e.read(&loc.key, pre));
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
        let acl_lines = &mut merge_lines;

        if loc.is_storage && is_direct {
            if loc.addr_key_not_sender {
                ictx.diags.borrow_mut().push(fhec_check::Diagnostic {
                    code: "FHE4001",
                    severity: Severity::Warning,
                    span: loc.first_write,
                    message: format!(
                        "encrypted write to `{}` is keyed by an address that is not `msg.sender`; \
                         the transaction sender gains read access to a ciphertext filed under \
                         another address",
                        loc.display
                    ),
                    fixits: Vec::new(),
                    rule: Some("§8.1"),
                });
            }
            if ictx.acl_insert {
                for op in [FheOp::AllowThis, FheOp::AllowSender] {
                    let call = ctx
                        .profile
                        .render_call(op, &[loc.ty], &[&loc.display])
                        .map_err(|e| LowerFailure {
                            span: stmt.span,
                            message: format!("profile refused an ACL call: {e} (internal)"),
                            code: None,
                        })?;
                    acl_lines.push(format!("{call};"));
                }
            } else {
                ictx.diags.borrow_mut().push(fhec_check::Diagnostic {
                    code: "FHE4010",
                    severity: Severity::Note,
                    span: loc.first_write,
                    message: format!(
                        "ACL suggestion: after the merged write, add \
                         `FHE.allowThis({0}); FHE.allowSender({0});`",
                        loc.display
                    ),
                    fixits: Vec::new(),
                    rule: Some("§8.1"),
                });
            }
        }
    }

    // Assemble the replacement block.
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("{i1}ebool {cond_temp} = {cond_text};\n"));
    for (canon, temp, ty_text) in &keys.rows {
        out.push_str(&format!("{i1}{ty_text} {temp} = {canon};\n"));
    }
    for d in &pre_decls {
        out.push_str(&format!("{i1}{d}\n"));
    }
    for (ty, name) in &then_env.decls {
        out.push_str(&format!("{i1}{} {name};\n", ty.solidity_name()));
    }
    out.push_str(&format!("{i1}{{\n"));
    for l in &then_lines {
        out.push_str(&format!("{i2}{l}\n"));
    }
    out.push_str(&format!("{i1}}}\n"));
    if let Some(env) = &else_env {
        for (ty, name) in &env.decls {
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

// ---------------------------------------------------------------------------
// Location classification
// ---------------------------------------------------------------------------

enum Canon {
    Path(LocKey, String, bool, bool), // key, display, is_storage, addr_key_not_sender
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
                    false,
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
                        false,
                    ))
                }
                _ => Ok(Canon::Undecidable(
                    e.span,
                    format!("cannot classify `{name}` as a writable location"),
                )),
            }
        }
        ast::ExprKind::Member(base, field) => match classify(ictx, base, keys, hoist)? {
            Canon::Path(mut key, display, is_storage, addr) => {
                key.segs.push(Seg::Field(field.to_string()));
                Ok(Canon::Path(
                    key,
                    format!("{display}.{field}"),
                    is_storage,
                    addr,
                ))
            }
            other => Ok(other),
        },
        ast::ExprKind::Index(base, ast::IndexKind::Index(Some(k))) => {
            match classify(ictx, base, keys, hoist)? {
                Canon::Path(mut key, display, is_storage, addr) => {
                    let (key_id, key_text, is_addr_key) = classify_key(ictx, base, k, keys, hoist)?;
                    let not_sender =
                        is_addr_key && strip_parens(&ctx.snippet(k.span)) != "msg.sender";
                    key.segs.push(Seg::Key(key_id));
                    Ok(Canon::Path(
                        key,
                        format!("{display}[{key_text}]"),
                        is_storage,
                        addr || not_sender,
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
        Canon::Path(key, display, is_storage, addr_key_not_sender) => {
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
                addr_key_not_sender,
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
            Ok(Canon::Path(key, display, _, _)) => {
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
        Canon::Path(key, display, _, _) => Ok(env.borrow().read(&key, &display)),
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
        Canon::Path(key, display, _, _) => {
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
