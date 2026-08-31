//! FHE4009 — known-empty reader set at a `return` or `emit` (spec §8.12).
//!
//! Fires only on the narrow, safely-decidable case: an encrypted value
//! built *entirely* from number literals through profile operations, with
//! no read of any kind. Anything else — a state variable (already has at
//! least `allowThis` from R1), a parameter, a local, or an opaque call
//! states no fact and is silently skipped, per spec §8.12's own warning
//! that an encrypted parameter must never trigger this.

use fhec_bind::BoundUnit;
use solar_ast as ast;

use crate::diag::{codes, Diagnostic, Severity};
use crate::sites::CheckedUnit;
use crate::ty::{PlainTy, Ty};

/// Scans every function body for a `return`/`emit` reaching a known-empty
/// encrypted value. Must run after the main type-checking walk: it reads
/// `out.types` and `out.cast_sugar_sites`, populated during that walk.
///
/// A `return` only counts in a `public`/`external` function — the same
/// boundary R3 uses (spec §8.3): an `internal` return never leaves the
/// contract at this site, so its value's journey is not over yet and it may
/// still gain a real, persistent reader later in the same transaction (the
/// common `internal` accessor feeding a storage write is exactly this
/// shape). An `emit` always counts regardless of the emitting function's
/// visibility: it is the boundary itself, spec §8.10's "only boundary at
/// which an EOA receives a handle it must read later."
pub(crate) fn scan(unit: &BoundUnit<'_>, out: &mut CheckedUnit) {
    let mut diags = Vec::new();
    for (_, info) in unit.functions() {
        let Some(body) = info.ast.body.as_ref() else {
            continue;
        };
        let returns_count = matches!(
            info.ast.header.visibility(),
            Some(ast::Visibility::Public) | Some(ast::Visibility::External)
        );
        for stmt in body.iter() {
            walk_stmt(out, stmt, returns_count, &mut diags);
        }
    }
    out.diagnostics.append(&mut diags);
}

fn walk_stmt<'ast>(
    out: &CheckedUnit,
    stmt: &'ast ast::Stmt<'ast>,
    returns_count: bool,
    diags: &mut Vec<Diagnostic>,
) {
    use ast::StmtKind::*;
    match &stmt.kind {
        Return(Some(e)) if returns_count => check_site(out, e, "return", diags),
        Return(_) => {}
        Emit(_, args) => {
            for a in args.exprs() {
                check_site(out, a, "emit", diags);
            }
        }
        Block(b) | UncheckedBlock(b) | Precondition(b) => {
            for s in b.iter() {
                walk_stmt(out, s, returns_count, diags);
            }
        }
        If(_, t, e) => {
            walk_stmt(out, t, returns_count, diags);
            if let Some(e) = e {
                walk_stmt(out, e, returns_count, diags);
            }
        }
        While(_, b) | DoWhile(b, _) => walk_stmt(out, b, returns_count, diags),
        For { body, init, .. } => {
            walk_stmt(out, body, returns_count, diags);
            if let Some(i) = init {
                walk_stmt(out, i, returns_count, diags);
            }
        }
        Try(t) => {
            for c in t.clauses.iter() {
                for s in c.block.iter() {
                    walk_stmt(out, s, returns_count, diags);
                }
            }
        }
        _ => {}
    }
}

fn check_site(out: &CheckedUnit, e: &ast::Expr<'_>, site: &str, diags: &mut Vec<Diagnostic>) {
    if !matches!(out.types.get(e.span), Some(Ty::Encrypted(_))) {
        return; // only encrypted values are in scope
    }
    if !is_empty_provenance(out, e) {
        return;
    }
    diags.push(Diagnostic {
        code: codes::ACL_EMPTY_READER_SET,
        severity: Severity::Warning,
        span: e.span,
        message: format!(
            "this value reaches a {site} built entirely from literals through profile \
             operations, with no read of any kind: its reader set is known to be empty, so \
             nothing but this transaction can read it (spec §8.12)"
        ),
        fixits: Vec::new(),
        rule: Some("§8.12"),
    });
}

/// Whether `e`'s value is provably built with no read at all: a number
/// literal, or a cast/profile operation applied only to such values.
/// Anything that reads a name (state variable, parameter, or local) is not
/// decidable here and returns `false` — never a guess in the other
/// direction (spec §1.3, §8.12).
fn is_empty_provenance(out: &CheckedUnit, e: &ast::Expr<'_>) -> bool {
    match &e.peel_parens().kind {
        ast::ExprKind::Lit(..) => true,
        ast::ExprKind::Unary(_, x) => is_empty_provenance(out, x),
        ast::ExprKind::Binary(l, _, r) => {
            is_empty_provenance(out, l) && is_empty_provenance(out, r)
        }
        ast::ExprKind::Ternary(c, a, b) => {
            is_empty_provenance(out, c)
                && is_empty_provenance(out, a)
                && is_empty_provenance(out, b)
        }
        ast::ExprKind::Call(callee, args) => {
            let is_cast_sugar = out.cast_sugar_sites.iter().any(|s| s.call_span == e.span);
            // The checker types a call's callee *object* (`FHE`, or the
            // encrypted receiver of method syntax), not the member
            // expression itself — mirror that dispatch here.
            let is_profile_call = match &callee.peel_parens().kind {
                ast::ExprKind::Member(obj, _) => matches!(
                    out.types.get(obj.span),
                    Some(Ty::Plain(PlainTy::FheLib))
                        | Some(Ty::Encrypted(_))
                        | Some(Ty::Plain(PlainTy::EncTypeRef(_)))
                ),
                _ => false,
            };
            (is_cast_sugar || is_profile_call) && args.exprs().all(|a| is_empty_provenance(out, a))
        }
        _ => false,
    }
}
