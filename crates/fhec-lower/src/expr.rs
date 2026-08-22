//! The recursive expression renderer.
//!
//! Renders the text of an expression after all rewrites: operator/ternary
//! sites become profile calls (nested sites render inline — one patch per
//! outermost site, spec §2.5 / fhec-check's nesting contract), and an optional
//! substitution hook lets the if-lowering pass (spec §5.2) substitute branch
//! version temps for reads of written locations.

use fhec_check::{OperandKind, OperandPlan};
use fhec_ir::{EType, FheOp};
use solar_ast as ast;
use solar_interface::Span;

use crate::ctx::Ctx;

/// A lowering failure: refuse rather than miscompile (spec §1.3). Mapped to
/// a diagnostic by the driver: an explicit `code` (set via [`fail_coded`] at
/// failure sites the spec assigns a stable code, e.g. FHE3013 §5.2 or FHE4003
/// §8.2) takes precedence; otherwise the driver falls back to its legacy
/// message-text heuristic (FHE3011 undecidable-aliasing, or FHE9001 internal-
/// invariant-violation for messages tagged `(internal)`).
#[derive(Debug, Clone)]
pub(crate) struct LowerFailure {
    pub span: Span,
    pub message: String,
    /// The stable catalog code and spec rule for this failure, when the
    /// failure site already knows its classification.
    pub code: Option<(&'static str, Option<&'static str>)>,
}

pub(crate) type Result<T> = std::result::Result<T, LowerFailure>;

pub(crate) fn fail<T>(span: Span, message: impl Into<String>) -> Result<T> {
    Err(LowerFailure {
        span,
        message: message.into(),
        code: None,
    })
}

/// Like [`fail`], but tags the failure with its stable catalog code and spec
/// rule directly, bypassing the driver's message-text heuristic.
pub(crate) fn fail_coded<T>(
    span: Span,
    message: impl Into<String>,
    code: &'static str,
    rule: Option<&'static str>,
) -> Result<T> {
    Err(LowerFailure {
        span,
        message: message.into(),
        code: Some((code, rule)),
    })
}

/// The substitution hook: returns the replacement text for an expression that
/// reads a location the current branch environment has versioned.
pub(crate) type Subst<'r, 'ast> = &'r dyn Fn(&'ast ast::Expr<'ast>) -> Option<String>;

pub(crate) struct Renderer<'r, 'a, 'ast> {
    pub ctx: &'r Ctx<'a, 'ast>,
    pub subst: Option<Subst<'r, 'ast>>,
}

impl<'r, 'a, 'ast> Renderer<'r, 'a, 'ast> {
    pub fn new(ctx: &'r Ctx<'a, 'ast>) -> Self {
        Renderer { ctx, subst: None }
    }

    pub fn with_subst(ctx: &'r Ctx<'a, 'ast>, subst: Subst<'r, 'ast>) -> Self {
        Renderer {
            ctx,
            subst: Some(subst),
        }
    }

    /// The rendered text of `e` after all rewrites within it.
    pub fn render_expr(&self, e: &'ast ast::Expr<'ast>) -> Result<String> {
        if let Some(subst) = self.subst {
            if let Some(replacement) = subst(e) {
                return Ok(replacement);
            }
        }
        if let Some(&i) = self.ctx.ops_by_span.get(&e.span) {
            return self.render_operator_site(e, i);
        }
        if let Some(&i) = self.ctx.terns_by_span.get(&e.span) {
            return self.render_ternary_site(e, i);
        }
        // No rewrite at this node: render children and splice the changes into
        // the original text.
        let mut subs: Vec<(fhec_ir::ByteRange, String)> = Vec::new();
        self.collect_child_subs(e, &mut subs)?;
        let range = self.ctx.range(e.span);
        let text = self.ctx.snippet(e.span);
        // `splice_within` works on file-relative offsets; rebase to the slice.
        let rebased: Vec<(fhec_ir::ByteRange, String)> = subs
            .into_iter()
            .map(|(r, s)| {
                (
                    fhec_ir::ByteRange::new(r.start - range.start, r.end - range.start),
                    s,
                )
            })
            .collect();
        let mut rebased = rebased;
        Ok(crate::ctx::splice_within(
            &text,
            fhec_ir::ByteRange::new(0, text.len()),
            &mut rebased,
        ))
    }

    /// Renders every child expression; when a child's rendering differs from
    /// its source text, records a substitution at the child's range.
    fn collect_child_subs(
        &self,
        e: &'ast ast::Expr<'ast>,
        subs: &mut Vec<(fhec_ir::ByteRange, String)>,
    ) -> Result<()> {
        for child in child_exprs(e) {
            let rendered = self.render_expr(child)?;
            if rendered != self.ctx.snippet(child.span) {
                subs.push((self.ctx.range(child.span), rendered));
            }
        }
        Ok(())
    }

    fn render_operator_site(&self, e: &'ast ast::Expr<'ast>, i: usize) -> Result<String> {
        let site = &self.ctx.checked.operator_sites[i];
        let children: Vec<&'ast ast::Expr<'ast>> = match &e.kind {
            ast::ExprKind::Binary(l, _, r) => vec![l, r],
            ast::ExprKind::Unary(_, x) => vec![x],
            _ => {
                return fail(
                    e.span,
                    "operator site does not match the expression shape (internal)",
                )
            }
        };
        if children.len() != site.operands.len() {
            return fail(e.span, "operator site arity mismatch (internal)");
        }
        let mut types: Vec<EType> = Vec::with_capacity(children.len());
        let mut texts: Vec<String> = Vec::with_capacity(children.len());
        for (child, plan) in children.into_iter().zip(site.operands.iter()) {
            let raw = self.render_expr(child)?;
            let (ty, text) = self.wrap_operand(plan, raw, e.span)?;
            types.push(ty);
            texts.push(text);
        }
        let args: Vec<&str> = texts.iter().map(String::as_str).collect();
        self.ctx
            .profile
            .render_call(site.op, &types, &args)
            .map_err(|err| LowerFailure {
                span: e.span,
                message: format!("profile refused a checked operation: {err} (internal)"),
                code: None,
            })
    }

    fn render_ternary_site(&self, e: &'ast ast::Expr<'ast>, i: usize) -> Result<String> {
        let site = &self.ctx.checked.ternary_sites[i];
        let ast::ExprKind::Ternary(c, t, f) = &e.kind else {
            return fail(
                e.span,
                "ternary site does not match the expression shape (internal)",
            );
        };
        let cond = self.render_expr(c)?;
        let (t_ty, t_text) = {
            let raw = self.render_expr(t)?;
            self.wrap_operand(&site.arms[0], raw, e.span)?
        };
        let (f_ty, f_text) = {
            let raw = self.render_expr(f)?;
            self.wrap_operand(&site.arms[1], raw, e.span)?
        };
        self.ctx
            .profile
            .render_call(
                FheOp::Select,
                &[EType::Ebool, t_ty, f_ty],
                &[&cond, &t_text, &f_text],
            )
            .map_err(|err| LowerFailure {
                span: e.span,
                message: format!("profile refused a checked select: {err} (internal)"),
                code: None,
            })
    }

    /// Applies an operand's conversion plan to its rendered text.
    pub fn wrap_operand(
        &self,
        plan: &OperandPlan,
        text: String,
        site_span: Span,
    ) -> Result<(EType, String)> {
        let profile = self.ctx.profile;
        let wrap_err = |err: fhec_targets::ProfileError| LowerFailure {
            span: site_span,
            message: format!("profile refused a checked coercion: {err} (internal)"),
            code: None,
        };
        match plan.kind {
            OperandKind::AlreadyEncrypted(ty) => Ok((ty, text)),
            OperandKind::TrivialEncrypt { to } | OperandKind::LiteralEncrypt { to } => {
                let call = profile
                    .render_call(FheOp::TrivialEncrypt { to }, &[], &[&text])
                    .map_err(wrap_err)?;
                Ok((to, call))
            }
            OperandKind::WidenEncrypted { from, to } => {
                let call = profile
                    .render_call(FheOp::Widen { from, to }, &[EType::Euint(from)], &[&text])
                    .map_err(wrap_err)?;
                Ok((EType::Euint(to), call))
            }
        }
    }
}

/// The direct child expressions of an expression node, in source order.
pub(crate) fn child_exprs<'ast>(e: &'ast ast::Expr<'ast>) -> Vec<&'ast ast::Expr<'ast>> {
    use ast::ExprKind as K;
    match &e.kind {
        K::Array(items) => items.iter().map(|b| &**b).collect(),
        K::Assign(l, _, r) => vec![l, r],
        K::Binary(l, _, r) => vec![l, r],
        K::Call(callee, args) => {
            let mut v = vec![&**callee];
            v.extend(call_arg_exprs(args));
            v
        }
        K::CallOptions(base, named) => {
            let mut v = vec![&**base];
            v.extend(named.iter().map(|n| &*n.value));
            v
        }
        K::Delete(x) => vec![x],
        K::Ident(_) | K::Lit(..) | K::New(_) | K::TypeCall(_) | K::Type(_) | K::Err(_) => vec![],
        K::Index(base, kind) => {
            let mut v = vec![&**base];
            match kind {
                ast::IndexKind::Index(i) => v.extend(i.iter().map(|b| &**b)),
                ast::IndexKind::Range(l, r) => {
                    v.extend(l.iter().map(|b| &**b));
                    v.extend(r.iter().map(|b| &**b));
                }
            }
            v
        }
        K::Member(base, _) => vec![base],
        K::Payable(args) => call_arg_exprs(args),
        K::Ternary(c, t, f) => vec![c, t, f],
        K::Tuple(items) => items.iter().filter_map(|o| o.as_deref().unspan()).collect(),
        K::Unary(_, x) => vec![x],
    }
}

/// The argument expressions of a call, in source order.
pub(crate) fn call_arg_exprs<'ast>(args: &'ast ast::CallArgs<'ast>) -> Vec<&'ast ast::Expr<'ast>> {
    match &args.kind {
        ast::CallArgsKind::Unnamed(items) => items.iter().map(|b| &**b).collect(),
        ast::CallArgsKind::Named(named) => named.iter().map(|n| &*n.value).collect(),
    }
}
