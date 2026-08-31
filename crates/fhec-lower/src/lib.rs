//! Pipeline stage 6 (Lower): the three ordered rewrite passes — operators →
//! if/select → ACL — that turn a checked compilation unit into a
//! [`RewritePlan`] of byte-range patches (spec §4, §5, §8).
//!
//! # Contract
//!
//! [`lower`] must run inside the same solar session that parsed, bound, and
//! checked the unit, and only when [`CheckedUnit::has_errors`] is false — the
//! prime directive (spec §1.3) forbids producing output for a unit the
//! checker refused. When lowering itself finds a fault (undecidable aliasing
//! FHE3011, an unsupported statement form in an encrypted branch FHE3013, an
//! ACL callee whose declared type cannot be derived FHE4003, an ACL grant
//! with nowhere legal to go FHE4004, or an internal
//! invariant violation FHE9001), every patch of the affected *file* is
//! dropped: a partially lowered file would be a miscompile, and refusal is
//! always safer.
//!
//! Only `.fsol` files receive rewrite patches (spec §2.1). The §2.6 import
//! rewrite (`.fsol` → `.sol` in import specifiers) applies to every file of
//! the unit and is the single exception.
//!
//! # Determinism
//!
//! Temporaries follow spec §2.4 (`__fhe_<hint>_<n>`, one counter per
//! function, collision skips forward). Within a function, constructs are
//! processed in source order; the same input always produces the same plan.

#![warn(missing_docs)]

use std::cell::RefCell;

use fhec_bind::{BoundUnit, FileId, SourceFile};
use fhec_check::{CheckedUnit, Diagnostic, Severity};
use fhec_emit::TempNamer;
use fhec_ir::{FilePlan, RewritePlan};
use fhec_targets::TargetProfile;
use solar_interface::source_map::SourceMap;

/// The diagnostic codes this crate emits from its own rules (spec §9).
///
/// Codes forwarded from a lowering failure are assigned in [`fault_code`];
/// this module holds the ones a rule cites directly.
pub(crate) mod codes {
    /// An ACL grant would have to be written where no statement may go
    /// (spec §8).
    pub(crate) const ACL_POSITION_ILLEGAL: &str = "FHE4004";
}

mod ctx;
mod expr;
mod idents;
mod imports;
mod pass_acl;
mod pass_if;
mod pass_ops;
mod policy_bind;

use ctx::Ctx;

/// How the ACL pass applies its insertions (spec §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AclMode {
    /// Insert `allowThis`/`allowSender`/`allowTransient` patches (default).
    Insert,
    /// Emit FHE4010–FHE4012 notes with the would-be insertions instead of
    /// patching (`--acl=suggest`).
    Suggest,
}

/// Options for [`lower`].
#[derive(Clone, Copy, Debug)]
pub struct LowerOptions {
    /// ACL insertion mode.
    pub acl_mode: AclMode,
}

impl Default for LowerOptions {
    fn default() -> Self {
        LowerOptions {
            acl_mode: AclMode::Insert,
        }
    }
}

/// The result of stage 6.
pub struct LowerResult {
    /// One [`FilePlan`] per input file, in unit order. Files the lowerer had
    /// to refuse (see [`LowerResult::failed_files`]) have empty plans.
    pub plan: RewritePlan,
    /// Diagnostics produced while lowering: FHE3011/FHE3013/FHE4003 errors,
    /// FHE4001/FHE4002 warnings, FHE4010–FHE4012 suggest-mode notes, FHE9001
    /// internal errors.
    pub diagnostics: Vec<Diagnostic>,
    /// Files whose patches were dropped because lowering found a fault.
    pub failed_files: Vec<FileId>,
}

/// Runs the three lowering passes over a checked unit.
///
/// See the crate docs for the session and no-errors preconditions.
pub fn lower<'ast>(
    files: &[SourceFile<'ast>],
    unit: &BoundUnit<'ast>,
    checked: &CheckedUnit,
    profile: &dyn TargetProfile,
    sm: &SourceMap,
    opts: &LowerOptions,
) -> LowerResult {
    let ctx = Ctx::new(files, unit, checked, profile, sm);
    let diags: RefCell<Vec<Diagnostic>> = RefCell::new(Vec::new());
    let mut plan = RewritePlan::new();
    let mut failed_files: Vec<FileId> = Vec::new();

    if checked.has_errors() {
        // Precondition violated: refuse everything, loudly but safely.
        for f in files {
            plan.push(FilePlan::new(f.name.clone()));
        }
        return LowerResult {
            plan,
            diagnostics: Vec::new(),
            failed_files: unit.files().map(|(id, _)| id).collect(),
        };
    }

    let acl_insert = opts.acl_mode == AclMode::Insert;
    let file_ids: Vec<FileId> = unit.files().map(|(id, _)| id).collect();

    for (file_idx, file) in files.iter().enumerate() {
        let file_id = file_ids[file_idx];
        let mut file_plan = FilePlan::new(file.name.clone());
        let mut failed = false;

        // §2.6 import rewriting applies to every file, dialect or not.
        imports::rewrite_imports(&ctx, file_idx, &mut file_plan);

        if ctx.is_dialect(file_id) {
            let taken = idents::file_idents(file.ast);
            let functions: Vec<fhec_bind::FunctionId> = unit
                .functions()
                .filter(|(_, info)| info.file.index() == file_idx)
                .map(|(id, _)| id)
                .collect();

            'functions: for function in functions {
                let namer = RefCell::new(TempNamer::new(taken.iter().cloned()));
                let errors: RefCell<Vec<expr::LowerFailure>> = RefCell::new(Vec::new());

                // Pass 2 — encrypted ifs, innermost handled via recursion.
                let mut if_sites: Vec<&fhec_check::EncryptedIfSite> = checked
                    .if_sites
                    .iter()
                    .filter(|s| s.function == function && s.depth == 0)
                    .collect();
                if_sites.sort_by_key(|s| ctx.range(s.span).start);
                let mut if_spans: Vec<solar_interface::Span> = Vec::new();

                for site in &if_sites {
                    let Some(stmt) = find_stmt(&ctx, function, site.span) else {
                        push_internal(&diags, site.span, "if-site statement not found");
                        failed = true;
                        break 'functions;
                    };
                    let base_indent = ctx.line_indent(file_id, ctx.range(site.span).start);
                    let ictx = pass_if::IfCtx {
                        ctx: &ctx,
                        namer: &namer,
                        function,
                        if_span: site.span,
                        acl_insert,
                        diags: &diags,
                        errors: &errors,
                    };
                    match pass_if::lower_top_if(&ictx, stmt, &base_indent) {
                        Ok(text) => {
                            file_plan.push(fhec_ir::Patch::replace(
                                ctx.range(site.span),
                                text,
                                fhec_ir::Provenance::new("§5.2 if-select", ctx.range(site.span)),
                            ));
                            if_spans.push(site.span);
                        }
                        Err(f) => {
                            push_failure(&diags, &f);
                            failed = true;
                            break 'functions;
                        }
                    }
                }

                // Pass 3 — ACL rules, in source order, same namer.
                let owned = match pass_acl::run_function(
                    &ctx,
                    function,
                    &namer,
                    acl_insert,
                    &diags,
                    &if_spans,
                    &mut file_plan,
                ) {
                    Ok(o) => o,
                    Err(f) => {
                        push_failure(&diags, &f);
                        failed = true;
                        break 'functions;
                    }
                };

                // Pass 1 — everything expression-level outside spans the
                // other passes own.
                let mut skips = if_spans;
                skips.extend(owned.owned_stmts);
                let skips = pass_ops::SkipSpans { spans: skips };
                if let Err(f) = pass_ops::run_function(&ctx, function, &skips, &mut file_plan) {
                    push_failure(&diags, &f);
                    failed = true;
                    break 'functions;
                }
            }

            // Sugar and shared-boundary expansion are per-file (signatures,
            // not bodies).
            if !failed {
                if let Err(f) = pass_ops::expand_sugar(&ctx, file_idx, &mut file_plan) {
                    push_failure(&diags, &f);
                    failed = true;
                }
            }
            if !failed {
                if let Err(f) = pass_ops::expand_shared(&ctx, file_idx, &mut file_plan) {
                    push_failure(&diags, &f);
                    failed = true;
                }
            }
        }

        if failed {
            // Refuse the whole file (spec §1.3): a partial rewrite would be a
            // miscompile. The import rewrite goes down with it.
            failed_files.push(file_id);
            plan.push(FilePlan::new(file.name.clone()));
        } else {
            plan.push(file_plan);
        }
    }

    LowerResult {
        plan,
        diagnostics: diags.into_inner(),
        failed_files,
    }
}

fn push_failure(diags: &RefCell<Vec<Diagnostic>>, f: &expr::LowerFailure) {
    let (code, rule) = match f.code {
        Some((code, rule)) => (code, rule),
        None if f.message.contains("(internal)") => ("FHE9001", None),
        None => ("FHE3011", Some("§5.2")),
    };
    diags.borrow_mut().push(Diagnostic {
        code,
        severity: Severity::Error,
        span: f.span,
        message: f.message.clone(),
        fixits: Vec::new(),
        rule,
    });
}

fn push_internal(diags: &RefCell<Vec<Diagnostic>>, span: solar_interface::Span, msg: &str) {
    diags.borrow_mut().push(Diagnostic {
        code: "FHE9001",
        severity: Severity::Error,
        span,
        message: format!("{msg} (internal)"),
        fixits: Vec::new(),
        rule: None,
    });
}

/// Finds the statement with exactly this span in a function body.
fn find_stmt<'ast>(
    ctx: &Ctx<'_, 'ast>,
    function: fhec_bind::FunctionId,
    span: solar_interface::Span,
) -> Option<&'ast solar_ast::Stmt<'ast>> {
    use solar_ast::visit::Visit;
    use std::ops::ControlFlow;

    struct Finder<'ast> {
        span: solar_interface::Span,
        found: Option<&'ast solar_ast::Stmt<'ast>>,
    }
    impl<'ast> Visit<'ast> for Finder<'ast> {
        type BreakValue = ();
        fn visit_stmt(&mut self, s: &'ast solar_ast::Stmt<'ast>) -> ControlFlow<()> {
            if s.span == self.span {
                self.found = Some(s);
                return ControlFlow::Break(());
            }
            self.walk_stmt(s)
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
