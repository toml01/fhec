//! Import-specifier rewriting (spec §2.6): a specifier ending in `.fsol` is
//! rewritten to end in `.sol`. This applies to every file of the unit — it is
//! the only permitted byte difference in otherwise-untouched files.

use fhec_ir::{FilePlan, Patch, Provenance};
use solar_ast as ast;

use crate::ctx::Ctx;

pub(crate) fn rewrite_imports(ctx: &Ctx<'_, '_>, file_idx: usize, plan: &mut FilePlan) {
    let source = ctx.files[file_idx].ast;
    for item in source.items.iter() {
        let ast::ItemKind::Import(import) = &item.kind else {
            continue;
        };
        let lit_span = import.path.span;
        let lit_text = ctx.snippet(lit_span);
        // The literal text includes the quotes; check the specifier tail.
        let Some(stripped) = lit_text
            .strip_suffix('"')
            .and_then(|t| t.strip_suffix(".fsol"))
        else {
            continue;
        };
        let replacement = format!("{stripped}.sol\"");
        plan.push(Patch::replace(
            ctx.range(lit_span),
            replacement,
            Provenance::new("§2.6 import-rewrite", ctx.range(lit_span)),
        ));
    }
}
