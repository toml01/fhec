//! The `in eT name` encrypted-input parameter sugar checks (spec §2.3).

use fhec_bind::{BoundUnit, SourceFile};
use solar_ast as ast;
use solar_interface::Span;

use crate::decl::declared_ty;
use crate::diag::{codes, Diagnostic};
use crate::sites::{CheckedUnit, InSugarSite};
use crate::trust::Trust;
use crate::ty::Ty;

/// Scans sugar occurrences: legality (FHE1010/1011/1012) and expansion sites.
pub(crate) fn scan<'ast>(
    files: &[SourceFile<'ast>],
    unit: &BoundUnit<'ast>,
    trust: &Trust,
    out: &mut CheckedUnit,
) {
    // Function/constructor parameters: the legal position.
    for (fid, f) in unit.functions() {
        let legal_kind = matches!(
            f.ast.kind,
            ast::FunctionKind::Function | ast::FunctionKind::Constructor
        );
        let sites_before = out.sugar_sites.len();
        for &p in &f.params {
            let v = unit.var(p);
            let Some(in_sugar) = v.decl.in_sugar else {
                continue;
            };
            if !legal_kind {
                bad_position(out, v.decl.span, f.ast.kind.to_str());
                continue;
            }
            let ty = declared_ty(unit, trust, &v.decl.ty);
            let Ty::Encrypted(ety) = ty else {
                out.diagnostics.push(
                    Diagnostic::error(
                        codes::IN_SUGAR_NON_ENCRYPTED,
                        v.decl.ty.span,
                        "`in` must be followed by an encrypted type \
                         (ebool, euint8..euint128, eaddress)",
                    )
                    .with_rule("§2.3"),
                );
                continue;
            };
            let Some(name) = v.name else {
                out.diagnostics.push(
                    Diagnostic::error(
                        codes::IN_SUGAR_BAD_POSITION,
                        v.decl.span,
                        "an `in` parameter must be named: the expansion declares \
                         `<name>_input` and converts it into `<name>`",
                    )
                    .with_rule("§2.3"),
                );
                continue;
            };
            let generated = format!("{}_input", name.as_str());
            if ident_occurs(f.ast, &generated) {
                out.diagnostics.push(
                    Diagnostic::error(
                        codes::IN_SUGAR_NAME_COLLISION,
                        v.decl.span,
                        format!(
                            "the expansion needs the identifier `{generated}`, which is \
                             already used in this function; rename one of them \
                             (the transpiler never renames silently)"
                        ),
                    )
                    .with_rule("§2.3"),
                );
                continue;
            }
            out.sugar_sites.push(InSugarSite {
                param_span: v.decl.span,
                params_span: f.ast.header.parameters.span,
                in_span: in_sugar.kw_span,
                ty: ety,
                name: name.as_str().to_string(),
                has_body: f.ast.body.is_some(),
                body_span: f.ast.body.as_ref().map(|b| b.span),
                function: fid,
                file: f.file,
            });
        }
        // The expansion appends one shared `inputProof` parameter per
        // function with sugar (spec §2.3); that name must be free too.
        if out.sugar_sites.len() > sites_before && ident_occurs(f.ast, "inputProof") {
            out.diagnostics.push(
                Diagnostic::error(
                    codes::IN_SUGAR_NAME_COLLISION,
                    f.ast.header.span,
                    "the expansion appends a `bytes memory inputProof` parameter, but \
                     `inputProof` is already used in this function; rename one of them \
                     (the transpiler never renames silently)",
                )
                .with_rule("§2.3"),
            );
        }
        // Return-parameter lists (named and unnamed): never legal.
        for r in f.ast.header.returns() {
            if r.in_sugar.is_some() {
                bad_position(out, r.span, "returns list");
            }
        }
    }

    // Event/error parameter lists and state variables: never legal. These
    // are not iterable through BoundUnit, so walk the file item trees.
    for file in files {
        for item in file.ast.items.iter() {
            scan_item(out, item);
        }
    }
}

fn scan_item(out: &mut CheckedUnit, item: &ast::Item<'_>) {
    match &item.kind {
        ast::ItemKind::Contract(c) => {
            for inner in c.body.iter() {
                scan_item(out, inner);
            }
        }
        ast::ItemKind::Event(ev) => {
            for p in ev.parameters.vars.iter() {
                if p.in_sugar.is_some() {
                    bad_position(out, p.span, "event parameter list");
                }
            }
        }
        ast::ItemKind::Error(err) => {
            for p in err.parameters.vars.iter() {
                if p.in_sugar.is_some() {
                    bad_position(out, p.span, "error parameter list");
                }
            }
        }
        ast::ItemKind::Variable(v) if v.in_sugar.is_some() => {
            bad_position(out, v.span, "variable declaration");
        }
        _ => {}
    }
}

fn bad_position(out: &mut CheckedUnit, span: Span, position: &str) {
    out.diagnostics.push(
        Diagnostic::error(
            codes::IN_SUGAR_BAD_POSITION,
            span,
            format!(
                "the `in` encrypted-input sugar is only permitted in function and \
                 constructor parameter lists, not in a {position}"
            ),
        )
        .with_rule("§2.3"),
    );
}

/// Whether any identifier inside the function item equals `needle`
/// (spec §2.3: the expansion must not collide, and the transpiler must not
/// rename silently).
fn ident_occurs<'ast>(f: &'ast ast::ItemFunction<'ast>, needle: &str) -> bool {
    use ast::visit::Visit;
    use std::ops::ControlFlow;

    struct Search<'x> {
        needle: &'x str,
    }
    impl<'ast> Visit<'ast> for Search<'_> {
        type BreakValue = ();
        fn visit_ident(
            &mut self,
            ident: &'ast solar_interface::Ident,
        ) -> ControlFlow<Self::BreakValue> {
            if ident.as_str() == self.needle {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        }
    }
    Search { needle }.visit_item_function(f).is_break()
}
