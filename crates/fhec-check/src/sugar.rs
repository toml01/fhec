//! The `in eT name` encrypted-input parameter sugar checks (spec §2.3).

use fhec_bind::{BoundUnit, FunctionInfo, SourceFile};
use solar_ast as ast;
use solar_interface::Span;

use crate::decl::declared_ty;
use crate::diag::{codes, Diagnostic};
use crate::sites::{CheckedUnit, InSugarSite};
use crate::trust::Trust;
use crate::ty::Ty;

/// The proof every `in` parameter of one function verifies against.
///
/// A function's sugared parameters all use the implicit trailing-proof form
/// or all bind the same author-declared proof parameter; mixing the two, or
/// binding two different proofs, is FHE1014.
enum ProofMode {
    /// `in eT name`: the expansion appends one `bytes memory inputProof`.
    Appended,
    /// `in(name) eT ...`: the named same-list `bytes` parameter is used and
    /// nothing is appended.
    Bound(String),
}

/// Scans sugar occurrences: legality (FHE1010–FHE1014) and expansion sites.
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
        // The proof binding is a property of the whole parameter list, so it
        // is resolved before any site is stated: an inconsistent or
        // unresolvable binding states no site at all, and the unit is
        // refused (§1.3).
        let mode = if legal_kind {
            match proof_mode(unit, f, out) {
                Ok(mode) => mode,
                Err(()) => {
                    scan_returns(out, f);
                    continue;
                }
            }
        } else {
            ProofMode::Appended
        };
        let sites_before = out.sugar_sites.len();
        for &p in &f.params {
            let v = unit.var(p);
            let Some(in_sugar) = v.decl.in_sugar else {
                continue;
            };
            if v.decl.shared.is_some() {
                // `in shared eT name` is the §2.8 shared boundary, not an
                // external input: it expands to a different wire type and a
                // different materializer. `crate::shared` owns it.
                continue;
            }
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
            // A bodiless declaration generates no local and keeps the
            // author's parameter name, so no name is introduced to collide.
            let generated = format!("{}_input", name.as_str());
            if f.ast.body.is_some() && ident_occurs(f.ast, &generated) {
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
            if let Some(span) = modifier_reference(f.ast, name.as_str()) {
                refuse_modifier_reference(out, span, name.as_str(), &generated, "§2.3");
                continue;
            }
            out.sugar_sites.push(InSugarSite {
                param_span: v.decl.span,
                params_span: f.ast.header.parameters.span,
                in_span: in_sugar.kw_span,
                proof: match &mode {
                    ProofMode::Appended => None,
                    ProofMode::Bound(proof) => Some(proof.clone()),
                },
                ty: ety,
                name: name.as_str().to_string(),
                has_body: f.ast.body.is_some(),
                body_span: f.ast.body.as_ref().map(|b| b.span),
                function: fid,
                file: f.file,
            });
        }
        // The implicit form appends one shared `inputProof` parameter per
        // function with sugar (spec §2.3); that name must be free too. The
        // explicit binder appends nothing and introduces no fixed generated
        // name, so it has nothing to guard here.
        if matches!(mode, ProofMode::Appended)
            && out.sugar_sites.len() > sites_before
            && ident_occurs(f.ast, "inputProof")
        {
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
        scan_returns(out, f);
    }

    // Event/error parameter lists and state variables: never legal. These
    // are not iterable through BoundUnit, so walk the file item trees.
    for file in files {
        for item in file.ast.items.iter() {
            scan_item(out, item);
        }
    }
}

/// Return-parameter lists (named and unnamed): never legal.
fn scan_returns(out: &mut CheckedUnit, f: &FunctionInfo<'_>) {
    for r in f.ast.header.returns() {
        if r.in_sugar.is_some() {
            bad_position(out, r.span, "returns list");
        }
    }
}

/// Resolves the one proof every sugared parameter of `f` verifies against.
///
/// `Err(())` means the binding is illegal and was reported; the caller states
/// no site for the function.
fn proof_mode(
    unit: &BoundUnit<'_>,
    f: &FunctionInfo<'_>,
    out: &mut CheckedUnit,
) -> Result<ProofMode, ()> {
    // `in shared` parameters carry the `in` marker too but bind no proof
    // (§2.8); they are not part of this list's proof agreement.
    let sugared: Vec<&ast::VariableDefinition<'_>> = f
        .params
        .iter()
        .map(|&p| unit.var(p).decl)
        .filter(|d| d.in_sugar.is_some() && d.shared.is_none())
        .collect();
    let Some(first) = sugared.first() else {
        return Ok(ProofMode::Appended);
    };
    let first_sugar = first.in_sugar.expect("filtered on `in_sugar`");

    // Every sugared parameter of one list must agree with the first: same
    // form, and — in the explicit form — the same proof identifier. Mixing
    // is refused rather than resolved (§1.3): the two forms produce
    // different ABIs.
    let mut consistent = true;
    for decl in &sugared[1..] {
        let sugar = decl.in_sugar.expect("filtered on `in_sugar`");
        let agrees = match (first_sugar.proof, sugar.proof) {
            (None, None) => true,
            (Some(a), Some(b)) => a.as_str() == b.as_str(),
            _ => false,
        };
        if agrees {
            continue;
        }
        consistent = false;
        out.diagnostics.push(
            Diagnostic::error(
                codes::IN_SUGAR_PROOF_BINDING_INCONSISTENT,
                sugar.span,
                format!(
                    "this `in` parameter uses {}, but the first `in` parameter of this list \
                     uses {} — every `in` parameter of one parameter list must verify \
                     against the same proof",
                    describe_form(sugar.proof),
                    describe_form(first_sugar.proof),
                ),
            )
            .with_rule("§2.3"),
        );
    }
    if !consistent {
        return Err(());
    }

    let Some(proof) = first_sugar.proof else {
        return Ok(ProofMode::Appended);
    };

    // The binder must name exactly one parameter of this same list, declared
    // `bytes memory` or `bytes calldata`. Anything else is refused; the
    // transpiler never guesses which parameter carries the proof.
    let named: Vec<&ast::VariableDefinition<'_>> = f
        .params
        .iter()
        .map(|&p| unit.var(p).decl)
        .filter(|d| d.name.is_some_and(|n| n.as_str() == proof.as_str()))
        .collect();
    let [target] = named[..] else {
        let message = if named.is_empty() {
            format!(
                "`in({0})` must name a `bytes memory` or `bytes calldata` parameter of this \
                 parameter list, but no such parameter is declared here",
                proof.as_str()
            )
        } else {
            // Solidity forbids duplicate parameter names (the binder reports
            // FHE1020), so this is unreachable in a well-formed list; the
            // binding is still ambiguous, so it is refused rather than
            // resolved to the first match (§1.3).
            format!(
                "`in({0})` is ambiguous: this parameter list declares `{0}` more than once",
                proof.as_str()
            )
        };
        out.diagnostics.push(
            Diagnostic::error(codes::IN_SUGAR_PROOF_BINDING_INVALID, proof.span, message)
                .with_rule("§2.3"),
        );
        return Err(());
    };
    let is_bytes = matches!(
        target.ty.kind,
        ast::TypeKind::Elementary(ast::ElementaryType::Bytes)
    );
    let location_ok = matches!(
        target.data_location,
        Some(ast::DataLocation::Memory | ast::DataLocation::Calldata)
    );
    if !is_bytes || !location_ok {
        out.diagnostics.push(
            Diagnostic::error(
                codes::IN_SUGAR_PROOF_BINDING_INVALID,
                target.span,
                format!(
                    "`in({0})` names this parameter, which must be declared \
                     `bytes memory {0}` or `bytes calldata {0}` to carry the input proof",
                    proof.as_str()
                ),
            )
            .with_rule("§2.3"),
        );
        return Err(());
    }
    Ok(ProofMode::Bound(proof.as_str().to_string()))
}

/// Names one of the two sugar forms for an FHE1014 message.
fn describe_form(proof: Option<solar_interface::Ident>) -> String {
    match proof {
        Some(p) => format!("the explicit binder `in({})`", p.as_str()),
        None => "the implicit trailing proof (`in`)".to_string(),
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

/// The span of the first modifier-invocation argument that names `needle`.
///
/// A modifier invocation belongs to the function *header* and is evaluated
/// before the body opens, but a dialect-managed parameter only exists as
/// `<name>` from the materializer onwards — in the header the parameter is
/// the wire name. A reference from a modifier argument would therefore emit
/// an undeclared identifier (spec §2.3, §2.8).
pub(crate) fn modifier_reference<'ast>(
    f: &'ast ast::ItemFunction<'ast>,
    needle: &str,
) -> Option<Span> {
    use ast::visit::Visit;
    use std::ops::ControlFlow;

    struct Search<'x> {
        needle: &'x str,
    }
    impl<'ast> Visit<'ast> for Search<'_> {
        type BreakValue = Span;
        fn visit_ident(
            &mut self,
            ident: &'ast solar_interface::Ident,
        ) -> ControlFlow<Self::BreakValue> {
            if ident.as_str() == self.needle {
                ControlFlow::Break(ident.span)
            } else {
                ControlFlow::Continue(())
            }
        }
    }
    for m in f.header.modifiers.iter() {
        // Only the arguments: the modifier's own name cannot shadow a
        // parameter.
        if let Some(args) = m.arguments.exprs().next().map(|_| &m.arguments) {
            for e in args.exprs() {
                if let ControlFlow::Break(span) = (Search { needle }).visit_expr(e) {
                    return Some(span);
                }
            }
        }
    }
    None
}

/// Emits the "a modifier invocation cannot name this parameter" refusal.
pub(crate) fn refuse_modifier_reference(
    out: &mut CheckedUnit,
    span: Span,
    name: &str,
    wire: &str,
    rule: &'static str,
) {
    out.diagnostics.push(
        Diagnostic::error(
            codes::SUGAR_NAME_IN_MODIFIER,
            span,
            format!(
                "a modifier invocation cannot name `{name}`: the header declares the \
                 parameter as `{wire}`, and `{name}` only exists from the start of the \
                 function body; move the check into the body"
            ),
        )
        .with_rule(rule),
    );
}

/// Whether any identifier inside the function item equals `needle`
/// (spec §2.3, §2.8: a fixed generated name must not collide, and the
/// transpiler must not rename silently).
pub(crate) fn ident_occurs<'ast>(f: &'ast ast::ItemFunction<'ast>, needle: &str) -> bool {
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
