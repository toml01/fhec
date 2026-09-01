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
//! Every inserted grant sequence that is not withheld under FHE4014 is
//! wrapped in the spec §8.1 initialization guard —
//! `if (FHE.isInitialized(<handle>)) { ... }` — because a grant on a handle
//! that carries no CoFHE permission (an unwritten slot's zero sentinel, a
//! `.wrap`-derived value arriving through a parameter) reverts instead of
//! granting, and provenance is a runtime property (issue #103).
//!
//! Dedupe (spec §8.6): an equivalent existing call suppresses the insertion —
//! same ACL function, syntactically identical argument after parenthesis
//! stripping; method syntax counts as library syntax. An author-written
//! `allowPublic` or `allowGlobal` on a copied local also subsumes only R1's
//! `allowThis`. R1 scans forward from the trigger to the next write of the
//! same location or the end of the block; R2/R3 insert *before* their trigger,
//! so their window scans backward from the trigger to the start of the block
//! (a §8.6 refinement — the spec's forward window is written for R1). The
//! §8.1 initialization guard is transparent to every window scan (one
//! level), so a re-transpile of guarded output inserts nothing (spec §1.4).

use std::cell::RefCell;

use fhec_bind::{FunctionId, MethodResolution};
use fhec_check::{
    EncryptedArgCall, EncryptedReturn, EncryptedStorageWrite, PlainTy, PolicyReader, PolicyReaders,
    ReaderRoot, Severity, SlotKind, Ty,
};
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

    // R5 — policy grants at event arguments (spec §8.10). `emit` can never
    // appear inside an encrypted branch (checker-rejected), so every emit
    // statement of this function is in scope; patch byte position, not push
    // order, decides the final splice order, so running this after W/C/R is
    // safe.
    for stmt in collect_emit_stmts(ctx, function) {
        if !inside_if(stmt.span) {
            rule_r5(
                ctx,
                function,
                stmt,
                namer,
                acl_insert,
                diags,
                plan,
                &mut outcome,
            )?;
        }
    }

    // Re-application (spec §8.11): a plain write to a state variable a
    // policy names (in its readers or its `public if` condition) re-emits
    // that policy's grants. Scoped to a target that is not a mapping/array
    // (`policy.keys` empty) — a mapping/array target cannot be re-applied
    // regardless of where the trigger fires (spec §8.11, FHE4007). An
    // event target is excluded too: it has no persistent handle outside an
    // actual `emit` to re-grant. A state-variable target is always
    // nameable by its own bare name; a struct-field target additionally
    // needs a way to *reach* that struct from the trigger's function — see
    // `find_struct_reach` — and silently skips re-application there when
    // no unambiguous one exists, rather than guess.
    let triggers = reapply_triggers(&ctx.checked.policies);
    if !triggers.is_empty() {
        for stmt in collect_assign_stmts(ctx, function) {
            if !inside_if(stmt.span) {
                rule_reapply(
                    ctx,
                    function,
                    stmt,
                    &triggers,
                    namer,
                    acl_insert,
                    diags,
                    plan,
                    &mut outcome,
                )?;
            }
        }
    }
    Ok(outcome)
}

/// Every policy a write to a given state variable must re-apply (spec
/// §8.11): the variable names a bindable (non-mapping/array) target's
/// reader, or its `public if` condition.
fn reapply_triggers(
    policies: &fhec_check::PolicyTable,
) -> std::collections::HashMap<fhec_bind::VarId, Vec<&fhec_check::Policy>> {
    use fhec_check::{PolicyReader, PolicyReaders, ReaderRoot};
    let mut out: std::collections::HashMap<fhec_bind::VarId, Vec<&fhec_check::Policy>> =
        std::collections::HashMap::new();
    let all = policies
        .by_state_var
        .values()
        .chain(policies.by_struct_field.values())
        .chain(policies.by_event_param.values());
    for p in all {
        if !p.keys.is_empty() {
            continue; // FHE4007: a mapping/array target cannot be re-applied
        }
        if matches!(p.owner, fhec_check::PolicyOwner::Event(_)) {
            continue; // no persistent handle outside an emit to re-grant
        }
        let roots: Vec<&ReaderRoot> = match &p.readers {
            PolicyReaders::Public { condition: Some(c) } => vec![&c.root],
            PolicyReaders::Public { condition: None } => Vec::new(),
            PolicyReaders::List(list) => list
                .iter()
                .filter_map(|r| match r {
                    PolicyReader::Path(pp) => Some(&pp.root),
                    PolicyReader::This | PolicyReader::Global => None,
                })
                .collect(),
        };
        for root in roots {
            if let ReaderRoot::StateVar(vid) = root {
                out.entry(*vid).or_default().push(p);
            }
        }
    }
    out
}

/// Every plain `lhs = rhs;` expression-statement in a function's body, in
/// source order.
fn collect_assign_stmts<'ast>(
    ctx: &Ctx<'_, 'ast>,
    function: fhec_bind::FunctionId,
) -> Vec<&'ast ast::Stmt<'ast>> {
    use solar_ast::visit::Visit;
    use std::ops::ControlFlow;

    struct Finder<'ast> {
        out: Vec<&'ast ast::Stmt<'ast>>,
    }
    impl<'ast> Visit<'ast> for Finder<'ast> {
        type BreakValue = ();
        fn visit_stmt(&mut self, s: &'ast ast::Stmt<'ast>) -> ControlFlow<()> {
            if let ast::StmtKind::Expr(e) = &s.kind {
                if matches!(e.kind, ast::ExprKind::Assign(_, None, _)) {
                    self.out.push(s);
                }
            }
            self.walk_stmt(s)
        }
    }

    let Some(body) = ctx.unit.function(function).ast.body.as_ref() else {
        return Vec::new();
    };
    let mut f = Finder { out: Vec::new() };
    for s in body.iter() {
        let _ = f.visit_stmt(s);
    }
    f.out
}

#[allow(clippy::too_many_arguments)]
fn rule_reapply(
    ctx: &Ctx<'_, '_>,
    function: fhec_bind::FunctionId,
    stmt: &ast::Stmt<'_>,
    triggers: &std::collections::HashMap<fhec_bind::VarId, Vec<&fhec_check::Policy>>,
    namer: &RefCell<TempNamer>,
    acl_insert: bool,
    diags: &RefCell<Vec<fhec_check::Diagnostic>>,
    plan: &mut FilePlan,
    outcome: &mut AclOutcome,
) -> Result<()> {
    let ast::StmtKind::Expr(e) = &stmt.kind else {
        return Ok(());
    };
    let ast::ExprKind::Assign(lhs, None, _) = &e.kind else {
        return Ok(());
    };
    let ast::ExprKind::Ident(id) = &lhs.peel_parens().kind else {
        return Ok(());
    };
    let Some(fhec_bind::Resolution::StateVar(vid)) = ctx.unit.resolve(*id) else {
        return Ok(());
    };
    let Some(policies) = triggers.get(vid) else {
        return Ok(());
    };

    let indent = ctx.line_indent(ctx.unit.function(function).file, ctx.range(stmt.span).start);
    let at = after_stmt_offset(
        ctx.text(ctx.unit.function(function).file),
        ctx.range(stmt.span).end,
    );
    // A struct-field target's accessor declaration is only worth emitting
    // if it ends up backing at least one actual (non-deduped) call — an
    // unused `Storage storage $ = _getStorage();` would be dead code.
    // Tracked separately and spliced in front only for the struct types
    // that were actually used, in first-use order.
    let mut pending_prelude: Vec<(fhec_bind::TypeDeclId, String)> = Vec::new();
    let mut used_structs: std::collections::HashSet<fhec_bind::TypeDeclId> =
        std::collections::HashSet::new();
    // Caches both outcomes per struct type: `Some(Some(text))` a found
    // reach, `Some(None)` a already-diagnosed unreachable struct (so two
    // policies on the same struct at the same trigger warn once, not
    // twice).
    let mut reach_cache: std::collections::HashMap<fhec_bind::TypeDeclId, Option<String>> =
        std::collections::HashMap::new();
    let mut lines: Vec<String> = Vec::new();
    // One inline (single-line) guard rendering per policy, for suggest mode.
    let mut inline: Vec<String> = Vec::new();
    for policy in policies {
        let (target_text, ty, struct_ty) = match policy.owner {
            fhec_check::PolicyOwner::StateVar(_) => {
                let Some(ty) = target_encrypted_type(ctx, policy) else {
                    continue;
                };
                (policy.target.clone(), ty, None)
            }
            fhec_check::PolicyOwner::Struct(struct_ty) => {
                let Some(ty) = policy.direct_value_ty else {
                    continue;
                };
                let Some(contract) = ctx.unit.function(function).contract else {
                    continue;
                };
                let cached = reach_cache.entry(struct_ty).or_insert_with(|| {
                    match find_struct_reach(ctx, contract, struct_ty) {
                        Some(StructReach::DirectVar(name)) => Some(name),
                        Some(StructReach::Accessor(fn_name)) => {
                            let temp = namer.borrow_mut().fresh(TempHint::Val);
                            let struct_name = ctx.unit.type_decl(struct_ty).name;
                            pending_prelude.push((
                                struct_ty,
                                format!("{struct_name} storage {temp} = {fn_name}();"),
                            ));
                            Some(temp)
                        }
                        None => {
                            // No unambiguous way to reach this struct from
                            // this function: skip re-application here
                            // rather than guess (spec §1.3) — but the gap
                            // is real, so it must not go unstated (spec
                            // §8.11's own principle for the mapping/array
                            // case, extended to this reason). The policy's
                            // own R4 grants at its own write sites are
                            // unaffected.
                            diags.borrow_mut().push(fhec_check::Diagnostic {
                                code: "FHE4007",
                                severity: Severity::Warning,
                                span: policy.span,
                                message: format!(
                                    "this policy's target field `{}` cannot be re-applied here: \
                                     `{}` is not reachable from this function through exactly \
                                     one state variable or one parameterless accessor, so the \
                                     write to `{}` here does not refresh its grants (spec \
                                     §8.11)",
                                    policy.target,
                                    ctx.unit.type_decl(struct_ty).name,
                                    strip_parens(&ctx.snippet(lhs.span))
                                ),
                                fixits: Vec::new(),
                                rule: Some("§8.11"),
                            });
                            None
                        }
                    }
                });
                let Some(reach) = cached else {
                    continue;
                };
                (format!("{reach}.{}", policy.target), ty, Some(struct_ty))
            }
            fhec_check::PolicyOwner::Event(_) => continue,
        };
        let window = forward_window(ctx, function, stmt.span, &target_text);
        let rendering =
            crate::policy_bind::render_readers(ctx, function, policy, &target_text, &[])?;
        let calls =
            crate::policy_bind::render_call_lines(ctx, stmt.span, ty, &target_text, &rendering)?;
        let missing: Vec<String> = calls
            .into_iter()
            .filter(|call| {
                !window.iter().any(|s| {
                    matches_through_guard(ctx, s, &|s| {
                        policy_call_matches(
                            ctx,
                            function,
                            s,
                            &call.fn_name,
                            &call.arg0,
                            call.arg1.as_deref(),
                        )
                    })
                })
            })
            .map(|call| call.text)
            .collect();
        if !missing.is_empty() {
            // Spec §8.1 initialization guard on the re-application target:
            // this is the guard's most-live site — the trigger writes a
            // *reader*, so nothing here proves the target itself was ever
            // written, and a grant on an unwritten handle reverts.
            inline.push(guard_inline(ctx, &target_text, &missing));
            lines.extend(guard_lines(ctx, &target_text, &missing));
            if let Some(struct_ty) = struct_ty {
                used_structs.insert(struct_ty);
            }
        }
    }
    if lines.is_empty() {
        return Ok(());
    }
    let prelude: Vec<String> = pending_prelude
        .into_iter()
        .filter(|(ty, _)| used_structs.contains(ty))
        .map(|(_, line)| line)
        .collect();
    let lines: Vec<String> = prelude.iter().cloned().chain(lines).collect();

    if !acl_insert {
        let joined = prelude
            .into_iter()
            .chain(inline)
            .collect::<Vec<_>>()
            .join(" ");
        diags.borrow_mut().push(fhec_check::Diagnostic {
            code: crate::codes::SUGGEST_POLICY_GRANT,
            severity: Severity::Note,
            span: stmt.span,
            message: format!(
                "ACL suggestion: after this write, re-apply the policy with `{joined}`"
            ),
            fixits: Vec::new(),
            rule: Some("§8.11"),
        });
        return Ok(());
    }
    brace_lone_stmt(ctx, function, stmt.span, plan, outcome)?;
    for call in lines {
        plan.push(Patch::insert(
            at,
            format!("\n{indent}{call}"),
            Provenance::new("§8.11 re-application", ctx.range(stmt.span))
                .with_code(crate::codes::SUGGEST_POLICY_GRANT),
        ));
    }
    Ok(())
}

/// The encrypted type of a state-variable-attached policy's target.
fn target_encrypted_type(_ctx: &Ctx<'_, '_>, policy: &fhec_check::Policy) -> Option<EType> {
    policy.direct_value_ty
}

/// A way to reach a struct-typed value from an arbitrary function of the
/// same contract, found for spec §8.11 re-application at a site other than
/// the policy's own write.
enum StructReach {
    /// A state variable of exactly this struct type — always safely
    /// nameable by its own name, no pointer or accessor needed.
    DirectVar(String),
    /// The one parameterless function of the contract returning exactly
    /// this struct type by storage reference (the ERC-7201 accessor
    /// shape); the caller must declare a fresh local bound to a call of it.
    Accessor(String),
}

/// Finds `StructReach` for `struct_ty` within `contract`, or `None` when no
/// *unambiguous* one exists (zero or more than one candidate either way) —
/// the caller skips re-application there rather than guess (spec §1.3).
/// Deliberately scoped to `contract`'s own members: an accessor or state
/// variable declared in a base contract is not searched, since resolving
/// that safely runs into the same incomplete-inheritance hazards the
/// binder itself refuses to guess past.
fn find_struct_reach(
    ctx: &Ctx<'_, '_>,
    contract: fhec_bind::ContractId,
    struct_ty: fhec_bind::TypeDeclId,
) -> Option<StructReach> {
    let info = ctx.unit.contract(contract);

    let mut direct_vars = info.state_vars.iter().filter_map(|&vid| {
        let var = ctx.unit.var(vid);
        if crate::policy_bind::declared_struct(ctx, var) != Some(struct_ty) {
            return None;
        }
        Some(var.name?.as_str().to_string())
    });
    if let Some(name) = direct_vars.next() {
        return if direct_vars.next().is_none() {
            Some(StructReach::DirectVar(name))
        } else {
            None // ambiguous: more than one state variable of this type
        };
    }

    let mut accessors = info.functions.iter().filter_map(|&fid| {
        let f = ctx.unit.function(fid);
        if !f.params.is_empty() || f.returns.len() != 1 {
            return None;
        }
        let ret_var = ctx.unit.var(f.returns[0]);
        if ret_var.decl.data_location != Some(ast::DataLocation::Storage) {
            return None;
        }
        if crate::policy_bind::declared_struct(ctx, ret_var) != Some(struct_ty) {
            return None;
        }
        f.name_str.clone()
    });
    let first = accessors.next()?;
    if accessors.next().is_some() {
        return None; // ambiguous: more than one candidate accessor
    }
    Some(StructReach::Accessor(first))
}

/// Every `emit` statement in a function's body, in source order.
fn collect_emit_stmts<'ast>(
    ctx: &Ctx<'_, 'ast>,
    function: fhec_bind::FunctionId,
) -> Vec<&'ast ast::Stmt<'ast>> {
    use solar_ast::visit::Visit;
    use std::ops::ControlFlow;

    struct Finder<'ast> {
        out: Vec<&'ast ast::Stmt<'ast>>,
    }
    impl<'ast> Visit<'ast> for Finder<'ast> {
        type BreakValue = ();
        fn visit_stmt(&mut self, s: &'ast ast::Stmt<'ast>) -> ControlFlow<()> {
            if matches!(s.kind, ast::StmtKind::Emit(..)) {
                self.out.push(s);
            }
            self.walk_stmt(s)
        }
    }

    let Some(body) = ctx.unit.function(function).ast.body.as_ref() else {
        return Vec::new();
    };
    let mut f = Finder { out: Vec::new() };
    for s in body.iter() {
        let _ = f.visit_stmt(s);
    }
    f.out
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

    // FHE4014 (spec §8.1): a `.wrap`-derived value has no permission
    // registered for anyone, including this contract — inserting any grant
    // here (R1's own, or a policy's R4 sequence) would revert, not merely
    // fail to help. This check precedes the R4 policy lookup below: the
    // withholding applies uniformly, regardless of which rule would
    // otherwise own the insertion.
    if w.value_wrapped {
        diags.borrow_mut().push(fhec_check::Diagnostic {
            code: crate::codes::ACL_GRANT_ON_UNPERMISSIONED_HANDLE,
            severity: Severity::Warning,
            span: w.lvalue_span,
            message: format!(
                "the value written to `{lvalue}` is a `.wrap(...)` reinterpretation, which \
                 never registers a CoFHE permission for anyone, including this contract; \
                 inserting `FHE.allowThis` here would revert the transaction rather than grant \
                 access, so no ACL call is inserted for this write. Add an explicit grant only \
                 if this handle is independently known to carry a real permission (spec §8.1)"
            ),
            fixits: Vec::new(),
            rule: Some("§8.1"),
        });
        return Ok(());
    }

    // R4 (spec §8.9): a policy on the written slot replaces this rule's
    // ownership decision entirely, and FHE4001 is not emitted — the author
    // has stated who owns the value, so nothing is being withheld.
    if let Some(node) = find_expr(ctx, w.function, w.lvalue_span) {
        if let Some(bound) =
            crate::policy_bind::bind_write(ctx, &ctx.checked.policies, w.function, node)?
        {
            return rule_r4(ctx, w, &lvalue, &bound, acl_insert, diags, plan, outcome);
        }
    }

    // Whether the slot's owner is provably `msg.sender`. Only a mapping
    // keyed exactly by `msg.sender` earns that proof; every other slot kind
    // — a simple state variable (no key at all), an array element or struct
    // field (no owner key), or a mapping keyed by anything else (a
    // different address, or a non-address key) — has none, so guessing the
    // sender grant there is the same confidentiality leak (spec §1.3,
    // §8.1).
    let sender_provably_owns = matches!(
        &w.slot,
        SlotKind::Mapping {
            key_is_msg_sender: true,
            ..
        }
    );
    if !sender_provably_owns {
        let reason = sender_unproven_reason(&w.slot);
        diags.borrow_mut().push(fhec_check::Diagnostic {
            code: "FHE4001",
            severity: Severity::Warning,
            span: w.lvalue_span,
            message: format!(
                "encrypted write to `{lvalue}` {reason}, so its owner is not provably \
                 `msg.sender`; the sender grant is withheld here, so the transaction sender \
                 does not gain read access to a ciphertext that is not provably its own. \
                 Add an explicit grant if that is what you intend"
            ),
            fixits: Vec::new(),
            rule: Some("§8.1"),
        });
    }

    // `allowThis` is always right: it grants the contract access to its own
    // slot. `allowSender` is a claim about who owns the value, and on a slot
    // that is not provably owned by `msg.sender` that claim is a
    // confidentiality leak — so it is never guessed there (spec §1.3, §8.1).
    let ops: &[FheOp] = if sender_provably_owns {
        &[FheOp::AllowThis, FheOp::AllowSender]
    } else {
        &[FheOp::AllowThis]
    };

    let window = forward_window(ctx, w.function, w.stmt_span, &lvalue);
    // `FHE.allowThis(ptr); slot = ptr;` grants the same handle the store
    // files, so it counts (spec §8.6).
    let local = assigned_local(ctx, w.function, w.stmt_span, &lvalue);
    let local_window = local
        .as_ref()
        .map(|(name, var)| local_grant_window(ctx, w.function, w.stmt_span, name, *var))
        .unwrap_or_default();
    let mut missing: Vec<FheOp> = Vec::new();
    for &op in ops {
        let name = ctx.profile.acl_fn_name(op).unwrap_or_default();
        let equivalent_grant = window.iter().any(|s| {
            matches_through_guard(ctx, s, &|s| {
                acl_call_matches(ctx, w.function, s, &name, &lvalue, None)
            })
        }) || local.as_ref().is_some_and(|(l, _)| {
            local_window.iter().any(|s| {
                matches_through_guard(ctx, s, &|s| {
                    acl_call_matches(ctx, w.function, s, &name, l, None)
                })
            })
        });
        // An explicit broad grant on the local copied into the slot makes the
        // handle readable by this contract already, so R1 need not append its
        // `allowThis`. This is deliberately not applied to `allowSender`:
        // §8.1 treats that as the separate, owner-proven grant, and §8.6 only
        // extends this broad-grant subsumption to the unconditional contract
        // grant.
        let broad_local_grant = op == FheOp::AllowThis
            && local.as_ref().is_some_and(|(l, _)| {
                local_window.iter().any(|s| {
                    matches_through_guard(ctx, s, &|s| {
                        ["allowPublic", "allowGlobal"]
                            .into_iter()
                            .any(|name| acl_call_matches(ctx, w.function, s, name, l, None))
                    })
                })
            });
        let granted = equivalent_grant || broad_local_grant;
        if !granted {
            missing.push(op);
        }
    }
    if missing.is_empty() {
        return Ok(());
    }

    let indent = ctx.line_indent(w.file, ctx.range(w.stmt_span).start);
    let at = after_stmt_offset(ctx.text(w.file), ctx.range(w.stmt_span).end);
    let calls: Vec<String> = missing
        .iter()
        .map(|op| {
            ctx.profile
                .render_call(*op, &[w.value_ty], &[&lvalue])
                .map(|c| format!("{c};"))
        })
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| internal(w.stmt_span, e))?;
    // Spec §8.1 initialization guard: the written handle's provenance is
    // not provable here (a copy, a parameter, an opaque call, ...), and a
    // grant on an uninitialized handle reverts instead of granting.
    let lines = guard_lines(ctx, &lvalue, &calls);
    if acl_insert {
        // `return slot = value;` states both an R1 write and an R3 return on
        // one statement. R1's insertion point is R3's replacement end, so the
        // grants would land after the `return` and never run (spec §8.0).
        // R3 owns the statement: hand the (guarded) lines over.
        if is_return_site(ctx, w.function, w.stmt_span) {
            outcome
                .pending_r1
                .push((w.stmt_span, w.file, w.function, lines));
            return Ok(());
        }
        brace_lone_stmt(ctx, w.function, w.stmt_span, plan, outcome)?;
        for line in lines {
            plan.push(Patch::insert(
                at,
                format!("\n{indent}{line}"),
                Provenance::new("§8.1 R1", ctx.range(w.stmt_span)).with_code("FHE4010"),
            ));
        }
    } else {
        let insertion: String = lines.iter().map(|l| format!("\n{indent}{l}")).collect();
        diags.borrow_mut().push(fhec_check::Diagnostic {
            code: "FHE4010",
            severity: Severity::Note,
            span: w.stmt_span,
            message: format!(
                "ACL suggestion: after this write, add `{}`",
                guard_inline(ctx, &lvalue, &calls)
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
// R4 — policy grants at storage writes (spec §8.9)
// ---------------------------------------------------------------------------

/// Replaces R1's ownership decision for a write whose slot carries a reader
/// policy: `allowThis` unconditionally, then every resolved reader, in
/// policy order (spec §8.9). Dedupe (§8.6), the return-site handover to R3,
/// brace-wrapping, and suggest-mode all apply exactly as they do for R1.
#[allow(clippy::too_many_arguments)]
fn rule_r4(
    ctx: &Ctx<'_, '_>,
    w: &EncryptedStorageWrite,
    lvalue: &str,
    bound: &crate::policy_bind::BoundWrite<'_>,
    acl_insert: bool,
    diags: &RefCell<Vec<fhec_check::Diagnostic>>,
    plan: &mut FilePlan,
    outcome: &mut AclOutcome,
) -> Result<()> {
    check_cross_reader_copy(ctx, w, bound.policy, diags);

    let rendering = crate::policy_bind::render_readers(
        ctx,
        w.function,
        bound.policy,
        &bound.self_text,
        &bound.key_texts,
    )?;
    let lines =
        crate::policy_bind::render_call_lines(ctx, w.lvalue_span, w.value_ty, lvalue, &rendering)?;

    let window = forward_window(ctx, w.function, w.stmt_span, lvalue);
    let missing: Vec<&crate::policy_bind::CallLine> = lines
        .iter()
        .filter(|c| {
            !window.iter().any(|s| {
                matches_through_guard(ctx, s, &|s| {
                    policy_call_matches(ctx, w.function, s, &c.fn_name, &c.arg0, c.arg1.as_deref())
                })
            })
        })
        .collect();
    if missing.is_empty() {
        return Ok(());
    }

    let indent = ctx.line_indent(w.file, ctx.range(w.stmt_span).start);
    let at = after_stmt_offset(ctx.text(w.file), ctx.range(w.stmt_span).end);
    let calls: Vec<String> = missing.iter().map(|c| c.text.clone()).collect();
    // Spec §8.1 initialization guard, exactly as at a plain R1 write; the
    // §8.9 zero-address guard on individual readers nests inside it.
    let guarded = guard_lines(ctx, lvalue, &calls);
    if acl_insert {
        // Same R1/R3 handover as the plain-ownership path (spec §8.0).
        if is_return_site(ctx, w.function, w.stmt_span) {
            outcome
                .pending_r1
                .push((w.stmt_span, w.file, w.function, guarded));
            return Ok(());
        }
        brace_lone_stmt(ctx, w.function, w.stmt_span, plan, outcome)?;
        for line in guarded {
            plan.push(Patch::insert(
                at,
                format!("\n{indent}{line}"),
                Provenance::new("§8.9 R4", ctx.range(w.stmt_span))
                    .with_code(crate::codes::SUGGEST_POLICY_GRANT),
            ));
        }
    } else {
        let insertion: String = guarded.iter().map(|l| format!("\n{indent}{l}")).collect();
        diags.borrow_mut().push(fhec_check::Diagnostic {
            code: crate::codes::SUGGEST_POLICY_GRANT,
            severity: Severity::Note,
            span: w.stmt_span,
            message: format!(
                "ACL suggestion: after this write, add `{}`",
                guard_inline(ctx, lvalue, &calls)
            ),
            fixits: vec![fhec_check::FixIt {
                span: zero_width_at(w.stmt_span),
                replacement: insertion,
                safe: true,
            }],
            rule: Some("§8.9"),
        });
    }
    Ok(())
}

/// The varying middle clause of the withheld-sender-grant note (spec §8.1),
/// phrased per slot kind: a `SimpleVar` has no key at all, so it reads
/// differently from a mapping keyed by something other than `msg.sender`.
/// Only called for a slot [`rule_r1`] has already established is not
/// provably owned by `msg.sender`.
fn sender_unproven_reason(slot: &SlotKind) -> &'static str {
    match slot {
        SlotKind::SimpleVar => "targets a state variable, which has no key at all",
        SlotKind::Mapping {
            key_is_address: true,
            ..
        } => "is keyed by an address that is not `msg.sender`",
        SlotKind::Mapping { .. } => "is keyed by an expression that is not `msg.sender`",
        SlotKind::ArrayIndex { .. } => "targets an array element, which carries no owner key",
        SlotKind::StructField => "targets a struct field, which carries no owner key",
    }
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
    if c.is_view_or_pure {
        // Neither a `view` nor a `pure` function can make the external call
        // `allowTransient` requires (spec §8.2, §8.4) — inserting it would
        // not compile, so this warns instead of guessing a grant. `pure`
        // cannot reach this rule to begin with: it cannot make an external
        // call at all, so R2's site (an external call) never exists in a
        // `pure` function. `view` CAN legally call another `view`/`pure`
        // external function, so this guard is the reachable case; leaving
        // the statement alone (no `owned_stmts` claim) lets pass 1 still
        // lower any operator sites inside the call's arguments normally.
        diags.borrow_mut().push(fhec_check::Diagnostic {
            code: "FHE4002",
            severity: Severity::Warning,
            span: c.call_span,
            message: "a `view` or `pure` function cannot grant ACL access to this call's \
                      encrypted argument; the callee must have been granted access elsewhere"
                .to_string(),
            fixits: Vec::new(),
            rule: Some("§8.4"),
        });
        return Ok(());
    }
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
        let deduped = window.iter().any(|s| {
            matches_through_guard(ctx, s, &|s| {
                acl_call_matches_normalized(ctx, c.function, s, &transient, &arg_key, &callee_key)
            })
        });
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
        let replaced: Vec<(Span, String, &str)> = args
            .iter()
            .filter(|a| a.rendered != a.original)
            .map(|a| (a.span, a.rendered.clone(), "§4.1 operator-lowering"))
            .collect();
        if replaced.is_empty() {
            return Ok(());
        }
        // A patch inside the statement means pass 1 must not render it again
        // (it would overlap, spec §2.5 FHE9001).
        push_arg_rewrites(ctx, c, &replaced, plan)?;
        outcome.owned_stmts.push(c.stmt_span);
        return Ok(());
    }

    if !acl_insert {
        let list = args
            .iter()
            .filter(|a| !a.deduped)
            .map(|a| {
                let handle = strip_parens(&a.original);
                guard_inline(
                    ctx,
                    handle,
                    &[format!(
                        "FHE.allowTransient({handle}, address({callee_key}));"
                    )],
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

    let mut replaced: Vec<(Span, String, &str)> = Vec::new();
    for a in &args {
        if a.deduped {
            if a.rendered != a.original {
                replaced.push((a.span, a.rendered.clone(), "§4.1 operator-lowering"));
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
            replaced.push((a.span, temp.clone(), "§8.2 R2 arg-hoist"));
            temp
        };
        let call = ctx
            .profile
            .render_call(FheOp::AllowTransient, &[a.ty], &[&handle, &account])
            .map_err(|e| internal(c.stmt_span, e))?;
        // Spec §8.1 initialization guard: an argument handle whose
        // provenance is not provable (a parameter, a copy, an opaque call)
        // may be uninitialized, and granting on one reverts.
        lines.extend(guard_lines(ctx, &handle, &[format!("{call};")]));
        let _ = a.node; // arg AST currently only needed for rendering above
    }

    let insertion: String = lines.iter().map(|l| format!("{l}\n{indent}")).collect();
    plan.push(Patch::insert(
        ctx.range(c.stmt_span).start,
        insertion,
        Provenance::new("§8.2 R2", ctx.range(c.call_span)).with_code("FHE4011"),
    ));
    let callee_hoisted = !(c.callee_is_ident || is_simple_path(&callee_text));
    if push_arg_rewrites(ctx, c, &replaced, plan)? || callee_hoisted {
        // R2 replaced text inside the statement, so pass 1 must leave the
        // whole statement alone or the two patches overlap.
        outcome.owned_stmts.push(c.stmt_span);
    }
    Ok(())
}

/// Pushes the replacements R2 owes for its rewritten arguments.
///
/// An argument that sits inside a larger operator, ternary or cast site is
/// not replaced on its own: that whole site is rendered here with the
/// argument substituted, because pass 1 never re-enters a statement R2 owns
/// and would otherwise leave the outer operator unlowered.
///
/// Returns whether anything was pushed.
fn push_arg_rewrites<'ast>(
    ctx: &Ctx<'_, 'ast>,
    c: &EncryptedArgCall,
    replaced: &[(Span, String, &str)],
    plan: &mut FilePlan,
) -> Result<bool> {
    if replaced.is_empty() {
        return Ok(false);
    }
    let inner: Vec<Span> = replaced.iter().map(|(s, _, _)| *s).collect();
    let straddling = straddling_sites(ctx, c.stmt_span, &inner);
    let subst = |e: &'ast ast::Expr<'ast>| -> Option<String> {
        replaced
            .iter()
            .find(|(s, _, _)| *s == e.span)
            .map(|(_, text, _)| text.clone())
    };
    for site in &straddling {
        let node = find_expr(ctx, c.function, *site)
            .ok_or_else(|| lost(*site, "R2 straddling operator site"))?;
        let rendered = Renderer::with_subst(ctx, &subst).render_expr(node)?;
        plan.push(Patch::replace(
            ctx.range(*site),
            rendered,
            Provenance::new("§8.2 R2 straddling-site", ctx.range(*site)),
        ));
    }
    for (span, text, rule) in replaced {
        if straddling.iter().any(|s| ctx.contains(*s, *span)) {
            continue; // already inside a rendered site
        }
        plan.push(Patch::replace(
            ctx.range(*span),
            text.clone(),
            Provenance::new(*rule, ctx.range(*span)),
        ));
    }
    Ok(true)
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
    if r.is_view_or_pure {
        // Neither a `view` nor a `pure` function can make the external call
        // `allowTransient` requires (spec §8.4) — inserting it would not
        // compile, so both get the same warn-only treatment rather than a
        // guessed grant.
        diags.borrow_mut().push(fhec_check::Diagnostic {
            code: "FHE4002",
            severity: Severity::Warning,
            span: r.stmt_span,
            message: "a `view` or `pure` function cannot grant ACL access to its encrypted \
                      return value; the caller must have been granted access elsewhere"
                .to_string(),
            fixits: Vec::new(),
            rule: Some("§8.4"),
        });
        return refuse_pending_r1(ctx, r.stmt_span, outcome);
    }
    if r.in_library {
        // A library's `public`/`external` STATE-CHANGING members are
        // delegatecall-linked: `msg.sender` and storage are the host's, so
        // the real caller is whatever host code invoked this library
        // function in the same transaction, not an independent external
        // actor. R3 exists to grant *that* caller access; the host already
        // decides what to share (via its own R3 grant, typically through a
        // `shared(...)` return), so inserting a grant here would be
        // redundant — and would move the bytecode of an address-linked
        // library that may be pinned for reproducible deployment (spec
        // §8.3). This does not apply to a `view`/`pure` member (handled
        // above): Solidity's library-call protection only reverts a direct
        // `CALL` for a state-changing member, so a `view`/`pure` library
        // function is directly callable by an arbitrary external caller
        // with the real transaction sender as `msg.sender`, the same as any
        // other `view`/`pure` function.
        return refuse_pending_r1(ctx, r.stmt_span, outcome);
    }

    let transient = ctx
        .profile
        .acl_fn_name(FheOp::AllowTransient)
        .unwrap_or_default();
    let expr_key = strip_parens(&ctx.snippet(r.expr_span)).to_string();
    let window = backward_window(ctx, r.function, r.stmt_span);
    if window.iter().any(|s| {
        matches_through_guard(ctx, s, &|s| {
            acl_call_matches(
                ctx,
                r.function,
                s,
                &transient,
                &expr_key,
                Some("msg.sender"),
            )
        })
    }) {
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
                 `if (FHE.isInitialized(<ret>)) {{ FHE.allowTransient(<ret>, msg.sender); }}` \
                 before returning `{expr_key}`"
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
    // must run before the `return`, inside the text R3 owns. Already
    // guarded (spec §8.1) by the rule that handed them over.
    let storage_grants: String = take_pending_r1(outcome, r.stmt_span)
        .iter()
        .map(|c| format!("{c}\n{indent}"))
        .collect();
    // Spec §8.1 initialization guard on the hoisted return temp: a public
    // function can legally return a handle it never initialized, and
    // granting on one reverts.
    let guarded: String = guard_lines(ctx, &temp, &[format!("{call};")])
        .iter()
        .map(|l| format!("{l}\n{indent}"))
        .collect();
    plan.push(Patch::replace(
        fhec_ir::ByteRange::new(stmt_range.start, end),
        format!(
            "{} {} = {};\n{indent}{storage_grants}{guarded}return {temp};",
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
// R5 — policy grants at event arguments (spec §8.10)
// ---------------------------------------------------------------------------

/// One `emit` argument, resolved against the event's declared parameters.
struct EmitArg<'ast, 'p> {
    node: &'ast ast::Expr<'ast>,
    /// The declared parameter name, when named.
    param_name: Option<String>,
    /// The policy governing this position, when its parameter carries one.
    policy: Option<&'p fhec_check::Policy>,
}

#[allow(clippy::too_many_arguments)]
fn rule_r5<'a, 'ast>(
    ctx: &Ctx<'a, 'ast>,
    function: fhec_bind::FunctionId,
    stmt: &'ast ast::Stmt<'ast>,
    namer: &RefCell<TempNamer>,
    acl_insert: bool,
    diags: &RefCell<Vec<fhec_check::Diagnostic>>,
    plan: &mut FilePlan,
    outcome: &mut AclOutcome,
) -> Result<()> {
    let ast::StmtKind::Emit(path, call_args) = &stmt.kind else {
        return Ok(());
    };
    let first = path.segments()[0];
    let eid = match ctx.unit.resolve_span(first.span) {
        Some(fhec_bind::Resolution::Event(eid)) => *eid,
        // The declaration this `emit` names is not visible: the emitting
        // contract inherits a base the binder cannot see, or the event
        // comes through an unresolvable import. A policy on the true
        // declaration cannot be read from here, and per the
        // `IncompleteInheritance` contract its fallback is not a
        // resolution — inserting grants from it would be a guess, and R5's
        // insertion is a positive action, unlike the read-only
        // classification decisions that may consult it. Warn (FHE4015)
        // when the emit carries an encrypted argument instead of staying
        // silent (spec §8.10).
        Some(fhec_bind::Resolution::Unresolved(_)) | None => {
            warn_event_policy_indeterminate(ctx, stmt, first.as_str(), call_args, diags);
            return Ok(());
        }
        // A qualified `emit A.Ev(...)` resolves its first segment to the
        // contract, not the event: not a shape this revision binds
        // (documented scope decision, like the named-argument arity case
        // below) — leave untouched rather than guess.
        Some(_) => return Ok(()),
    };
    let event = ctx.unit.event(eid);
    let params = &event.ast.parameters.vars;
    let arg_nodes = crate::expr::call_arg_exprs(call_args);
    if arg_nodes.len() != params.len() {
        // Named-argument emit-call syntax, or an arity this dialect does not
        // otherwise reach: not a shape this revision binds (documented scope
        // decision) — leave untouched rather than guess.
        return Ok(());
    }

    let args: Vec<EmitArg<'ast, 'a>> = arg_nodes
        .iter()
        .zip(params.iter())
        .map(|(&node, p)| {
            let param_name = p.name.map(|n| n.as_str().to_string());
            let policy = param_name
                .as_ref()
                .and_then(|n| ctx.checked.policies.by_event_param.get(&(eid, n.clone())));
            EmitArg {
                node,
                param_name,
                policy,
            }
        })
        .collect();
    if !args.iter().any(|a| a.policy.is_some()) {
        return Ok(());
    }

    // Every position a governed argument's readers might reference by name
    // (including itself) must be safe to evaluate twice: a plain identifier
    // is; anything else is hoisted to `__fhe_evt_n` (spec §8.10 draft
    // decision) and used everywhere it is referenced.
    let mut needs_hoist = vec![false; args.len()];
    for (i, a) in args.iter().enumerate() {
        if a.policy.is_none() {
            continue;
        }
        // A `.wrap`-derived governed argument gets no grant at all (FHE4014
        // below), so nothing references it as *its own* target — hoisting
        // it here would be needless. It can still be hoisted below as
        // *another* reader's referenced position.
        if is_wrap_call(ctx, a.node) {
            continue;
        }
        let snippet = ctx.snippet(a.node.span);
        let text = strip_parens(&snippet);
        if !is_ident_text(text) {
            needs_hoist[i] = true;
        }
        if let PolicyReaders::List(list) = &a.policy.unwrap().readers {
            for reader in list {
                if let PolicyReader::Path(p) = reader {
                    if let ReaderRoot::EventParam(name) = &p.root {
                        if let Some(j) = args
                            .iter()
                            .position(|x| x.param_name.as_deref() == Some(name.as_str()))
                        {
                            let jsnippet = ctx.snippet(args[j].node.span);
                            let jtext = strip_parens(&jsnippet);
                            if !is_ident_text(jtext) {
                                needs_hoist[j] = true;
                            }
                        }
                    }
                }
            }
        }
    }

    let ty_of = |e: &'ast ast::Expr<'ast>| -> Option<EType> {
        match ctx.checked.types.get(e.span) {
            Some(Ty::Encrypted(t)) => Some(*t),
            _ => None,
        }
    };

    let indent = ctx.line_indent(ctx.unit.function(function).file, ctx.range(stmt.span).start);
    let mut prelude: Vec<String> = Vec::new();
    let mut arg_text: Vec<String> = Vec::with_capacity(args.len());
    for (i, a) in args.iter().enumerate() {
        let rendered = Renderer::new(ctx).render_expr(a.node)?;
        if needs_hoist[i] {
            let Some(ty) = ty_of(a.node) else {
                return fail_coded(
                    a.node.span,
                    "cannot hoist this event argument for single evaluation: its encrypted \
                     type could not be determined (spec §8.10)"
                        .to_string(),
                    "FHE4004",
                    Some("§8.10"),
                );
            };
            let temp = namer.borrow_mut().fresh(TempHint::Val);
            prelude.push(format!("{} {} = {};", ty.solidity_name(), temp, rendered));
            arg_text.push(temp);
        } else {
            arg_text.push(rendered);
        }
    }

    // Build the grant lines for every governed position, using the (now
    // hoist-stable) argument text as both `self` and every named reference.
    // Each position's sequence is wrapped in its own §8.1 initialization
    // guard on that position's handle: `grant_seqs` keeps the handle and
    // the raw calls together so suggest mode can render the same guard
    // inline.
    let window = backward_window(ctx, function, stmt.span);
    let mut grant_seqs: Vec<(String, Vec<String>)> = Vec::new();
    for (i, a) in args.iter().enumerate() {
        let Some(policy) = a.policy else { continue };
        let Some(ty) = ty_of(a.node) else { continue };
        // FHE4014 (spec §8.1, §8.10): a `.wrap`-derived argument has no
        // permission registered for anyone — withhold this position's
        // whole grant sequence rather than insert a call that would revert.
        if is_wrap_call(ctx, a.node) {
            diags.borrow_mut().push(fhec_check::Diagnostic {
                code: crate::codes::ACL_GRANT_ON_UNPERMISSIONED_HANDLE,
                severity: Severity::Warning,
                span: a.node.span,
                message: "this event argument is a `.wrap(...)` reinterpretation, which never \
                     registers a CoFHE permission for anyone; inserting its policy's grants \
                     here would revert the transaction rather than grant access, so none are \
                     inserted for this argument (spec §8.1)"
                    .to_string(),
                fixits: Vec::new(),
                rule: Some("§8.1"),
            });
            continue;
        }
        let target_text = &arg_text[i];
        let rendering = render_event_policy(ctx, function, policy, &args, &arg_text)?;
        let calls =
            crate::policy_bind::render_call_lines(ctx, a.node.span, ty, target_text, &rendering)?;
        let missing: Vec<String> = calls
            .into_iter()
            .filter(|call| {
                !window.iter().any(|s| {
                    matches_through_guard(ctx, s, &|s| {
                        policy_call_matches(
                            ctx,
                            function,
                            s,
                            &call.fn_name,
                            &call.arg0,
                            call.arg1.as_deref(),
                        )
                    })
                })
            })
            .map(|call| call.text)
            .collect();
        if !missing.is_empty() {
            grant_seqs.push((target_text.clone(), missing));
        }
    }
    if grant_seqs.is_empty() && prelude.is_empty() {
        return Ok(());
    }

    if !acl_insert {
        if !grant_seqs.is_empty() {
            let joined = grant_seqs
                .iter()
                .map(|(handle, calls)| guard_inline(ctx, handle, calls))
                .collect::<Vec<_>>()
                .join(" ");
            diags.borrow_mut().push(fhec_check::Diagnostic {
                code: crate::codes::SUGGEST_POLICY_GRANT,
                severity: Severity::Note,
                span: stmt.span,
                message: format!("ACL suggestion: before this emit, add `{joined}`"),
                fixits: Vec::new(),
                rule: Some("§8.10"),
            });
        }
        return Ok(());
    }

    brace_lone_stmt(ctx, function, stmt.span, plan, outcome)?;

    let mut lines = prelude;
    for (handle, calls) in &grant_seqs {
        lines.extend(guard_lines(ctx, handle, calls));
    }
    let insertion: String = lines.iter().map(|l| format!("{l}\n{indent}")).collect();
    plan.push(Patch::insert(
        ctx.range(stmt.span).start,
        insertion,
        Provenance::new("§8.10 R5", ctx.range(stmt.span))
            .with_code(crate::codes::SUGGEST_POLICY_GRANT),
    ));

    if needs_hoist.iter().any(|&h| h) {
        // A hoisted argument's slot in the emit call must read the temp, not
        // its original (now-duplicated) expression.
        let replaced: Vec<(Span, String, &str)> = args
            .iter()
            .enumerate()
            .filter(|(i, _)| needs_hoist[*i])
            .map(|(i, a)| (a.node.span, arg_text[i].clone(), "§8.10 R5 arg-hoist"))
            .collect();
        for (span, text, rule) in &replaced {
            plan.push(Patch::replace(
                ctx.range(*span),
                text.clone(),
                Provenance::new(*rule, ctx.range(*span)),
            ));
        }
        outcome.owned_stmts.push(stmt.span);
    }
    Ok(())
}

/// FHE4015 (spec §8.10): an `emit` that does not resolve to a visible event
/// declaration carries an encrypted argument. If the invisible declaration
/// carries a reader policy, its grants are not generated, and nothing else
/// would say so. When no argument is independently encrypted the emit stays
/// silent — no policy could govern a plaintext-only position (the same
/// conservative under-grant §8.2 applies to an `Unknown` callee).
fn warn_event_policy_indeterminate<'ast>(
    ctx: &Ctx<'_, 'ast>,
    stmt: &'ast ast::Stmt<'ast>,
    event_name: &str,
    call_args: &'ast ast::CallArgs<'ast>,
    diags: &RefCell<Vec<fhec_check::Diagnostic>>,
) {
    let any_encrypted = crate::expr::call_arg_exprs(call_args)
        .iter()
        .any(|e| matches!(ctx.checked.types.get(e.span), Some(Ty::Encrypted(_))));
    if !any_encrypted {
        return;
    }
    diags.borrow_mut().push(fhec_check::Diagnostic {
        code: crate::codes::ACL_EVENT_POLICY_INDETERMINATE,
        severity: Severity::Warning,
        span: stmt.span,
        message: format!(
            "cannot determine whether event `{event_name}`'s declaration carries a \
             `@custom:fhe-allow` reader policy: this contract's inheritance is incomplete \
             (a base or import is not resolvable), so the declaration this `emit` resolves \
             to is not visible to this analysis; if it does carry a policy, its grants are \
             NOT inserted here — write them explicitly before the `emit`, or make every \
             base of this contract resolvable (spec §8.10)"
        ),
        fixits: Vec::new(),
        rule: Some("§8.10"),
    });
}

/// Renders one event-attached policy's readers at its emit site: an
/// `EventParam` root renders the corresponding argument's (possibly
/// hoisted) text, and a `StateVar` root renders exactly as R4 does — the
/// variable's name, re-confirmed unshadowed at the emitting function's
/// scope (spec §8.8 resolution rule 5, §8.9). A bound key, `self`, or a
/// sibling field never arrives here: check-time resolution refuses or
/// cannot produce them for an event target.
fn render_event_policy<'ast, 'p>(
    ctx: &Ctx<'_, 'ast>,
    function: fhec_bind::FunctionId,
    policy: &fhec_check::Policy,
    args: &[EmitArg<'ast, 'p>],
    arg_text: &[String],
) -> Result<crate::policy_bind::PolicyRendering> {
    use crate::policy_bind::{PolicyRendering, RenderedReader};
    match &policy.readers {
        PolicyReaders::Public { condition } => {
            if condition.is_some() {
                return fail_coded(
                    policy.span,
                    "a gated `public if` policy on an event parameter has no re-application \
                     site to gate (spec §8.10, §8.11): only a plain `public` reader is \
                     supported on an event target"
                        .to_string(),
                    "FHE4005",
                    Some("§8.10"),
                );
            }
            Ok(PolicyRendering::Public { condition: None })
        }
        PolicyReaders::List(list) => {
            let mut out = Vec::new();
            for reader in list {
                match reader {
                    PolicyReader::This => {}
                    PolicyReader::Global => out.push(RenderedReader::Global),
                    PolicyReader::Path(p) => {
                        let mut text = match &p.root {
                            ReaderRoot::EventParam(name) => {
                                let j = args
                                    .iter()
                                    .position(|a| a.param_name.as_deref() == Some(name.as_str()))
                                    .expect("resolved at check time");
                                arg_text[j].clone()
                            }
                            ReaderRoot::StateVar(vid) => {
                                let name = ctx
                                    .unit
                                    .var(*vid)
                                    .name
                                    .map(|n| n.as_str().to_string())
                                    .ok_or_else(|| lost(p.span, "policy state-variable reader"))?;
                                crate::policy_bind::confirm_state_var_in_scope(
                                    ctx, function, *vid, &name, p.span,
                                )?;
                                name
                            }
                            ReaderRoot::Key(_)
                            | ReaderRoot::SelfRef
                            | ReaderRoot::SiblingField(_) => {
                                return fail_coded(
                                    p.span,
                                    "this reader root cannot arise for an event-attached \
                                     policy: an event target binds no keys, has no `self` \
                                     location, and has no sibling fields (internal)"
                                        .to_string(),
                                    "FHE9001",
                                    None,
                                );
                            }
                        };
                        for seg in &p.tail {
                            text.push('.');
                            text.push_str(seg);
                        }
                        out.push(RenderedReader::Named {
                            text,
                            is_const_nonzero: false,
                        });
                    }
                }
            }
            Ok(PolicyRendering::List(out))
        }
    }
}

// ---------------------------------------------------------------------------
// R2 rewrites that straddle a rewritten argument
// ---------------------------------------------------------------------------

/// Every operator, ternary and cast-sugar site the lowerer knows inside
/// `stmt_span`.
fn sites_in(ctx: &Ctx<'_, '_>, stmt_span: Span) -> Vec<Span> {
    let mut out: Vec<Span> = ctx
        .ops_by_span
        .keys()
        .chain(ctx.terns_by_span.keys())
        .chain(ctx.cast_sugar_by_span.keys())
        .copied()
        .filter(|s| ctx.contains(stmt_span, *s))
        .collect();
    out.sort_by_key(|s| (s.lo(), std::cmp::Reverse(s.hi())));
    out
}

/// The outermost sites that *contain* one of `inner` without being contained
/// by any of them.
///
/// R2 replaces each `inner` span with a temp, and pass 1 never re-enters a
/// statement R2 owns, so a site that straddles a replaced argument has to be
/// rendered here or it is never lowered at all.
fn straddling_sites(ctx: &Ctx<'_, '_>, stmt_span: Span, inner: &[Span]) -> Vec<Span> {
    let mut out: Vec<Span> = Vec::new();
    for site in sites_in(ctx, stmt_span) {
        if inner.iter().any(|i| ctx.contains(*i, site)) {
            continue; // inside a replaced argument: R2 already rendered it
        }
        if !inner.iter().any(|i| ctx.contains(site, *i)) {
            continue; // unrelated to any replaced argument
        }
        if out.iter().any(|o| ctx.contains(*o, site)) {
            continue; // already covered by an outer straddling site
        }
        out.push(site);
    }
    out
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
        if writes_to(ctx, s, WriteTarget::Text(lvalue)) {
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

/// The identifier a storage write copies, for `slot = local;` exactly.
///
/// CoFHE files ACL permissions against the ciphertext *handle*, so a grant on
/// `local` already covers `slot` once the handle is stored there. The
/// idiomatic shape is compute into a local, grant on the local, then store
/// (spec §8.6).
///
/// The RHS must *resolve* to a local variable or parameter — not merely be
/// identifier-shaped text. A state variable, a free function reference, or
/// any other bare identifier is rejected: the write-barrier this feeds
/// ([`local_grant_window`]) only sees sibling statements in the same block,
/// so it cannot prove a state variable (or anything reachable through a call)
/// still holds the value an earlier grant covered (spec §1.3).
/// Spec §8.12 "Cross-reader copy" (FHE4008): a storage write whose
/// right-hand value is a bare read of another policy-governed slot, with no
/// intervening profile operation, and the two policies name different
/// readers (neither being `this`-only). A handle produced by a profile
/// operation is fresh and never reaches here — `decompose` only matches an
/// identifier/member/index read shape, never a call.
fn check_cross_reader_copy(
    ctx: &Ctx<'_, '_>,
    w: &EncryptedStorageWrite,
    target_policy: &fhec_check::Policy,
    diags: &RefCell<Vec<fhec_check::Diagnostic>>,
) {
    let Some((stmts, idx)) = enclosing_block(ctx, w.function, w.stmt_span) else {
        return;
    };
    let ast::StmtKind::Expr(e) = &stmts[idx].kind else {
        return;
    };
    let ast::ExprKind::Assign(lhs, None, rhs) = &e.kind else {
        return;
    };
    if strip_parens(&ctx.snippet(lhs.span)) != strip_parens(&ctx.snippet(w.lvalue_span)) {
        return;
    }
    let Some(source_policy) = crate::policy_bind::find_read_policy(ctx, &ctx.checked.policies, rhs)
    else {
        return;
    };
    if !crate::policy_bind::cross_reader_copy_finding(target_policy, source_policy) {
        return;
    }
    diags.borrow_mut().push(fhec_check::Diagnostic {
        code: "FHE4008",
        severity: Severity::Warning,
        span: w.lvalue_span,
        message: format!(
            "`{}` is a handle copied from another policy-governed slot with no intervening \
             profile operation; the profile files permissions against the handle, not the \
             slot, so it now carries the union of both slots' readers, not just this one's \
             (spec §8.12)",
            strip_parens(&ctx.snippet(w.lvalue_span))
        ),
        fixits: Vec::new(),
        rule: Some("§8.12"),
    });
}

fn assigned_local<'ast>(
    ctx: &Ctx<'_, 'ast>,
    function: fhec_bind::FunctionId,
    stmt_span: Span,
    lvalue: &str,
) -> Option<(String, fhec_bind::VarId)> {
    let (stmts, idx) = enclosing_block(ctx, function, stmt_span)?;
    let ast::StmtKind::Expr(e) = &stmts[idx].kind else {
        return None;
    };
    let ast::ExprKind::Assign(lhs, None, rhs) = &e.kind else {
        return None;
    };
    if strip_parens(&ctx.snippet(lhs.span)) != lvalue {
        return None;
    }
    let ast::ExprKind::Ident(ident) = &rhs.peel_parens().kind else {
        return None;
    };
    let var = match ctx.unit.resolve(*ident) {
        Some(fhec_bind::Resolution::Local(v)) | Some(fhec_bind::Resolution::Param(v)) => *v,
        _ => return None,
    };
    let text = strip_parens(&ctx.snippet(rhs.span)).to_string();
    Some((text, var))
}

/// Whether a statement declares a variable named `name`.
fn declares<'ast>(stmt: &'ast ast::Stmt<'ast>, name: &str) -> bool {
    match &stmt.kind {
        ast::StmtKind::DeclSingle(v) => v.name.is_some_and(|n| n.as_str() == name),
        ast::StmtKind::DeclMulti(vars, _) => vars.iter().any(|v| {
            v.as_ref()
                .unspan()
                .and_then(|v| v.name)
                .is_some_and(|n| n.as_str() == name)
        }),
        _ => false,
    }
}

/// Statements before the trigger that can still hold a grant on `local`:
/// nearest first, stopping at the statement that reassigns or declares it.
fn local_grant_window<'ast>(
    ctx: &Ctx<'_, 'ast>,
    function: fhec_bind::FunctionId,
    trigger: Span,
    local_name: &str,
    local_var: fhec_bind::VarId,
) -> Vec<&'ast ast::Stmt<'ast>> {
    let mut out = Vec::new();
    for s in backward_window(ctx, function, trigger) {
        if writes_to(
            ctx,
            s,
            WriteTarget::Var {
                name: local_name,
                id: local_var,
            },
        ) || declares(s, local_name)
        {
            break;
        }
        out.push(s);
    }
    out
}

/// What [`writes_to`] compares a candidate lvalue against.
#[derive(Clone, Copy)]
pub(crate) enum WriteTarget<'a> {
    /// An arbitrary source-text lvalue path (a state variable, a mapping or
    /// array element, a struct field, ...). Compared by snippet text only —
    /// there is no single resolved identity for a structural path.
    Text(&'a str),
    /// A resolved local variable or parameter. Compared by [`VarId`]
    /// identity once a candidate resolves to one, which is immune to
    /// comments/whitespace and to two differently-spelled spans that name
    /// the same variable.
    ///
    /// [`VarId`]: fhec_bind::VarId
    Var { name: &'a str, id: fhec_bind::VarId },
}

impl WriteTarget<'_> {
    fn text(&self) -> &str {
        match self {
            WriteTarget::Text(s) => s,
            WriteTarget::Var { name, .. } => name,
        }
    }
}

/// Whether a statement can assign to, delete, or inc/dec `target` anywhere
/// in its subtree.
///
/// This is deliberately conservative: assembly and parser-recovery nodes are
/// barriers because proving that they leave the tracked value untouched would
/// require semantics this pass does not model (spec §1.3).
pub(crate) fn writes_to<'ast>(
    ctx: &Ctx<'_, 'ast>,
    stmt: &'ast ast::Stmt<'ast>,
    target: WriteTarget<'_>,
) -> bool {
    use solar_ast::visit::Visit;
    use std::ops::ControlFlow;

    struct Search<'a, 'ctx, 'ast> {
        ctx: &'a Ctx<'ctx, 'ast>,
        target: WriteTarget<'a>,
    }

    impl<'ast> Search<'_, '_, 'ast> {
        fn lvalue_matches(&self, lhs: &'ast ast::Expr<'ast>) -> bool {
            if strip_parens(&self.ctx.snippet(lhs.span)) == self.target.text() {
                return true;
            }
            match &lhs.peel_parens().kind {
                ast::ExprKind::Tuple(items) => items.iter().any(|item| {
                    item.as_ref()
                        .unspan()
                        .is_some_and(|item| self.lvalue_matches(item))
                }),
                // A bare identifier: when tracking a resolved local/param,
                // resolve the candidate too and compare identity rather than
                // text — a comment or extra parenthesization must not hide a
                // real write (spec §1.3). When tracking arbitrary text (a
                // state variable, a mapping/array/struct path), the fast
                // text-compare above is the only available identity, so a
                // mismatch here means a genuinely different lvalue.
                ast::ExprKind::Ident(ident) => match self.target {
                    WriteTarget::Var { id, .. } => matches!(
                        self.ctx.unit.resolve(*ident),
                        Some(fhec_bind::Resolution::Local(v))
                            | Some(fhec_bind::Resolution::Param(v))
                            if *v == id
                    ),
                    WriteTarget::Text(_) => false,
                },
                // Every valid non-tuple Solidity lvalue has one of these
                // shapes. A different shape is a recovery/unsupported case,
                // where stopping is the only sound answer.
                ast::ExprKind::Member(_, _) | ast::ExprKind::Index(_, _) => false,
                _ => true,
            }
        }
    }

    impl<'ast> Visit<'ast> for Search<'_, '_, 'ast> {
        type BreakValue = ();

        fn visit_stmt(&mut self, stmt: &'ast ast::Stmt<'ast>) -> ControlFlow<()> {
            if matches!(
                stmt.kind,
                ast::StmtKind::Assembly(_) | ast::StmtKind::Placeholder
            ) {
                return ControlFlow::Break(());
            }
            self.walk_stmt(stmt)
        }

        fn visit_expr(&mut self, e: &'ast ast::Expr<'ast>) -> ControlFlow<()> {
            let writes = match &e.kind {
                ast::ExprKind::Assign(lhs, _, _) | ast::ExprKind::Delete(lhs) => {
                    self.lvalue_matches(lhs)
                }
                ast::ExprKind::Unary(op, target)
                    if matches!(
                        op.kind,
                        ast::UnOpKind::PreInc
                            | ast::UnOpKind::PreDec
                            | ast::UnOpKind::PostInc
                            | ast::UnOpKind::PostDec
                    ) =>
                {
                    self.lvalue_matches(target)
                }
                ast::ExprKind::Err(_) => true,
                _ => false,
            };
            if writes {
                ControlFlow::Break(())
            } else {
                self.walk_expr(e)
            }
        }
    }

    Search { ctx, target }.visit_stmt(stmt).is_break()
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

/// Whether a method-syntax broad-grant call on an encrypted receiver of
/// Solidity type `receiver_type` actually resolves to the trusted profile
/// library, as opposed to an in-unit, non-profile `using` binding (spec
/// §8.6, issue #87).
///
/// [`fhec_bind::BoundUnit::method_candidates`] cannot see a `using`
/// directive that lives in a file outside the compilation unit, which is
/// exactly where CoFHE's real `using BindingsEuintN for euintN global;`
/// lives (inside `FHE.sol`) unless that file happens to be part of the unit
/// (the vendored/conformance-corpus case). So `MethodResolution::NoBinding`
/// or `::External` — no in-unit candidate resolves the call at all — is the
/// ordinary real-world shape and is trusted by default; only an in-unit
/// candidate (`MethodResolution::Functions`) is checked against
/// [`fhec_check::is_profile_library_function`], the same gate library
/// syntax (`FHE.allowPublic(ptr)`) already gets via `PlainTy::FheLib`.
fn method_call_is_trusted(
    ctx: &Ctx<'_, '_>,
    function: FunctionId,
    receiver_type: &str,
    method: solar_interface::Symbol,
) -> bool {
    let info = ctx.unit.function(function);
    match ctx
        .unit
        .method_candidates(info.contract, info.file, receiver_type, method)
    {
        MethodResolution::Functions(ids) => ids
            .iter()
            .all(|&fid| fhec_check::is_profile_library_function(ctx.unit, ctx.profile, fid)),
        MethodResolution::External { .. } | MethodResolution::NoBinding => true,
    }
}

/// [`acl_call_matches`] with the account operand compared modulo an
/// `address(...)` wrapper (the inserted grant always wraps, spec §8.2).
fn acl_call_matches_normalized<'ast>(
    ctx: &Ctx<'_, 'ast>,
    function: FunctionId,
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
    // Library syntax: FHE.name(handle, account). The checker only records
    // `FheLib` after its resolution-based profile-library trust check.
    let lib = matches!(
        ctx.checked.types.get(base.span),
        Some(Ty::Plain(PlainTy::FheLib))
    ) && arg_texts.len() == 2
        && arg_texts[0] == arg0
        && account_matches(&arg_texts[1]);
    // Method syntax: handle.name(account).
    let method_syn = matches!(ctx.checked.types.get(base.span), Some(Ty::Encrypted(t)) if
        method_call_is_trusted(ctx, function, t.solidity_name(), method.name))
        && base_text == arg0
        && arg_texts.len() == 1
        && account_matches(&arg_texts[0]);
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

/// Like [`acl_call_matches`], but also recognizes the call as the sole
/// statement inside an else-less `if`'s body (spec §8.9's zero-address
/// guard, and a `public if <condition>` gate, spec §8.11):
/// `if (<anything>) FHE.<name>(<args>);`. The guard's own condition text is
/// not compared for dedupe purposes — any single wrapped statement that
/// itself matches states the same fact §8.6 already recognizes ungated.
pub(crate) fn policy_call_matches<'ast>(
    ctx: &Ctx<'_, 'ast>,
    function: FunctionId,
    stmt: &'ast ast::Stmt<'ast>,
    name: &str,
    arg0: &str,
    arg1: Option<&str>,
) -> bool {
    if acl_call_matches(ctx, function, stmt, name, arg0, arg1) {
        return true;
    }
    let ast::StmtKind::If(_, then, None) = &stmt.kind else {
        return false;
    };
    let inner = match &then.kind {
        ast::StmtKind::Block(b) if b.len() == 1 => &b[0],
        ast::StmtKind::Block(_) => return false,
        _ => then,
    };
    acl_call_matches(ctx, function, inner, name, arg0, arg1)
}

/// Whether a statement is an ACL call `FHE.<name>(arg0[, arg1])` or
/// `arg0.<name>([arg1])` with the given argument texts (spec §8.6).
fn acl_call_matches<'ast>(
    ctx: &Ctx<'_, 'ast>,
    function: FunctionId,
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

    // Library syntax: FHE.name(handle[, account]) — the base must have
    // passed the checker's resolution-based profile-library trust rule.
    let lib_match = matches!(
        ctx.checked.types.get(base.span),
        Some(Ty::Plain(PlainTy::FheLib))
    ) && match (arg_texts.first(), arg1) {
        (Some(a0), None) => a0 == arg0 && arg_texts.len() == 1,
        (Some(a0), Some(a1)) => {
            a0 == arg0 && arg_texts.get(1).map(String::as_str) == Some(a1) && arg_texts.len() == 2
        }
        (None, _) => false,
    };
    // Method syntax: handle.name([account]) — the base is the handle.
    let method_match = matches!(ctx.checked.types.get(base.span), Some(Ty::Encrypted(t)) if
        method_call_is_trusted(ctx, function, t.solidity_name(), method.name))
        && base_text == arg0
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
pub(crate) fn find_expr<'ast>(
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

/// Whether `e`, peeled, is exactly a `eT.wrap(x)` UDVT cast (spec §8.1
/// FHE4014): a compile-time-only type reinterpretation that never reaches
/// CoFHE, so it registers no permission for anyone on its result,
/// regardless of `x`. Mirrors `fhec_check`'s `is_wrap_call` (checker-side
/// twin, used for the R1/R4 write fact); this free-function copy is for
/// sites — R5's emit arguments — that have no such fact to consult.
fn is_wrap_call(ctx: &Ctx<'_, '_>, e: &ast::Expr<'_>) -> bool {
    let ast::ExprKind::Call(callee, _) = &e.peel_parens().kind else {
        return false;
    };
    let ast::ExprKind::Member(obj, name) = &callee.peel_parens().kind else {
        return false;
    };
    name.as_str() == "wrap"
        && matches!(
            ctx.checked.types.get(obj.span),
            Some(Ty::Plain(PlainTy::EncTypeRef(_)))
        )
}

// ---------------------------------------------------------------------------
// The initialization guard (spec §8.1)
// ---------------------------------------------------------------------------

/// Renders the spec §8.1 initialization guard around one handle's grant
/// sequence, as physical lines with no leading indentation (the caller
/// prefixes each line with the site indent): a single call stays on the
/// guard's own line, two or more open a block. The calls themselves are
/// complete statements (trailing `;` included).
pub(crate) fn guard_lines(ctx: &Ctx<'_, '_>, handle: &str, calls: &[String]) -> Vec<String> {
    let probe = ctx.profile.is_initialized_fn();
    match calls {
        [] => Vec::new(),
        [one] => vec![format!("if ({probe}({handle})) {{ {one} }}")],
        many => {
            let mut out = Vec::with_capacity(many.len() + 2);
            out.push(format!("if ({probe}({handle})) {{"));
            out.extend(many.iter().map(|c| format!("    {c}")));
            out.push("}".to_string());
            out
        }
    }
}

/// The same guard on one line, for suggest-mode messages (spec §8.1).
pub(crate) fn guard_inline(ctx: &Ctx<'_, '_>, handle: &str, calls: &[String]) -> String {
    format!(
        "if ({}({handle})) {{ {} }}",
        ctx.profile.is_initialized_fn(),
        calls.join(" ")
    )
}

/// The body statements of a spec §8.1 initialization guard: an else-less
/// `if` whose condition is a call to the trusted profile's initialization
/// probe (`FHE.isInitialized(...)`). Spec §8.6 makes such a guard
/// transparent to the window scan — its body's statements count as if they
/// stood in the window directly — so a re-transpile of guarded output
/// recognizes the grants it inserted and `T(T(x)) == T(x)` holds (spec
/// §1.4). The condition's argument is deliberately not compared, matching
/// the §8.6 rule for the zero-address guard.
fn init_guard_body<'ast>(
    ctx: &Ctx<'_, 'ast>,
    stmt: &'ast ast::Stmt<'ast>,
) -> Option<&'ast [ast::Stmt<'ast>]> {
    let ast::StmtKind::If(cond, then, None) = &stmt.kind else {
        return None;
    };
    let ast::ExprKind::Call(callee, _) = &cond.peel_parens().kind else {
        return None;
    };
    let ast::ExprKind::Member(base, name) = &callee.peel_parens().kind else {
        return None;
    };
    let probe = ctx.profile.is_initialized_fn();
    let probe_name = probe.rsplit('.').next().unwrap_or(&probe);
    if name.as_str() != probe_name {
        return None;
    }
    // Same trust rule library-syntax grants get (spec §8.6): the base must
    // be the checker-confirmed profile library, not a same-named impostor.
    if !matches!(
        ctx.checked.types.get(base.span),
        Some(Ty::Plain(PlainTy::FheLib))
    ) {
        return None;
    }
    Some(match &then.kind {
        ast::StmtKind::Block(b) => b,
        _ => std::slice::from_ref(then),
    })
}

/// Applies `matches` to a window statement directly and, when the statement
/// is a §8.1 initialization guard, to each statement of the guard's body
/// (one level — spec §8.6 guard transparency).
fn matches_through_guard<'ast>(
    ctx: &Ctx<'_, 'ast>,
    stmt: &'ast ast::Stmt<'ast>,
    matches: &dyn Fn(&'ast ast::Stmt<'ast>) -> bool,
) -> bool {
    if matches(stmt) {
        return true;
    }
    init_guard_body(ctx, stmt).is_some_and(|body| body.iter().any(matches))
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
