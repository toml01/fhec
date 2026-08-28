//! Operators, ternary, assignments: the §3.2 interaction table, §3.3
//! coercions, §4 operator legality, §5.4–§5.5 select/short-circuit rules,
//! and lvalue analysis (storage-write facts, §8.1).

use fhec_bind::{Resolution, VarOwner};
use fhec_ir::{EType, EWidth, FheOp};
use solar_ast as ast;
use solar_interface::Span;

use crate::diag::{codes, Diagnostic, FixIt};
use crate::sites::{
    CompoundAssignSite, EncryptedStorageWrite, OperandKind, OperandPlan, OperatorSite, SlotKind,
    TernarySite,
};
use crate::ty::{PlainTy, Ty};
use crate::walk::FnChecker;

/// Outcome of planning one operand against a target encrypted type.
enum Plan {
    Ok(OperandKind),
    /// Diagnostic already emitted.
    Failed,
}

/// Everything the walker needs to know about an assignment target.
pub(crate) struct LvalueInfo {
    /// The declaration branch-depth of the root (0 = state var / outside).
    pub(crate) decl_depth: u32,
    /// The tracked slot index of the root, when it is a direct local name.
    pub(crate) slot: Option<usize>,
    /// The root local's name, when the lvalue is a bare identifier.
    pub(crate) root_name: Option<String>,
    /// Whether the lvalue provably writes contract storage.
    pub(crate) is_storage: bool,
    /// The slot kind for ACL rule R1.
    pub(crate) slot_kind: SlotKind,
}

impl Default for LvalueInfo {
    fn default() -> Self {
        LvalueInfo {
            decl_depth: 0,
            slot: None,
            root_name: None,
            is_storage: false,
            slot_kind: SlotKind::SimpleVar,
        }
    }
}

impl<'ast> FnChecker<'_, 'ast> {
    // ---- binary operators -------------------------------------------------

    pub(crate) fn binary(
        &mut self,
        e: &'ast ast::Expr<'ast>,
        l: &'ast ast::Expr<'ast>,
        op: ast::BinOp,
        r: &'ast ast::Expr<'ast>,
    ) -> Ty {
        let lty = self.type_expr(l);

        // Plaintext `&&`/`||` short-circuits: `r` may never execute at
        // runtime. Only the ENCRYPTED form (either side `ebool`) forgoes
        // short-circuit (spec §5.5, handled below), and that is already
        // known to be impossible here whenever `l` alone is encrypted.
        // Model the short-circuit exactly like an `if`/`else` (spec §6):
        // join "r never ran" with "r ran", instead of committing to a
        // read/assignment inside `r` as unconditional.
        let maybe_short_circuits =
            matches!(op.kind, ast::BinOpKind::And | ast::BinOpKind::Or) && !lty.is_encrypted();
        let pre_r = maybe_short_circuits.then(|| self.snapshot());
        let rty = self.type_expr(r);
        if let Some(pre_r) = &pre_r {
            if !rty.is_encrypted() {
                // Confirmed plain: exactly one side of `l` genuinely
                // decided the outcome without ever evaluating `r`.
                let after = self.snapshot();
                self.restore(pre_r);
                self.join_into(&after);
            }
            // Otherwise `rty` turned out encrypted despite `lty` not being
            // (a mixed, most likely already-illegal shape) — fall through
            // unchanged into the encrypted-domain handling below, which
            // only needs `lty` or `rty` to be encrypted, not both.
        }

        if !lty.is_encrypted() && !rty.is_encrypted() {
            return self.plain_binary(&lty, op.kind, &rty);
        }

        use ast::BinOpKind::*;
        let fhe_op = match op.kind {
            Add => FheOp::Add,
            Sub => FheOp::Sub,
            Mul => FheOp::Mul,
            Div => FheOp::Div,
            Rem => FheOp::Rem,
            BitAnd | And => FheOp::And,
            BitOr | Or => FheOp::Or,
            BitXor => FheOp::Xor,
            Shl => FheOp::Shl,
            Shr => FheOp::Shr,
            Eq => FheOp::Eq,
            Ne => FheOp::Ne,
            Lt => FheOp::Lt,
            Le => FheOp::Lte,
            Gt => FheOp::Gt,
            Ge => FheOp::Gte,
            Pow => {
                self.out.diagnostics.push(
                    Diagnostic::error(
                        codes::OPERATOR_UNSUPPORTED,
                        e.span,
                        "`**` has no FHE operation; `x.square()` exists for `x ** 2` \
                         but is not applied automatically",
                    )
                    .with_rule("§4.1"),
                );
                return Ty::Unknown;
            }
            Sar => {
                self.error(
                    codes::OPERATOR_UNSUPPORTED,
                    e.span,
                    "`>>>` is not defined for encrypted operands",
                );
                return Ty::Unknown;
            }
        };
        let logical = matches!(op.kind, And | Or);
        let comparison = op.kind.is_cmp();
        let shift = matches!(op.kind, Shl | Shr);

        // §5.5: both sides of encrypted `&&`/`||` always execute.
        if logical {
            for side in [l, r] {
                if let Some(sp) = self.side_effect_span(side) {
                    self.out.diagnostics.push(
                        Diagnostic::error(
                            codes::SIDE_EFFECT_OPERAND,
                            sp,
                            "side-effecting operand of an encrypted `&&`/`||`: there is \
                             no short-circuit, both sides always execute",
                        )
                        .with_rule("§5.5"),
                    );
                }
            }
        }

        // Decide the common operand type.
        let target: EType = if shift {
            match self.shift_target(e.span, &lty, &rty) {
                Some(t) => t,
                None => return Ty::Unknown,
            }
        } else {
            match self.common_target(e.span, &lty, &rty) {
                Some(t) => t,
                None => return Ty::Unknown,
            }
        };

        // Operator/type legality (§4.1).
        let type_ok = match fhe_op {
            FheOp::Eq | FheOp::Ne => true,
            FheOp::And | FheOp::Or | FheOp::Xor => target.is_euint() || target == EType::Ebool,
            _ => target.is_euint(),
        };
        if !type_ok {
            self.out.diagnostics.push(
                Diagnostic::error(
                    codes::OPERATOR_UNSUPPORTED,
                    e.span,
                    format!(
                        "operator `{}` is not defined for `{}`",
                        op.kind.to_str(),
                        target.solidity_name()
                    ),
                )
                .with_rule("§4.1"),
            );
            return Ty::Unknown;
        }

        // Plan both operands.
        let asymmetric_shift = shift && lty.is_encrypted();
        let lp = self.plan_operand(l, &lty, target, false);
        let rp = self.plan_operand(r, &rty, target, asymmetric_shift);
        let (Plan::Ok(lk), Plan::Ok(rk)) = (lp, rp) else {
            return Ty::Unknown;
        };

        let operands = [target, target];
        let result = match self.profile.result_type(fhe_op, &operands) {
            Ok(Some(t)) => t,
            Ok(None) => return Ty::Unknown,
            Err(err) => {
                self.out.diagnostics.push(
                    Diagnostic::error(
                        codes::OP_NOT_IN_PROFILE,
                        e.span,
                        format!("{err} (pinned profile {})", self.profile.version()),
                    )
                    .with_rule("§1.5"),
                );
                return Ty::Unknown;
            }
        };

        self.flag_uninit_in(l.span, "as an operand of a lowered FHE operation");
        self.flag_uninit_in(r.span, "as an operand of a lowered FHE operation");
        self.note_site(e.span);
        let site = OperatorSite {
            span: e.span,
            op: fhe_op,
            result,
            operands: vec![
                OperandPlan {
                    span: l.span,
                    kind: lk,
                },
                OperandPlan {
                    span: r.span,
                    kind: rk,
                },
            ],
            no_short_circuit: logical,
            function: self.fid,
            file: self.file,
        };
        self.out.operator_sites.push(site);
        let _ = comparison;
        Ty::Encrypted(result)
    }

    /// Best-effort plain result typing (no patches; solc is the authority).
    #[allow(clippy::only_used_in_recursion)]
    fn plain_binary(&self, lty: &Ty, op: ast::BinOpKind, rty: &Ty) -> Ty {
        use ast::BinOpKind::*;
        if *lty == Ty::Unknown || *rty == Ty::Unknown {
            return Ty::Unknown;
        }
        match op {
            Lt | Le | Gt | Ge | Eq | Ne | Or | And => Ty::Plain(PlainTy::Bool),
            Add | Sub | Mul | Div | Rem | Pow => match (lty, rty) {
                (
                    Ty::Plain(PlainTy::NumLit { value: Some(a) }),
                    Ty::Plain(PlainTy::NumLit { value: Some(b) }),
                ) => {
                    let v = match op {
                        Add => a.checked_add(*b),
                        Sub => a.checked_sub(*b),
                        Mul => a.checked_mul(*b),
                        Div => a.checked_div(*b),
                        Rem => a.checked_rem(*b),
                        Pow => u32::try_from(*b).ok().and_then(|p| a.checked_pow(p)),
                        _ => None,
                    };
                    Ty::Plain(PlainTy::NumLit { value: v })
                }
                (Ty::Plain(PlainTy::NumLit { .. }), other)
                | (other, Ty::Plain(PlainTy::NumLit { .. })) => other.clone(),
                (Ty::Plain(PlainTy::Uint(a)), Ty::Plain(PlainTy::Uint(b))) => {
                    Ty::Plain(PlainTy::Uint(*a.max(b)))
                }
                _ => Ty::Plain(PlainTy::Opaque),
            },
            BitAnd | BitOr | BitXor | Shl | Shr | Sar => match (lty, rty) {
                (Ty::Plain(PlainTy::Uint(a)), _) => Ty::Plain(PlainTy::Uint(*a)),
                (Ty::Plain(PlainTy::NumLit { .. }), Ty::Plain(PlainTy::NumLit { .. })) => {
                    Ty::Plain(PlainTy::NumLit { value: None })
                }
                _ => Ty::Plain(PlainTy::Opaque),
            },
        }
    }

    /// The common encrypted type for a symmetric operator (spec §3.2, §3.3).
    fn common_target(&mut self, span: Span, lty: &Ty, rty: &Ty) -> Option<EType> {
        match (lty, rty) {
            (Ty::Encrypted(a), Ty::Encrypted(b)) => match (a, b) {
                (EType::Euint(wa), EType::Euint(wb)) => Some(EType::Euint(*wa.max(wb))),
                _ if a == b => Some(*a),
                _ => {
                    self.out.diagnostics.push(
                        Diagnostic::error(
                            codes::INCOMPATIBLE_ENCRYPTED,
                            span,
                            format!(
                                "incompatible encrypted operand types `{}` and `{}`",
                                a.solidity_name(),
                                b.solidity_name()
                            ),
                        )
                        .with_rule("§3.3"),
                    );
                    None
                }
            },
            (Ty::Encrypted(a), other) | (other, Ty::Encrypted(a)) => {
                match other {
                    Ty::Unknown => {
                        self.out.diagnostics.push(
                            Diagnostic::error(
                                codes::ENCRYPTED_MEETS_UNKNOWN,
                                span,
                                "an encrypted operand meets an expression the checker \
                                 cannot type; refusing to guess (annotate the other \
                                 operand or restructure)",
                            )
                            .with_rule("§3.2"),
                        );
                        None
                    }
                    // The plain side's convertibility is checked during
                    // operand planning; the target is the encrypted side.
                    _ => Some(*a),
                }
            }
            _ => unreachable!("common_target requires an encrypted side"),
        }
    }

    /// §4.3: the shift target is the width of the *shifted* operand.
    fn shift_target(&mut self, span: Span, lty: &Ty, rty: &Ty) -> Option<EType> {
        match lty {
            Ty::Encrypted(EType::Euint(w)) => {
                if let Ty::Encrypted(EType::Euint(rw)) = rty {
                    if rw > w {
                        self.out.diagnostics.push(
                            Diagnostic::error(
                                codes::NARROWING_REQUIRED,
                                span,
                                format!(
                                    "the shift amount (`euint{}`) is wider than the \
                                     shifted operand (`euint{}`); narrowing is never \
                                     implicit",
                                    rw.bits(),
                                    w.bits()
                                ),
                            )
                            .with_rule("§4.3"),
                        );
                        return None;
                    }
                }
                Some(EType::Euint(*w))
            }
            Ty::Encrypted(other) => {
                self.out.diagnostics.push(
                    Diagnostic::error(
                        codes::OPERATOR_UNSUPPORTED,
                        span,
                        format!("shifts are not defined for `{}`", other.solidity_name()),
                    )
                    .with_rule("§4.1"),
                );
                None
            }
            Ty::Unknown => {
                self.out.diagnostics.push(
                    Diagnostic::error(
                        codes::ENCRYPTED_MEETS_UNKNOWN,
                        span,
                        "the shifted operand cannot be typed while the shift amount is \
                         encrypted; refusing to guess",
                    )
                    .with_rule("§3.2"),
                );
                None
            }
            // Plain shifted by encrypted amount: the encrypted side dictates.
            _ => match rty {
                Ty::Encrypted(EType::Euint(w)) => Some(EType::Euint(*w)),
                Ty::Encrypted(other) => {
                    self.out.diagnostics.push(
                        Diagnostic::error(
                            codes::OPERATOR_UNSUPPORTED,
                            span,
                            format!(
                                "shift amounts of type `{}` are not defined",
                                other.solidity_name()
                            ),
                        )
                        .with_rule("§4.1"),
                    );
                    None
                }
                _ => unreachable!("shift_target requires an encrypted side"),
            },
        }
    }

    /// Plans one operand against the target type, emitting the §3.3
    /// diagnostics on failure. `no_widen`: §4.3 shift amounts never widen the
    /// *shifted* side's width upward from the right (already checked), but a
    /// narrower encrypted amount does widen; pass `false` to allow widening.
    fn plan_operand(
        &mut self,
        expr: &'ast ast::Expr<'ast>,
        ty: &Ty,
        target: EType,
        _shift_rhs: bool,
    ) -> Plan {
        match ty {
            Ty::Encrypted(t) if *t == target => Plan::Ok(OperandKind::AlreadyEncrypted(*t)),
            Ty::Encrypted(EType::Euint(w)) => match target {
                EType::Euint(tw) if *w < tw => {
                    Plan::Ok(OperandKind::WidenEncrypted { from: *w, to: tw })
                }
                EType::Euint(tw) => {
                    debug_assert!(*w > tw);
                    self.out.diagnostics.push(
                        Diagnostic::error(
                            codes::NARROWING_REQUIRED,
                            expr.span,
                            format!(
                                "this context requires narrowing `euint{}` to `euint{}`; \
                                 narrowing is never inserted implicitly (cast explicitly \
                                 with FHE.asEuint{} if intended)",
                                w.bits(),
                                tw.bits(),
                                tw.bits()
                            ),
                        )
                        .with_rule("§3.3"),
                    );
                    Plan::Failed
                }
                _ => {
                    self.incompatible(expr.span, EType::Euint(*w), target);
                    Plan::Failed
                }
            },
            Ty::Encrypted(t) => {
                self.incompatible(expr.span, *t, target);
                Plan::Failed
            }
            Ty::Plain(PlainTy::NumLit { value }) => {
                let fits = match (target, value) {
                    (EType::Euint(w), Some(v)) => w.bits() >= 128 || *v < (1u128 << w.bits()),
                    _ => false,
                };
                if fits {
                    Plan::Ok(OperandKind::LiteralEncrypt { to: target })
                } else {
                    self.out.diagnostics.push(
                        Diagnostic::error(
                            codes::LITERAL_OUT_OF_RANGE,
                            expr.span,
                            format!(
                                "this literal does not fit `{}` (negative literals and \
                                 non-numeric literals never coerce to encrypted types)",
                                target.solidity_name()
                            ),
                        )
                        .with_rule("§3.3"),
                    );
                    Plan::Failed
                }
            }
            Ty::Plain(p) => {
                if p.converts_to(target) {
                    Plan::Ok(OperandKind::TrivialEncrypt { to: target })
                } else {
                    self.out.diagnostics.push(
                        Diagnostic::error(
                            codes::NOT_CONVERTIBLE,
                            expr.span,
                            format!(
                                "this plaintext operand does not implicitly convert to \
                                 `{}`'s plaintext analogue `{}`",
                                target.solidity_name(),
                                target.plaintext_type()
                            ),
                        )
                        .with_rule("§3.3"),
                    );
                    Plan::Failed
                }
            }
            Ty::Unknown => {
                self.out.diagnostics.push(
                    Diagnostic::error(
                        codes::ENCRYPTED_MEETS_UNKNOWN,
                        expr.span,
                        "this operand cannot be typed but meets an encrypted operand; \
                         refusing to guess",
                    )
                    .with_rule("§3.2"),
                );
                Plan::Failed
            }
        }
    }

    fn incompatible(&mut self, span: Span, got: EType, want: EType) {
        self.out.diagnostics.push(
            Diagnostic::error(
                codes::INCOMPATIBLE_ENCRYPTED,
                span,
                format!(
                    "incompatible encrypted types: `{}` where `{}` is required (no \
                     implicit conversion crosses encrypted kinds)",
                    got.solidity_name(),
                    want.solidity_name()
                ),
            )
            .with_rule("§3.3"),
        );
    }

    // ---- unary --------------------------------------------------------------

    pub(crate) fn unary(
        &mut self,
        e: &'ast ast::Expr<'ast>,
        op: ast::UnOp,
        x: &'ast ast::Expr<'ast>,
    ) -> Ty {
        use ast::UnOpKind::*;
        match op.kind {
            PreInc | PreDec | PostInc | PostDec => {
                let xty = self.type_expr(x);
                if xty.is_encrypted() {
                    self.out.diagnostics.push(
                        Diagnostic::error(
                            codes::INC_DEC_VALUE_USED,
                            e.span,
                            "the value of `++`/`--` on an encrypted variable cannot be \
                             used inside a larger expression (the pre/post distinction \
                             has no encrypted analogue); use a statement form",
                        )
                        .with_rule("§4.2"),
                    );
                    return Ty::Unknown;
                }
                xty
            }
            Neg => {
                let xty = self.type_expr(x);
                if let Ty::Encrypted(t) = &xty {
                    let mut d = Diagnostic::error(
                        codes::UNARY_MINUS,
                        e.span,
                        "unary minus is not defined on encrypted values",
                    )
                    .with_rule("§3.3");
                    if let (EType::Euint(w), Ok(snippet)) = (*t, self.sm.span_to_snippet(x.span)) {
                        d = d.with_fixit(FixIt {
                            span: e.span,
                            replacement: format!("FHE.sub(FHE.asEuint{}(0), {snippet})", w.bits()),
                            safe: false,
                        });
                    }
                    self.out.diagnostics.push(d);
                    return Ty::Unknown;
                }
                match xty {
                    Ty::Plain(PlainTy::NumLit { .. }) => {
                        // A negative literal never coerces to euintN (§3.3):
                        // model it as an unfitting literal.
                        Ty::Plain(PlainTy::NumLit { value: None })
                    }
                    other => other,
                }
            }
            Not => {
                let xty = self.type_expr(x);
                match xty {
                    Ty::Encrypted(EType::Ebool) => self.unary_site(e, x, FheOp::Not, EType::Ebool),
                    Ty::Encrypted(t) => {
                        self.error(
                            codes::OPERATOR_UNSUPPORTED,
                            e.span,
                            format!("`!` is not defined for `{}`", t.solidity_name()),
                        );
                        Ty::Unknown
                    }
                    Ty::Plain(_) => Ty::Plain(PlainTy::Bool),
                    Ty::Unknown => Ty::Unknown,
                }
            }
            BitNot => {
                let xty = self.type_expr(x);
                match xty {
                    Ty::Encrypted(t @ EType::Euint(_)) => self.unary_site(e, x, FheOp::Not, t),
                    Ty::Encrypted(t) => {
                        self.error(
                            codes::OPERATOR_UNSUPPORTED,
                            e.span,
                            format!("`~` is not defined for `{}`", t.solidity_name()),
                        );
                        Ty::Unknown
                    }
                    other => other,
                }
            }
        }
    }

    fn unary_site(
        &mut self,
        e: &'ast ast::Expr<'ast>,
        x: &'ast ast::Expr<'ast>,
        op: FheOp,
        t: EType,
    ) -> Ty {
        self.flag_uninit_in(x.span, "as an operand of a lowered FHE operation");
        self.note_site(e.span);
        let site = OperatorSite {
            span: e.span,
            op,
            result: t,
            operands: vec![OperandPlan {
                span: x.span,
                kind: OperandKind::AlreadyEncrypted(t),
            }],
            no_short_circuit: false,
            function: self.fid,
            file: self.file,
        };
        self.out.operator_sites.push(site);
        Ty::Encrypted(t)
    }

    // ---- ternary --------------------------------------------------------------

    pub(crate) fn ternary(
        &mut self,
        e: &'ast ast::Expr<'ast>,
        c: &'ast ast::Expr<'ast>,
        a: &'ast ast::Expr<'ast>,
        b: &'ast ast::Expr<'ast>,
    ) -> Ty {
        let cty = self.type_expr(c);
        // A real `ebool` condition lowers to `FHE.select`, which always
        // evaluates BOTH arms (spec §5.4/§5.5) — so typing them
        // unconditionally, one after the other, is the correct model.
        // Anything else (a plaintext condition, or an already-erroring
        // non-`ebool` encrypted one) is a genuine runtime branch: exactly
        // one arm executes, so a read/assignment inside one arm must not be
        // treated as unconditional. Decided from `cty` alone, before typing
        // either arm, so the join can be applied while typing them.
        if !matches!(cty, Ty::Encrypted(EType::Ebool)) {
            let snap = self.snapshot();
            let aty = self.type_expr(a);
            let a_states = self.snapshot();
            self.restore(&snap);
            let bty = self.type_expr(b);
            let b_states = self.snapshot();
            self.join_all(&[&a_states, &b_states]);
            return match cty {
                Ty::Encrypted(other) => {
                    self.error(
                        codes::CONDITION_NOT_EBOOL,
                        c.span,
                        format!(
                            "`?:` condition has type `{}`; encrypted conditions must be \
                             `ebool`",
                            other.solidity_name()
                        ),
                    );
                    Ty::Unknown
                }
                // Plaintext condition: NOT lowered even with encrypted arms
                // (spec §5.4).
                _ => {
                    if aty == bty {
                        aty
                    } else {
                        Ty::Unknown
                    }
                }
            };
        }
        let aty = self.type_expr(a);
        let bty = self.type_expr(b);
        {
            for side in [a, b] {
                if let Some(sp) = self.side_effect_span(side) {
                    self.out.diagnostics.push(
                        Diagnostic::error(
                            codes::SIDE_EFFECT_OPERAND,
                            sp,
                            "side-effecting arm of an encrypted `?:`: both arms \
                                 always execute",
                        )
                        .with_rule("§5.5"),
                    );
                }
            }
            let target = match (&aty, &bty) {
                (Ty::Encrypted(_), _) | (_, Ty::Encrypted(_)) => {
                    match self.common_target(e.span, &aty, &bty) {
                        Some(t) => t,
                        None => return Ty::Unknown,
                    }
                }
                // Both arms plaintext: infer the encrypted analogue when
                // it is unambiguous; literals alone carry no width.
                (Ty::Plain(pa), Ty::Plain(pb)) => {
                    let cand = |p: &PlainTy| match p {
                        PlainTy::Bool => Some(EType::Ebool),
                        PlainTy::Address => Some(EType::Eaddress),
                        PlainTy::Uint(bits) => EWidth::ALL
                            .into_iter()
                            .find(|w| w.bits() == *bits)
                            .map(EType::Euint),
                        _ => None,
                    };
                    match (cand(pa), cand(pb)) {
                        (Some(x), Some(y)) if x == y => x,
                        (Some(x), None) if matches!(pb, PlainTy::NumLit { .. }) => x,
                        (None, Some(y)) if matches!(pa, PlainTy::NumLit { .. }) => y,
                        _ => {
                            self.out.diagnostics.push(
                                Diagnostic::error(
                                    codes::NOT_CONVERTIBLE,
                                    e.span,
                                    "cannot infer the common encrypted type of these \
                                         plaintext arms; make at least one arm encrypted \
                                         or give both a definite width",
                                )
                                .with_rule("§5.4"),
                            );
                            return Ty::Unknown;
                        }
                    }
                }
                _ => {
                    self.out.diagnostics.push(
                        Diagnostic::error(
                            codes::ENCRYPTED_MEETS_UNKNOWN,
                            e.span,
                            "an arm of this encrypted `?:` cannot be typed; refusing \
                                 to guess",
                        )
                        .with_rule("§3.2"),
                    );
                    return Ty::Unknown;
                }
            };
            let pa = self.plan_operand(a, &aty, target, false);
            let pb = self.plan_operand(b, &bty, target, false);
            let (Plan::Ok(ka), Plan::Ok(kb)) = (pa, pb) else {
                return Ty::Unknown;
            };
            self.flag_uninit_in(c.span, "as a `select` condition");
            self.flag_uninit_in(a.span, "as a `select` arm");
            self.flag_uninit_in(b.span, "as a `select` arm");
            self.note_site(e.span);
            let site = TernarySite {
                span: e.span,
                cond_span: c.span,
                arms: [
                    OperandPlan {
                        span: a.span,
                        kind: ka,
                    },
                    OperandPlan {
                        span: b.span,
                        kind: kb,
                    },
                ],
                result: target,
                function: self.fid,
                file: self.file,
            };
            self.out.ternary_sites.push(site);
            Ty::Encrypted(target)
        }
    }

    // ---- assignment -------------------------------------------------------------

    pub(crate) fn assign(
        &mut self,
        e: &'ast ast::Expr<'ast>,
        lhs: &'ast ast::Expr<'ast>,
        op: Option<ast::BinOp>,
        rhs: &'ast ast::Expr<'ast>,
    ) -> Ty {
        let rty = self.type_expr(rhs);

        // A tuple assignment has one write target for each named component,
        // not one opaque tuple target. In particular, `(, x, y) = f()`
        // definitely assigns both `x` and `y`; treating the tuple expression
        // as an ordinary lvalue would leave their definite-assignment slots
        // untouched and later report FHE2007 falsely.
        if op.is_none() && matches!(lhs.peel_parens().kind, ast::ExprKind::Tuple(_)) {
            self.assign_tuple_lvalues(lhs, Some(rhs));
            return Ty::Plain(PlainTy::Opaque);
        }

        let (lty, lv) = self.analyze_lvalue(lhs);

        match op {
            None => {
                self.simple_assign(lhs, rhs.span, &rty, &lty, &lv);
                // A bare copy from an encrypted local/named-return that is
                // itself not definitely assigned propagates that unassigned
                // status to the target, rather than unconditionally
                // becoming Assigned — otherwise the copy silently launders
                // an uninitialized handle (spec §6; issue #82's hazard
                // class, one function-local hop earlier).
                if matches!(lty, Ty::Encrypted(_)) && self.rhs_is_unassigned_slot(rhs) {
                    if let Some(idx) = lv.slot {
                        self.slots[idx].state = AState::Unassigned;
                    }
                }
            }
            Some(binop) => match &lty {
                Ty::Encrypted(t) => {
                    self.compound(e, lhs, binop, rhs, &rty, &lv, *t);
                }
                _ => {
                    if rty.is_encrypted() {
                        self.error(
                            codes::EBOOL_AS_BOOL,
                            rhs.span,
                            "an encrypted value cannot compound-assign into a \
                                 plaintext location",
                        );
                    }
                    self.plain_write(&lv, lhs.span, &lty);
                }
            },
        }
        lty
    }

    /// Applies the simple-assignment bookkeeping to every present tuple
    /// component. Holes have no target, while nested tuples are flattened
    /// recursively so every named lvalue receives its own assignment state.
    ///
    /// When `rhs` is itself an explicit tuple literal of the same shape
    /// (`(r, other) = (x, y);`), each component's write additionally
    /// inherits its paired RHS element's status when that element is a bare
    /// reference to an unassigned tracked slot (spec §6), same as a simple
    /// assignment. A call-returning-tuple RHS (`(ok, r) = f(...);`, this
    /// issue's original shape) has no per-component identity to inspect
    /// here — that hazard is instead caught at the callee's own exit
    /// points, which is what the rest of this PR adds.
    fn assign_tuple_lvalues(
        &mut self,
        lhs: &'ast ast::Expr<'ast>,
        rhs: Option<&'ast ast::Expr<'ast>>,
    ) {
        if let ast::ExprKind::Tuple(lels) = &lhs.peel_parens().kind {
            let rels = rhs.and_then(|r| match &r.peel_parens().kind {
                ast::ExprKind::Tuple(rels) if rels.len() == lels.len() => Some(rels),
                _ => None,
            });
            for (i, lel) in lels.iter().enumerate() {
                if let Some(lel) = lel.as_ref().unspan() {
                    let rel = rels
                        .and_then(|rels| rels[i].as_ref().unspan())
                        .map(|v| &**v);
                    self.assign_tuple_lvalues(lel, rel);
                }
            }
            return;
        }

        let (lty, lv) = self.analyze_lvalue(lhs);
        // The checker intentionally does not model individual tuple-result
        // types. Solidity checks component compatibility; the checker only
        // needs the target type here to record the definite assignment.
        self.record_simple_write(lhs, &lty, &lv);
        if matches!(lty, Ty::Encrypted(_)) && rhs.is_some_and(|r| self.rhs_is_unassigned_slot(r)) {
            if let Some(idx) = lv.slot {
                self.slots[idx].state = AState::Unassigned;
            }
        }
    }

    /// Whether `rhs` (peeled of parens) is a bare reference to a tracked
    /// local/parameter/named-return that is not currently definitely
    /// assigned. Used to propagate an uninitialized handle through a copy
    /// (`r = x;`) instead of unconditionally marking the copy's target
    /// assigned.
    fn rhs_is_unassigned_slot(&self, rhs: &'ast ast::Expr<'ast>) -> bool {
        let ast::ExprKind::Ident(id) = &rhs.peel_parens().kind else {
            return false;
        };
        let Some(Resolution::Local(_) | Resolution::Param(_)) = self.unit.resolve(*id) else {
            return false;
        };
        let Some(idx) = self.slot_of(id.as_str()) else {
            return false;
        };
        self.slots[idx].encrypted.is_some() && self.slots[idx].state != AState::Assigned
    }

    /// Shared simple-assignment checks and write bookkeeping.
    fn simple_assign(
        &mut self,
        lhs: &'ast ast::Expr<'ast>,
        rhs_span: Span,
        rty: &Ty,
        lty: &Ty,
        lv: &LvalueInfo,
    ) {
        if *lty == Ty::Plain(PlainTy::Bool) && *rty == Ty::Encrypted(EType::Ebool) {
            self.error(
                codes::EBOOL_AS_BOOL,
                rhs_span,
                "`ebool` cannot be assigned to a plaintext `bool`; decryption \
                 is an explicit asynchronous operation",
            );
        }
        self.record_simple_write(lhs, lty, lv);
    }

    /// Records the mutation represented by one simple-assignment target.
    fn record_simple_write(&mut self, lhs: &'ast ast::Expr<'ast>, lty: &Ty, lv: &LvalueInfo) {
        match lty {
            Ty::Encrypted(t) => self.finish_encrypted_write(lv, lhs.span, *t),
            _ => self.plain_write(lv, lhs.span, lty),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn compound(
        &mut self,
        e: &'ast ast::Expr<'ast>,
        lhs: &'ast ast::Expr<'ast>,
        op: ast::BinOp,
        rhs: &'ast ast::Expr<'ast>,
        rty: &Ty,
        lv: &LvalueInfo,
        t: EType,
    ) -> Ty {
        use ast::BinOpKind::*;
        let fhe_op = match op.kind {
            Add => FheOp::Add,
            Sub => FheOp::Sub,
            Mul => FheOp::Mul,
            Div => FheOp::Div,
            Rem => FheOp::Rem,
            BitAnd => FheOp::And,
            BitOr => FheOp::Or,
            BitXor => FheOp::Xor,
            Shl => FheOp::Shl,
            Shr => FheOp::Shr,
            _ => {
                self.error(
                    codes::OPERATOR_UNSUPPORTED,
                    e.span,
                    format!(
                        "compound `{}=` is not defined for encrypted values",
                        op.kind.to_str()
                    ),
                );
                return Ty::Unknown;
            }
        };
        let type_ok = match fhe_op {
            FheOp::And | FheOp::Or | FheOp::Xor => t.is_euint() || t == EType::Ebool,
            _ => t.is_euint(),
        };
        if !type_ok {
            self.error(
                codes::OPERATOR_UNSUPPORTED,
                e.span,
                format!(
                    "operator `{}` is not defined for `{}`",
                    op.kind.to_str(),
                    t.solidity_name()
                ),
            );
            return Ty::Unknown;
        }
        // Shift amounts never widen the shifted side; other rhs must not be
        // wider than the target (§3.3 rule 3 / §4.3).
        let plan = self.plan_operand(rhs, rty, t, matches!(fhe_op, FheOp::Shl | FheOp::Shr));
        let Plan::Ok(kind) = plan else {
            return Ty::Unknown;
        };
        // The compound reads L before writing it.
        self.uninit_lvalue_read(lv, lhs.span);
        self.flag_uninit_in(rhs.span, "as an operand of a lowered FHE operation");
        self.note_site(e.span);
        let site = CompoundAssignSite {
            span: e.span,
            lhs_span: lhs.span,
            lhs: t,
            op: fhe_op,
            rhs: OperandPlan {
                span: rhs.span,
                kind,
            },
            function: self.fid,
            file: self.file,
        };
        self.out.compound_sites.push(site);
        self.finish_encrypted_write(lv, lhs.span, t);
        Ty::Encrypted(t)
    }

    /// FHE2007 when a compound/inc-dec target reads a possibly-uninitialized
    /// tracked local.
    pub(crate) fn uninit_lvalue_read(&mut self, lv: &LvalueInfo, span: Span) {
        if let Some(idx) = lv.slot {
            if self.slots[idx].encrypted.is_some() && self.slots[idx].state != AState::Assigned {
                self.pending.push((idx, span));
                self.flag_uninit_in(span, "as an operand of a lowered FHE operation");
            }
        }
    }

    /// Bookkeeping shared by every encrypted write: definite assignment,
    /// branch-merge logging, and the R1 storage-write fact (spec §8.1).
    pub(crate) fn finish_encrypted_write(&mut self, lv: &LvalueInfo, span: Span, t: EType) {
        if let Some(name) = &lv.root_name {
            let name = name.clone();
            self.note_assign(&name, span);
        }
        if self.branch_depth == 0 && lv.is_storage {
            let fact = EncryptedStorageWrite {
                stmt_span: self.current_stmt_span,
                lvalue_span: span,
                slot: lv.slot_kind.clone(),
                value_ty: t,
                in_view_or_pure: self.is_view_or_pure,
                function: self.fid,
                file: self.file,
            };
            self.out.acl.storage_writes.push(fact);
        }
        // Encrypted writes to storage inside a branch belong to the
        // enclosing if-site's merge lowering; locals are logged by
        // note_assign above. Nothing else to do here.
    }

    /// Bookkeeping for a plaintext (or unprovable) write: §7.1 FHE3006.
    pub(crate) fn plain_write(&mut self, lv: &LvalueInfo, span: Span, _ty: &Ty) {
        self.branch_plain_write(span, lv.decl_depth);
        if let Some(name) = &lv.root_name {
            let name = name.clone();
            self.note_assign(&name, span);
        }
    }

    // ---- lvalues -------------------------------------------------------------

    /// Analyzes an assignment target: its type plus write-relevant facts.
    pub(crate) fn analyze_lvalue(&mut self, e: &'ast ast::Expr<'ast>) -> (Ty, LvalueInfo) {
        let e = e.peel_parens();
        match &e.kind {
            ast::ExprKind::Ident(id) => {
                let res = self.unit.resolve(*id).cloned();
                match &res {
                    Some(Resolution::StateVar(_)) => {
                        let ty = self
                            .var_decl_ty(res.as_ref().expect("checked"))
                            .map(|(t, _)| t)
                            .unwrap_or(Ty::Unknown);
                        (
                            ty,
                            LvalueInfo {
                                decl_depth: 0,
                                slot: None,
                                root_name: None,
                                is_storage: true,
                                slot_kind: SlotKind::SimpleVar,
                            },
                        )
                    }
                    Some(Resolution::Local(_) | Resolution::Param(_)) => {
                        let name = id.as_str().to_string();
                        let slot = self.slot_of(&name);
                        let decl_depth = slot.map(|s| self.slots[s].decl_depth).unwrap_or(0);
                        let (ty, owner) = self
                            .var_decl_ty(res.as_ref().expect("checked"))
                            .unwrap_or((Ty::Unknown, VarOwner::Local(self.fid)));
                        // A local *storage pointer* rebinding is not a
                        // storage write; writes through it are (handled at
                        // Member/Index below via is_storage propagation).
                        let _ = owner;
                        (
                            ty,
                            LvalueInfo {
                                decl_depth,
                                slot,
                                root_name: Some(name),
                                is_storage: false,
                                slot_kind: SlotKind::SimpleVar,
                            },
                        )
                    }
                    _ => {
                        let ty = self.ident_ty(*id);
                        (ty, LvalueInfo::default())
                    }
                }
            }
            ast::ExprKind::Index(base, kind) => {
                let (bty, binfo) = self.analyze_lvalue(base);
                let base_is_storage = binfo.is_storage || self.storage_pointer_root(base);
                match kind {
                    ast::IndexKind::Index(Some(k)) => {
                        let kty = self.type_expr(k);
                        if kty.is_encrypted() {
                            self.error(
                                codes::ENCRYPTED_INDEX,
                                k.span,
                                "an encrypted value cannot index an array or mapping: \
                                 the access pattern would leak the ciphertext",
                            );
                        }
                        let (vty, slot_kind) = match bty {
                            Ty::Plain(PlainTy::Mapping(_, v)) => (
                                *v,
                                SlotKind::Mapping {
                                    key_span: k.span,
                                    key_is_msg_sender: self.is_msg_sender(k),
                                    key_is_address: kty == Ty::Plain(PlainTy::Address),
                                },
                            ),
                            Ty::Plain(PlainTy::Array(el)) => {
                                (*el, SlotKind::ArrayIndex { index_span: k.span })
                            }
                            _ => (Ty::Unknown, SlotKind::ArrayIndex { index_span: k.span }),
                        };
                        (
                            vty,
                            LvalueInfo {
                                decl_depth: binfo.decl_depth,
                                slot: None,
                                root_name: None,
                                is_storage: base_is_storage,
                                slot_kind,
                            },
                        )
                    }
                    _ => (Ty::Unknown, LvalueInfo::default()),
                }
            }
            ast::ExprKind::Member(base, name) => {
                let (bty, binfo) = self.analyze_lvalue(base);
                let base_is_storage = binfo.is_storage || self.storage_pointer_root(base);
                let fty = match &bty {
                    Ty::Plain(PlainTy::Struct(td)) => {
                        if let fhec_bind::TypeDeclKind::Struct(s) = &self.unit.type_decl(*td).kind {
                            s.fields
                                .iter()
                                .find(|f| f.name.is_some_and(|n| n.as_str() == name.as_str()))
                                .map(|f| declared_ty_of(self, &f.ty))
                                .unwrap_or(Ty::Unknown)
                        } else {
                            Ty::Unknown
                        }
                    }
                    _ => Ty::Unknown,
                };
                (
                    fty,
                    LvalueInfo {
                        decl_depth: binfo.decl_depth,
                        slot: None,
                        root_name: None,
                        is_storage: base_is_storage,
                        slot_kind: SlotKind::StructField,
                    },
                )
            }
            _ => {
                let ty = self.type_expr(e);
                (ty, LvalueInfo::default())
            }
        }
    }

    /// Whether the lvalue root is a local declared with `storage` location
    /// (writes through it hit contract storage).
    fn storage_pointer_root(&self, e: &'ast ast::Expr<'ast>) -> bool {
        match &e.peel_parens().kind {
            ast::ExprKind::Ident(id) => match self.unit.resolve(*id) {
                Some(Resolution::Local(v) | Resolution::Param(v)) => {
                    self.unit.var(*v).decl.data_location == Some(ast::DataLocation::Storage)
                }
                _ => false,
            },
            ast::ExprKind::Index(base, _) | ast::ExprKind::Member(base, _) => {
                self.storage_pointer_root(base)
            }
            _ => false,
        }
    }

    /// Whether an expression is exactly `msg.sender`.
    fn is_msg_sender(&self, e: &'ast ast::Expr<'ast>) -> bool {
        is_msg_sender(self.unit, e)
    }

    // ---- side effects (spec §5.5) ------------------------------------------------

    /// The span of the first side effect inside an operand expression, if any.
    pub(crate) fn side_effect_span(&self, e: &'ast ast::Expr<'ast>) -> Option<Span> {
        use ast::ExprKind::*;
        match &e.kind {
            Assign(..) | Delete(_) | New(_) | CallOptions(..) => Some(e.span),
            Unary(op, x) => {
                if op.kind.has_side_effects() {
                    Some(e.span)
                } else {
                    self.side_effect_span(x)
                }
            }
            Call(callee, args) => {
                let callee_p = callee.peel_parens();
                let pure_callee = match &callee_p.kind {
                    Member(obj, mname) => {
                        // Profile FHE calls / casts / wrap are the allowed
                        // (known) operand calls.
                        let obj_ty = self.out.types.get(obj.span);
                        match obj_ty {
                            Some(Ty::Plain(PlainTy::FheLib)) => true,
                            Some(Ty::Encrypted(_)) => {
                                op_by_name(mname.as_str()).is_some()
                                    || cast_target_by_name_ok(mname.as_str())
                            }
                            Some(Ty::Plain(PlainTy::EncTypeRef(_))) => {
                                matches!(mname.as_str(), "wrap" | "unwrap")
                            }
                            _ => false,
                        }
                    }
                    Ident(id) => {
                        matches!(
                            self.unit.resolve(*id),
                            Some(Resolution::Builtin(b)) if matches!(
                                b.0,
                                "keccak256" | "sha256" | "ripemd160" | "ecrecover" | "addmod"
                                    | "mulmod" | "gasleft" | "blockhash" | "blobhash"
                            )
                        ) || matches!(
                            self.unit.resolve(*id),
                            Some(Resolution::Contract(_) | Resolution::TypeName(_))
                        ) || matches!(
                            self.unit.resolve(*id),
                            Some(r @ (Resolution::External { .. } | Resolution::Unresolved(_)))
                                if self.trust.encrypted_type(self.unit, id.as_str(), r).is_some()
                        )
                    }
                    Type(_) => true,
                    _ => false,
                };
                if !pure_callee {
                    return Some(e.span);
                }
                args.exprs().find_map(|a| self.side_effect_span(a))
            }
            Binary(l, _, r) => self
                .side_effect_span(l)
                .or_else(|| self.side_effect_span(r)),
            Ternary(c, a, b) => self
                .side_effect_span(c)
                .or_else(|| self.side_effect_span(a))
                .or_else(|| self.side_effect_span(b)),
            Tuple(els) => els
                .iter()
                .find_map(|el| el.as_ref().unspan().and_then(|e| self.side_effect_span(e))),
            Array(els) => els.iter().find_map(|e| self.side_effect_span(e)),
            Index(base, kind) => self.side_effect_span(base).or_else(|| match kind {
                ast::IndexKind::Index(i) => i.as_ref().and_then(|e| self.side_effect_span(e)),
                ast::IndexKind::Range(a, b) => a
                    .as_ref()
                    .and_then(|e| self.side_effect_span(e))
                    .or_else(|| b.as_ref().and_then(|e| self.side_effect_span(e))),
            }),
            Member(obj, _) => self.side_effect_span(obj),
            Payable(args) => args.exprs().find_map(|a| self.side_effect_span(a)),
            Lit(..) | Ident(_) | Type(_) | TypeCall(_) | Err(_) => None,
        }
    }
}

/// `declared_ty` without borrowing the checker twice.
fn declared_ty_of<'ast>(chk: &FnChecker<'_, 'ast>, ty: &ast::Type<'ast>) -> Ty {
    crate::decl::declared_ty(chk.unit, chk.trust, ty)
}

/// Whether an expression is exactly `msg.sender`, proven by name resolution
/// (`msg` must resolve to the [`Resolution::Builtin`]) rather than by
/// spelling — a parameter or local named `msg` shadows the builtin and must
/// not be mistaken for it (the same class of bug as issue #61). Public so
/// every ownership-proof site (R1's direct write in `pass_acl::rule_r1` via
/// [`crate::sites::SlotKind::Mapping::key_is_msg_sender`], and the
/// encrypted-if merge path in `fhec_lower::pass_if`) proves ownership the
/// same way instead of re-deriving it by text comparison.
pub fn is_msg_sender<'ast>(unit: &fhec_bind::BoundUnit<'ast>, e: &'ast ast::Expr<'ast>) -> bool {
    if let ast::ExprKind::Member(obj, name) = &e.peel_parens().kind {
        if name.as_str() == "sender" {
            if let ast::ExprKind::Ident(id) = &obj.peel_parens().kind {
                return matches!(
                    unit.resolve(*id),
                    Some(Resolution::Builtin(b)) if b.0 == "msg"
                );
            }
        }
    }
    false
}

/// Local alias avoiding a name clash in `side_effect_span`.
fn cast_target_by_name_ok(name: &str) -> bool {
    crate::trust::cast_target_by_name(name).is_some()
}

use crate::trust::op_by_name;
use crate::walk::AState;
