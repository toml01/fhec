//! Expression typing (spec §3, §4) and rewrite-site construction.

use fhec_bind::{MethodResolution, Resolution, TypeDeclKind};
use fhec_ir::{EType, FheOp};
use solar_ast as ast;
use solar_interface::Span;

use crate::decl::{custom_ty, declared_ty, elementary};
use crate::diag::{codes, Diagnostic};
use crate::sites::{CastSugarSite, EncryptedArgCall, IncDecSite};
use crate::trust::{cast_target_by_name, op_by_name};
use crate::ty::{PlainTy, Ty};
use crate::walk::FnChecker;

/// How a call's callee classifies for legality and ACL purposes.
enum CallClass {
    /// A trusted profile FHE operation or cast.
    Fhe,
    /// An in-unit internal call (same contract, library, free function...).
    Internal(Vec<fhec_bind::FunctionId>),
    /// A proven external call; the span is the callee *object* expression.
    External {
        callee_span: Span,
        callee_is_ident: bool,
    },
    /// A builtin (`require`, `keccak256`, casts, constructors, ...).
    Builtin,
    /// Cannot classify.
    Opaque,
}

impl<'ast> FnChecker<'_, 'ast> {
    /// Records a (non-`Unknown`) type for a span and returns it.
    fn rec(&mut self, span: Span, ty: Ty) -> Ty {
        if ty != Ty::Unknown {
            self.out.types.record(span, ty.clone());
        }
        ty
    }

    /// Types a statement-position expression (`Expr;`): the only place the
    /// `++`/`--` statement forms are legal on encrypted targets (spec §4.2).
    pub(crate) fn type_root_expr(&mut self, e: &'ast ast::Expr<'ast>) {
        let peeled = e.peel_parens();
        if let ast::ExprKind::Unary(op, target) = &peeled.kind {
            if matches!(
                op.kind,
                ast::UnOpKind::PreInc
                    | ast::UnOpKind::PreDec
                    | ast::UnOpKind::PostInc
                    | ast::UnOpKind::PostDec
            ) {
                let (t_ty, lv) = self.analyze_lvalue(target);
                if let Ty::Encrypted(t) = t_ty {
                    if !t.is_euint() {
                        self.error(
                            codes::OPERATOR_UNSUPPORTED,
                            e.span,
                            format!(
                                "`{}` is not defined for `{}`",
                                op.kind.to_str(),
                                t.solidity_name()
                            ),
                        );
                        return;
                    }
                    self.uninit_lvalue_read(&lv, target.span);
                    self.note_site(e.span);
                    let site = IncDecSite {
                        span: e.span,
                        target_span: target.span,
                        ty: t,
                        is_increment: matches!(
                            op.kind,
                            ast::UnOpKind::PreInc | ast::UnOpKind::PostInc
                        ),
                        function: self.fid,
                        file: self.file,
                    };
                    self.out.incdec_sites.push(site);
                    self.finish_encrypted_write(&lv, target.span, t);
                    return;
                }
                // Plaintext / unknown inc-dec: a write.
                self.plain_write(&lv, target.span, &t_ty);
                return;
            }
        }
        self.type_expr(e);
    }

    /// Types any expression, returning its encryptedness type.
    pub(crate) fn type_expr(&mut self, e: &'ast ast::Expr<'ast>) -> Ty {
        use ast::ExprKind::*;
        let ty = match &e.kind {
            Lit(lit, _) => self.lit_ty(lit),
            Ident(id) => self.ident_ty(*id),
            Member(obj, name) => self.member_ty(obj, *name),
            Call(callee, args) => self.call(e, callee, args),
            CallOptions(inner, opts) => {
                for o in opts.iter() {
                    self.type_expr(&*o.value);
                }
                self.type_expr(inner)
            }
            Binary(l, op, r) => self.binary(e, l, *op, r),
            Unary(op, x) => self.unary(e, *op, x),
            Ternary(c, a, b) => self.ternary(e, c, a, b),
            Assign(lhs, op, rhs) => self.assign(e, lhs, *op, rhs),
            Index(base, kind) => self.index(base, kind),
            Delete(x) => {
                let xty = self.type_expr(x);
                if xty.is_encrypted() {
                    self.error(
                        codes::DELETE_ON_ENCRYPTED,
                        e.span,
                        "`delete` on an encrypted value produces an uninitialized handle \
                         that FHE operations silently replace with a default; assign \
                         `FHE.asEuintN(0)` explicitly if that is intended",
                    );
                } else {
                    let (_, lv) = self.analyze_lvalue(x);
                    self.plain_write(&lv, x.span, &xty);
                }
                Ty::Plain(PlainTy::Unit)
            }
            Tuple(els) => {
                let mut tys = Vec::new();
                for el in els.iter() {
                    if let Some(el) = el.as_ref().unspan() {
                        tys.push(self.type_expr(el));
                    } else {
                        tys.push(Ty::Unknown);
                    }
                }
                if tys.len() == 1 {
                    tys.pop().expect("one element")
                } else {
                    Ty::Plain(PlainTy::Opaque)
                }
            }
            Array(els) => {
                for el in els.iter() {
                    self.type_expr(el);
                }
                Ty::Plain(PlainTy::Opaque)
            }
            Payable(args) => {
                for a in args.exprs() {
                    self.type_expr(a);
                }
                Ty::Plain(PlainTy::Address)
            }
            New(_) => Ty::Unknown,
            TypeCall(_) => Ty::Plain(PlainTy::Opaque),
            Type(t) => match &t.kind {
                ast::TypeKind::Elementary(el) => Ty::Plain(elementary(*el)),
                _ => Ty::Plain(PlainTy::Opaque),
            },
            Err(_) => Ty::Unknown,
        };
        self.rec(e.span, ty)
    }

    fn lit_ty(&self, lit: &ast::Lit<'_>) -> Ty {
        match &lit.kind {
            ast::LitKind::Number(v) => Ty::Plain(PlainTy::NumLit {
                value: u128::try_from(*v).ok(),
            }),
            ast::LitKind::Bool(_) => Ty::Plain(PlainTy::Bool),
            ast::LitKind::Address(_) => Ty::Plain(PlainTy::Address),
            _ => Ty::Plain(PlainTy::Opaque),
        }
    }

    pub(crate) fn ident_ty(&mut self, id: solar_interface::Ident) -> Ty {
        let Some(res) = self.unit.resolve(id).cloned() else {
            return Ty::Unknown;
        };
        match &res {
            Resolution::Local(_) | Resolution::Param(_) => {
                self.note_read(id.as_str(), id.span);
                self.var_decl_ty(&res)
                    .map(|(t, _)| t)
                    .unwrap_or(Ty::Unknown)
            }
            Resolution::StateVar(_) | Resolution::FileConst(_) => self
                .var_decl_ty(&res)
                .map(|(t, _)| t)
                .unwrap_or(Ty::Unknown),
            Resolution::Function(_) => Ty::Plain(PlainTy::Opaque),
            Resolution::Contract(c) => Ty::Plain(PlainTy::ContractRef(*c)),
            Resolution::TypeName(td) => match &self.unit.type_decl(*td).kind {
                TypeDeclKind::Udvt(_) => {
                    match custom_ty(self.unit, self.trust, id.as_str(), &res) {
                        Ty::Encrypted(t) => Ty::Plain(PlainTy::EncTypeRef(t)),
                        _ => Ty::Plain(PlainTy::Opaque),
                    }
                }
                _ => Ty::Plain(PlainTy::TypeRef(*td)),
            },
            Resolution::Builtin(b) => Ty::Plain(PlainTy::BuiltinRef(b.0)),
            Resolution::Event(_) | Resolution::Error(_) => Ty::Plain(PlainTy::Opaque),
            Resolution::Namespace(_) => Ty::Plain(PlainTy::Opaque),
            Resolution::External { .. } | Resolution::Unresolved(_) => {
                let name = id.as_str();
                if self.trust.is_fhe_library(self.unit, name, &res) {
                    Ty::Plain(PlainTy::FheLib)
                } else if let Some(t) = self.trust.encrypted_type(self.unit, name, &res) {
                    Ty::Plain(PlainTy::EncTypeRef(t))
                } else {
                    Ty::Unknown
                }
            }
        }
    }

    fn member_ty(&mut self, obj: &'ast ast::Expr<'ast>, name: solar_interface::Ident) -> Ty {
        let obj_ty = self.type_expr(obj);
        let n = name.as_str();
        match &obj_ty {
            Ty::Plain(PlainTy::FheLib) => Ty::Plain(PlainTy::FheFn(n.to_string())),
            Ty::Encrypted(t) => Ty::Plain(PlainTy::MethodRef(*t, n.to_string())),
            Ty::Plain(PlainTy::Struct(td)) => {
                if let TypeDeclKind::Struct(s) = &self.unit.type_decl(*td).kind {
                    for field in s.fields.iter() {
                        if field.name.is_some_and(|f| f.as_str() == n) {
                            return declared_ty(self.unit, self.trust, &field.ty);
                        }
                    }
                }
                Ty::Unknown
            }
            // External-input handles are UDVTs: no member access we model.
            Ty::Plain(PlainTy::ExternalInput(_)) => Ty::Unknown,
            Ty::Plain(PlainTy::Array(_)) if n == "length" => Ty::Plain(PlainTy::Uint(256)),
            Ty::Plain(PlainTy::BuiltinRef(b)) => match (*b, n) {
                ("msg", "sender") => Ty::Plain(PlainTy::Address),
                ("msg", "value") => Ty::Plain(PlainTy::Uint(256)),
                ("msg", "data") => Ty::Plain(PlainTy::Bytes),
                ("block", "timestamp" | "number" | "gaslimit" | "basefee" | "chainid") => {
                    Ty::Plain(PlainTy::Uint(256))
                }
                ("block", "coinbase") => Ty::Plain(PlainTy::Address),
                ("tx", "origin") => Ty::Plain(PlainTy::Address),
                ("tx", "gasprice") => Ty::Plain(PlainTy::Uint(256)),
                _ => Ty::Plain(PlainTy::Opaque),
            },
            Ty::Plain(PlainTy::TypeRef(td)) => {
                if matches!(self.unit.type_decl(*td).kind, TypeDeclKind::Enum(_)) {
                    Ty::Plain(PlainTy::Enum(*td))
                } else {
                    Ty::Plain(PlainTy::Opaque)
                }
            }
            _ => Ty::Unknown,
        }
    }

    fn index(&mut self, base: &'ast ast::Expr<'ast>, kind: &'ast ast::IndexKind<'ast>) -> Ty {
        let base_ty = self.type_expr(base);
        match kind {
            ast::IndexKind::Index(Some(k)) => {
                let kty = self.type_expr(k);
                if kty.is_encrypted() {
                    self.error(
                        codes::ENCRYPTED_INDEX,
                        k.span,
                        "an encrypted value cannot index an array or mapping: the \
                         access pattern would leak the ciphertext",
                    );
                }
                match base_ty {
                    Ty::Plain(PlainTy::Mapping(_, v)) => *v,
                    Ty::Plain(PlainTy::Array(el)) => *el,
                    _ => Ty::Unknown,
                }
            }
            ast::IndexKind::Index(None) => Ty::Unknown,
            ast::IndexKind::Range(a, b) => {
                if let Some(a) = a {
                    self.type_expr(a);
                }
                if let Some(b) = b {
                    self.type_expr(b);
                }
                Ty::Plain(PlainTy::Opaque)
            }
        }
    }

    // ---- calls -----------------------------------------------------------

    fn call(
        &mut self,
        e: &'ast ast::Expr<'ast>,
        callee: &'ast ast::Expr<'ast>,
        args: &'ast ast::CallArgs<'ast>,
    ) -> Ty {
        // Peel call options (`x.f{gas: 1}(...)`) down to the real callee.
        let mut callee = callee.peel_parens();
        while let ast::ExprKind::CallOptions(inner, opts) = &callee.kind {
            for o in opts.iter() {
                self.type_expr(&*o.value);
            }
            callee = inner.peel_parens();
        }

        let mut arg_tys: Vec<(Span, Ty)> = Vec::new();
        let mut type_args = |chk: &mut Self| {
            for a in args.exprs() {
                let t = chk.type_expr(a);
                arg_tys.push((a.span, t));
            }
        };

        // Elementary casts: `uint32(x)`, `address(x)`.
        if let ast::ExprKind::Type(t) = &callee.kind {
            type_args(self);
            return match &t.kind {
                ast::TypeKind::Elementary(el) => Ty::Plain(elementary(*el)),
                _ => Ty::Unknown,
            };
        }

        let (class, result) = self.classify_call(callee, args, &mut type_args);

        match &class {
            CallClass::External {
                callee_span,
                callee_is_ident,
            } => {
                if self.branch_depth > 0 {
                    self.error(
                        codes::EXTERNAL_CALL_IN_BRANCH,
                        e.span,
                        "external calls cannot appear inside an encrypted branch: both \
                         branches always execute (hoist the call out of the `if`)",
                    );
                } else {
                    let enc_args: Vec<(Span, EType)> = arg_tys
                        .iter()
                        .filter_map(|(sp, t)| t.etype().map(|et| (*sp, et)))
                        .collect();
                    if !enc_args.is_empty() {
                        for (sp, _) in &enc_args {
                            self.flag_uninit_in(
                                *sp,
                                "as an encrypted argument to an external call",
                            );
                        }
                        let fact = EncryptedArgCall {
                            call_span: e.span,
                            stmt_span: self.current_stmt_span,
                            callee_span: *callee_span,
                            callee_is_ident: *callee_is_ident,
                            args: enc_args,
                            function: self.fid,
                            file: self.file,
                        };
                        self.out.acl.external_args.push(fact);
                    }
                }
            }
            CallClass::Internal(fids) => {
                if self.branch_depth > 0 {
                    let safe = fids.iter().all(|f| self.branch_safe(*f));
                    if !safe {
                        self.error(
                            codes::UNVERIFIED_CALL_IN_BRANCH,
                            e.span,
                            "only profile FHE calls and same-contract functions the \
                             checker has verified branch-safe may be called inside an \
                             encrypted branch",
                        );
                    }
                }
            }
            CallClass::Opaque => {
                if self.branch_depth > 0 {
                    self.error(
                        codes::UNVERIFIED_CALL_IN_BRANCH,
                        e.span,
                        "this call cannot be verified branch-safe; only profile FHE \
                         calls and verified same-contract functions may be called \
                         inside an encrypted branch",
                    );
                }
            }
            CallClass::Fhe | CallClass::Builtin => {}
        }

        result
    }

    /// Classifies the callee and computes the call's result type. `type_args`
    /// is invoked exactly once (argument evaluation order).
    fn classify_call(
        &mut self,
        callee: &'ast ast::Expr<'ast>,
        args: &'ast ast::CallArgs<'ast>,
        type_args: &mut dyn FnMut(&mut Self),
    ) -> (CallClass, Ty) {
        match &callee.kind {
            ast::ExprKind::Member(obj, mname) => {
                let obj_ty = self.type_expr(obj);
                let n = mname.as_str();
                type_args(self);
                let arg_etys: Vec<Option<EType>> = args
                    .exprs()
                    .map(|a| self.out.types.get(a.span).and_then(|t| t.etype()))
                    .collect();
                match &obj_ty {
                    Ty::Plain(PlainTy::FheLib) => {
                        let res = self.fhe_call_result(None, n, &arg_etys);
                        (CallClass::Fhe, res)
                    }
                    Ty::Encrypted(t) => {
                        if let Some(res) = self.profile_method_result(*t, n, &arg_etys) {
                            (CallClass::Fhe, res)
                        } else {
                            // An in-unit `using` binding, or unknown.
                            let m = self.unit.method_candidates(
                                self.contract,
                                self.file,
                                t.solidity_name(),
                                mname.name,
                            );
                            match m {
                                MethodResolution::Functions(fids) => {
                                    let ret = self.common_return_ty(&fids);
                                    (CallClass::Internal(fids), ret)
                                }
                                _ => (CallClass::Opaque, Ty::Unknown),
                            }
                        }
                    }
                    Ty::Plain(PlainTy::EncTypeRef(t)) => match n {
                        "wrap" => (CallClass::Builtin, Ty::Encrypted(*t)),
                        "unwrap" => (CallClass::Builtin, Ty::Plain(PlainTy::FixedBytes(32))),
                        _ => (CallClass::Opaque, Ty::Unknown),
                    },
                    Ty::Plain(PlainTy::ContractRef(c)) => {
                        // Static member call: library or base-contract scope.
                        let fid = self.unit.function_by_name(*c, n);
                        match fid {
                            Some(f) => {
                                let ret = self.common_return_ty(&[f]);
                                (CallClass::Internal(vec![f]), ret)
                            }
                            None => (CallClass::Opaque, Ty::Unknown),
                        }
                    }
                    Ty::Plain(PlainTy::ContractInstance(_)) => (
                        CallClass::External {
                            callee_span: obj.span,
                            callee_is_ident: matches!(
                                obj.peel_parens().kind,
                                ast::ExprKind::Ident(_)
                            ),
                        },
                        Ty::Unknown,
                    ),
                    Ty::Plain(PlainTy::Address)
                        if matches!(
                            n,
                            "transfer" | "send" | "call" | "delegatecall" | "staticcall"
                        ) =>
                    {
                        (
                            CallClass::External {
                                callee_span: obj.span,
                                callee_is_ident: matches!(
                                    obj.peel_parens().kind,
                                    ast::ExprKind::Ident(_)
                                ),
                            },
                            Ty::Unknown,
                        )
                    }
                    Ty::Plain(PlainTy::BuiltinRef("this")) => (
                        CallClass::External {
                            callee_span: obj.span,
                            callee_is_ident: true,
                        },
                        Ty::Unknown,
                    ),
                    Ty::Plain(PlainTy::BuiltinRef("abi" | "super")) => {
                        (CallClass::Builtin, Ty::Unknown)
                    }
                    _ => (CallClass::Opaque, Ty::Unknown),
                }
            }
            ast::ExprKind::Ident(id) => {
                let res = self.unit.resolve(*id).cloned();
                type_args(self);
                match res {
                    Some(Resolution::Builtin(b)) => {
                        let name = b.0;
                        if matches!(name, "require" | "assert") {
                            if let Some(first) = args.exprs().next() {
                                if self.out.types.get(first.span)
                                    == Some(&Ty::Encrypted(EType::Ebool))
                                {
                                    self.error(
                                        codes::EBOOL_AS_BOOL,
                                        first.span,
                                        format!(
                                            "`{name}` requires a plaintext `bool`; an \
                                             `ebool` cannot be inspected synchronously"
                                        ),
                                    );
                                }
                            }
                        }
                        if matches!(name, "require" | "assert" | "revert" | "selfdestruct")
                            && self.branch_depth > 0
                        {
                            self.error(
                                codes::REVERT_IN_BRANCH,
                                callee.span,
                                format!(
                                    "`{name}` cannot appear inside an encrypted branch: \
                                     encrypted conditions cannot revert"
                                ),
                            );
                        }
                        let ret = match name {
                            "keccak256" | "sha256" | "blockhash" | "blobhash" => {
                                Ty::Plain(PlainTy::FixedBytes(32))
                            }
                            "ripemd160" => Ty::Plain(PlainTy::FixedBytes(20)),
                            "ecrecover" => Ty::Plain(PlainTy::Address),
                            "addmod" | "mulmod" | "gasleft" => Ty::Plain(PlainTy::Uint(256)),
                            "require" | "assert" | "revert" | "selfdestruct" => {
                                Ty::Plain(PlainTy::Unit)
                            }
                            _ => Ty::Plain(PlainTy::Opaque),
                        };
                        (CallClass::Builtin, ret)
                    }
                    Some(Resolution::Function(fids)) => {
                        let ret = self.common_return_ty(&fids);
                        (CallClass::Internal(fids), ret)
                    }
                    Some(Resolution::Contract(c)) => {
                        // A contract cast: `IERC20(addr)`.
                        (CallClass::Builtin, Ty::Plain(PlainTy::ContractInstance(c)))
                    }
                    Some(Resolution::TypeName(td)) => match &self.unit.type_decl(td).kind {
                        TypeDeclKind::Struct(_) => {
                            (CallClass::Builtin, Ty::Plain(PlainTy::Struct(td)))
                        }
                        TypeDeclKind::Enum(_) => (CallClass::Builtin, Ty::Plain(PlainTy::Enum(td))),
                        TypeDeclKind::Udvt(_) => {
                            let r = Resolution::TypeName(td);
                            match self.trust.encrypted_type(self.unit, id.as_str(), &r) {
                                // `eT(x)` explicit cast sugar (spec §2.9).
                                Some(t) => (CallClass::Fhe, self.cast_sugar_call(callee, args, t)),
                                None => (CallClass::Builtin, Ty::Unknown),
                            }
                        }
                    },
                    Some(r @ (Resolution::External { .. } | Resolution::Unresolved(_))) => {
                        match self.trust.encrypted_type(self.unit, id.as_str(), &r) {
                            // `eT(x)` explicit cast sugar (spec §2.9).
                            Some(t) => (CallClass::Fhe, self.cast_sugar_call(callee, args, t)),
                            None => (CallClass::Opaque, Ty::Unknown),
                        }
                    }
                    _ => (CallClass::Opaque, Ty::Unknown),
                }
            }
            _ => {
                self.type_expr(callee);
                type_args(self);
                (CallClass::Opaque, Ty::Unknown)
            }
        }
    }

    /// Handles the bare-cast-sugar callee shape `eT(x)` (spec §2.9): `callee`
    /// already resolved to the trusted encrypted type `ty`. Requires exactly
    /// one argument (else FHE1018) and, on success, states a
    /// [`CastSugarSite`] for the lowerer — the argument itself gets exactly
    /// the type-checking an author-written `FHE.as<T>(x)` call already gets
    /// (arguments are typed by the caller's `type_args`, before this runs).
    fn cast_sugar_call(
        &mut self,
        callee: &'ast ast::Expr<'ast>,
        args: &'ast ast::CallArgs<'ast>,
        ty: EType,
    ) -> Ty {
        if args.exprs().count() != 1 {
            self.out.diagnostics.push(
                Diagnostic::error(
                    codes::CAST_SUGAR_BAD_ARITY,
                    callee.span.to(args.span),
                    "explicit cast sugar (`eT(...)`) called with a number of \
                     arguments other than one",
                )
                .with_rule("§2.9"),
            );
            return Ty::Unknown;
        }
        self.out.cast_sugar_sites.push(CastSugarSite {
            call_span: callee.span.to(args.span),
            callee_span: callee.span,
            ty,
            function: self.fid,
            file: self.file,
        });
        Ty::Encrypted(ty)
    }

    /// Result type of `FHE.<name>(...)` (or `None`-receiver profile lookups).
    fn fhe_call_result(
        &mut self,
        receiver: Option<EType>,
        name: &str,
        arg_etys: &[Option<EType>],
    ) -> Ty {
        if let Some(target) = cast_target_by_name(name) {
            return Ty::Encrypted(target);
        }
        let Some(op) = op_by_name(name) else {
            return Ty::Unknown;
        };
        let mut operands: Vec<EType> = Vec::new();
        if let Some(r) = receiver {
            operands.push(r);
        }
        match op {
            FheOp::AllowTransient => {
                // [handle, account]: only the handle is encrypted.
                if let Some(Some(t)) = arg_etys.first() {
                    operands.push(*t);
                } else if receiver.is_none() {
                    return Ty::Unknown;
                }
            }
            _ => {
                for t in arg_etys {
                    match t {
                        Some(t) => operands.push(*t),
                        // A non-encrypted argument to a profile op: not a
                        // combination we model — leave it to solc.
                        None => return Ty::Unknown,
                    }
                }
            }
        }
        match self.profile.result_type(op, &operands) {
            Ok(Some(t)) => Ty::Encrypted(t),
            Ok(None) => Ty::Plain(PlainTy::Unit),
            // An existing call the pinned profile lacks: solc's business
            // (we emit FHE5001 only for operations *we* would emit).
            Err(_) => Ty::Unknown,
        }
    }

    /// Result of `a.<name>(...)` with encrypted receiver via the profile.
    fn profile_method_result(
        &mut self,
        receiver: EType,
        name: &str,
        arg_etys: &[Option<EType>],
    ) -> Option<Ty> {
        if cast_target_by_name(name).is_some() || op_by_name(name).is_some() {
            let t = self.fhe_call_result(Some(receiver), name, arg_etys);
            // Casts: `x.asEuint64()` — receiver-only.
            Some(t)
        } else {
            None
        }
    }

    /// The declared return type shared by all candidates (single return
    /// value), or `Unknown`.
    ///
    /// A `shared(...)` return (§2.8) is always `Unknown` at a call site. The
    /// declaration names the *plaintext-side* encrypted type `eT`, but the
    /// value the call actually yields is the profile's `sharedT` wire handle,
    /// which no rewrite of this checker understands. The binder resolves such
    /// a return type so the shared-return statement rule can compare against
    /// it; call-site inference must not inherit that knowledge, or an operator
    /// over the result would lower to `FHE.op(sharedT, ...)` (§1.3 — refuse
    /// rather than guess).
    fn common_return_ty(&mut self, fids: &[fhec_bind::FunctionId]) -> Ty {
        let mut common: Option<Ty> = None;
        for &f in fids {
            let info = self.unit.function(f);
            let rets = info.ast.header.returns();
            if rets.len() != 1 || rets[0].shared.is_some() {
                return Ty::Unknown;
            }
            let t = declared_ty(self.unit, self.trust, &rets[0].ty);
            match &common {
                None => common = Some(t),
                Some(c) if *c == t => {}
                Some(_) => return Ty::Unknown,
            }
        }
        common.unwrap_or(Ty::Unknown)
    }

    /// Recursive branch-safety verification of an in-unit callee (spec §7.1
    /// FHE3008). Conservative: yes only when every construct is provably
    /// effect-free with respect to state, reverts, events, and calls.
    fn branch_safe(&mut self, fid: fhec_bind::FunctionId) -> bool {
        if let Some(&v) = self.safe_cache.get(&fid) {
            return v;
        }
        // Cycle guard: treat in-progress as unsafe.
        self.safe_cache.insert(fid, false);
        let info = self.unit.function(fid);
        // Same-contract restriction (spec §7.1): the callee must be the
        // current contract's own or inherited function, or an in-unit
        // library function reached via qualified call — v1 verifies only
        // same-contract-or-base functions.
        let same_contract = match (self.contract, info.contract) {
            (Some(cur), Some(callee_c)) => {
                cur == callee_c || self.unit.linearization(cur).order.contains(&callee_c)
            }
            _ => false,
        };
        let verdict = same_contract
            && info.ast.header.modifiers.is_empty()
            && match &info.ast.body {
                Some(body) => body.stmts.iter().all(|s| self.stmt_branch_safe(s)),
                None => false,
            };
        self.safe_cache.insert(fid, verdict);
        verdict
    }

    fn stmt_branch_safe(&mut self, s: &ast::Stmt<'ast>) -> bool {
        use ast::StmtKind::*;
        match &s.kind {
            DeclSingle(v) => v
                .initializer
                .as_ref()
                .is_none_or(|e| self.expr_branch_safe(e)),
            DeclMulti(_, rhs) => self.expr_branch_safe(rhs),
            Block(b) | UncheckedBlock(b) => b.stmts.iter().all(|s| self.stmt_branch_safe(s)),
            // A `precondition` block (spec §2.7) is never legal in a callee
            // reached from an encrypted branch, and proving it harmless would
            // be a guess: refuse (spec §1.3).
            Precondition(_) => false,
            Break | Continue | Placeholder => true,
            Return(e) => e.as_ref().is_none_or(|e| self.expr_branch_safe(e)),
            Expr(e) => self.expr_branch_safe(e),
            If(c, t, e) => {
                self.expr_branch_safe(c)
                    && self.stmt_branch_safe(t)
                    && e.as_ref().is_none_or(|e| self.stmt_branch_safe(e))
            }
            While(c, b) => self.expr_branch_safe(c) && self.stmt_branch_safe(b),
            DoWhile(b, c) => self.stmt_branch_safe(b) && self.expr_branch_safe(c),
            For {
                init,
                cond,
                next,
                body,
            } => {
                init.as_ref().is_none_or(|s| self.stmt_branch_safe(s))
                    && cond.as_ref().is_none_or(|e| self.expr_branch_safe(e))
                    && next.as_ref().is_none_or(|e| self.expr_branch_safe(e))
                    && self.stmt_branch_safe(body)
            }
            Emit(..) | Revert(..) | Assembly(_) | Try(_) => false,
        }
    }

    fn expr_branch_safe(&mut self, e: &ast::Expr<'ast>) -> bool {
        use ast::ExprKind::*;
        match &e.kind {
            Assign(lhs, _, rhs) => {
                // Writes to state are never branch-safe; local writes are.
                let root_is_state = self.lvalue_root_is_state(lhs);
                !root_is_state && self.expr_branch_safe(lhs) && self.expr_branch_safe(rhs)
            }
            Delete(x) => !self.lvalue_root_is_state(x) && self.expr_branch_safe(x),
            Unary(op, x) => {
                if op.kind.has_side_effects() && self.lvalue_root_is_state(x) {
                    return false;
                }
                self.expr_branch_safe(x)
            }
            Call(callee, args) => {
                let callee_ok = match &callee.peel_parens().kind {
                    Member(obj, mname) => {
                        let obj_p = obj.peel_parens();
                        let is_fhe_lib = match &obj_p.kind {
                            Ident(id) => self.unit.resolve(*id).is_some_and(|r| {
                                self.trust.is_fhe_library(self.unit, id.as_str(), r)
                            }),
                            _ => false,
                        };
                        is_fhe_lib
                            || op_by_name(mname.as_str()).is_some()
                            || cast_target_by_name(mname.as_str()).is_some()
                            || matches!(mname.as_str(), "wrap" | "unwrap")
                    }
                    Ident(id) => match self.unit.resolve(*id) {
                        Some(Resolution::Function(fids)) => {
                            let fids = fids.clone();
                            fids.iter().all(|f| self.branch_safe(*f))
                        }
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
                        _ => false,
                    },
                    Type(_) => true,
                    _ => false,
                };
                callee_ok
                    && self.expr_branch_safe(callee)
                    && args.exprs().all(|a| self.expr_branch_safe(a))
            }
            CallOptions(..) | New(_) => false,
            Binary(l, _, r) => self.expr_branch_safe(l) && self.expr_branch_safe(r),
            Ternary(c, a, b) => {
                self.expr_branch_safe(c) && self.expr_branch_safe(a) && self.expr_branch_safe(b)
            }
            Tuple(els) => els.iter().all(|el| {
                el.as_ref()
                    .unspan()
                    .is_none_or(|e| self.expr_branch_safe(e))
            }),
            Array(els) => els.iter().all(|e| self.expr_branch_safe(e)),
            Index(base, kind) => {
                self.expr_branch_safe(base)
                    && match kind {
                        ast::IndexKind::Index(i) => {
                            i.as_ref().is_none_or(|e| self.expr_branch_safe(e))
                        }
                        ast::IndexKind::Range(a, b) => {
                            a.as_ref().is_none_or(|e| self.expr_branch_safe(e))
                                && b.as_ref().is_none_or(|e| self.expr_branch_safe(e))
                        }
                    }
            }
            Member(obj, _) => self.expr_branch_safe(obj),
            Payable(args) => args.exprs().all(|a| self.expr_branch_safe(a)),
            Lit(..) | Ident(_) | Type(_) | TypeCall(_) | Err(_) => true,
        }
    }

    fn lvalue_root_is_state(&self, e: &ast::Expr<'ast>) -> bool {
        match &e.peel_parens().kind {
            ast::ExprKind::Ident(id) => matches!(
                self.unit.resolve(*id),
                Some(Resolution::StateVar(_)) | None | Some(Resolution::Unresolved(_))
            ),
            ast::ExprKind::Index(base, _) => self.lvalue_root_is_state(base),
            ast::ExprKind::Member(base, _) => self.lvalue_root_is_state(base),
            _ => false,
        }
    }
}
