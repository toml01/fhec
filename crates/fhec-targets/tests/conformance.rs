//! Conformance of the CoFHE profile against the spec §4 operator table and
//! the FHE.sol ground truth.

use fhec_ir::{EType, EWidth, FheOp};
use fhec_targets::{CofheProfile, ProfileError, TargetProfile};

const EBOOL: EType = EType::Ebool;
const EADDR: EType = EType::Eaddress;

fn euints() -> impl Iterator<Item = EType> {
    EWidth::ALL.into_iter().map(EType::Euint)
}

/// Spec §4.1: every operator row must render for every euint width.
#[test]
fn euint_op_completeness() {
    let profile = CofheProfile::v0_2();

    let same_result = [
        FheOp::Add,
        FheOp::Sub,
        FheOp::Mul,
        FheOp::Div,
        FheOp::Rem,
        FheOp::And,
        FheOp::Or,
        FheOp::Xor,
        FheOp::Shl,
        FheOp::Shr,
        FheOp::Min,
        FheOp::Max,
    ];
    let ebool_result = [
        FheOp::Eq,
        FheOp::Ne,
        FheOp::Lt,
        FheOp::Lte,
        FheOp::Gt,
        FheOp::Gte,
    ];

    for t in euints() {
        for op in same_result {
            assert_eq!(profile.result_type(op, &[t, t]), Ok(Some(t)), "{op} on {t}");
            assert!(profile.render_call(op, &[t, t], &["a", "b"]).is_ok());
        }
        for op in ebool_result {
            assert_eq!(
                profile.result_type(op, &[t, t]),
                Ok(Some(EBOOL)),
                "{op} on {t}"
            );
        }
        assert_eq!(profile.result_type(FheOp::Not, &[t]), Ok(Some(t)));
        assert_eq!(
            profile.result_type(FheOp::Select, &[EBOOL, t, t]),
            Ok(Some(t))
        );
    }
}

/// Spec §4.1: ebool supports the logical family, eq/ne, and select — and
/// nothing arithmetic or ordered.
#[test]
fn ebool_op_surface() {
    let profile = CofheProfile::v0_2();

    for op in [FheOp::And, FheOp::Or, FheOp::Xor, FheOp::Eq, FheOp::Ne] {
        assert_eq!(profile.result_type(op, &[EBOOL, EBOOL]), Ok(Some(EBOOL)));
    }
    assert_eq!(profile.result_type(FheOp::Not, &[EBOOL]), Ok(Some(EBOOL)));
    assert_eq!(
        profile.result_type(FheOp::Select, &[EBOOL, EBOOL, EBOOL]),
        Ok(Some(EBOOL))
    );

    for op in [FheOp::Add, FheOp::Lt, FheOp::Shl, FheOp::Min] {
        assert!(
            matches!(
                profile.result_type(op, &[EBOOL, EBOOL]),
                Err(ProfileError::Unsupported { .. })
            ),
            "{op} must be unsupported on ebool"
        );
    }
}

/// Spec §4.1: eaddress supports only eq, ne, and select arms.
#[test]
fn eaddress_op_surface() {
    let profile = CofheProfile::v0_2();

    for op in [FheOp::Eq, FheOp::Ne] {
        assert_eq!(profile.result_type(op, &[EADDR, EADDR]), Ok(Some(EBOOL)));
    }
    assert_eq!(
        profile.result_type(FheOp::Select, &[EBOOL, EADDR, EADDR]),
        Ok(Some(EADDR))
    );

    // The typed Unsupported error is what the checker maps to FHE5001.
    let err = profile
        .result_type(FheOp::Add, &[EADDR, EADDR])
        .unwrap_err();
    assert_eq!(
        err,
        ProfileError::Unsupported {
            op: FheOp::Add,
            operands: vec![EADDR, EADDR],
        }
    );
    for op in [FheOp::Lt, FheOp::And, FheOp::Not, FheOp::Shl] {
        let operands: &[EType] = if op == FheOp::Not {
            &[EADDR]
        } else {
            &[EADDR, EADDR]
        };
        assert!(
            matches!(
                profile.result_type(op, operands),
                Err(ProfileError::Unsupported { .. })
            ),
            "{op} must be unsupported on eaddress"
        );
    }
}

/// ACL operations exist for all seven encrypted types and are void.
#[test]
fn acl_ops_all_types() {
    let profile = CofheProfile::v0_2();
    for t in EType::ALL {
        for op in [FheOp::AllowThis, FheOp::AllowSender, FheOp::AllowGlobal] {
            assert_eq!(profile.result_type(op, &[t]), Ok(None), "{op} on {t}");
        }
        assert_eq!(profile.result_type(FheOp::AllowTransient, &[t]), Ok(None));
    }
    assert_eq!(
        profile.acl_fn_name(FheOp::AllowThis),
        Some("allowThis".to_string())
    );
    assert_eq!(
        profile.acl_fn_name(FheOp::AllowTransient),
        Some("allowTransient".to_string())
    );
    assert_eq!(profile.acl_fn_name(FheOp::Add), None);
}

/// Rendered call snapshots (real CoFHE spelling, library-qualified).
#[test]
fn render_snapshots() {
    let profile = CofheProfile::v0_2();
    let e32 = EType::Euint(EWidth::W32);

    assert_eq!(
        profile
            .render_call(FheOp::Add, &[e32, e32], &["count", "FHE.asEuint32(1)"])
            .unwrap(),
        "FHE.add(count, FHE.asEuint32(1))"
    );
    assert_eq!(
        profile
            .render_call(
                FheOp::Select,
                &[EBOOL, e32, e32],
                &["__fhe_cond_0", "__fhe_then_1", "__fhe_pre_2"],
            )
            .unwrap(),
        "FHE.select(__fhe_cond_0, __fhe_then_1, __fhe_pre_2)"
    );
    assert_eq!(
        profile
            .render_call(FheOp::AllowThis, &[e32], &["count"])
            .unwrap(),
        "FHE.allowThis(count)"
    );
    assert_eq!(
        profile
            .render_call(FheOp::AllowTransient, &[e32], &["ret", "msg.sender"])
            .unwrap(),
        "FHE.allowTransient(ret, msg.sender)"
    );
    assert_eq!(
        profile
            .render_call(FheOp::TrivialEncrypt { to: e32 }, &[], &["1"])
            .unwrap(),
        "FHE.asEuint32(1)"
    );
    assert_eq!(
        profile
            .render_call(
                FheOp::FromExternal { ty: e32 },
                &[],
                &["newCount_input", "inputProof"]
            )
            .unwrap(),
        "FHE.asEuint32(newCount_input, inputProof)"
    );
    assert_eq!(
        profile
            .render_call(
                FheOp::Widen {
                    from: EWidth::W8,
                    to: EWidth::W128,
                },
                &[EType::Euint(EWidth::W8)],
                &["x"],
            )
            .unwrap(),
        "FHE.asEuint128(x)"
    );
}

/// Mixed-width operands are a profile-level mismatch: the checker must
/// widen first (spec §3.3 rule 3); the profile never widens silently.
#[test]
fn mixed_width_is_rejected() {
    let profile = CofheProfile::v0_2();
    let e8 = EType::Euint(EWidth::W8);
    let e32 = EType::Euint(EWidth::W32);
    assert!(matches!(
        profile.result_type(FheOp::Add, &[e8, e32]),
        Err(ProfileError::Unsupported { .. })
    ));
    // Shift amounts too (spec §4.3: both operands the same width).
    assert!(matches!(
        profile.result_type(FheOp::Shl, &[e32, e8]),
        Err(ProfileError::Unsupported { .. })
    ));
}

/// Narrowing or same-width "widening" is not a widen.
#[test]
fn widen_direction_is_enforced() {
    let profile = CofheProfile::v0_2();
    let ok = FheOp::Widen {
        from: EWidth::W16,
        to: EWidth::W64,
    };
    assert_eq!(
        profile.result_type(ok, &[EType::Euint(EWidth::W16)]),
        Ok(Some(EType::Euint(EWidth::W64)))
    );

    let narrow = FheOp::Widen {
        from: EWidth::W64,
        to: EWidth::W16,
    };
    assert!(matches!(
        profile.result_type(narrow, &[EType::Euint(EWidth::W64)]),
        Err(ProfileError::Unsupported { .. })
    ));

    let same = FheOp::Widen {
        from: EWidth::W32,
        to: EWidth::W32,
    };
    assert!(matches!(
        profile.result_type(same, &[EType::Euint(EWidth::W32)]),
        Err(ProfileError::Unsupported { .. })
    ));
}

/// Arity misuse is a typed caller error, distinct from Unsupported.
#[test]
fn wrong_arity_is_typed() {
    let profile = CofheProfile::v0_2();
    let e32 = EType::Euint(EWidth::W32);

    let err = profile
        .render_call(FheOp::Add, &[e32, e32], &["a"])
        .unwrap_err();
    assert_eq!(
        err,
        ProfileError::WrongArity {
            op: FheOp::Add,
            expected: 2,
            got: 1,
        }
    );

    let err = profile
        .result_type(FheOp::Select, &[EBOOL, e32])
        .unwrap_err();
    assert_eq!(
        err,
        ProfileError::WrongArity {
            op: FheOp::Select,
            expected: 3,
            got: 2,
        }
    );
}

/// The cast matrix from FHE.sol: casts to eaddress do not exist; self-casts
/// do not exist; everything else does.
#[test]
fn cast_matrix() {
    let profile = CofheProfile::v0_2();
    for from in EType::ALL {
        for to in EType::ALL {
            let expected = from != to && to != EADDR;
            assert_eq!(
                profile.can_cast(from, to),
                expected,
                "can_cast({from}, {to})"
            );
        }
    }
}

/// Profile metadata matches the pinned checkout.
#[test]
fn profile_metadata() {
    let profile = CofheProfile::v0_2();
    assert_eq!(profile.id(), "cofhe");
    assert_eq!(profile.version(), "0.2.x");
    assert_eq!(profile.pragma_range(), ">=0.8.25 <0.9.0");
    assert_eq!(
        profile.import_lines(),
        vec!["import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";".to_string()]
    );
    assert!(!profile.capabilities().has_decrypt);
    assert_eq!(
        profile.external_input_type(EType::Euint(EWidth::W32)),
        "externalEuint32"
    );
    assert_eq!(profile.input_proof_param(), "bytes memory inputProof");
    assert_eq!(profile.conversion_fn(EType::Eaddress), "FHE.asEaddress");
    assert_eq!(profile.conversion_fn(EBOOL), "FHE.asEbool");
}

/// The multi-parameter batch prelude matches FHE.sol's batch-verification
/// API: one array, one verification call, one wrap per input.
#[test]
fn batch_input_statements_shape() {
    let profile = CofheProfile::v0_2();
    let stmts = profile.batch_input_statements(
        &[
            (EBOOL, "flag_input", "flag"),
            (EType::Euint(EWidth::W64), "amount_input", "amount"),
        ],
        "inputProof",
        "__fhe_inputs_0",
        "__fhe_hashes_1",
    );
    assert_eq!(
        stmts,
        vec![
            "UnsignedEncryptedInput[] memory __fhe_inputs_0 = new UnsignedEncryptedInput[](2);"
                .to_string(),
            "__fhe_inputs_0[0] = UnsignedEncryptedInput(uint256(externalEbool.unwrap(flag_input)), 0, Utils.EBOOL_TFHE);"
                .to_string(),
            "__fhe_inputs_0[1] = UnsignedEncryptedInput(uint256(externalEuint64.unwrap(amount_input)), 0, Utils.EUINT64_TFHE);"
                .to_string(),
            "bytes32[] memory __fhe_hashes_1 = Impl.verifyBatchInputs(__fhe_inputs_0, inputProof);"
                .to_string(),
            "ebool flag = ebool.wrap(__fhe_hashes_1[0]);".to_string(),
            "euint64 amount = euint64.wrap(__fhe_hashes_1[1]);".to_string(),
        ]
    );
}

/// Select requires the condition to be ebool.
#[test]
fn select_condition_must_be_ebool() {
    let profile = CofheProfile::v0_2();
    let e32 = EType::Euint(EWidth::W32);
    assert!(matches!(
        profile.result_type(FheOp::Select, &[e32, e32, e32]),
        Err(ProfileError::Unsupported { .. })
    ));
    // Mismatched arms are rejected too.
    assert!(matches!(
        profile.result_type(FheOp::Select, &[EBOOL, e32, EADDR]),
        Err(ProfileError::Unsupported { .. })
    ));
}
