//! Integration tests: parse + bind + check over inline sources, asserting
//! sites, facts, and exact diagnostic codes per spec rule.

use fhec_check::*;
use fhec_targets::CofheProfile;
use solar_parse::{
    ast,
    interface::{source_map::FileName, ColorChoice, Session},
    Parser,
};

/// Parses `sources`, binds, checks, and hands the result plus a snippet
/// function to `f`.
fn with_checked<R: Send>(
    sources: &[(&str, &str)],
    f: impl FnOnce(&CheckedUnit, &dyn Fn(solar_parse::interface::Span) -> String) -> R + Send,
) -> R {
    let sess = Session::builder()
        .with_buffer_emitter(ColorChoice::Never)
        .build();
    sess.enter(|| {
        let arena = ast::Arena::new();
        let mut files = Vec::new();
        for (name, src) in sources {
            let mut parser = Parser::from_source_code(
                &sess,
                &arena,
                FileName::Custom((*name).to_string()),
                (*src).to_string(),
            )
            .expect("source registration must succeed");
            let unit = match parser.parse_file() {
                Ok(u) => u,
                Err(e) => {
                    e.emit();
                    panic!("test source {name} must parse");
                }
            };
            let unit: &ast::SourceUnit<'_> = arena.alloc(unit);
            files.push(fhec_bind::SourceFile {
                name: (*name).to_string(),
                ast: unit,
            });
        }
        let bound = fhec_bind::bind(
            files
                .iter()
                .map(|f| fhec_bind::SourceFile {
                    name: f.name.clone(),
                    ast: f.ast,
                })
                .collect(),
        );
        assert!(
            bound.diagnostics().is_empty(),
            "bind must be clean: {:?}",
            bound.diagnostics()
        );
        let profile = CofheProfile::v0_1();
        let checked = check(&files, &bound, &profile, sess.source_map());
        let sm = sess.source_map();
        let snippet = move |span| sm.span_to_snippet(span).expect("span must resolve");
        f(&checked, &snippet)
    })
}

/// Wraps a function body in the standard test contract.
fn contract(body: &str) -> String {
    format!(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         contract C {{\n\
           euint32 a;\n\
           euint32 b;\n\
           euint8 a8;\n\
           euint64 a64;\n\
           ebool eb;\n\
           eaddress ea1;\n\
           eaddress ea2;\n\
           uint256 plainState;\n\
           bool boolState;\n\
           mapping(address => euint32) balances;\n\
           mapping(uint256 => euint32) byId;\n\
           event Ping(uint256 x);\n\
           function fhelper(euint32 x) internal returns (euint32) {{ return FHE.add(x, x); }}\n\
           function stateWriter() internal {{ plainState = 1; }}\n\
           function f(uint32 p, address addr) public {{\n{body}\n}}\n\
         }}\n"
    )
}

/// Diagnostic codes produced for a body, sorted.
fn codes_for(body: &str) -> Vec<String> {
    with_checked(&[("t.fsol", &contract(body))], |c, _| {
        let mut v: Vec<String> = c.diagnostics.iter().map(|d| d.code.to_string()).collect();
        v.sort();
        v
    })
}

fn assert_codes(body: &str, expected: &[&str]) {
    let got = codes_for(body);
    let mut want: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(got, want, "body: {body}");
}

// ---- positive typing / sites -------------------------------------------------

#[test]
fn add_site_with_exact_span() {
    with_checked(&[("t.fsol", &contract("a = a + b;"))], |c, snip| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        assert_eq!(c.operator_sites.len(), 1);
        let s = &c.operator_sites[0];
        assert_eq!(snip(s.span), "a + b");
        assert_eq!(s.op, fhec_ir::FheOp::Add);
        assert_eq!(s.result.solidity_name(), "euint32");
        assert!(matches!(
            s.operands[0].kind,
            OperandKind::AlreadyEncrypted(_)
        ));
        // The write produces an R1 fact.
        assert_eq!(c.acl.storage_writes.len(), 1);
    });
}

#[test]
fn widening_picks_the_wider_side() {
    with_checked(&[("t.fsol", &contract("a = a8 + a;"))], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        let s = &c.operator_sites[0];
        assert!(matches!(
            s.operands[0].kind,
            OperandKind::WidenEncrypted { .. }
        ));
        assert!(matches!(
            s.operands[1].kind,
            OperandKind::AlreadyEncrypted(_)
        ));
        assert_eq!(s.result.solidity_name(), "euint32");
    });
}

#[test]
fn literal_and_plain_coercion() {
    with_checked(&[("t.fsol", &contract("a = a + 1; a = a * p;"))], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        assert!(matches!(
            c.operator_sites[0].operands[1].kind,
            OperandKind::LiteralEncrypt { .. }
        ));
        assert!(matches!(
            c.operator_sites[1].operands[1].kind,
            OperandKind::TrivialEncrypt { .. }
        ));
    });
}

#[test]
fn comparisons_produce_ebool() {
    with_checked(
        &[("t.fsol", &contract("ebool r = a <= b; eb = r;"))],
        |c, _| {
            assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
            let s = &c.operator_sites[0];
            assert_eq!(s.op, fhec_ir::FheOp::Lte);
            assert_eq!(s.result.solidity_name(), "ebool");
        },
    );
}

#[test]
fn nested_sites_are_all_emitted() {
    with_checked(&[("t.fsol", &contract("a = a + b + a8;"))], |c, snip| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        assert_eq!(c.operator_sites.len(), 2);
        let spans: Vec<String> = c.operator_sites.iter().map(|s| snip(s.span)).collect();
        assert!(spans.contains(&"a + b".to_string()));
        assert!(spans.contains(&"a + b + a8".to_string()));
    });
}

#[test]
fn method_and_library_calls_type_through_profile() {
    with_checked(
        &[(
            "t.fsol",
            &contract("a = a.add(b) + FHE.mul(a, b); ebool r = a.lte(b); eb = r;"),
        )],
        |c, _| {
            assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
            // Only the outer `+` is an operator site; the method/library
            // calls pass through.
            assert_eq!(c.operator_sites.len(), 1);
            assert_eq!(c.operator_sites[0].op, fhec_ir::FheOp::Add);
        },
    );
}

#[test]
fn square_rol_ror_type_through_profile() {
    assert_codes("a = a.square(); a = a.rol(b); a = a.ror(b);", &[]);
}

#[test]
fn boolean_ops_are_sites_without_short_circuit() {
    with_checked(
        &[("t.fsol", &contract("eb = eb && (a < b) || !eb;"))],
        |c, _| {
            assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
            let and = c
                .operator_sites
                .iter()
                .find(|s| s.op == fhec_ir::FheOp::And)
                .expect("and site");
            assert!(and.no_short_circuit);
            assert!(c.operator_sites.iter().any(|s| s.op == fhec_ir::FheOp::Not));
        },
    );
}

#[test]
fn ternary_becomes_select_site() {
    with_checked(
        &[("t.fsol", &contract("a = eb ? a : FHE.asEuint32(0);"))],
        |c, snip| {
            assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
            assert_eq!(c.ternary_sites.len(), 1);
            assert_eq!(snip(c.ternary_sites[0].cond_span), "eb");
            assert_eq!(c.ternary_sites[0].result.solidity_name(), "euint32");
        },
    );
}

#[test]
fn plain_ternary_with_encrypted_arms_is_not_lowered() {
    assert_codes("a = p > 0 ? a : b;", &[]);
    with_checked(&[("t.fsol", &contract("a = p > 0 ? a : b;"))], |c, _| {
        assert!(c.ternary_sites.is_empty());
    });
}

#[test]
fn shift_amount_rules() {
    // Literal amount: encrypted to the shifted width.
    assert_codes("a = a << 2;", &[]);
    // Narrower encrypted amount widens.
    assert_codes("a = a << a8;", &[]);
    // Wider encrypted amount would need narrowing.
    assert_codes("a = a << a64;", &["FHE2004"]);
}

#[test]
fn eaddress_supports_only_eq_ne() {
    assert_codes("eb = ea1 == ea2; eb = ea1 != ea2;", &[]);
    assert_codes("ea1 = ea1 & ea2;", &["FHE2006"]);
    assert_codes("eb = ea1 < ea2;", &["FHE2006"]);
}

#[test]
fn ebool_logical_and_bitwise_ok_ordering_rejected() {
    assert_codes("eb = eb ^ eb; eb = eb & eb; eb = eb | eb;", &[]);
    assert_codes("eb = eb < eb;", &["FHE2006"]);
    assert_codes("a = a & eb;", &["FHE2002"]);
}

#[test]
fn compound_assignment_lowers() {
    with_checked(&[("t.fsol", &contract("a += b; a <<= 1;"))], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        assert_eq!(c.compound_sites.len(), 2);
        assert_eq!(c.compound_sites[0].op, fhec_ir::FheOp::Add);
        assert_eq!(c.compound_sites[1].op, fhec_ir::FheOp::Shl);
        // Compound writes are storage writes too (R1).
        assert_eq!(c.acl.storage_writes.len(), 2);
    });
}

#[test]
fn statement_incdec_lowers_value_use_rejected() {
    with_checked(&[("t.fsol", &contract("a++; --a;"))], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        assert_eq!(c.incdec_sites.len(), 2);
        assert!(c.incdec_sites[0].is_increment);
        assert!(!c.incdec_sites[1].is_increment);
    });
    assert_codes("b = a++;", &["FHE2011"]);
}

#[test]
fn plain_only_code_produces_nothing() {
    with_checked(
        &[(
            "t.fsol",
            &contract(
                "uint256 x = p + 1; if (x > 2) { plainState = x; } \
                 bool ok = x == 3 && p < 9; boolState = ok;",
            ),
        )],
        |c, _| {
            assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
            assert_eq!(c.rewrite_site_count(), 0);
            assert!(c.acl.storage_writes.is_empty());
        },
    );
}

#[test]
fn unknown_calls_degrade_silently() {
    // An unmodeled call with an encrypted argument: no site, no diagnostic
    // (solc remains the authority) — as long as no operator meets it.
    assert_codes("FHE.verifyDecryptResult(a, p, msg.data);", &[]);
}

// ---- interaction-table and coercion errors ------------------------------------

#[test]
fn encrypted_meets_unknown_is_an_error() {
    assert_codes("a = a + unknownFn();", &["FHE2001"]);
}

#[test]
fn literal_out_of_range() {
    assert_codes("a8 = a8 + 300;", &["FHE2003"]);
    assert_codes("a = a + (-1);", &["FHE2003"]);
}

#[test]
fn plaintext_not_convertible() {
    assert_codes("a = a + addr;", &["FHE2008"]);
    // uint64 does not implicitly narrow to euint32's analogue.
    assert_codes("uint64 w = 1; a = a + w;", &["FHE2008"]);
}

#[test]
fn unary_minus_has_fixit() {
    with_checked(&[("t.fsol", &contract("a = -a;"))], |c, _| {
        let d = c
            .diagnostics
            .iter()
            .find(|d| d.code == "FHE2005")
            .expect("FHE2005");
        assert_eq!(d.fixits.len(), 1);
        assert_eq!(d.fixits[0].replacement, "FHE.sub(FHE.asEuint32(0), a)");
        assert!(!d.fixits[0].safe);
    });
}

#[test]
fn pow_rejected() {
    assert_codes("a = a ** 2;", &["FHE2006"]);
}

#[test]
fn condition_not_ebool_has_fixit() {
    with_checked(&[("t.fsol", &contract("if (a) { b = a; }"))], |c, _| {
        let d = c
            .diagnostics
            .iter()
            .find(|d| d.code == "FHE2009")
            .expect("FHE2009");
        assert_eq!(d.fixits[0].replacement, "FHE.ne(a, FHE.asEuint32(0))");
    });
}

#[test]
fn sites_in_view_functions_rejected() {
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         contract C { euint32 a; \
           function g() public view returns (euint32) { return FHE.add(a, a); } \
           function h() public view returns (euint32) { euint32 r = a; return r; } \
           function bad() public view returns (euint32) { euint32 x = a; x = x; return x; } \
           function bad2(euint32 y) internal view returns (euint32) { return y; } \
           function worse() public view returns (euint32) { euint32 z = a; z += z; return z; } \
         }";
    with_checked(&[("t.fsol", src)], |c, _| {
        // Existing FHE calls in view functions are NOT our business (g);
        // reading/returning handles is legal (h, bad, bad2); only a rewrite
        // site inside view is FHE2010 (worse).
        let v: Vec<&str> = c
            .diagnostics
            .iter()
            .map(|d| d.code)
            .filter(|c| *c == "FHE2010")
            .collect();
        assert_eq!(v.len(), 1, "{:?}", c.diagnostics);
    });
}

// ---- definite assignment (§6) --------------------------------------------------

#[test]
fn definite_assignment_matrix() {
    // Used before any assignment.
    assert_codes("euint32 x; a = x + a;", &["FHE2007"]);
    // Initialized: fine.
    assert_codes("euint32 x = a; a = x + a;", &[]);
    // Assigned on one plaintext branch only.
    assert_codes("euint32 x; if (p > 0) { x = a; } a = x + a;", &["FHE2007"]);
    // Assigned on both plaintext branches: fine.
    assert_codes(
        "euint32 x; if (p > 0) { x = a; } else { x = b; } a = x + a;",
        &[],
    );
    // Assigned only inside a loop body.
    assert_codes(
        "euint32 x; for (uint256 i = 0; i < p; i++) { x = a; } a = x + a;",
        &["FHE2007"],
    );
    // Nested plaintext ifs, all paths assign: fine.
    assert_codes(
        "euint32 x; if (p > 0) { if (p > 1) { x = a; } else { x = b; } } else { x = b; } a = x + a;",
        &[],
    );
}

#[test]
fn encrypted_branch_write_needs_pre_value() {
    // The merge reads the pre-value, which is possibly uninitialized.
    assert_codes("euint32 x; if (eb) { x = a; }", &["FHE2007"]);
    // Pre-assigned: fine, and afterwards x is usable.
    assert_codes("euint32 x = b; if (eb) { x = a; } a = x + b;", &[]);
    // A local declared inside the branch needs no pre-value.
    assert_codes("if (eb) { euint32 t = a; a = t; }", &[]);
}

#[test]
fn uninit_in_select_and_return_positions() {
    assert_codes("euint32 x; a = eb ? x : a;", &["FHE2007"]);
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         contract C { euint32 a; \
           function r() public returns (euint32) { euint32 x; return x; } \
         }";
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(
            c.diagnostics.iter().any(|d| d.code == "FHE2007"),
            "{:?}",
            c.diagnostics
        );
    });
}

// ---- reject rules (§7) -----------------------------------------------------------

#[test]
fn branch_reject_rules_each_trigger() {
    assert_codes("if (eb) { return; }", &["FHE3001"]);
    assert_codes("while (p > 0) { if (eb) { break; } }", &["FHE3002"]);
    assert_codes("if (eb) { require(p > 0); }", &["FHE3003"]);
    assert_codes("if (eb) { revert(); }", &["FHE3003"]);
    assert_codes("if (eb) { payable(addr).transfer(1); }", &["FHE3004"]);
    assert_codes("if (eb) { emit Ping(1); }", &["FHE3005"]);
    assert_codes("if (eb) { plainState = 1; }", &["FHE3006"]);
    assert_codes("if (eb) { if (p > 0) { a = b; } }", &["FHE3007"]);
    assert_codes("if (eb) { stateWriter(); }", &["FHE3008"]);
    assert_codes("if (eb) { assembly { } }", &["FHE3009"]);
    assert_codes("if (eb) { delete a; }", &["FHE3010"]);
}

#[test]
fn branch_legal_twins_pass() {
    // Encrypted writes, FHE calls, verified same-contract computation,
    // nested encrypted ifs, branch-local plain declarations: all legal.
    assert_codes("if (eb) { a = b; }", &[]);
    assert_codes("if (eb) { a = FHE.add(a, b); }", &[]);
    assert_codes("if (eb) { a = fhelper(a); }", &[]);
    assert_codes("if (eb) { if (a < b) { a = b; } }", &[]);
    assert_codes(
        "if (eb) { euint32 t = a; uint256 u = 1; u = 2; a = t; plainStateRead(u); }",
        &["FHE3008"],
    );
    // (the last also shows unverified calls still reject; drop the call:)
    assert_codes(
        "if (eb) { euint32 t = a; uint256 u = 1; u = 2; a = t; }",
        &[],
    );
}

#[test]
fn global_rejects() {
    assert_codes("delete a;", &["FHE3010"]);
    assert_codes("byId[uint256(euint32.unwrap(a))] = b;", &[]); // plain index fine
    assert_codes("a = byId[p]; byId[p] = a;", &[]);
    assert_codes("euint32 v = balances[addr]; a = v;", &[]);
    assert_codes("byId[p] = b; b = byId[p];", &[]);
}

#[test]
fn encrypted_index_rejected() {
    // Reading and writing through an encrypted index.
    assert_codes("a = byId[a8];", &["FHE3020"]);
    assert_codes("byId[a8] = a;", &["FHE3020"]);
}

#[test]
fn encrypted_loop_conditions_rejected() {
    assert_codes("while (eb) { a = b; }", &["FHE3021"]);
    assert_codes("do { a = b; } while (eb);", &["FHE3021"]);
    assert_codes("for (uint256 i = 0; eb; i++) { }", &["FHE3021"]);
}

#[test]
fn ebool_in_plaintext_bool_context() {
    assert_codes("require(eb);", &["FHE3022"]);
    assert_codes("boolState = eb;", &["FHE3022"]);
    assert_codes("bool ok = eb;", &["FHE3022"]);
}

#[test]
fn side_effecting_encrypted_operands() {
    assert_codes("eb = eb && stateWriterB();", &["FHE2001", "FHE3012"]);
    assert_codes("a = eb ? fhelperWrite() : b;", &["FHE2001", "FHE3012"]);
    // FHE calls and profile methods are fine as operands.
    assert_codes("eb = eb && FHE.lt(a, b); eb = eb || a.lte(b);", &[]);
}

// ---- ACL facts (§8) ------------------------------------------------------------

#[test]
fn acl_facts_r1_variants() {
    with_checked(
        &[(
            "t.fsol",
            &contract(
                "a = FHE.asEuint32(p); \
                 balances[msg.sender] = a; \
                 balances[addr] = a; \
                 byId[p] = a;",
            ),
        )],
        |c, _| {
            assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
            assert_eq!(c.acl.storage_writes.len(), 4);
            assert!(matches!(c.acl.storage_writes[0].slot, SlotKind::SimpleVar));
            match &c.acl.storage_writes[1].slot {
                SlotKind::Mapping {
                    key_is_msg_sender, ..
                } => assert!(*key_is_msg_sender),
                other => panic!("expected mapping slot, got {other:?}"),
            }
            match &c.acl.storage_writes[2].slot {
                SlotKind::Mapping {
                    key_is_msg_sender,
                    key_is_address,
                    ..
                } => {
                    assert!(!*key_is_msg_sender);
                    assert!(*key_is_address);
                }
                other => panic!("expected mapping slot, got {other:?}"),
            }
            match &c.acl.storage_writes[3].slot {
                SlotKind::Mapping { key_is_address, .. } => assert!(!*key_is_address),
                other => panic!("expected mapping slot, got {other:?}"),
            }
        },
    );
}

#[test]
fn acl_facts_r2_external_call() {
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         interface IVault { function push(euint32 v, uint256 tag) external; }\n\
         contract C { euint32 a; IVault vault;\n\
           function f() public { vault.push(a, 1); }\n\
           function g(address who) public { IVault(who).push(a, 2); }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, snip| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        assert_eq!(c.acl.external_args.len(), 2);
        let f0 = &c.acl.external_args[0];
        assert_eq!(snip(f0.callee_span), "vault");
        assert!(f0.callee_is_ident);
        assert_eq!(f0.args.len(), 1);
        assert_eq!(f0.args[0].1.solidity_name(), "euint32");
        let f1 = &c.acl.external_args[1];
        assert_eq!(snip(f1.callee_span), "IVault(who)");
        assert!(!f1.callee_is_ident);
    });
}

#[test]
fn acl_facts_r3_returns() {
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         contract C { euint32 a;\n\
           function pub_() public returns (euint32) { return a; }\n\
           function ext_() external returns (euint32) { return a; }\n\
           function int_() internal returns (euint32) { return a; }\n\
           function view_() public view returns (euint32) { return a; }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        assert_eq!(c.acl.returns.len(), 4);
        assert!(c.acl.returns[0].is_public_or_external);
        assert!(!c.acl.returns[0].is_view);
        assert!(c.acl.returns[1].is_public_or_external);
        assert!(!c.acl.returns[2].is_public_or_external);
        assert!(c.acl.returns[3].is_view);
    });
}

// ---- `in` sugar (§2.3) -----------------------------------------------------------

#[test]
fn sugar_site_for_legal_parameter() {
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         contract C { euint32 a;\n\
           function deposit(in euint32 amount, uint256 tag) public { a = amount; }\n\
           constructor(in ebool flag) { }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, snip| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        assert_eq!(c.sugar_sites.len(), 2);
        let s = &c.sugar_sites[0];
        assert_eq!(s.name, "amount");
        assert_eq!(s.ty.solidity_name(), "euint32");
        assert!(s.has_body);
        assert_eq!(snip(s.in_span), "in");
        assert_eq!(snip(s.param_span), "in euint32 amount");
        assert_eq!(c.sugar_sites[1].ty.solidity_name(), "ebool");
    });
}

#[test]
fn sugar_on_bodiless_declaration() {
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         interface I { function deposit(in euint32 amount) external; }";
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        assert_eq!(c.sugar_sites.len(), 1);
        assert!(!c.sugar_sites[0].has_body);
        assert!(c.sugar_sites[0].body_span.is_none());
    });
}

#[test]
fn sugar_error_cases() {
    // Non-encrypted type.
    let src1 = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        contract C { function f(in uint32 x) public { } }";
    with_checked(&[("t.fsol", src1)], |c, _| {
        assert_eq!(c.diagnostics.len(), 1);
        assert_eq!(c.diagnostics[0].code, "FHE1010");
    });
    // Name collision with the generated identifier.
    let src2 = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        contract C { function f(in euint32 x) public { uint256 x_input = 1; x_input = 2; } }";
    with_checked(&[("t.fsol", src2)], |c, _| {
        assert!(
            c.diagnostics.iter().any(|d| d.code == "FHE1011"),
            "{:?}",
            c.diagnostics
        );
    });
    // Bad positions: modifier parameter list and returns list.
    let src3 = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        contract C { modifier m(in euint32 x) { _; } \
                     function g() public returns (in euint32 r) { } }";
    with_checked(&[("t.fsol", src3)], |c, _| {
        let v: Vec<&str> = c.diagnostics.iter().map(|d| d.code).collect();
        assert_eq!(v.iter().filter(|c| **c == "FHE1012").count(), 2, "{v:?}");
    });
    // Local declarations with `in` do not parse (upstream rejection is
    // preserved), so no FHE1012 case exists for locals.
}

// ---- helpers referenced from bodies ------------------------------------------

// `unknownFn`, `stateWriterB`, `fhelperWrite`, `plainStateRead` are
// deliberately undeclared in the test contract: they resolve to Unknown
// (MaybeExternal through the profile import), which is exactly the
// degradation under test.
