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
        let profile = CofheProfile::v0_2();
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
fn tuple_assignment_definitely_initializes_named_components() {
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         contract C {\n\
           function pair(euint64 a) internal returns (ebool, euint64) {\n\
             return (FHE.asEbool(true), a);\n\
           }\n\
           function triple(euint64 a) internal returns (uint256, ebool, euint64) {\n\
             return (0, FHE.asEbool(true), a);\n\
           }\n\
           function tuple_assign(euint64 a) external returns (euint64 r) {\n\
             ebool ok;\n\
             euint64 v;\n\
             (ok, v) = pair(a);\n\
             r = ok ? v : euint64(0);\n\
           }\n\
           function tuple_assign_with_hole(euint64 a) external returns (euint64 r) {\n\
             ebool ok;\n\
             euint64 v;\n\
             (, ok, v) = triple(a);\n\
             r = ok ? v : euint64(0);\n\
           }\n\
           function tuple_decl(euint64 a) external returns (euint64 r) {\n\
             (ebool ok, euint64 v) = pair(a);\n\
             r = ok ? v : euint64(0);\n\
           }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
    });
}

// ---- issue #82: unassigned encrypted named return at function exit -----

#[test]
fn named_return_never_assigned_is_flagged_at_function_exit() {
    // The issue #82 repro: `success` is a named return that is never
    // assigned on any path, yet the caller's tuple declaration treats it
    // as initialized (§6 could not see this from the call site).
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         library L {\n\
           function bad(euint64 a, euint64 b) internal returns (ebool success, euint64 res) {\n\
             euint64 d = a - b;\n\
             if (d <= a) { res = d; } else { res = euint64(0); }\n\
           }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, snip| {
        let fhe2007: Vec<_> = c
            .diagnostics
            .iter()
            .filter(|d| d.code == "FHE2007")
            .collect();
        assert_eq!(fhe2007.len(), 1, "{:?}", c.diagnostics);
        assert_eq!(snip(fhe2007[0].span), "ebool success");
    });
}

#[test]
fn named_return_assigned_before_branching_stays_clean() {
    // The issue's `good` control: assigning `success` before any branch
    // makes it definitely assigned on every path.
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         library L {\n\
           function good(euint64 a, euint64 b) internal returns (ebool success, euint64 res) {\n\
             success = a <= b;\n\
             euint64 d = a - b;\n\
             if (d <= a) { res = d; } else { res = euint64(0); }\n\
           }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
    });
}

#[test]
fn named_return_assigned_on_every_if_else_arm_stays_clean() {
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         library L {\n\
           function f(bool cond, euint64 a, euint64 b) internal returns (euint64 res) {\n\
             if (cond) { res = a; } else { res = b; }\n\
           }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
    });
}

#[test]
fn named_return_assigned_on_early_return_still_flags_the_fallthrough_path() {
    // `success` is assigned on the branch that returns early, but the
    // fallthrough path (cond == false) never assigns it: still a bug.
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         library L {\n\
           function f(bool cond, euint64 a, euint64 b) internal returns (ebool success, euint64 res) {\n\
             if (cond) {\n\
               success = a <= b;\n\
               res = a;\n\
               return;\n\
             }\n\
             res = b;\n\
           }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, snip| {
        let fhe2007: Vec<_> = c
            .diagnostics
            .iter()
            .filter(|d| d.code == "FHE2007")
            .collect();
        assert_eq!(fhe2007.len(), 1, "{:?}", c.diagnostics);
        assert_eq!(snip(fhe2007[0].span), "ebool success");
    });
}

#[test]
fn only_the_unassigned_named_return_is_flagged_among_several() {
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         library L {\n\
           function f(euint64 a, euint64 b) internal returns (euint64 res, ebool ok, euint64 extra) {\n\
             res = a;\n\
             extra = b;\n\
           }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, snip| {
        let fhe2007: Vec<_> = c
            .diagnostics
            .iter()
            .filter(|d| d.code == "FHE2007")
            .collect();
        assert_eq!(fhe2007.len(), 1, "{:?}", c.diagnostics);
        assert_eq!(snip(fhe2007[0].span), "ebool ok");
    });
}

#[test]
fn named_return_unassigned_but_every_path_uses_explicit_return_expr_stays_clean() {
    // Both arms return an explicit tuple; the named-return locals are never
    // read by either arm and the closing brace is never reached.
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         library L {\n\
           function f(bool cond, euint64 a, euint64 b) internal returns (ebool success, euint64 res) {\n\
             if (cond) {\n\
               return (FHE.asEbool(true), a);\n\
             } else {\n\
               return (FHE.asEbool(false), b);\n\
             }\n\
           }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
    });
}

#[test]
fn plain_named_return_left_unassigned_is_not_flagged() {
    // A plain (non-encrypted) named return returning the zero value is
    // ordinary, valid Solidity: this diagnostic is encrypted-type-specific.
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         library L {\n\
           function f(euint64 a) internal returns (uint256 count, euint64 res) {\n\
             res = a;\n\
           }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
    });
}

// ---- external-review follow-up: terminated-arm join precision ----------

#[test]
fn if_arm_that_returns_does_not_pollute_the_join_with_else() {
    // `then` always returns; only `else` can reach the closing brace, and
    // it assigns `res` — no false FHE2007.
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         library L {\n\
           function f(bool c, euint64 a) internal returns (euint64 res) {\n\
             if (c) { return a; } else { res = a; }\n\
           }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
    });
}

#[test]
fn if_arm_that_reverts_does_not_pollute_the_join_with_then() {
    // `else` always reverts; only `then` can reach the closing brace, and
    // it assigns `res` — no false FHE2007.
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         error Err();\n\
         library L {\n\
           function f(bool c, euint64 a) internal returns (euint64 res) {\n\
             if (c) { res = a; } else { revert Err(); }\n\
           }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
    });
}

#[test]
fn a_function_that_only_reverts_has_no_reachable_exit_and_stays_clean() {
    // The closing brace is never reached (the only statement always
    // reverts), so the named return is never actually exposed unassigned.
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         library L {\n\
           function f() internal returns (euint64 r) {\n\
             revert();\n\
           }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
    });
}

#[test]
fn try_catch_where_every_clause_assigns_stays_clean() {
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         library L {\n\
           function ext(euint64 a) internal returns (euint64) { return a; }\n\
           function f(euint64 a, euint64 b) internal returns (euint64 res) {\n\
             try L.ext(a) returns (euint64 v) {\n\
               res = v;\n\
             } catch {\n\
               res = b;\n\
             }\n\
           }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
    });
}

#[test]
fn do_while_break_before_assignment_still_flags_the_named_return() {
    // The `break` exits before `r = a;` ever runs; the statement after the
    // `break` is unreachable, so `r` is never actually assigned.
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         library L {\n\
           function f(euint64 a) internal returns (euint64 r) {\n\
             do { break; r = a; } while (false);\n\
           }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, snip| {
        let fhe2007: Vec<_> = c
            .diagnostics
            .iter()
            .filter(|d| d.code == "FHE2007")
            .collect();
        assert_eq!(fhe2007.len(), 1, "{:?}", c.diagnostics);
        assert_eq!(snip(fhe2007[0].span), "euint64 r");
    });
}

#[test]
fn for_loop_zero_trip_does_not_count_the_increment_as_having_run() {
    // The condition starts (and stays) `false`, so the body — and the
    // increment `r = a`, which only runs after a body iteration — never
    // execute even once.
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         library L {\n\
           function f(euint64 a) internal returns (euint64 r) {\n\
             for (; false; r = a) {}\n\
           }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, snip| {
        let fhe2007: Vec<_> = c
            .diagnostics
            .iter()
            .filter(|d| d.code == "FHE2007")
            .collect();
        assert_eq!(fhe2007.len(), 1, "{:?}", c.diagnostics);
        assert_eq!(snip(fhe2007[0].span), "euint64 r");
    });
}

#[test]
fn modifier_with_early_return_before_placeholder_still_flags_the_guarded_function() {
    // The function body itself assigns `res` on every path, but the
    // modifier can `return;` before `_;` runs, skipping the body entirely
    // on that path — a real, unassigned-crossing-the-boundary hazard the
    // body-only analysis cannot see.
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         contract C {\n\
           modifier guarded(bool ok) {\n\
             if (!ok) { return; }\n\
             _;\n\
           }\n\
           function f(bool ok, euint64 a) public guarded(ok) returns (euint64 res) {\n\
             res = a;\n\
           }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, snip| {
        let fhe2007: Vec<_> = c
            .diagnostics
            .iter()
            .filter(|d| d.code == "FHE2007")
            .collect();
        assert_eq!(fhe2007.len(), 1, "{:?}", c.diagnostics);
        assert_eq!(snip(fhe2007[0].span), "euint64 res");
    });
}

#[test]
fn modifier_whose_placeholder_always_runs_first_stays_clean() {
    // The placeholder is unconditionally first, so the function body always
    // runs; a `return;` after it doesn't skip anything.
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         contract C {\n\
           modifier guarded(bool ok) {\n\
             _;\n\
             if (!ok) { return; }\n\
           }\n\
           function f(bool ok, euint64 a) public guarded(ok) returns (euint64 res) {\n\
             res = a;\n\
           }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
    });
}

#[test]
fn encrypted_branch_write_needs_pre_value() {
    // The merge reads the pre-value, which is possibly uninitialized.
    assert_codes("euint32 x; if (eb) { x = a; }", &["FHE2007"]);
    // Both branch environments produce x independently, so the merge needs
    // no incoming value.
    assert_codes(
        "euint32 x; if (eb) { x = a; } else { x = b; } a = x + b;",
        &[],
    );
    // A read before the assignment still needs the incoming value, even
    // though the final state of each arm is assigned.
    assert_codes(
        "euint32 x; if (eb) { x = x; } else { x = b; }",
        &["FHE2007"],
    );
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

// ---- §2.3 explicit proof binder --------------------------------------------

#[test]
fn binder_resolves_a_same_list_bytes_parameter() {
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         contract C {\n\
           function f(in(sig) euint32 x, bytes calldata sig, bytes calldata data) public {\n\
             x; sig; data;\n\
           }\n\
           function g(in(p) ebool a, bytes memory p, in(p) eaddress b) public { a; b; p; }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, snip| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        assert_eq!(c.sugar_sites.len(), 3);
        assert_eq!(c.sugar_sites[0].proof.as_deref(), Some("sig"));
        assert_eq!(snip(c.sugar_sites[0].in_span), "in");
        assert_eq!(snip(c.sugar_sites[0].param_span), "in(sig) euint32 x");
        assert_eq!(c.sugar_sites[1].proof.as_deref(), Some("p"));
        assert_eq!(c.sugar_sites[2].proof.as_deref(), Some("p"));
    });
}

#[test]
fn binder_does_not_reserve_the_appended_proof_name() {
    // The bound form appends nothing, so an author parameter called
    // `inputProof` is the normal case, not the FHE1011 collision.
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         contract C {\n\
           function f(in(inputProof) euint32 x, bytes memory inputProof) public { x; inputProof; }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        assert_eq!(c.sugar_sites.len(), 1);
        assert_eq!(c.sugar_sites[0].proof.as_deref(), Some("inputProof"));
    });
}

#[test]
fn binder_still_guards_the_generated_raw_input_name() {
    // The binder introduces no new fixed generated name, but `<name>_input`
    // is still generated, so a bound proof spelled that way collides.
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         contract C {\n\
           function f(in(x_input) euint32 x, bytes memory x_input) public { x; x_input; }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, _| {
        let codes: Vec<&str> = c.diagnostics.iter().map(|d| d.code).collect();
        assert_eq!(codes, vec!["FHE1011"]);
    });
}

#[test]
fn binder_form_is_decided_per_function() {
    // The two forms may not mix in one list, but two functions of one
    // contract may each pick their own.
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         contract C {\n\
           function implicit(in euint32 x) public { x; }\n\
           function explicit(in(sig) euint32 x, bytes calldata sig) public { x; sig; }\n\
         }";
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        let proofs: Vec<Option<&str>> = c.sugar_sites.iter().map(|s| s.proof.as_deref()).collect();
        assert_eq!(proofs, vec![None, Some("sig")]);
    });
}

#[test]
fn binder_bodiless_declaration_states_a_site() {
    let src = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         interface I { function deposit(in(p) euint32 a, bytes calldata p) external; }";
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        assert_eq!(c.sugar_sites.len(), 1);
        assert!(!c.sugar_sites[0].has_body);
        assert_eq!(c.sugar_sites[0].proof.as_deref(), Some("p"));
    });
}

#[test]
fn binder_error_cases_state_no_site() {
    let head = "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n";
    // FHE1013: the binder names nothing in this list.
    let cases: &[(&str, &str)] = &[
        (
            "contract C { function f(in(sig) euint32 x, bytes calldata other) public { x; other; } }",
            "FHE1013",
        ),
        // FHE1013: named parameter is not `bytes`.
        (
            "contract C { function f(in(sig) euint32 x, uint256 sig) public { x; sig; } }",
            "FHE1013",
        ),
        // FHE1013: `bytes` without a memory/calldata location.
        (
            "contract C { function f(in(sig) euint32 x, bytes storage sig) internal { x; sig; } }",
            "FHE1013",
        ),
        // FHE1013: a fixed-width `bytesNN` is a value type, not `bytes`.
        (
            "contract C { function f(in(sig) euint32 x, bytes32 sig) public { x; sig; } }",
            "FHE1013",
        ),
        (
            "contract C { function f(in(sig) euint32 x, bytes1 sig) public { x; sig; } }",
            "FHE1013",
        ),
        // FHE1013: `string memory` has the right location but the wrong type.
        (
            "contract C { function f(in(sig) euint32 x, string memory sig) public { x; sig; } }",
            "FHE1013",
        ),
        // FHE1013: an unnamed `bytes memory` parameter carries no name the
        // binder could match, so the list declares no `sig`.
        (
            "contract C { function f(in(sig) euint32 x, bytes memory) public { x; } }",
            "FHE1013",
        ),
        // FHE1013: the binder resolves against this parameter list only, so a
        // `bytes memory` in the `returns` list never matches.
        (
            "contract C { function f(in(sig) euint32 x) public returns (bytes memory sig) \
             { x; sig = \"\"; } }",
            "FHE1013",
        ),
        // FHE1014: implicit and explicit mixed in one list.
        (
            "contract C { function f(in euint32 x, in(sig) euint32 y, bytes memory sig) public \
             { x; y; sig; } }",
            "FHE1014",
        ),
        // FHE1014: two binders naming different proofs.
        (
            "contract C { function f(in(a) euint32 x, in(b) euint32 y, bytes memory a, \
             bytes memory b) public { x; y; a; b; } }",
            "FHE1014",
        ),
    ];
    for (body, code) in cases {
        let src = format!("{head}{body}");
        with_checked(&[("t.fsol", &src)], |c, _| {
            let codes: Vec<&str> = c.diagnostics.iter().map(|d| d.code).collect();
            assert_eq!(codes, vec![*code], "{body}");
            assert!(c.sugar_sites.is_empty(), "{body}: {:?}", c.sugar_sites);
        });
    }
}

// ---- §2.7 `precondition` blocks ---------------------------------------------

/// A contract whose `g` carries an `in euint32` parameter, so a
/// `precondition` block is legal there. `pre` is the block body; `rest` is
/// the remainder of `g`'s body.
fn pre_contract(pre: &str, rest: &str) -> String {
    format!(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         contract P {{\n\
           euint32 enc;\n\
           uint256 plainState;\n\
           uint256[2] plainArr;\n\
           struct Pair {{ uint256 a; uint256 b; }}\n\
           Pair pairState;\n\
           mapping(address => bool) operators;\n\
           error Bad(address who);\n\
           event Ping(uint256 x);\n\
           function isOperator(address who) public view returns (bool) {{\n\
             return operators[who];\n\
           }}\n\
           function encGetter() public view returns (euint32) {{ return enc; }}\n\
           function bump() public {{ plainState += 1; }}\n\
           function g(address from, uint256[] memory list, in euint32 amount) public {{\n\
             precondition {{\n{pre}\n}}\n{rest}\n}}\n\
         }}\n"
    )
}

/// Error codes for a source, sorted (warnings and notes dropped).
fn error_codes(src: &str) -> Vec<String> {
    with_checked(&[("t.fsol", src)], |c, _| {
        let mut v: Vec<String> = c
            .diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .map(|d| d.code.to_string())
            .collect();
        v.sort();
        v
    })
}

fn assert_pre_codes(pre: &str, expected: &[&str]) {
    let got = error_codes(&pre_contract(pre, "enc = amount;"));
    let mut want: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(got, want, "precondition body: {pre}");
}

#[test]
fn precondition_plaintext_guard_is_accepted() {
    let src = pre_contract(
        "if (!isOperator(from)) revert Bad(from);\n\
         require(from != address(0), \"zero\");",
        "enc = amount;",
    );
    with_checked(&[("t.fsol", &src)], |c, snip| {
        let errs: Vec<&str> = c
            .diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .map(|d| d.code)
            .collect();
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(c.precondition_sites.len(), 1);
        let site = &c.precondition_sites[0];
        assert_eq!(snip(site.marker_span), "precondition ");
        let block = snip(site.block_span);
        assert!(block.starts_with('{') && block.ends_with('}'), "{block}");
        assert_eq!(c.sugar_sites.len(), 1);
        assert_eq!(c.sugar_sites[0].function, site.function);
    });
}

#[test]
fn precondition_permits_block_local_declaration_and_assignment() {
    assert_pre_codes(
        "uint256 n = plainState;\n\
         n = n + 1;\n\
         n++;\n\
         if (n == 0) revert Bad(from);",
        &[],
    );
}

#[test]
fn precondition_block_scope_does_not_escape() {
    // Re-declaring the same name after the block is legal, which proves the
    // block introduced its own scope (FHE1020 would fire otherwise).
    let src = pre_contract(
        "uint256 n = 1; n = n + 1;",
        "uint256 n = 2; n; enc = amount;",
    );
    assert_eq!(error_codes(&src), Vec::<String>::new());
}

#[test]
fn precondition_rejects_the_managed_encrypted_input() {
    assert_pre_codes("amount;", &["FHE3014"]);
    assert_pre_codes(
        "if (isOperator(from)) revert Bad(from);\namount;",
        &["FHE3014"],
    );
}

/// The bound proof parameter is an ordinary `bytes` parameter: the author
/// declares it, it exists on entry, and nothing is generated for it. Only the
/// encrypted input itself is dialect-managed. A guard may therefore read the
/// proof while the input stays refused (FHE3014).
#[test]
fn precondition_reads_a_bound_proof_but_not_the_bound_input() {
    let bound = |pre: &str| {
        format!(
            "pragma solidity ^0.8.25;\n\
             import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
             contract B {{\n\
               euint32 enc;\n\
               error NoProof();\n\
               function g(in(proof) euint32 amount, bytes calldata proof) public {{\n\
                 precondition {{\n{pre}\n}}\n\
                 enc = amount;\n\
               }}\n\
             }}\n"
        )
    };

    // The proof is readable: as a whole value, and through `.length`.
    let ok = bound(
        "if (proof.length == 0) revert NoProof();\n\
         require(proof.length > 64, \"short proof\");\n\
         proof;",
    );
    assert_eq!(error_codes(&ok), Vec::<String>::new());
    with_checked(&[("t.fsol", &ok)], |c, _| {
        assert_eq!(c.precondition_sites.len(), 1);
        assert_eq!(c.sugar_sites.len(), 1);
        assert_eq!(c.sugar_sites[0].proof.as_deref(), Some("proof"));
    });

    // The encrypted input it binds is still refused, in the same function.
    let bad = bound("require(proof.length > 64, \"short proof\");\namount;");
    assert_eq!(error_codes(&bad), ["FHE3014"]);
    with_checked(&[("t.fsol", &bad)], |c, snip| {
        let d = c
            .diagnostics
            .iter()
            .find(|d| d.code == "FHE3014")
            .expect("FHE3014");
        assert_eq!(snip(d.span), "amount");
    });
}

/// Both codes apply to `amount == enc`, and FHE3014 is the useful one: it
/// names the input and says why it does not exist yet.
#[test]
fn precondition_prefers_fhe3014_for_a_nested_managed_input() {
    assert_pre_codes("if (amount == enc) revert Bad(from);", &["FHE3014"]);
    assert_pre_codes("enc.add(amount);", &["FHE3014"]);
    let src = pre_contract("if (amount == enc) revert Bad(from);", "enc = amount;");
    with_checked(&[("t.fsol", &src)], |c, snip| {
        let d = c
            .diagnostics
            .iter()
            .find(|d| d.code == "FHE3014")
            .expect("FHE3014");
        // The span points at the input itself, not at the comparison.
        assert_eq!(snip(d.span), "amount");
    });
}

#[test]
fn precondition_rejects_encrypted_expressions() {
    // Encrypted state read.
    assert_pre_codes("enc;", &["FHE3015"]);
    // A `view` call returning an encrypted value.
    assert_pre_codes("encGetter();", &["FHE3015"]);
    // An encrypted local declaration.
    assert_pre_codes("euint32 t = enc;", &["FHE3015"]);
}

/// A type the positive fragment does not cover is `Unknown`, which means
/// "the checker does not know" — never "plaintext". A qualified type name
/// can hide an encrypted value, so reading one is refused (§1.3).
#[test]
fn precondition_rejects_an_unresolved_type() {
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\" as Fhe;\n\
        contract Holder { struct Box { uint256 v; } }\n\
        contract P {\n\
          euint32 enc;\n\
          Holder.Box boxState;\n\
          Fhe.euint32 hidden;\n\
          function g(in euint32 amount) public {\n\
            precondition { boxState; hidden; Holder.Box memory b = boxState; b; }\n\
            enc = amount;\n\
          }\n\
        }\n";
    assert_eq!(
        error_codes(src),
        ["FHE3015", "FHE3015", "FHE3015", "FHE3015"]
    );
    with_checked(&[("t.fsol", src)], |c, _| {
        for d in c.diagnostics.iter().filter(|d| d.code == "FHE3015") {
            assert!(
                d.message.contains("cannot prove is plaintext"),
                "{}",
                d.message
            );
        }
    });
}

/// A *plain* container can still hold encrypted data: `euint32[]` types as a
/// plain array of encrypted elements, and a plain struct may declare an
/// encrypted field. The root type alone therefore cannot decide (§1.3).
///
#[test]
fn precondition_rejects_a_nested_encrypted_type() {
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        struct Wallet { uint256 id; euint32 secret; }\n\
        contract P {\n\
          euint32 enc;\n\
          euint32[] encList;\n\
          Wallet walletState;\n\
          function getWallet() public view returns (Wallet memory w) { w = walletState; }\n\
          function g(in euint32 amount) public {\n\
            precondition {\n\
              euint32[] memory xs;\n\
              encList;\n\
              walletState;\n\
              getWallet();\n\
            }\n\
            enc = amount;\n\
          }\n\
        }\n";
    assert_eq!(
        error_codes(src),
        ["FHE3015", "FHE3015", "FHE3015", "FHE3015"]
    );
    with_checked(&[("t.fsol", src)], |c, snip| {
        let by = |text: &str| {
            c.diagnostics
                .iter()
                .find(|d| snip(d.span) == text)
                .unwrap_or_else(|| panic!("no diagnostic on {text}"))
                .message
                .clone()
        };
        assert!(by("euint32[] memory xs").contains("`euint32`"));
        assert!(by("encList").contains("`euint32`"));
        assert!(by("walletState").contains("`euint32`"));
        assert!(by("getWallet()").contains("returns `euint32`"));
    });
}

#[test]
fn precondition_rejects_state_writes() {
    assert_pre_codes("plainState = 1;", &["FHE3015"]);
    assert_pre_codes("plainState += 1;", &["FHE3015"]);
    assert_pre_codes("operators[from] = true;", &["FHE3015"]);
    assert_pre_codes("delete plainState;", &["FHE3015"]);
    // The message names a *state* write; local assignment stays legal.
    let src = pre_contract("plainState = 1;", "enc = amount;");
    with_checked(&[("t.fsol", &src)], |c, _| {
        let d = c
            .diagnostics
            .iter()
            .find(|d| d.code == "FHE3015")
            .expect("FHE3015");
        assert!(d.message.contains("state write"), "{}", d.message);
    });
}

#[test]
fn precondition_rejects_parameter_writes() {
    assert_pre_codes("from = address(0);", &["FHE3015"]);
}

/// An element or member write to a variable declared *outside* the block
/// reaches the same variable the whole-variable write would, so it must get
/// the same verdict *and* the same reason.
#[test]
fn precondition_element_writes_follow_the_base_variable() {
    // A state array: still a state write, and the message must say so.
    assert_pre_codes("plainArr[0] = 1;", &["FHE3015"]);
    let src = pre_contract("plainArr[0] = 1;", "enc = amount;");
    with_checked(&[("t.fsol", &src)], |c, _| {
        let d = c
            .diagnostics
            .iter()
            .find(|d| d.code == "FHE3015")
            .expect("FHE3015");
        assert!(d.message.contains("state write"), "{}", d.message);
    });
}

/// A Solidity reference type binds to existing data instead of copying it, so
/// a write *through* a block-local can mutate data the block does not own. The
/// checker does not prove freshness (§1.3): it refuses every through-write,
/// however the local was declared.
#[test]
fn precondition_rejects_every_write_through_a_local() {
    // Round 2's case: `a` is bound to the parameter's array.
    assert_pre_codes("uint256[] memory a = list; a[0] = 1;", &["FHE3015"]);
    // A storage pointer to a state array is the same hazard.
    assert_pre_codes("uint256[2] storage a = plainArr; a[0] = 1;", &["FHE3015"]);
    // A struct member through an aliasing local.
    assert_pre_codes("Pair memory p = pairState; p.a = 1;", &["FHE3015"]);
    // A local with no initializer, and one the initializer freshly allocates:
    // both refused now, because a later rebind can make either alias.
    assert_pre_codes("uint256[2] memory a; a[0] = 1;", &["FHE3015"]);
    assert_pre_codes("Pair memory p; p.a = 1;", &["FHE3015"]);
    assert_pre_codes(
        "uint256[] memory a = new uint256[](3); a[0] = 1;",
        &["FHE3015"],
    );
    assert_pre_codes(
        "uint256[2] memory a = [uint256(1), 2]; a[0] = 3;",
        &["FHE3015"],
    );
    assert_pre_codes("Pair memory p = Pair(1, 2); p.a = 3;", &["FHE3015"]);
    let src = pre_contract("uint256[2] memory a; a[0] = 1;", "enc = amount;");
    with_checked(&[("t.fsol", &src)], |c, _| {
        let d = c
            .diagnostics
            .iter()
            .find(|d| d.code == "FHE3015")
            .expect("FHE3015");
        assert!(d.message.contains("write through `a`"), "{}", d.message);
    });
}

/// Writing the local *itself* only rebinds the name, so it stays legal for a
/// reference type too. Only the element or member write is refused.
#[test]
fn precondition_permits_rebinding_a_reference_typed_local() {
    assert_pre_codes("uint256[] memory a = list; a = list;", &[]);
    assert_pre_codes("uint256[] memory a; a = list;", &[]);
    assert_pre_codes("Pair memory p; p = pairState;", &[]);
    assert_pre_codes("uint256[] memory a = new uint256[](3); a = list;", &[]);
}

/// The three escapes round 3 found. Each one made a local *look* fresh at its
/// declaration while the data it reached lived outside the block.
#[test]
fn precondition_rejects_the_rebind_and_container_escapes() {
    // 1. Declared without an initializer, then rebound to a named return.
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        struct Pair { uint256 a; uint256 b; }\n\
        contract P {\n\
          euint32 enc;\n\
          function g(in euint32 amount) public returns (Pair memory outPair) {\n\
            precondition { Pair memory p; p = outPair; p.a = 1; }\n\
            enc = amount;\n\
          }\n\
        }\n";
    assert_eq!(error_codes(src), ["FHE3015"]);
    // The same escape through a parameter, and through a state variable.
    assert_pre_codes("uint256[] memory a; a = list; a[0] = 1;", &["FHE3015"]);
    assert_pre_codes("Pair memory p; p = pairState; p.a = 1;", &["FHE3015"]);
    // 2. A tuple declaration: the element carries no initializer of its own.
    assert_pre_codes(
        "(uint256[] memory a, uint256 n) = (list, 0); n; a[0] = 1;",
        &["FHE3015"],
    );
    // 3. A freshly allocated outer container holding an aliasing reference.
    assert_pre_codes(
        "uint256[][] memory n = new uint256[][](1); n[0] = list; n[0][0] = 1;",
        &["FHE3015", "FHE3015"],
    );
}

/// The binder resolves a named return to `Resolution::Local`, but it is part
/// of the signature: writing it from the guard escapes the block.
#[test]
fn precondition_rejects_named_return_writes() {
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        contract P {\n\
          euint32 enc;\n\
          function g(in euint32 amount) public returns (uint256 outPlain) {\n\
            precondition { outPlain = 42; }\n\
            enc = amount;\n\
          }\n\
        }\n";
    assert_eq!(error_codes(src), vec!["FHE3015".to_string()]);
    with_checked(&[("t.fsol", src)], |c, _| {
        let d = c
            .diagnostics
            .iter()
            .find(|d| d.code == "FHE3015")
            .expect("FHE3015");
        assert!(
            d.message.contains("declared outside the block"),
            "{}",
            d.message
        );
    });
}

/// The whitelist covers "an in-unit contract or type conversion" (§2.7).
/// `payable(x)` is a Solidity primitive, and `Lib.Money(x)` / `Money.wrap(x)`
/// name a type, not a function: none of them runs user code.
#[test]
fn precondition_permits_plaintext_conversions() {
    assert_pre_codes("payable(from);", &[]);
    assert_pre_codes(
        "if (payable(from) == payable(address(0))) revert Bad(from);",
        &[],
    );
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        library Lib {\n\
          type Money is uint256;\n\
          struct Pair { uint256 a; uint256 b; }\n\
        }\n\
        contract P {\n\
          euint32 enc;\n\
          error Bad();\n\
          function g(uint256 n, in euint32 amount) public {\n\
            precondition {\n\
              uint256 back = Lib.Money.unwrap(Lib.Money.wrap(n));\n\
              Lib.Pair(back, 1);\n\
              if (back == 0) revert Bad();\n\
            }\n\
            enc = amount;\n\
          }\n\
        }\n";
    assert_eq!(error_codes(src), Vec::<String>::new());
}

/// `wrap`/`unwrap` names a type, not a function — but only a *plaintext* type
/// may be converted here. A profile encrypted type is refused however it is
/// spelled: bare (`euint32.wrap`) or qualified (`Lib.euint32.wrap`).
#[test]
fn precondition_rejects_wrap_of_an_encrypted_type() {
    let src = "pragma solidity ^0.8.25;\n\
        type euint32 is bytes32;\n\
        library Lib {\n\
          type euint64 is bytes32;\n\
          type Money is uint256;\n\
        }\n\
        contract P {\n\
          euint32 enc;\n\
          function g(bytes32 raw, uint256 n, in euint32 amount) public {\n\
            precondition {\n\
              euint32.unwrap(enc2(raw));\n\
              Lib.euint64.wrap(raw);\n\
              Lib.euint64.unwrap(Lib.euint64.wrap(raw));\n\
              Lib.Money.unwrap(Lib.Money.wrap(n));\n\
            }\n\
            enc = amount;\n\
          }\n\
          function enc2(bytes32 raw) internal pure returns (bytes32) { return raw; }\n\
        }\n";
    // Three refusals: the bare `unwrap` and both qualified forms. The
    // genuinely plaintext `Lib.Money` conversions stay legal.
    assert_eq!(error_codes(src), ["FHE3015", "FHE3015", "FHE3015"]);
}

/// The conservative default holds for everything that is not recognizably a
/// plaintext conversion.
#[test]
fn precondition_still_rejects_member_and_unresolved_calls() {
    // A member call on a state variable of an in-unit contract type.
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        interface IThing { function ok() external view returns (bool); }\n\
        library Lib { function pure_(uint256 x) internal pure returns (uint256) { return x; } }\n\
        contract P {\n\
          euint32 enc;\n\
          IThing thing;\n\
          error Bad();\n\
          function g(uint256 n, in euint32 amount) public {\n\
            precondition {\n\
              if (!thing.ok()) revert Bad();\n\
              Lib.pure_(n);\n\
            }\n\
            enc = amount;\n\
          }\n\
        }\n";
    assert_eq!(error_codes(src), ["FHE3015", "FHE3015"]);
}

#[test]
fn precondition_rejects_state_changing_and_member_calls() {
    assert_pre_codes("bump();", &["FHE3015"]);
    assert_pre_codes(
        "if (FHE.isInitialized(enc)) revert Bad(from);",
        &["FHE3015"],
    );
}

/// `view`/`pure` forbids state access, not memory mutation: a `pure` callee
/// may still write through a `memory` array/struct/`bytes`/`string`
/// argument, letting an effect escape the block by proxy instead of through
/// a direct write. `calldata` is read-only, so a callee that only takes
/// `calldata` reference parameters stays permitted.
#[test]
fn precondition_rejects_a_call_that_can_write_through_a_memory_argument() {
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        contract P {\n\
          euint32 enc;\n\
          function g(uint256[] memory list, in euint32 amount) public returns (uint256) {\n\
            precondition {\n\
              require(list.length > 0, \"empty\");\n\
              zap(list);\n\
            }\n\
            enc = amount;\n\
            return list[0];\n\
          }\n\
          function zap(uint256[] memory a) internal pure { a[0] = 42; }\n\
        }\n";
    assert_eq!(error_codes(src), ["FHE3015"]);
}

#[test]
fn precondition_permits_a_call_that_only_takes_calldata_arguments() {
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        contract P {\n\
          euint32 enc;\n\
          error Bad();\n\
          function g(uint256[] calldata list, in euint32 amount) public {\n\
            precondition {\n\
              if (!nonEmpty(list)) revert Bad();\n\
            }\n\
            enc = amount;\n\
          }\n\
          function nonEmpty(uint256[] calldata a) internal pure returns (bool) { return a.length > 0; }\n\
        }\n";
    assert_eq!(error_codes(src), Vec::<String>::new());
}

#[test]
fn precondition_rejects_imported_and_unresolved_calls() {
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        import { extCheck } from \"@vendor/Helper.sol\";\n\
        contract P {\n\
          euint32 enc;\n\
          error Bad(address who);\n\
          function g(address from, in euint32 amount) public {\n\
            precondition { if (!extCheck(from)) revert Bad(from); }\n\
            enc = amount;\n\
          }\n\
        }\n";
    assert_eq!(error_codes(src), ["FHE3015"]);
}

/// `msg.sender` is permitted in a `precondition` block (§2.7) even when the
/// contract inherits from a base the binder cannot see completely (an
/// external or unresolved import) — the ordinary shape of a real contract.
/// A builtin is a positive file-scope fact, so incomplete inheritance must
/// not replace it with `Resolution::Unresolved` and cause FHE3015.
#[test]
fn precondition_permits_msg_sender_with_an_unresolved_base() {
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        import {Base} from \"@some/pkg/Base.sol\";\n\
        contract P is Base {\n\
          euint32 enc;\n\
          mapping(address => bool) operators;\n\
          error Bad(address who);\n\
          function isOperator(address who, address spender) public view returns (bool) {\n\
            return operators[who] && operators[spender];\n\
          }\n\
          function g(address from, in euint32 amount) public {\n\
            precondition {\n\
              if (!isOperator(from, msg.sender)) revert Bad(from);\n\
            }\n\
            enc = amount;\n\
          }\n\
        }\n";
    assert_eq!(error_codes(src), Vec::<String>::new());
}

#[test]
fn precondition_rejects_unsupported_statement_forms() {
    assert_pre_codes("emit Ping(1);", &["FHE3015"]);
    assert_pre_codes("return;", &["FHE3015"]);
    assert_pre_codes(
        "for (uint256 i = 0; i < 2; i++) { plainState; }",
        &["FHE3015"],
    );
    assert_pre_codes("while (false) { }", &["FHE3015"]);
    assert_pre_codes("assembly { }", &["FHE3015"]);
    assert_pre_codes("try this.bump() { } catch { }", &["FHE3015"]);
}

#[test]
fn precondition_permits_nested_blocks_and_plaintext_if() {
    assert_pre_codes(
        "{ uint256 n = 1; if (n == 1) { if (!isOperator(from)) revert Bad(from); } }",
        &[],
    );
}

#[test]
fn precondition_late_position_is_fhe1017() {
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        contract P {\n\
          euint32 enc;\n\
          function g(uint256 z, in euint32 amount) public {\n\
            z;\n\
            precondition { z; }\n\
            enc = amount;\n\
          }\n\
        }\n";
    with_checked(&[("t.fsol", src)], |c, snip| {
        let v: Vec<&str> = c.diagnostics.iter().map(|d| d.code).collect();
        assert_eq!(v, ["FHE1017"], "{:?}", c.diagnostics);
        assert_eq!(snip(c.diagnostics[0].span), "precondition");
        assert!(c.precondition_sites.is_empty());
    });
}

#[test]
fn precondition_duplicate_is_fhe1017() {
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        contract P {\n\
          euint32 enc;\n\
          function g(in euint32 amount) public {\n\
            precondition { }\n\
            precondition { }\n\
            enc = amount;\n\
          }\n\
        }\n";
    with_checked(&[("t.fsol", src)], |c, _| {
        let v: Vec<&str> = c.diagnostics.iter().map(|d| d.code).collect();
        assert_eq!(v, ["FHE1017"], "{:?}", c.diagnostics);
        // A duplicate refuses the unit: no site survives.
        assert!(c.precondition_sites.is_empty());
    });
}

#[test]
fn nested_precondition_is_a_duplicate() {
    let src = pre_contract("precondition { }", "enc = amount;");
    with_checked(&[("t.fsol", &src)], |c, _| {
        let v: Vec<&str> = c.diagnostics.iter().map(|d| d.code).collect();
        assert_eq!(v, ["FHE1017"], "{:?}", c.diagnostics);
        assert!(c.precondition_sites.is_empty());
    });
}

#[test]
fn precondition_without_a_managed_input_is_fhe1017() {
    let bare = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        contract P { function g(address from) public { precondition { from; } } }";
    with_checked(&[("t.fsol", bare)], |c, _| {
        let v: Vec<&str> = c.diagnostics.iter().map(|d| d.code).collect();
        assert_eq!(v, ["FHE1017"], "{:?}", c.diagnostics);
        assert!(c.precondition_sites.is_empty());
    });
    // A modifier is never a legal host: it cannot carry `in` parameters.
    let modifier = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        contract P { modifier m() { precondition { } _; } }";
    with_checked(&[("t.fsol", modifier)], |c, _| {
        let v: Vec<&str> = c.diagnostics.iter().map(|d| d.code).collect();
        assert_eq!(v, ["FHE1017"], "{:?}", c.diagnostics);
    });
}

#[test]
fn no_precondition_leaves_the_sugar_untouched() {
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        contract P { euint32 enc; function g(in euint32 a) public { enc = a; } }";
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.precondition_sites.is_empty());
        assert_eq!(c.sugar_sites.len(), 1);
    });
}

// ---- the shared boundary (spec §2.8) -----------------------------------------

/// Wraps contract members in a bare unit, without the standard test contract.
fn unit(members: &str) -> String {
    format!(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         contract S {{\n\
           euint32 a;\n\
           euint64 b;\n\
           uint256 plain;\n\
         {members}\n\
         }}\n"
    )
}

fn shared_codes(members: &str) -> Vec<&'static str> {
    with_checked(&[("t.fsol", &unit(members))], |c, _| {
        c.diagnostics.iter().map(|d| d.code).collect()
    })
}

#[test]
fn shared_input_states_a_site_and_no_in_sugar_site() {
    let src = unit("function g(in shared euint32 amount) external { a = amount; }");
    with_checked(&[("t.fsol", &src)], |c, snip| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        // The §2.3 scan must not claim it: `in shared` is a different
        // expansion with a different wire type.
        assert!(c.sugar_sites.is_empty());
        assert_eq!(c.shared_input_sites.len(), 1);
        let s = &c.shared_input_sites[0];
        assert_eq!(snip(s.param_span), "in shared euint32 amount");
        assert_eq!(s.name, "amount");
        assert_eq!(s.ty.solidity_name(), "euint32");
        assert!(s.has_body);
    });
}

#[test]
fn shared_return_states_one_site_per_function_and_suppresses_r3() {
    let src = unit(
        "function g(bool c) public returns (shared(msg.sender) euint64) {\n\
           if (c) { return b; }\n\
           return b;\n\
         }",
    );
    with_checked(&[("t.fsol", &src)], |c, snip| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        assert_eq!(c.shared_return_sites.len(), 1);
        let s = &c.shared_return_sites[0];
        assert_eq!(snip(s.decl_span), "shared(msg.sender) euint64");
        assert_eq!(s.ty.solidity_name(), "euint64");
        assert_eq!(s.recipient, "msg.sender");
        assert_eq!(s.return_exprs.len(), 2);
        // §8.3 R3 must not also fire: the share call is the grant.
        assert!(c.acl.returns.is_empty());
    });
}

#[test]
fn a_shared_return_recipient_shadowed_by_a_parameter_named_msg_is_refused() {
    // Regression for issue #61: the recipient must *resolve* to the Solidity
    // builtin, not merely be spelled `msg.sender`. A parameter literally
    // named `msg` shadows the builtin, so `msg.sender` here is a
    // caller-controlled struct field, not the transaction sender.
    let src = unit(
        "struct Msg { address sender; }\n\
         function f(Msg memory msg) external returns (shared(msg.sender) euint64) {\n\
           return b;\n\
         }",
    );
    with_checked(&[("t.fsol", &src)], |c, _| {
        let d = c
            .diagnostics
            .iter()
            .find(|d| d.code == "FHE1015")
            .unwrap_or_else(|| panic!("expected FHE1015, got {:?}", c.diagnostics));
        assert_eq!(d.severity, Severity::Error);
        assert_eq!(
            d.message,
            "the only recipient this version accepts is `msg.sender`; the transpiler cannot \
             prove another expression names the caller"
        );
        assert!(
            c.shared_return_sites.is_empty(),
            "a shadowed recipient must not become a legal site"
        );
    });
}

#[test]
fn a_shared_return_recipient_shadowed_by_a_body_local_msg_is_refused() {
    // Regression for issue #61 (follow-up): the header recipient resolves
    // to the builtin fine (nothing named `msg` is in scope yet at the
    // header), but the lowerer re-emits the literal text `msg.sender` at
    // every `return`, so a local declared later in the body — even after
    // the point the header itself was checked — must still be refused: it
    // shadows the builtin from its declaration onward, and a `return` past
    // it would read the local instead of the real sender.
    let src = unit(
        "struct Msg { address sender; }\n\
         function f(bool c) external returns (shared(msg.sender) euint64) {\n\
           if (c) {\n\
             Msg memory msg;\n\
             msg.sender = address(0);\n\
             return b;\n\
           }\n\
           return b;\n\
         }",
    );
    with_checked(&[("t.fsol", &src)], |c, _| {
        let d = c
            .diagnostics
            .iter()
            .find(|d| d.code == "FHE1015")
            .unwrap_or_else(|| panic!("expected FHE1015, got {:?}", c.diagnostics));
        assert_eq!(d.severity, Severity::Error);
        assert!(
            d.message.contains("declares a local named `msg`"),
            "{:?}",
            d.message
        );
        assert!(c.shared_return_sites.is_empty());
    });
}

#[test]
fn a_shared_return_recipient_shadowed_by_a_try_catch_binder_named_msg_is_refused() {
    // Same hazard as the body-local case, via a `try`/`catch` binder rather
    // than an ordinary declaration.
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        interface IVault {\n\
          function pull() external returns (bytes memory);\n\
        }\n\
        contract S {\n\
          euint64 b;\n\
          IVault vault;\n\
          function f() external returns (shared(msg.sender) euint64) {\n\
            try vault.pull() returns (bytes memory msg) {\n\
              msg;\n\
              return b;\n\
            } catch {\n\
              return b;\n\
            }\n\
          }\n\
        }\n";
    with_checked(&[("t.fsol", src)], |c, _| {
        let d = c
            .diagnostics
            .iter()
            .find(|d| d.code == "FHE1015")
            .unwrap_or_else(|| panic!("expected FHE1015, got {:?}", c.diagnostics));
        assert_eq!(d.severity, Severity::Error);
        assert!(
            d.message.contains("declares a local named `msg`"),
            "{:?}",
            d.message
        );
        assert!(c.shared_return_sites.is_empty());
    });
}

#[test]
fn a_shared_return_recipient_shadowed_by_an_own_state_variable_named_msg_is_refused() {
    // A state variable named `msg` is the contract's own member, resolved
    // before the builtin fallback is ever consulted — the primary
    // (header-recipient) check already refuses it, with no need for the
    // body-declaration scan.
    let src = unit(
        "address msg;\n\
         function f() external returns (shared(msg.sender) euint64) {\n\
           return b;\n\
         }",
    );
    with_checked(&[("t.fsol", &src)], |c, _| {
        let d = c
            .diagnostics
            .iter()
            .find(|d| d.code == "FHE1015")
            .unwrap_or_else(|| panic!("expected FHE1015, got {:?}", c.diagnostics));
        assert_eq!(d.severity, Severity::Error);
        assert_eq!(
            d.message,
            "the only recipient this version accepts is `msg.sender`; the transpiler cannot \
             prove another expression names the caller"
        );
        assert!(c.shared_return_sites.is_empty());
    });
}

#[test]
fn an_in_unit_base_declaring_msg_is_refused_even_behind_an_opaque_base() {
    // Guards the `IncompleteInheritance` fallback trust (used so a
    // `shared(msg.sender)` return stays legal under a package base) against
    // waving through a *real*, in-unit shadow. Solidity gives the rightmost
    // direct base precedence, so `Base` — listed last — is the one member
    // the binder can certify despite the opaque `ReentrancyGuardTransient`
    // earlier in the list; its `msg` member resolves positively and must
    // never fall back to "what file scope would have said".
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        import {ReentrancyGuardTransient} from \"@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol\";\n\
        contract Base {\n\
          address msg;\n\
        }\n\
        contract Derived is ReentrancyGuardTransient, Base {\n\
          euint64 b;\n\
          function f() external returns (shared(msg.sender) euint64) {\n\
            return b;\n\
          }\n\
        }\n";
    with_checked(&[("t.fsol", src)], |c, _| {
        let d = c
            .diagnostics
            .iter()
            .find(|d| d.code == "FHE1015")
            .unwrap_or_else(|| panic!("expected FHE1015, got {:?}", c.diagnostics));
        assert_eq!(d.severity, Severity::Error);
        assert_eq!(
            d.message,
            "the only recipient this version accepts is `msg.sender`; the transpiler cannot \
             prove another expression names the caller"
        );
        assert!(c.shared_return_sites.is_empty());
    });
}

#[test]
fn an_ordinary_encrypted_return_still_states_an_r3_fact() {
    // Guards the suppression above against over-reach.
    let src = unit("function g() public returns (euint64) { return b; }");
    with_checked(&[("t.fsol", &src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        assert!(c.shared_return_sites.is_empty());
        assert_eq!(c.acl.returns.len(), 1);
    });
}

#[test]
fn a_bodiless_shared_declaration_states_a_site_with_no_returns() {
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        interface I {\n\
          function g(in shared euint32 amount) external;\n\
          function h() external returns (shared(msg.sender) euint64);\n\
        }";
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        assert_eq!(c.shared_input_sites.len(), 1);
        assert!(!c.shared_input_sites[0].has_body);
        assert_eq!(c.shared_return_sites.len(), 1);
        assert!(c.shared_return_sites[0].return_exprs.is_empty());
    });
}

#[test]
fn illegal_shared_positions_are_fhe1015() {
    for members in [
        // Kind, visibility, and mutability of a shared input. `public` is
        // illegal as well: a public function is callable internally, and
        // lowering rewrites the declaration alone, so an internal call site
        // would still pass the unshared `eT`.
        "function g(in shared euint32 amount) internal { a = amount; }",
        "function g(in shared euint32 amount) private { a = amount; }",
        "function g(in shared euint32 amount) public { a = amount; }",
        "function g(in shared euint32 amount) external view { amount; }",
        "function g(in shared euint32 amount) external pure { amount; }",
        "constructor(in shared euint32 amount) { a = amount; }",
        "modifier m(in shared euint32 amount) { _; }",
        // The MVP mixing rule.
        "function g(in shared euint32 s, in euint32 e) external { a = s; a = e; }",
        "function g(in(p) shared euint32 s, bytes calldata p) external { a = s; p; }",
        // Shape of a shared input.
        "function g(in shared(msg.sender) euint32 s) external { a = s; }",
        "function g(in shared uint256 s) external { s; }",
        // An encrypted type is a value type: no data location applies, and
        // the declaration rewrite must not drop the keyword in silence.
        "function g(in shared euint32 calldata s) external { a = s; }",
        "function g(in shared euint32 memory s) external { a = s; }",
        // Kind, visibility, and mutability of a shared return.
        "function g() internal returns (shared(msg.sender) euint64) { return b; }",
        "function g() public view returns (shared(msg.sender) euint64) { return b; }",
        // Shape of a shared return.
        "function g() public returns (shared(msg.sender) euint64 out) { out = b; }",
        "function g() public returns (shared(msg.sender) euint64, uint256) { return (b, 1); }",
        "function g() public returns (shared(msg.sender) uint256) { return 1; }",
        "function g() public returns (shared(msg.sender) euint64 memory) { return b; }",
        "address owner;\nfunction g() public returns (shared(owner) euint64) { return b; }",
        // Statement shape inside a shared-return function.
        "function g() public returns (shared(msg.sender) euint64) { return; }",
        "function g(bool c) public returns (shared(msg.sender) euint64) { if (c) return b; return b; }",
        "function g() public returns (shared(msg.sender) euint64) { return b = b; }",
    ] {
        let got = shared_codes(members);
        assert_eq!(got, ["FHE1015"], "members: {members}");
        with_checked(&[("t.fsol", &unit(members))], |c, _| {
            assert!(c.shared_input_sites.is_empty(), "members: {members}");
            assert!(c.shared_return_sites.is_empty(), "members: {members}");
        });
    }
}

#[test]
fn a_shared_marker_in_a_try_declaration_list_is_fhe1015() {
    // Solar parses the success clause's `returns (...)` list and every `catch`
    // clause's argument list with the ordinary parameter grammar, so a marker
    // can be written in either. Neither list is reachable from a function
    // header, so the checker must find them by walking the body — otherwise
    // the raw marker text leaks into the generated Solidity unlowered.
    for members in [
        "function g() public {\n\
           try this.h() returns (shared(msg.sender) euint64 got) { got; } catch {}\n\
         }\n\
         function h() external returns (euint64) { return b; }",
        "function g() public {\n\
           try this.h() returns (euint64 got) { got; }\n\
           catch Error(in shared euint64 reason) { reason; }\n\
         }\n\
         function h() external returns (euint64) { return b; }",
    ] {
        assert_eq!(shared_codes(members), ["FHE1015"], "members: {members}");
    }
}

#[test]
fn a_shared_marker_in_a_local_declaration_is_a_parse_error() {
    // The counterpart of the rule above: solar's statement grammar never
    // reaches the marker in a local declaration, tuple or not, so there is
    // nothing for the checker to flag. Pinned so a later grammar change that
    // starts accepting the shape does not slip past the legality scan.
    for members in [
        "function g() public { shared(msg.sender) euint64 x = b; x; }",
        "function g() public { (shared(msg.sender) euint64 x, uint256 y) = (b, 1); x; y; }",
    ] {
        let src = unit(members);
        assert!(
            fhec_syntax::with_parsed_source("t.fsol", &src, |_| ()).is_err(),
            "members: {members}"
        );
    }
}

#[test]
fn the_generated_wire_name_must_be_free() {
    for members in [
        "function g(in shared euint32 amount) external { uint256 amount_shared = 1; a = amount; amount_shared; }",
        "function g(in shared euint32 amount, uint256 amount_shared) external { a = amount; amount_shared; }",
    ] {
        assert_eq!(shared_codes(members), ["FHE1016"], "members: {members}");
    }
}

#[test]
fn a_shared_return_must_return_exactly_its_declared_type() {
    for members in [
        // A different encrypted width.
        "function g() public returns (shared(msg.sender) euint32) { return b; }",
        // A plaintext value.
        "function g() public returns (shared(msg.sender) euint64) { return plain; }",
        // A value the checker cannot type (§1.3: refuse rather than guess).
        "function g() public returns (shared(msg.sender) euint64) { return unknownFn(); }",
    ] {
        assert_eq!(shared_codes(members), ["FHE2012"], "members: {members}");
    }
}

#[test]
fn a_call_to_a_shared_return_types_as_unknown_at_its_call_site() {
    // The binder resolves a shared return's declared type so the FHE2012 rule
    // above can compare against it. Call-site inference must NOT inherit that:
    // what the call actually yields is the `sharedT` wire handle, so an
    // encrypted operand meeting it is FHE2001, never `FHE.add(take(), b)`.
    let members = "function take() public returns (shared(msg.sender) euint64) { return b; }\n\
                   function use() public { b = take() + b; }";
    assert_eq!(shared_codes(members), ["FHE2001"], "members: {members}");
    // The two rules are separate code paths: `take`'s own statement-shape
    // check is unaffected and the site still stands.
    with_checked(&[("t.fsol", &unit(members))], |c, _| {
        assert_eq!(c.shared_return_sites.len(), 1);
    });
}

#[test]
fn a_plain_encrypted_return_still_types_at_its_call_site() {
    // Only a `shared(...)` return is opaque. Naming an ordinary return is a
    // Solidity style choice, so both forms must preserve the declared call
    // type and let an encrypted operator use it.
    for members in [
        "function take() public returns (euint64) { return b; }\n\
         function use() public { b = take() + b; }",
        "function take() public returns (euint64 out) { out = b; }\n\
         function use() public { b = take() + b; }",
    ] {
        assert!(shared_codes(members).is_empty(), "members: {members}");
        with_checked(&[("t.fsol", &unit(members))], |c, _| {
            assert_eq!(c.operator_sites.len(), 1, "members: {members}");
        });
    }
}

#[test]
fn shared_returns_accept_calls_with_named_or_unnamed_return_parameters() {
    let members = "function a1(euint64 value) internal returns (euint64) { return value; }\n\
                   function a2(euint64 value) internal returns (euint64 out) { return value; }\n\
                   function c1(euint64 value) external returns (shared(msg.sender) euint64) { return a1(value); }\n\
                   function c2(euint64 value) external returns (shared(msg.sender) euint64) { return a2(value); }";
    with_checked(&[("t.fsol", &unit(members))], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        assert_eq!(c.shared_return_sites.len(), 2);
    });
}

#[test]
fn incomplete_inheritance_keeps_inherited_members_in_the_known_prefix() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";
        import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

        library L {
            function pub(euint64 value) internal returns (euint64 out) { out = value; }
        }
        contract TClean {
            function c1(euint64 value) external returns (shared(msg.sender) euint64) {
                return L.pub(value);
            }
        }
        contract HelperBase is ReentrancyGuardTransient {
            function helper(euint64 value) internal returns (euint64) { return value; }
        }
        contract Derived is HelperBase {
            function c1(euint64 value) external returns (shared(msg.sender) euint64) {
                return helper(value);
            }
        }
    "#;
    // `helper` is declared by the in-unit base that precedes every opaque
    // base in the linearization, so it resolves and the shared return types.
    // This is the shape a real contract hits: a helper on a base that itself
    // inherits from node_modules.
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        assert_eq!(c.shared_return_sites.len(), 2);
    });
}

#[test]
fn a_file_scope_name_under_an_unseen_base_warns_but_still_rewrites() {
    // An inherited member shadows a file-scope name, so under an unseen base
    // `L` cannot be resolved positively (spec §1.3). The shared return is
    // still rewritten: it takes the encrypted type from the declaration, so
    // solc checks the assumption (spec §2.8).
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";
        import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

        library L {
            function pub(euint64 value) internal returns (euint64 out) { out = value; }
        }
        contract TDirty is ReentrancyGuardTransient {
            function c1(euint64 value) external returns (shared(msg.sender) euint64) {
                return L.pub(value);
            }
        }
    "#;
    with_checked(&[("t.fsol", src)], |c, _| {
        let d = c
            .diagnostics
            .iter()
            .find(|d| d.code == "FHE2012")
            .unwrap_or_else(|| panic!("expected FHE2012, got {:?}", c.diagnostics));
        assert_eq!(d.severity, Severity::Warning);
        assert!(!c.has_errors(), "{:?}", c.diagnostics);
        assert_eq!(
            c.shared_return_sites.len(),
            1,
            "the site must still be stated"
        );
    });
}

#[test]
fn a_proven_type_mismatch_on_a_shared_return_stays_an_error() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";

        contract C {
            function bad(uint256 p) external returns (shared(msg.sender) euint64) {
                return p;
            }
        }
    "#;
    with_checked(&[("t.fsol", src)], |c, _| {
        let d = c
            .diagnostics
            .iter()
            .find(|d| d.code == "FHE2012")
            .unwrap_or_else(|| panic!("expected FHE2012, got {:?}", c.diagnostics));
        assert_eq!(d.severity, Severity::Error);
        assert!(c.shared_return_sites.is_empty());
    });
}

#[test]
fn unseen_base_call_stays_unknown_and_explains_why() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";
        import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

        contract TDirty is ReentrancyGuardTransient {
            function c1(euint64 value) external returns (shared(msg.sender) euint64) {
                return couldBeInherited(value);
            }
        }
    "#;
    with_checked(&[("t.fsol", src)], |c, _| {
        assert_eq!(c.diagnostics.len(), 1, "{:?}", c.diagnostics);
        assert_eq!(c.diagnostics[0].code, "FHE2012");
        assert_eq!(c.diagnostics[0].severity, Severity::Warning);
        assert!(
            c.diagnostics[0].message.starts_with(
                "this function shares `euint64`, but `couldBeInherited` resolves to `Unknown` \
                 because contract `TDirty` inherits `ReentrancyGuardTransient`, which is \
                 outside the compilation unit"
            ),
            "{}",
            c.diagnostics[0].message
        );
        // The site is still stated: the rewrite reads the declared type, and
        // solc checks the assumption (spec §2.8).
        assert_eq!(c.shared_return_sites.len(), 1);
    });
}

/// Wraps contract members in a unit that also declares a vault interface, for
/// the §8.2 R2 interaction below.
fn vault_unit(members: &str) -> String {
    format!(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         interface IVault {{\n\
           function pull(euint64 v) external returns (euint64);\n\
           function idx(euint64 v) external returns (uint256);\n\
           function tag(uint256 t) external returns (uint256);\n\
         }}\n\
         contract S {{\n\
           euint64 b;\n\
           euint64 fee;\n\
           ebool flag;\n\
           euint64[] vals;\n\
           IVault vault;\n\
         {members}\n\
         }}\n"
    )
}

fn vault_codes(members: &str) -> Vec<&'static str> {
    with_checked(&[("t.fsol", &vault_unit(members))], |c, _| {
        c.diagnostics.iter().map(|d| d.code).collect()
    })
}

#[test]
fn a_shared_return_refuses_a_rewrite_site_the_r2_rule_would_swallow() {
    // §8.2 R2 owns the whole statement it anchors on: it renders its own call
    // site and pass 1 then skips every statement inside that span. While R3
    // applied, its whole-statement re-render happened to cover the returned
    // expression; a shared return suppresses R3 (§8.3) and wraps in place, so
    // nothing lowers the expression any more. Refuse rather than emit a
    // silently unlowered operator (§1.3).
    for members in [
        // The R2 fact anchors on the enclosing `try`, which contains the
        // `return`.
        "function g() public returns (shared(msg.sender) euint64) {\n\
           try vault.pull(b) returns (euint64 pulled) { return pulled - fee; }\n\
           catch { return fee; }\n\
         }",
        // The R2 fact anchors on the `return` statement itself.
        "function g() public returns (shared(msg.sender) euint64) {\n\
           return vals[vault.idx(b)] + fee;\n\
         }",
        // A ternary is a rewrite site too (§5.4).
        "function g() public returns (shared(msg.sender) euint64) {\n\
           try vault.pull(b) returns (euint64 pulled) { return flag ? pulled : fee; }\n\
           catch { return fee; }\n\
         }",
    ] {
        assert_eq!(vault_codes(members), ["FHE1015"], "members: {members}");
        with_checked(&[("t.fsol", &vault_unit(members))], |c, _| {
            assert!(c.shared_return_sites.is_empty(), "members: {members}");
        });
    }
}

#[test]
fn a_shared_return_with_nothing_left_to_lower_survives_an_r2_statement() {
    // The regression guard for the rule above: R2's own call site is the only
    // rewrite the statement needs, and R2 renders it itself. Nothing is at
    // risk, so the site must still be stated.
    let members = "function g() public returns (shared(msg.sender) euint64) {\n\
                     try vault.pull(b) returns (euint64 pulled) { return pulled; }\n\
                     catch { return fee; }\n\
                   }";
    assert!(vault_codes(members).is_empty(), "members: {members}");
    with_checked(&[("t.fsol", &vault_unit(members))], |c, snip| {
        assert_eq!(c.acl.external_args.len(), 1, "the R2 fact must still stand");
        assert_eq!(c.shared_return_sites.len(), 1);
        let exprs = &c.shared_return_sites[0].return_exprs;
        assert_eq!(
            exprs.iter().map(|s| snip(*s)).collect::<Vec<_>>(),
            ["pulled", "fee"]
        );
    });
}

#[test]
fn a_shared_return_without_any_r2_fact_is_untouched_by_the_rule() {
    // The common case: operators in the returned expression lower normally
    // because no R2 fact owns the statement.
    for members in [
        "function g() public returns (shared(msg.sender) euint64) { return b + fee; }",
        "function g() public returns (shared(msg.sender) euint64) { return flag ? b : fee; }",
        // An external call with no encrypted argument states no R2 fact.
        "function g() public returns (shared(msg.sender) euint64) {\n\
           return vals[vault.tag(1)] + fee;\n\
         }",
    ] {
        assert!(vault_codes(members).is_empty(), "members: {members}");
        with_checked(&[("t.fsol", &vault_unit(members))], |c, _| {
            assert!(c.acl.external_args.is_empty(), "members: {members}");
            assert_eq!(c.shared_return_sites.len(), 1, "members: {members}");
            assert_eq!(c.operator_sites.len() + c.ternary_sites.len(), 1);
        });
    }
}

#[test]
fn shared_stays_an_ordinary_identifier_in_the_checker_too() {
    // §1.4: plain Solidity naming a variable `shared` produces no site and no
    // diagnostic.
    let members = "uint256 shared;\n\
                   function g(uint256 shared_) public { shared = shared_; }";
    assert!(shared_codes(members).is_empty());
}

// ---- helpers referenced from bodies ------------------------------------------

// `unknownFn`, `stateWriterB`, `fhelperWrite`, `plainStateRead` are
// deliberately undeclared in the test contract: they resolve to Unknown
// (MaybeExternal through the profile import), which is exactly the
// degradation under test.

/// Diagnostic codes for a whole source file, sorted.
fn codes_for_source(src: &str) -> Vec<String> {
    with_checked(&[("t.fsol", src)], |c, _| {
        let mut v: Vec<String> = c.diagnostics.iter().map(|d| d.code.to_string()).collect();
        v.sort();
        v
    })
}

#[test]
fn modifier_invocation_naming_an_in_parameter_rejects_with_fhe1019() {
    // The modifier invocation is evaluated in the header, where the
    // parameter is `amount_input`; `amount` only exists in the body.
    let src = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               contract C {\n\
               \x20   euint32 stored;\n\
               \x20   modifier guard(euint32 v) { _; }\n\
               \x20   function f(in euint32 amount) public guard(amount) { stored = amount; }\n\
               }\n";
    let codes = codes_for_source(src);
    assert!(
        codes.iter().any(|c| c == "FHE1019"),
        "expected FHE1019, got {codes:?}"
    );
}

#[test]
fn modifier_invocation_not_naming_the_parameter_is_accepted() {
    let src = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               contract C {\n\
               \x20   euint32 stored;\n\
               \x20   modifier guard(uint256 v) { _; }\n\
               \x20   function f(in euint32 amount, uint256 cap) public guard(cap) { stored = amount; }\n\
               }\n";
    let codes = codes_for_source(src);
    assert!(
        !codes.iter().any(|c| c == "FHE1019"),
        "expected no FHE1019, got {codes:?}"
    );
}

#[test]
fn modifier_invocation_naming_an_in_shared_parameter_rejects_with_fhe1019() {
    let src = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               contract C {\n\
               \x20   euint32 stored;\n\
               \x20   modifier guard(euint32 v) { _; }\n\
               \x20   function f(in shared euint32 amount) external guard(amount) { stored = amount; }\n\
               }\n";
    let codes = codes_for_source(src);
    assert!(
        codes.iter().any(|c| c == "FHE1019"),
        "expected FHE1019, got {codes:?}"
    );
}

#[test]
fn a_file_scope_name_under_an_unseen_base_keeps_branch_legality() {
    // Regression: resolving the file-scope `Helper` here would classify the
    // call as a builtin and skip the §7 branch legality check, so the
    // side effect of the base's `Helper(...)` would run unconditionally
    // after the encrypted `if` is flattened.
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";
        import {ExternalBase} from "@vendor/External.sol";

        struct Helper { uint256 a; }

        contract Vault is ExternalBase {
            function f(euint64 x, ebool c) public returns (euint64) {
                euint64 y = x;
                if (c) {
                    Helper(1);
                    y = FHE.add(x, x);
                }
                return y;
            }
        }
    "#;
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(
            c.diagnostics.iter().any(|d| d.code == "FHE3008"),
            "an unverified call in an encrypted branch must be refused: {:?}",
            c.diagnostics
        );
    });
}

#[test]
fn an_unnamed_return_type_reaches_operator_lowering() {
    // The unnamed-return fix makes the call's type a fact, so an operator
    // over it lowers instead of refusing with FHE2001.
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";

        contract C {
            function g(euint64 v) internal returns (euint64) { return v; }
            function f(euint64 x) public returns (euint64) {
                return g(x) + x;
            }
        }
    "#;
    with_checked(&[("t.fsol", src)], |c, _| {
        assert!(c.diagnostics.is_empty(), "{:?}", c.diagnostics);
        assert_eq!(c.operator_sites.len(), 1);
    });
}

#[test]
fn a_selective_import_missing_the_source_type_rejects_with_fhe1021() {
    let src = "pragma solidity ^0.8.25;\n\
               import { sharedEbool, sharedEuint64 } from \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               interface I {\n\
               \x20   function onReceive(in shared euint64 amount) external returns (bytes4);\n\
               }\n";
    let codes = codes_for_source(src);
    assert_eq!(codes, vec!["FHE1021".to_string()], "{codes:?}");
}

#[test]
fn a_selective_import_missing_the_wire_type_rejects_with_fhe1021() {
    let src = "pragma solidity ^0.8.25;\n\
               import { FHE, euint64 } from \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               contract C {\n\
               \x20   euint64 stored;\n\
               \x20   function deposit(in euint64 amount) public { stored = amount; }\n\
               }\n";
    let codes = codes_for_source(src);
    assert_eq!(codes, vec!["FHE1021".to_string()], "{codes:?}");
}

#[test]
fn a_plain_import_needs_no_named_symbols() {
    let src = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               contract C {\n\
               \x20   euint64 stored;\n\
               \x20   function deposit(in euint64 amount) public { stored = amount; }\n\
               \x20   function receiveShared(in shared euint64 amount) external { stored = amount; }\n\
               }\n";
    let codes = codes_for_source(src);
    assert!(codes.is_empty(), "{codes:?}");
}

#[test]
fn a_complete_selective_import_is_accepted() {
    let src = "pragma solidity ^0.8.25;\n\
               import { FHE, euint64, externalEuint64 } from \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               contract C {\n\
               \x20   euint64 stored;\n\
               \x20   function deposit(in euint64 amount) public { stored = amount; }\n\
               }\n";
    let codes = codes_for_source(src);
    assert!(codes.is_empty(), "{codes:?}");
}

#[test]
fn an_unmodelled_profile_call_under_an_unseen_base_stays_an_error() {
    // The `Unknown` here comes from the profile not modelling the operation,
    // not from the unreadable base, and solc will not catch it — so the
    // FHE2012 warning must not extend to it (spec §2.8 restriction 8).
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";
        import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

        contract C is ReentrancyGuardTransient {
            function f(euint64 x) external returns (shared(msg.sender) euint64) {
                return FHE.thisOpIsNotModelled(x);
            }
        }
    "#;
    with_checked(&[("t.fsol", src)], |c, _| {
        let d = c
            .diagnostics
            .iter()
            .find(|d| d.code == "FHE2012")
            .unwrap_or_else(|| panic!("expected FHE2012, got {:?}", c.diagnostics));
        assert_eq!(d.severity, Severity::Error);
        assert!(c.shared_return_sites.is_empty());
    });
}

#[test]
fn a_precondition_may_call_require_under_an_unseen_base() {
    // Every name degrades under an incomplete linearization, `require`
    // included. Without restoring the builtin, a `precondition` block is
    // unusable in any contract that inherits from a package.
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";
        import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

        contract T is ReentrancyGuardTransient {
            euint32 v;
            function f(in euint32 amount) public {
                precondition {
                    require(true, "no");
                }
                v = amount;
            }
        }
    "#;
    let codes = codes_for_source(src);
    assert!(codes.is_empty(), "{codes:?}");
}

#[test]
fn a_precondition_refuses_an_inherited_call_whose_overloads_are_hidden() {
    // Solidity unions overloads across the whole linearization, so the known
    // prefix is a lower bound. A `view` overload here must not license the
    // state-changing one an unseen base may add.
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";
        import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

        contract Base {
            function helper(bool x) internal pure returns (uint256) { return x ? 1 : 0; }
        }
        contract T is ReentrancyGuardTransient, Base {
            euint32 v;
            function f(in euint32 amount) public {
                precondition {
                    uint256 g = helper(true);
                    require(g == 1, "no");
                }
                v = amount;
            }
        }
    "#;
    let codes = codes_for_source(src);
    assert!(codes.iter().any(|c| c == "FHE3015"), "{codes:?}");
}

#[test]
fn a_precondition_keeps_an_inherited_call_when_every_base_is_visible() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";

        contract Base {
            function helper(bool x) internal pure returns (uint256) { return x ? 1 : 0; }
        }
        contract T is Base {
            euint32 v;
            function f(in euint32 amount) public {
                precondition {
                    uint256 g = helper(true);
                    require(g == 1, "no");
                }
                v = amount;
            }
        }
    "#;
    let codes = codes_for_source(src);
    assert!(codes.is_empty(), "{codes:?}");
}

// ---- FHE1022: `FHE` shadowed at a generated-call insertion point --------------

/// The repro from issue #60: a state variable named `FHE` shadows the
/// profile library in the same contract a generated call would use it in.
#[test]
fn fhe1022_state_var_shadows_the_library() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";

        contract FakeLib {
            function add(euint32 x, euint32 y) external returns (euint32) { return x; }
        }
        contract Victim {
            euint32 a;
            euint32 b;
            FakeLib FHE;
            function f() external returns (euint32) {
                return a + b;
            }
        }
    "#;
    assert_eq!(codes_for_source(src), ["FHE1022"]);
}

/// A local variable named `FHE`, declared anywhere in the function, shadows
/// the library for the whole function (a safe over-approximation of the
/// live block scope).
#[test]
fn fhe1022_local_shadows_the_library() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";

        contract FakeLib {
            function add(euint32 x, euint32 y) external returns (euint32) { return x; }
        }
        contract Victim {
            euint32 a;
            euint32 b;
            function f() external returns (euint32) {
                FakeLib FHE = FakeLib(address(0));
                return a + b;
            }
        }
    "#;
    assert_eq!(codes_for_source(src), ["FHE1022"]);
}

/// A parameter named `FHE` shadows the library for the whole function.
#[test]
fn fhe1022_param_shadows_the_library() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";

        contract FakeLib {
            function add(euint32 x, euint32 y) external returns (euint32) { return x; }
        }
        contract Victim {
            euint32 a;
            euint32 b;
            function f(FakeLib FHE) external returns (euint32) {
                return a + b;
            }
        }
    "#;
    assert_eq!(codes_for_source(src), ["FHE1022"]);
}

/// A same-named local in an unrelated function of the same contract must
/// not refuse a function that never needs a generated `FHE.` call itself.
#[test]
fn fhe1022_is_scoped_to_the_function_that_needs_the_call() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";

        contract FakeLib {}
        contract C {
            euint32 a;
            euint32 b;
            function untouched() external pure returns (uint256) {
                FakeLib FHE = FakeLib(address(0));
                return 1;
            }
            function f() external returns (euint32) {
                return a + b;
            }
        }
    "#;
    assert!(codes_for_source(src).is_empty());
}

/// Regression: an in-unit `bytes32` UDVT literally named `euint32`, with no
/// `FHE` binding anywhere (no library, no import), types as encrypted
/// through the checker's permissive in-unit-UDVT trust path — but `FHE`
/// resolving to nothing at all (not to a competing declaration) must not be
/// reported as FHE1022; it is a loud undefined-identifier failure at solc,
/// not the silent-miscompile risk this rule guards against.
#[test]
fn fhe1022_does_not_fire_when_fhe_has_no_binding_at_all() {
    let src = r#"
        pragma solidity ^0.8.25;
        type euint32 is bytes32;
        contract C {
            euint32 a;
            euint32 b;
            function f(in euint32 amount) public {
                a = amount;
            }
        }
    "#;
    let codes = codes_for_source(src);
    assert!(!codes.iter().any(|c| c == "FHE1022"), "{codes:?}");
}

/// A named return variable named `FHE` shadows the library for the whole
/// function, same as any other local.
#[test]
fn fhe1022_named_return_shadows_the_library() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";

        contract FakeLib {
            function add(euint32 x, euint32 y) external returns (euint32) { return x; }
        }
        contract Victim {
            euint32 a;
            euint32 b;
            function f() external returns (FakeLib FHE) {
                a = a + b;
            }
        }
    "#;
    assert_eq!(codes_for_source(src), ["FHE1022"]);
}

/// A constructor parameter named `FHE` shadows the library for the R1
/// storage-write ACL grant the constructor body needs.
#[test]
fn fhe1022_constructor_param_shadows_the_library() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";

        contract FakeLib {}
        contract Victim {
            euint32 a;
            constructor(FakeLib FHE, in euint32 amount) {
                a = amount;
            }
        }
    "#;
    assert_eq!(codes_for_source(src), ["FHE1022"]);
}

/// Critical regression (issue #60 review): an unresolvable/external base
/// leaves `FHE` as `Unresolved(IncompleteInheritance)`, and when the
/// fallback is ALSO untrusted (no plain import of the profile anywhere,
/// only the in-unit UDVT bypass that types `euint32` independently of any
/// import), the unseen base is the only possible source of `FHE` — this
/// must refuse, not silently defer like the `NotFound` case.
#[test]
fn fhe1022_unseen_base_without_a_confirmed_import_is_refused() {
    let src = r#"
        pragma solidity ^0.8.25;
        import {UnseenBase} from "@external-lib/pkg/UnseenBase.sol";

        contract KnownBase {
            type euint32 is bytes32;
            euint32 a;
            euint32 b;
        }
        contract Victim is UnseenBase, KnownBase {
            function f() external returns (euint32) {
                return a + b;
            }
        }
    "#;
    assert_eq!(codes_for_source(src), ["FHE1022"]);
}

/// The same unseen-base shape, but the file also plain-imports the profile
/// library — the exact shape of the original issue's repro family. The
/// binder's own fallback policy (`trust.rs` rule 3) already gives this the
/// benefit of the doubt to avoid refusing every inheriting contract, and
/// `emit_trust` must preserve that: it must not refuse merely because an
/// unseen base exists.
#[test]
fn fhe1022_incomplete_inheritance_with_a_confirmed_import_is_trusted() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";
        import {UnseenBase} from "@external-lib/pkg/UnseenBase.sol";

        contract Victim is UnseenBase {
            euint32 a;
            euint32 b;
            function f() external returns (euint32) {
                return a + b;
            }
        }
    "#;
    let codes = codes_for_source(src);
    assert!(!codes.iter().any(|c| c == "FHE1022"), "{codes:?}");
}

/// Critical regression (issue #60 review): a plain import of an unrelated,
/// untrusted file (not the profile) makes `FHE` resolve as
/// `Unresolved(MaybeExternal)`. That import's contents are invisible to the
/// binder and could define anything under that name — this must refuse, the
/// same as any other untrusted `Unresolved` reason besides `NotFound`.
#[test]
fn fhe1022_untrusted_plain_import_is_refused() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "attacker.sol";

        type euint32 is bytes32;

        contract Victim {
            euint32 a;
            euint32 b;
            function f() external returns (euint32) {
                return a + b;
            }
        }
    "#;
    assert_eq!(codes_for_source(src), ["FHE1022"]);
}

/// The batch `in`-sugar materializer's `Impl`/`Utils`/`UnsignedEncryptedInput`
/// identifiers (issue #79) get the same emit-time trust check as `FHE`: a
/// state variable named `Impl` shadows the batch materializer's own call.
#[test]
fn fhe1022_batch_materializer_impl_is_shadowed() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";

        contract FakeImpl {}
        contract Victim {
            FakeImpl Impl;
            function f(in ebool flag, in eaddress owner_) public {}
        }
    "#;
    assert_eq!(codes_for_source(src), ["FHE1022"]);
}

/// A single (non-batch) `in` parameter never reaches the batch materializer,
/// so a state variable named `Impl` alongside it must not be flagged.
#[test]
fn fhe1022_single_in_param_does_not_check_the_batch_materializer_names() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";

        contract FakeImpl {}
        contract Victim {
            FakeImpl Impl;
            function f(in ebool flag) public {}
        }
    "#;
    assert!(codes_for_source(src).is_empty());
}

/// PROBE (round-3 review item 1): an in-unit FHE.sol stand-in declaring
/// `library Impl` and `library Utils` alongside `library FHE`, plain-imported
/// by the victim file — the real profile-library shape when the profile file
/// is part of the compilation unit. Multi-param `in` sugar here must not be
/// spuriously refused: `Impl`/`Utils` resolve to `Resolution::Contract` from
/// the same trusted import, not `Unresolved`.
#[test]
fn probe_fhe1022_in_unit_fhe_sol_with_batch_sugar() {
    let fhe_sol = r#"
        pragma solidity ^0.8.25;
        type ebool is bytes32;
        type eaddress is bytes32;
        library FHE {
            function select(ebool c, ebool a, ebool b) internal pure returns (ebool) { return a; }
            function allowThis(ebool v) internal pure {}
        }
        library Impl {
            function verifyBatchInputs(uint256[] memory, bytes memory) internal pure returns (bytes32[] memory r) {}
        }
        library Utils {
            uint8 constant EBOOL_TFHE = 0;
            uint8 constant EADDRESS_TFHE = 1;
        }
        struct UnsignedEncryptedInput { uint256 data; uint8 securityZone; uint8 utype; }
    "#;
    let victim = r#"
        pragma solidity ^0.8.25;
        import "./FHE.sol";
        contract Victim {
            function f(in ebool flag, in eaddress owner_) public {}
        }
    "#;
    with_checked(&[("FHE.sol", fhe_sol), ("Victim.fsol", victim)], |c, _| {
        let mut v: Vec<String> = c.diagnostics.iter().map(|d| d.code.to_string()).collect();
        v.sort();
        assert!(v.is_empty(), "{v:?}");
    });
}

/// Critical regression (round-3 review item 2): a known, in-unit,
/// *earlier* base already declares `FakeLib FHE`, but a *later*, opaque
/// base in the same `is` list means `inherited_member_in_known_prefix`
/// cannot certify it as the provably-first member — and the file also
/// imports the real profile, so the incomplete-inheritance fallback alone
/// would otherwise wave this through. The real, visible shadow must win.
#[test]
fn fhe1022_known_ancestor_shadow_beats_a_trailing_opaque_base() {
    // `a`/`b` are declared directly on `Victim` (own member, resolved
    // without touching inheritance at all) so the construct isolates the
    // one thing under test: `FHE` resolution specifically, inherited from
    // `KnownBase`, which is *not* the rightmost direct base and so is not
    // covered by `inherited_member_in_known_prefix`'s "rightmost known
    // base" special case either.
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";
        import {UnseenBase} from "@external-lib/pkg/UnseenBase.sol";

        contract FakeLib {
            function add(euint32 x, euint32 y) external returns (euint32) { return x; }
        }
        contract KnownBase {
            FakeLib FHE;
        }
        contract Victim is KnownBase, UnseenBase {
            euint32 a;
            euint32 b;
            function f() external returns (euint32) {
                return a + b;
            }
        }
    "#;
    assert_eq!(codes_for_source(src), ["FHE1022"]);
}

/// Same shape, but the ordering is reversed (`UnseenBase, KnownBase`) so
/// `inherited_member_in_known_prefix` *would* have found the shadow via its
/// own "rightmost known base" special case — pinning that the new
/// known-ancestor check does not depend on which arm of that function
/// happens to fire.
#[test]
fn fhe1022_known_ancestor_shadow_found_regardless_of_base_order() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";
        import {UnseenBase} from "@external-lib/pkg/UnseenBase.sol";

        contract FakeLib {
            function add(euint32 x, euint32 y) external returns (euint32) { return x; }
        }
        contract KnownBase {
            euint32 a;
            euint32 b;
            FakeLib FHE;
        }
        contract Victim is UnseenBase, KnownBase {
            function f() external returns (euint32) {
                return a + b;
            }
        }
    "#;
    assert_eq!(codes_for_source(src), ["FHE1022"]);
}

/// Item 4 (round-3 review): `Utils` shadowed by a state variable, alongside
/// a legitimately trusted `Impl`/`UnsignedEncryptedInput` from a real plain
/// import — pins that each batch-materializer name is checked
/// independently, not as an all-or-nothing bundle.
#[test]
fn fhe1022_batch_materializer_utils_is_shadowed() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";

        contract FakeUtils {}
        contract Victim {
            FakeUtils Utils;
            function f(in ebool flag, in eaddress owner_) public {}
        }
    "#;
    assert_eq!(codes_for_source(src), ["FHE1022"]);
}

/// Item 4: `UnsignedEncryptedInput` shadowed by an in-unit struct that is
/// not the profile's own declaration.
#[test]
fn fhe1022_batch_materializer_unsigned_encrypted_input_is_shadowed() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";

        struct UnsignedEncryptedInput { uint256 x; }
        contract Victim {
            function f(in ebool flag, in eaddress owner_) public {}
        }
    "#;
    assert_eq!(codes_for_source(src), ["FHE1022"]);
}

/// Item 3 (round-3 review): the batch materializer also writes
/// `externalT.unwrap(...)` and `eT.wrap(...)` calls for every parameter
/// type; a state variable literally named `externalEbool` (the wire type of
/// one of the `in` parameters here) must be caught even though `Impl`,
/// `Utils`, and `UnsignedEncryptedInput` stay correctly trusted.
#[test]
fn fhe1022_batch_materializer_external_wire_type_is_shadowed() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";

        contract FakeExternalEbool {}
        contract Victim {
            FakeExternalEbool externalEbool;
            function f(in ebool flag, in eaddress owner_) public {}
        }
    "#;
    assert_eq!(codes_for_source(src), ["FHE1022"]);
}

/// Item 3: the plain encrypted type name side (`eT.wrap(...)`), not just the
/// external wire-type side.
#[test]
fn fhe1022_batch_materializer_plain_type_is_shadowed() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";

        contract FakeEbool {}
        contract Victim {
            FakeEbool ebool;
            function f(in ebool flag, in eaddress owner_) public {}
        }
    "#;
    assert_eq!(codes_for_source(src), ["FHE1022"]);
}

/// Item 5 (round-3 review): a bodiless multi-`in` declaration never reaches
/// `batch_input_statements` (signature rewrite only), so it must not be
/// scanned for the batch-materializer names at all.
#[test]
fn fhe1022_bodiless_multi_in_declaration_is_not_scanned() {
    let src = r#"
        pragma solidity ^0.8.25;
        import "@fhenixprotocol/cofhe-contracts/FHE.sol";

        contract FakeImpl {}
        abstract contract Victim {
            FakeImpl Impl;
            function f(in ebool flag, in eaddress owner_) external virtual;
        }
    "#;
    assert!(codes_for_source(src).is_empty());
}

/// Round-4 regression: an in-unit `import "./FHE.sol"` combined with an
/// unrelated unseen/external base — issue #47's shape, and an ordinary,
/// common pattern (e.g. a token contract that both vendors the profile
/// library in-unit and inherits an external OpenZeppelin base) — must not
/// spuriously refuse. Every resolution the checker sees is wrapped in
/// `Unresolved(IncompleteInheritance)` because of the unseen base, so this
/// exercises the unwrap fix in `is_fhe_library` (a plain `a + b` operator,
/// which needs `FHE` trusted) and in `encrypted_type`/
/// `external_input_type`/`is_trusted_profile_declaration` (multi-param `in`
/// sugar, which needs `euint32`, `Impl`, `Utils`, and
/// `UnsignedEncryptedInput` all trusted) at once.
#[test]
fn fhe1022_in_unit_import_with_an_unseen_base_stays_trusted() {
    let fhe_sol = r#"
        pragma solidity ^0.8.25;
        type euint32 is bytes32;
        type ebool is bytes32;
        type eaddress is bytes32;
        type externalEbool is bytes32;
        type externalEaddress is bytes32;
        library FHE {
            function add(euint32 x, euint32 y) internal pure returns (euint32) { return x; }
            function select(ebool c, ebool a, ebool b) internal pure returns (ebool) { return a; }
            function allowThis(ebool v) internal pure {}
        }
        library Impl {
            function verifyBatchInputs(uint256[] memory, bytes memory) internal pure returns (bytes32[] memory r) {}
        }
        library Utils {
            uint8 constant EBOOL_TFHE = 0;
            uint8 constant EADDRESS_TFHE = 1;
        }
        struct UnsignedEncryptedInput { uint256 data; uint8 securityZone; uint8 utype; }
    "#;
    let victim = r#"
        pragma solidity ^0.8.25;
        import "./FHE.sol";
        import {UnseenBase} from "@external-lib/pkg/UnseenBase.sol";

        contract Victim is UnseenBase {
            euint32 a;
            euint32 b;
            function f() external returns (euint32) {
                return a + b;
            }
            function g(in ebool flag, in eaddress owner_) public {}
        }
    "#;
    with_checked(&[("FHE.sol", fhe_sol), ("Victim.fsol", victim)], |c, _| {
        let mut v: Vec<String> = c.diagnostics.iter().map(|d| d.code.to_string()).collect();
        v.sort();
        assert!(v.is_empty(), "{v:?}");
    });
}
