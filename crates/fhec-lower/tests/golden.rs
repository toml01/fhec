//! Golden end-to-end tests: parse → bind → check → lower → splice, comparing
//! exact output strings, plus determinism and the §1.4 idempotence property
//! (`T(T(x)) == T(x)`, byte-exact) over every accepted golden.

use fhec_lower::{lower, AclMode, LowerOptions};
use fhec_targets::CofheProfile;
use solar_parse::{
    ast,
    interface::{source_map::FileName, ColorChoice, Session},
    Parser,
};

/// The transpile result for the test harness.
struct Out {
    /// Output text per file, in input order.
    files: Vec<(String, String)>,
    /// Whether any file plan had patches.
    any_patches: bool,
    check_error_codes: Vec<String>,
    lower_diag_codes: Vec<String>,
    /// The exact source text each lowering diagnostic's span covers, in the
    /// same order as `lower_diag_codes`, so tests can assert a diagnostic
    /// landed on the right construct (not just the right code).
    lower_diag_spans: Vec<String>,
    failed_files: usize,
}

fn transpile_with(sources: &[(&str, &str)], acl: AclMode) -> Out {
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
        let checked = fhec_check::check(&files, &bound, &profile, sess.source_map());
        let check_error_codes: Vec<String> = checked
            .diagnostics
            .iter()
            .filter(|d| d.severity == fhec_check::Severity::Error)
            .map(|d| d.code.to_string())
            .collect();

        let result = lower(
            &files,
            &bound,
            &checked,
            &profile,
            sess.source_map(),
            &LowerOptions { acl_mode: acl },
        );

        let mut out_files = Vec::new();
        let mut any_patches = false;
        for (i, plan) in result.plan.files.iter().enumerate() {
            any_patches |= !plan.is_empty();
            let spliced = fhec_emit::splice(sources[i].1, plan).expect("plan must splice");
            fhec_emit::validate_output(&plan.source_path, &spliced.text).unwrap_or_else(|e| {
                panic!(
                    "output must re-parse ({}): {e}\n--- output ---\n{}",
                    plan.source_path, spliced.text
                )
            });
            out_files.push((plan.source_path.clone(), spliced.text));
        }
        Out {
            files: out_files,
            any_patches,
            check_error_codes,
            lower_diag_codes: result
                .diagnostics
                .iter()
                .map(|d| format!("{}: {}", d.code, d.message))
                .collect(),
            lower_diag_spans: result
                .diagnostics
                .iter()
                .map(|d| {
                    sess.source_map()
                        .span_to_snippet(d.span)
                        .unwrap_or_default()
                })
                .collect(),
            failed_files: result.failed_files.len(),
        }
    })
}

fn transpile(sources: &[(&str, &str)]) -> Out {
    let out = transpile_with(sources, AclMode::Insert);
    assert!(
        out.check_error_codes.is_empty(),
        "golden inputs must check clean: {:?}",
        out.check_error_codes
    );
    out
}

/// Transpiles a single-file source and asserts the exact output, then
/// determinism and idempotence.
fn golden(input: &str, expected: &str) {
    let out = transpile(&[("t.fsol", input)]);
    assert_eq!(out.failed_files, 0, "diags: {:?}", out.lower_diag_codes);
    assert_eq!(out.files[0].1, expected, "first transpile mismatch");

    // Determinism: same input, same bytes.
    let again = transpile(&[("t.fsol", input)]);
    assert_eq!(again.files[0].1, expected, "non-deterministic output");

    // Idempotence (spec §1.4): T(T(x)) == T(x), byte-exact.
    let second = transpile(&[("t.fsol", expected)]);
    assert_eq!(second.failed_files, 0, "T(x) must be accepted again");
    assert_eq!(second.files[0].1, expected, "T(T(x)) != T(x)");
}

fn contract(body: &str) -> String {
    format!(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {{\n\
         \x20   euint32 a;\n\
         \x20   euint32 b;\n\
         \x20   euint8 a8;\n\
         \x20   ebool eb;\n\
         \x20   uint256 plainState;\n\
         \x20   mapping(address => euint32) balances;\n\
         \x20   mapping(uint256 => euint32) byId;\n\
         \x20   function f(uint32 p, address addr) public {{\n\
         {body}\n\
         \x20   }}\n\
         }}\n"
    )
}

fn golden_body(body_in: &str, body_out: &str) {
    golden(&contract(body_in), &contract(body_out));
}

// ---------------------------------------------------------------------------
// Operators (spec §4)
// ---------------------------------------------------------------------------

#[test]
fn add_with_acl() {
    golden_body(
        "        a = a + b;",
        "        a = FHE.add(a, b);\n\
         \x20       FHE.allowThis(a);\n\
         \x20       FHE.allowSender(a);",
    );
}

#[test]
fn literal_coercion() {
    golden_body(
        "        a = a + 1;",
        "        a = FHE.add(a, FHE.asEuint32(1));\n\
         \x20       FHE.allowThis(a);\n\
         \x20       FHE.allowSender(a);",
    );
}

#[test]
fn plain_operand_coercion() {
    golden_body(
        "        a = a * p;",
        "        a = FHE.mul(a, FHE.asEuint32(p));\n\
         \x20       FHE.allowThis(a);\n\
         \x20       FHE.allowSender(a);",
    );
}

#[test]
fn widening_picks_wider_side() {
    golden_body(
        "        a = a8 + a;",
        "        a = FHE.add(FHE.asEuint32(a8), a);\n\
         \x20       FHE.allowThis(a);\n\
         \x20       FHE.allowSender(a);",
    );
}

#[test]
fn nested_expression_single_patch() {
    golden_body(
        "        a = a + b * a8;",
        "        a = FHE.add(a, FHE.mul(b, FHE.asEuint32(a8)));\n\
         \x20       FHE.allowThis(a);\n\
         \x20       FHE.allowSender(a);",
    );
}

#[test]
fn comparison_and_not() {
    golden_body(
        "        eb = a < b;\n\
         \x20       eb = !eb;",
        "        eb = FHE.lt(a, b);\n\
         \x20       FHE.allowThis(eb);\n\
         \x20       FHE.allowSender(eb);\n\
         \x20       eb = FHE.not(eb);\n\
         \x20       FHE.allowThis(eb);\n\
         \x20       FHE.allowSender(eb);",
    );
}

#[test]
fn boolean_and_no_short_circuit() {
    golden_body(
        "        eb = eb && FHE.eq(a, b);",
        "        eb = FHE.and(eb, FHE.eq(a, b));\n\
         \x20       FHE.allowThis(eb);\n\
         \x20       FHE.allowSender(eb);",
    );
}

#[test]
fn ternary_to_select() {
    golden_body(
        "        a = eb ? a : b;",
        "        a = FHE.select(eb, a, b);\n\
         \x20       FHE.allowThis(a);\n\
         \x20       FHE.allowSender(a);",
    );
}

#[test]
fn compound_assignment() {
    golden_body(
        "        a += b;",
        "        a = FHE.add(a, b);\n\
         \x20       FHE.allowThis(a);\n\
         \x20       FHE.allowSender(a);",
    );
}

#[test]
fn increment_statement() {
    golden_body(
        "        a++;",
        "        a = FHE.add(a, FHE.asEuint32(1));\n\
         \x20       FHE.allowThis(a);\n\
         \x20       FHE.allowSender(a);",
    );
}

#[test]
fn plain_solidity_untouched() {
    let src = contract("        plainState = p + 1;");
    let out = transpile(&[("t.fsol", &src)]);
    assert!(!out.any_patches, "plain code must produce zero patches");
    assert_eq!(out.files[0].1, src);
}

// ---------------------------------------------------------------------------
// ACL dedupe and modes (spec §8.6, §8.1)
// ---------------------------------------------------------------------------

#[test]
fn dedupe_suppresses_existing_acl() {
    golden_body(
        "        a = a + b;\n\
         \x20       FHE.allowThis(a);\n\
         \x20       FHE.allowSender(a);",
        "        a = FHE.add(a, b);\n\
         \x20       FHE.allowThis(a);\n\
         \x20       FHE.allowSender(a);",
    );
}

#[test]
fn dedupe_inserts_only_missing_call() {
    golden_body(
        "        a = a + b;\n\
         \x20       FHE.allowThis(a);",
        "        a = FHE.add(a, b);\n\
         \x20       FHE.allowSender(a);\n\
         \x20       FHE.allowThis(a);",
    );
}

#[test]
fn method_syntax_counts_for_dedupe() {
    golden_body(
        "        a = a + b;\n\
         \x20       a.allowThis();\n\
         \x20       a.allowSender();",
        "        a = FHE.add(a, b);\n\
         \x20       a.allowThis();\n\
         \x20       a.allowSender();",
    );
}

#[test]
fn non_sender_key_warns() {
    let src = contract("        balances[addr] = a;");
    let out = transpile(&[("t.fsol", &src)]);
    assert!(out
        .lower_diag_codes
        .iter()
        .any(|d| d.starts_with("FHE4001")));
    assert_eq!(
        out.files[0].1,
        contract(
            "        balances[addr] = a;\n\
             \x20       FHE.allowThis(balances[addr]);\n\
             \x20       FHE.allowSender(balances[addr]);"
        )
    );
}

#[test]
fn suggest_mode_emits_notes_not_patches() {
    let src = contract("        a = a + b;");
    let out = transpile_with(&[("t.fsol", &src)], AclMode::Suggest);
    assert!(out.check_error_codes.is_empty());
    assert_eq!(
        out.files[0].1,
        contract("        a = FHE.add(a, b);"),
        "suggest mode must still lower operators"
    );
    assert!(out
        .lower_diag_codes
        .iter()
        .any(|d| d.starts_with("FHE4010")));
}

// ---------------------------------------------------------------------------
// R2 / R3 (spec §8.2, §8.3, §8.4)
// ---------------------------------------------------------------------------

fn r2_contract(body: &str) -> String {
    format!(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         interface IVault {{\n\
         \x20   function deposit(euint32 x) external;\n\
         }}\n\
         \n\
         contract C {{\n\
         \x20   euint32 a;\n\
         \x20   euint32 b;\n\
         \x20   IVault vault;\n\
         \x20   function f() public {{\n\
         {body}\n\
         \x20   }}\n\
         }}\n"
    )
}

#[test]
fn r2_identifier_arg_and_callee() {
    golden(
        &r2_contract("        vault.deposit(a);"),
        &r2_contract(
            "        FHE.allowTransient(a, address(vault));\n\
             \x20       vault.deposit(a);",
        ),
    );
}

#[test]
fn r2_complex_arg_hoists() {
    golden(
        &r2_contract("        vault.deposit(a + b);"),
        &r2_contract(
            "        euint32 __fhe_val_0 = FHE.add(a, b);\n\
             \x20       FHE.allowTransient(__fhe_val_0, address(vault));\n\
             \x20       vault.deposit(__fhe_val_0);",
        ),
    );
}

fn r3_contract(header: &str, body: &str) -> String {
    format!(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {{\n\
         \x20   euint32 a;\n\
         \x20   function g() {header} returns (euint32) {{\n\
         {body}\n\
         \x20   }}\n\
         }}\n"
    )
}

#[test]
fn r3_hoists_and_grants() {
    golden(
        &r3_contract("public", "        return a;"),
        &r3_contract(
            "public",
            "        euint32 __fhe_ret_0 = a;\n\
             \x20       FHE.allowTransient(__fhe_ret_0, msg.sender);\n\
             \x20       return __fhe_ret_0;",
        ),
    );
}

#[test]
fn r3_view_warns_only() {
    let src = r3_contract("public view", "        return a;");
    let out = transpile(&[("t.fsol", &src)]);
    assert!(!out.any_patches);
    assert!(out
        .lower_diag_codes
        .iter()
        .any(|d| d.starts_with("FHE4002")));
    assert_eq!(out.files[0].1, src);
}

#[test]
fn r3_internal_gets_nothing() {
    let src = r3_contract("internal", "        return a;");
    let out = transpile(&[("t.fsol", &src)]);
    assert!(!out.any_patches);
    assert_eq!(out.files[0].1, src);
}

// ---------------------------------------------------------------------------
// in-sugar (spec §2.3)
// ---------------------------------------------------------------------------

#[test]
fn sugar_expands_param_and_conversion() {
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   function setA(in euint32 amount) external {\n\
         \x20       a = amount;\n\
         \x20   }\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   function setA(InEuint32 memory amount_input) external {\n\
         \x20       euint32 amount = FHE.asEuint32(amount_input);\n\
         \x20       a = amount;\n\
         \x20       FHE.allowThis(a);\n\
         \x20       FHE.allowSender(a);\n\
         \x20   }\n\
         }\n",
    );
}

// ---------------------------------------------------------------------------
// if → select (spec §5)
// ---------------------------------------------------------------------------

#[test]
fn if_else_simple() {
    golden_body(
        "        if (eb) {\n\
         \x20           a = a + 1;\n\
         \x20       } else {\n\
         \x20           a = b;\n\
         \x20       }",
        "        {\n\
         \x20           ebool __fhe_cond_0 = eb;\n\
         \x20           euint32 __fhe_pre_1 = a;\n\
         \x20           euint32 __fhe_then_2;\n\
         \x20           {\n\
         \x20               __fhe_then_2 = FHE.add(__fhe_pre_1, FHE.asEuint32(1));\n\
         \x20           }\n\
         \x20           euint32 __fhe_else_3;\n\
         \x20           {\n\
         \x20               __fhe_else_3 = b;\n\
         \x20           }\n\
         \x20           a = FHE.select(__fhe_cond_0, __fhe_then_2, __fhe_else_3);\n\
         \x20           FHE.allowThis(a);\n\
         \x20           FHE.allowSender(a);\n\
         \x20       }",
    );
}

#[test]
fn if_without_else_merges_with_pre() {
    golden_body(
        "        if (eb) {\n\
         \x20           a = b;\n\
         \x20       }",
        "        {\n\
         \x20           ebool __fhe_cond_0 = eb;\n\
         \x20           euint32 __fhe_pre_1 = a;\n\
         \x20           euint32 __fhe_then_2;\n\
         \x20           {\n\
         \x20               __fhe_then_2 = b;\n\
         \x20           }\n\
         \x20           a = FHE.select(__fhe_cond_0, __fhe_then_2, __fhe_pre_1);\n\
         \x20           FHE.allowThis(a);\n\
         \x20           FHE.allowSender(a);\n\
         \x20       }",
    );
}

#[test]
fn if_mapping_write_hoists_key() {
    let out = transpile(&[(
        "t.fsol",
        &contract(
            "        if (eb) {\n\
             \x20           balances[addr] = a;\n\
             \x20       }",
        ),
    )]);
    assert_eq!(out.failed_files, 0, "diags: {:?}", out.lower_diag_codes);
    assert!(out
        .lower_diag_codes
        .iter()
        .any(|d| d.starts_with("FHE4001")));
    assert_eq!(
        out.files[0].1,
        contract(
            "        {\n\
             \x20           ebool __fhe_cond_0 = eb;\n\
             \x20           address __fhe_key_1 = addr;\n\
             \x20           euint32 __fhe_pre_2 = balances[__fhe_key_1];\n\
             \x20           euint32 __fhe_then_3;\n\
             \x20           {\n\
             \x20               __fhe_then_3 = a;\n\
             \x20           }\n\
             \x20           balances[__fhe_key_1] = FHE.select(__fhe_cond_0, __fhe_then_3, __fhe_pre_2);\n\
             \x20           FHE.allowThis(balances[__fhe_key_1]);\n\
             \x20           FHE.allowSender(balances[__fhe_key_1]);\n\
             \x20       }"
        )
    );
}

#[test]
fn if_distinct_literal_keys_are_distinct_locations() {
    golden_body(
        "        if (eb) {\n\
         \x20           byId[1] = a;\n\
         \x20       } else {\n\
         \x20           byId[2] = b;\n\
         \x20       }",
        "        {\n\
         \x20           ebool __fhe_cond_0 = eb;\n\
         \x20           euint32 __fhe_pre_1 = byId[1];\n\
         \x20           euint32 __fhe_pre_2 = byId[2];\n\
         \x20           euint32 __fhe_then_3;\n\
         \x20           {\n\
         \x20               __fhe_then_3 = a;\n\
         \x20           }\n\
         \x20           euint32 __fhe_else_4;\n\
         \x20           {\n\
         \x20               __fhe_else_4 = b;\n\
         \x20           }\n\
         \x20           byId[1] = FHE.select(__fhe_cond_0, __fhe_then_3, __fhe_pre_1);\n\
         \x20           FHE.allowThis(byId[1]);\n\
         \x20           FHE.allowSender(byId[1]);\n\
         \x20           byId[2] = FHE.select(__fhe_cond_0, __fhe_pre_2, __fhe_else_4);\n\
         \x20           FHE.allowThis(byId[2]);\n\
         \x20           FHE.allowSender(byId[2]);\n\
         \x20       }",
    );
}

#[test]
fn if_read_after_write_uses_version() {
    golden_body(
        "        if (eb) {\n\
         \x20           a = b;\n\
         \x20           a = a + 1;\n\
         \x20       }",
        "        {\n\
         \x20           ebool __fhe_cond_0 = eb;\n\
         \x20           euint32 __fhe_pre_1 = a;\n\
         \x20           euint32 __fhe_then_2;\n\
         \x20           euint32 __fhe_then_3;\n\
         \x20           {\n\
         \x20               __fhe_then_2 = b;\n\
         \x20               __fhe_then_3 = FHE.add(__fhe_then_2, FHE.asEuint32(1));\n\
         \x20           }\n\
         \x20           a = FHE.select(__fhe_cond_0, __fhe_then_3, __fhe_pre_1);\n\
         \x20           FHE.allowThis(a);\n\
         \x20           FHE.allowSender(a);\n\
         \x20       }",
    );
}

#[test]
fn if_branch_local_stays_direct() {
    golden_body(
        "        if (eb) {\n\
         \x20           euint32 t = a + 1;\n\
         \x20           a = t;\n\
         \x20       }",
        "        {\n\
         \x20           ebool __fhe_cond_0 = eb;\n\
         \x20           euint32 __fhe_pre_1 = a;\n\
         \x20           euint32 __fhe_then_2;\n\
         \x20           {\n\
         \x20               euint32 t = FHE.add(__fhe_pre_1, FHE.asEuint32(1));\n\
         \x20               __fhe_then_2 = t;\n\
         \x20           }\n\
         \x20           a = FHE.select(__fhe_cond_0, __fhe_then_2, __fhe_pre_1);\n\
         \x20           FHE.allowThis(a);\n\
         \x20           FHE.allowSender(a);\n\
         \x20       }",
    );
}

#[test]
fn nested_ifs_compose_innermost_first() {
    golden_body(
        "        if (eb) {\n\
         \x20           a = a + 1;\n\
         \x20           if (FHE.lt(a, b)) {\n\
         \x20               a = a + 2;\n\
         \x20           }\n\
         \x20       }",
        "        {\n\
         \x20           ebool __fhe_cond_0 = eb;\n\
         \x20           euint32 __fhe_pre_1 = a;\n\
         \x20           euint32 __fhe_then_2;\n\
         \x20           euint32 __fhe_then_6;\n\
         \x20           {\n\
         \x20               __fhe_then_2 = FHE.add(__fhe_pre_1, FHE.asEuint32(1));\n\
         \x20               {\n\
         \x20                   ebool __fhe_cond_3 = FHE.lt(__fhe_then_2, b);\n\
         \x20                   euint32 __fhe_pre_4 = __fhe_then_2;\n\
         \x20                   euint32 __fhe_then_5;\n\
         \x20                   {\n\
         \x20                       __fhe_then_5 = FHE.add(__fhe_pre_4, FHE.asEuint32(2));\n\
         \x20                   }\n\
         \x20                   __fhe_then_6 = FHE.select(__fhe_cond_3, __fhe_then_5, __fhe_pre_4);\n\
         \x20               }\n\
         \x20           }\n\
         \x20           a = FHE.select(__fhe_cond_0, __fhe_then_6, __fhe_pre_1);\n\
         \x20           FHE.allowThis(a);\n\
         \x20           FHE.allowSender(a);\n\
         \x20       }",
    );
}

#[test]
fn if_aliasing_rejects_with_fhe3011() {
    let src = contract(
        "        if (eb) {\n\
         \x20           balances[addr] = a;\n\
         \x20       } else {\n\
         \x20           balances[msg.sender] = b;\n\
         \x20       }",
    );
    let out = transpile(&[("t.fsol", &src)]);
    assert!(out
        .lower_diag_codes
        .iter()
        .any(|d| d.starts_with("FHE3011")));
    assert_eq!(out.failed_files, 1);
    assert_eq!(out.files[0].1, src, "a refused file must stay untouched");
}

#[test]
fn if_same_key_text_shares_one_temp() {
    golden_body(
        "        if (eb) {\n\
         \x20           balances[msg.sender] = a;\n\
         \x20       } else {\n\
         \x20           balances[msg.sender] = b;\n\
         \x20       }",
        "        {\n\
         \x20           ebool __fhe_cond_0 = eb;\n\
         \x20           address __fhe_key_1 = msg.sender;\n\
         \x20           euint32 __fhe_pre_2 = balances[__fhe_key_1];\n\
         \x20           euint32 __fhe_then_3;\n\
         \x20           {\n\
         \x20               __fhe_then_3 = a;\n\
         \x20           }\n\
         \x20           euint32 __fhe_else_4;\n\
         \x20           {\n\
         \x20               __fhe_else_4 = b;\n\
         \x20           }\n\
         \x20           balances[__fhe_key_1] = FHE.select(__fhe_cond_0, __fhe_then_3, __fhe_else_4);\n\
         \x20           FHE.allowThis(balances[__fhe_key_1]);\n\
         \x20           FHE.allowSender(balances[__fhe_key_1]);\n\
         \x20       }",
    );
}

// ---------------------------------------------------------------------------
// Import rewriting (spec §2.6)
// ---------------------------------------------------------------------------

#[test]
fn fsol_import_specifier_is_rewritten() {
    let other = "pragma solidity ^0.8.25;\ncontract D {}\n";
    let main = "pragma solidity ^0.8.25;\n\
                import \"./Other.fsol\";\n\
                contract C {}\n";
    let out = transpile(&[("Main.fsol", main), ("Other.fsol", other)]);
    assert_eq!(
        out.files[0].1,
        "pragma solidity ^0.8.25;\n\
         import \"./Other.sol\";\n\
         contract C {}\n"
    );
    assert_eq!(out.files[1].1, other);
}

#[test]
fn r2_cast_callee_hoists_with_declared_type() {
    let src = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               \n\
               interface IVault {\n\
               \x20   function deposit(euint32 x) external;\n\
               }\n\
               \n\
               contract C {\n\
               \x20   euint32 a;\n\
               \x20   address vaultAddr;\n\
               \x20   function f() public {\n\
               \x20       IVault(vaultAddr).deposit(a);\n\
               \x20   }\n\
               }\n";
    let expected = "pragma solidity ^0.8.25;\n\
                    import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
                    \n\
                    interface IVault {\n\
                    \x20   function deposit(euint32 x) external;\n\
                    }\n\
                    \n\
                    contract C {\n\
                    \x20   euint32 a;\n\
                    \x20   address vaultAddr;\n\
                    \x20   function f() public {\n\
                    \x20       IVault __fhe_callee_0 = IVault(vaultAddr);\n\
                    \x20       FHE.allowTransient(a, address(__fhe_callee_0));\n\
                    \x20       __fhe_callee_0.deposit(a);\n\
                    \x20   }\n\
                    }\n";
    golden(src, expected);
}

#[test]
fn r2_unknown_callee_passes_through_untouched() {
    let src = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               \n\
               interface IVault {\n\
               \x20   function deposit(euint32 x) external;\n\
               }\n\
               interface IRegistry {\n\
               \x20   function get() external returns (IVault);\n\
               }\n\
               \n\
               contract C {\n\
               \x20   euint32 a;\n\
               \x20   IRegistry reg;\n\
               \x20   function f() public {\n\
               \x20       reg.get().deposit(a);\n\
               \x20   }\n\
               }\n";
    // The checker types `reg.get()` as Unknown and states no R2 fact for the
    // call; no grant is inserted (a conservative under-grant: the call reverts
    // on the ACL check instead of leaking). The file passes through untouched.
    let out = transpile(&[("t.fsol", src)]);
    assert_eq!(out.failed_files, 0);
    assert!(!out.any_patches);
    assert_eq!(out.files[0].1, src);
}

#[test]
fn r2_dedupe_accepts_address_wrapped_grant() {
    golden(
        &r2_contract(
            "        FHE.allowTransient(a, address(vault));\n\
             \x20       vault.deposit(a);",
        ),
        &r2_contract(
            "        FHE.allowTransient(a, address(vault));\n\
             \x20       vault.deposit(a);",
        ),
    );
}

#[test]
fn r2_callee_type_underivable_rejects_with_fhe4003() {
    // The callee object is a ternary of two same-typed contract instances
    // under a plaintext condition: a definite `IVault` type, so an R2 site
    // exists, but not a shape `callee_type_text` can derive text for (only
    // casts and identifier-rooted index paths are, spec §8.2 draft decision).
    let src = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               \n\
               interface IVault {\n\
               \x20   function deposit(euint32 x) external;\n\
               }\n\
               \n\
               contract C {\n\
               \x20   euint32 a;\n\
               \x20   IVault vaultA;\n\
               \x20   IVault vaultB;\n\
               \x20   function f(bool cond) public {\n\
               \x20       (cond ? vaultA : vaultB).deposit(a);\n\
               \x20   }\n\
               }\n";
    let out = transpile(&[("t.fsol", src)]);
    assert!(
        out.lower_diag_codes
            .iter()
            .any(|d| d.starts_with("FHE4003")),
        "diags: {:?}",
        out.lower_diag_codes
    );
    assert_eq!(out.failed_files, 1);
    assert_eq!(out.files[0].1, src, "a refused file must stay untouched");
    assert_eq!(
        out.lower_diag_spans,
        vec!["(cond ? vaultA : vaultB)"],
        "FHE4003 must point at the callee expression, not the whole call"
    );
}

#[test]
fn if_unsupported_statement_rejects_with_fhe3013() {
    // A tuple declaration (`DeclMulti`) is a statement form the spec does not
    // enumerate for encrypted branches (spec §5.2).
    let src = contract(
        "        if (eb) {\n\
         \x20           (uint256 x, uint256 y) = (p, p);\n\
         \x20       }",
    );
    let out = transpile(&[("t.fsol", &src)]);
    assert!(
        out.lower_diag_codes
            .iter()
            .any(|d| d.starts_with("FHE3013")),
        "diags: {:?}",
        out.lower_diag_codes
    );
    assert_eq!(out.failed_files, 1);
    assert_eq!(out.files[0].1, src, "a refused file must stay untouched");
    assert_eq!(
        out.lower_diag_spans,
        vec!["(uint256 x, uint256 y) = (p, p);"],
        "FHE3013 must point at the offending statement"
    );
}
