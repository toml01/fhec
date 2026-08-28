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
        let profile = CofheProfile::v0_2();
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
         \x20       FHE.allowThis(a);",
    );
}

#[test]
fn literal_coercion() {
    golden_body(
        "        a = a + 1;",
        "        a = FHE.add(a, FHE.asEuint32(1));\n\
         \x20       FHE.allowThis(a);",
    );
}

#[test]
fn plain_operand_coercion() {
    golden_body(
        "        a = a * p;",
        "        a = FHE.mul(a, FHE.asEuint32(p));\n\
         \x20       FHE.allowThis(a);",
    );
}

#[test]
fn widening_picks_wider_side() {
    golden_body(
        "        a = a8 + a;",
        "        a = FHE.add(FHE.asEuint32(a8), a);\n\
         \x20       FHE.allowThis(a);",
    );
}

#[test]
fn nested_expression_single_patch() {
    golden_body(
        "        a = a + b * a8;",
        "        a = FHE.add(a, FHE.mul(b, FHE.asEuint32(a8)));\n\
         \x20       FHE.allowThis(a);",
    );
}

#[test]
fn comparison_and_not() {
    // `eb` is a simple state variable (no key at all), so R1 only guesses
    // `allowThis` — the same withholding as a `SimpleVar` write (issue #70).
    golden_body(
        "        eb = a < b;\n\
         \x20       eb = !eb;",
        "        eb = FHE.lt(a, b);\n\
         \x20       FHE.allowThis(eb);\n\
         \x20       eb = FHE.not(eb);\n\
         \x20       FHE.allowThis(eb);",
    );
}

#[test]
fn boolean_and_no_short_circuit() {
    golden_body(
        "        eb = eb && FHE.eq(a, b);",
        "        eb = FHE.and(eb, FHE.eq(a, b));\n\
         \x20       FHE.allowThis(eb);",
    );
}

#[test]
fn ternary_to_select() {
    golden_body(
        "        a = eb ? a : b;",
        "        a = FHE.select(eb, a, b);\n\
         \x20       FHE.allowThis(a);",
    );
}

#[test]
fn compound_assignment() {
    golden_body(
        "        a += b;",
        "        a = FHE.add(a, b);\n\
         \x20       FHE.allowThis(a);",
    );
}

#[test]
fn increment_statement() {
    golden_body(
        "        a++;",
        "        a = FHE.add(a, FHE.asEuint32(1));\n\
         \x20       FHE.allowThis(a);",
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
    // A mapping keyed by `msg.sender` still owes both grants (unlike a
    // simple state variable), so it can still exercise "only the missing
    // call is inserted".
    golden_body(
        "        balances[msg.sender] = a;\n\
         \x20       FHE.allowThis(balances[msg.sender]);",
        "        balances[msg.sender] = a;\n\
         \x20       FHE.allowSender(balances[msg.sender]);\n\
         \x20       FHE.allowThis(balances[msg.sender]);",
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
fn non_sender_key_warns_and_withholds_the_sender_grant() {
    // Spec §8.1: `allowThis` is unconditional, `allowSender` is a claim about
    // who owns the value and is never guessed for a slot filed under another
    // address.
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
             \x20       FHE.allowThis(balances[addr]);"
        )
    );
}

#[test]
fn msg_sender_key_still_receives_both_grants() {
    let src = contract("        balances[msg.sender] = a;");
    let out = transpile(&[("t.fsol", &src)]);
    assert!(
        !out.lower_diag_codes
            .iter()
            .any(|d| d.starts_with("FHE4001")),
        "diags: {:?}",
        out.lower_diag_codes
    );
    assert_eq!(
        out.files[0].1,
        contract(
            "        balances[msg.sender] = a;\n\
             \x20       FHE.allowThis(balances[msg.sender]);\n\
             \x20       FHE.allowSender(balances[msg.sender]);"
        )
    );
}

#[test]
fn simple_var_warns_and_withholds_the_sender_grant() {
    // Issue #70: a simple state variable has no key at all, so it has no
    // owner distinct from the contract — the same withholding as a mapping
    // slot filed under another address.
    let src = contract("        a = b;");
    let out = transpile(&[("t.fsol", &src)]);
    assert!(
        out.lower_diag_codes
            .iter()
            .any(|d| d.starts_with("FHE4001")),
        "diags: {:?}",
        out.lower_diag_codes
    );
    assert_eq!(
        out.files[0].1,
        contract(
            "        a = b;\n\
             \x20       FHE.allowThis(a);"
        )
    );
}

#[test]
fn non_address_mapping_key_warns_and_withholds_the_sender_grant() {
    // Issue #70: R1's "unproven" case is not limited to a proven-other
    // address — a mapping keyed by anything else (here a plain `uint256`) is
    // just as unproven.
    let src = contract("        byId[1] = a;");
    let out = transpile(&[("t.fsol", &src)]);
    assert!(
        out.lower_diag_codes
            .iter()
            .any(|d| d.starts_with("FHE4001")),
        "diags: {:?}",
        out.lower_diag_codes
    );
    assert_eq!(
        out.files[0].1,
        contract(
            "        byId[1] = a;\n\
             \x20       FHE.allowThis(byId[1]);"
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
         \x20   function setA(externalEuint32 amount_input, bytes memory inputProof) external {\n\
         \x20       euint32 amount = FHE.asEuint32(amount_input, inputProof);\n\
         \x20       a = amount;\n\
         \x20       FHE.allowThis(a);\n\
         \x20   }\n\
         }\n",
    );
}

#[test]
fn sugar_appends_proof_on_its_own_line_in_a_multiline_param_list() {
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint64 a;\n\
         \x20   function transfer(\n\
         \x20       address to,\n\
         \x20       in euint64 amount\n\
         \x20   ) external {\n\
         \x20       a = amount;\n\
         \x20       to;\n\
         \x20   }\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint64 a;\n\
         \x20   function transfer(\n\
         \x20       address to,\n\
         \x20       externalEuint64 amount_input,\n\
         \x20       bytes memory inputProof\n\
         \x20   ) external {\n\
         \x20       euint64 amount = FHE.asEuint64(amount_input, inputProof);\n\
         \x20       a = amount;\n\
         \x20       FHE.allowThis(a);\n\
         \x20       to;\n\
         \x20   }\n\
         }\n",
    );
}

#[test]
fn sugar_appends_proof_after_the_last_param_of_a_multiline_list() {
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   function transfer(\n\
         \x20       in euint32 amount,\n\
         \x20       address to\n\
         \x20   ) external {\n\
         \x20       a = amount;\n\
         \x20       to;\n\
         \x20   }\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   function transfer(\n\
         \x20       externalEuint32 amount_input,\n\
         \x20       address to,\n\
         \x20       bytes memory inputProof\n\
         \x20   ) external {\n\
         \x20       euint32 amount = FHE.asEuint32(amount_input, inputProof);\n\
         \x20       a = amount;\n\
         \x20       FHE.allowThis(a);\n\
         \x20       to;\n\
         \x20   }\n\
         }\n",
    );
}

#[test]
fn sugar_does_not_put_the_comma_inside_a_trailing_line_comment() {
    // A `//` comment runs to end-of-line. Attaching `,` to that text would
    // comment the comma out and leave the proof parameter unseparated.
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   function setA(\n\
         \x20       in euint32 amount // note\n\
         \x20   ) external {\n\
         \x20       a = amount;\n\
         \x20   }\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   function setA(\n\
         \x20       externalEuint32 amount_input // note\n\
         \x20       ,\n\
         \x20       bytes memory inputProof\n\
         \x20   ) external {\n\
         \x20       euint32 amount = FHE.asEuint32(amount_input, inputProof);\n\
         \x20       a = amount;\n\
         \x20       FHE.allowThis(a);\n\
         \x20   }\n\
         }\n",
    );
}

#[test]
fn sugar_multiline_trailing_comment_with_non_ascii_does_not_panic() {
    // `line_indent` slices at `at`. Subtracting 1 from the offset after a
    // trailing `€` lands inside that UTF-8 character and panics.
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   function setA(\n\
         \x20       in euint32 amount // note €\n\
         \x20   ) external {\n\
         \x20       a = amount;\n\
         \x20   }\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   function setA(\n\
         \x20       externalEuint32 amount_input // note €\n\
         \x20       ,\n\
         \x20       bytes memory inputProof\n\
         \x20   ) external {\n\
         \x20       euint32 amount = FHE.asEuint32(amount_input, inputProof);\n\
         \x20       a = amount;\n\
         \x20       FHE.allowThis(a);\n\
         \x20   }\n\
         }\n",
    );
}

#[test]
fn sugar_appends_proof_on_its_own_line_in_a_multiline_constructor() {
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   constructor(\n\
         \x20       in euint32 seed\n\
         \x20   ) {\n\
         \x20       a = seed;\n\
         \x20   }\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   constructor(\n\
         \x20       externalEuint32 seed_input,\n\
         \x20       bytes memory inputProof\n\
         \x20   ) {\n\
         \x20       euint32 seed = FHE.asEuint32(seed_input, inputProof);\n\
         \x20       a = seed;\n\
         \x20       FHE.allowThis(a);\n\
         \x20   }\n\
         }\n",
    );
}

#[test]
fn sugar_appends_proof_on_its_own_line_in_a_multiline_bodiless_declaration() {
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         interface I {\n\
         \x20   function deposit(\n\
         \x20       in euint32 amount\n\
         \x20   ) external;\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         interface I {\n\
         \x20   function deposit(\n\
         \x20       externalEuint32 amount,\n\
         \x20       bytes memory inputProof\n\
         \x20   ) external;\n\
         }\n",
    );
}

#[test]
fn sugar_binder_uses_the_bound_proof_and_appends_nothing() {
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   function setA(in(sig) euint32 amount, bytes calldata sig, bytes calldata data)\n\
         \x20       external\n\
         \x20   {\n\
         \x20       a = amount;\n\
         \x20       data;\n\
         \x20   }\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   function setA(externalEuint32 amount_input, bytes calldata sig, \
         bytes calldata data)\n\
         \x20       external\n\
         \x20   {\n\
         \x20       euint32 amount = FHE.asEuint32(amount_input, sig);\n\
         \x20       a = amount;\n\
         \x20       FHE.allowThis(a);\n\
         \x20       data;\n\
         \x20   }\n\
         }\n",
    );
}

#[test]
fn sugar_binder_batches_in_encrypted_parameter_order() {
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   function setA(in(p) euint32 x, bytes memory p, in(p) euint32 y) external {\n\
         \x20       a = x;\n\
         \x20       a = y;\n\
         \x20   }\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   function setA(externalEuint32 x_input, bytes memory p, externalEuint32 y_input) \
         external {\n\
         \x20       UnsignedEncryptedInput[] memory __fhe_inputs_0 = \
         new UnsignedEncryptedInput[](2);\n\
         \x20       __fhe_inputs_0[0] = \
         UnsignedEncryptedInput(uint256(externalEuint32.unwrap(x_input)), 0, \
         Utils.EUINT32_TFHE);\n\
         \x20       __fhe_inputs_0[1] = \
         UnsignedEncryptedInput(uint256(externalEuint32.unwrap(y_input)), 0, \
         Utils.EUINT32_TFHE);\n\
         \x20       bytes32[] memory __fhe_hashes_1 = \
         Impl.verifyBatchInputs(__fhe_inputs_0, p);\n\
         \x20       euint32 x = euint32.wrap(__fhe_hashes_1[0]);\n\
         \x20       euint32 y = euint32.wrap(__fhe_hashes_1[1]);\n\
         \x20       a = x;\n\
         \x20       FHE.allowThis(a);\n\
         \x20       a = y;\n\
         \x20       FHE.allowThis(a);\n\
         \x20   }\n\
         }\n",
    );
}

#[test]
fn sugar_binder_expands_a_constructor_parameter_list() {
    // A constructor is a parameter list like any other (spec §2.3), and the
    // binder may name a proof declared *before* the input it verifies.
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   constructor(bytes memory sig, in(sig) euint32 seed, uint256 tag) {\n\
         \x20       a = seed;\n\
         \x20       tag;\n\
         \x20   }\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   constructor(bytes memory sig, externalEuint32 seed_input, uint256 tag) {\n\
         \x20       euint32 seed = FHE.asEuint32(seed_input, sig);\n\
         \x20       a = seed;\n\
         \x20       FHE.allowThis(a);\n\
         \x20       tag;\n\
         \x20   }\n\
         }\n",
    );
}

// ---------------------------------------------------------------------------
// The shared boundary (spec §2.8)
// ---------------------------------------------------------------------------

/// Wraps contract members in a bare unit for shared-boundary goldens.
fn shared_unit(members: &str) -> String {
    format!(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         interface IVault {{\n\
         \x20   function pull(euint64 v) external returns (euint64);\n\
         }}\n\
         \n\
         contract S {{\n\
         \x20   euint32 a;\n\
         \x20   euint64 b;\n\
         \x20   euint64 c;\n\
         \x20   IVault vault;\n\
         {members}\
         }}\n"
    )
}

fn shared_golden(members_in: &str, members_out: &str) {
    golden(&shared_unit(members_in), &shared_unit(members_out));
}

#[test]
fn shared_input_receives_at_body_entry() {
    shared_golden(
        "\x20   function setA(in shared euint32 amount, uint256 tag) external {\n\
         \x20       a = amount;\n\
         \x20       tag;\n\
         \x20   }\n",
        "\x20   function setA(sharedEuint32 amount_shared, uint256 tag) external {\n\
         \x20       euint32 amount = FHE.receiveEuint32Param(amount_shared);\n\
         \x20       a = amount;\n\
         \x20       FHE.allowThis(a);\n\
         \x20       tag;\n\
         \x20   }\n",
    );
}

#[test]
fn several_shared_inputs_receive_one_by_one_in_parameter_order() {
    // Unlike external inputs (§2.3), shared handles carry no input proof, so
    // there is no batch to verify: each receives on its own.
    shared_golden(
        "\x20   function set(in shared euint64 second, in shared euint32 first) external {\n\
         \x20       b = second;\n\
         \x20       a = first;\n\
         \x20   }\n",
        "\x20   function set(sharedEuint64 second_shared, sharedEuint32 first_shared) external {\n\
         \x20       euint64 second = FHE.receiveEuint64Param(second_shared);\n\
         \x20       euint32 first = FHE.receiveEuint32Param(first_shared);\n\
         \x20       b = second;\n\
         \x20       FHE.allowThis(b);\n\
         \x20       a = first;\n\
         \x20       FHE.allowThis(a);\n\
         \x20   }\n",
    );
}

#[test]
fn shared_return_wraps_in_place_and_emits_no_r3_grant() {
    shared_golden(
        "\x20   function take() public returns (shared(msg.sender) euint64) {\n\
         \x20       return b;\n\
         \x20   }\n",
        "\x20   function take() public returns (sharedEuint64) {\n\
         \x20       return FHE.shareEuint64(b, msg.sender);\n\
         \x20   }\n",
    );
}

#[test]
fn shared_return_lowers_nested_operators_and_shares_once() {
    shared_golden(
        "\x20   function take() public returns (shared(msg.sender) euint64) {\n\
         \x20       return b + c;\n\
         \x20   }\n",
        "\x20   function take() public returns (sharedEuint64) {\n\
         \x20       return FHE.shareEuint64(FHE.add(b, c), msg.sender);\n\
         \x20   }\n",
    );
}

#[test]
fn shared_return_keeps_the_r2_grant() {
    // The §8.2 R2 rule owns the `try` statement and inserts its grant before
    // it; the share wrap brackets the returned expression inside the clause
    // block. Neither displaces the other, and the grant survives.
    shared_golden(
        "\x20   function drain() public returns (shared(msg.sender) euint64) {\n\
         \x20       try vault.pull(b) returns (euint64 pulled) {\n\
         \x20           return pulled;\n\
         \x20       } catch {\n\
         \x20           return c;\n\
         \x20       }\n\
         \x20   }\n",
        "\x20   function drain() public returns (sharedEuint64) {\n\
         \x20       FHE.allowTransient(b, address(vault));\n\
         \x20       try vault.pull(b) returns (euint64 pulled) {\n\
         \x20           return FHE.shareEuint64(pulled, msg.sender);\n\
         \x20       } catch {\n\
         \x20           return FHE.shareEuint64(c, msg.sender);\n\
         \x20       }\n\
         \x20   }\n",
    );
}

#[test]
fn shared_return_evaluates_its_expression_once() {
    // The wrap never hoists and re-reads, so a call in the returned
    // expression appears exactly once in the output.
    let members = "\x20   uint256 reads;\n\
                   \x20   function fetch() internal returns (euint64 out) {\n\
                   \x20       reads += 1;\n\
                   \x20       out = b;\n\
                   \x20   }\n\
                   \x20   function take() public returns (shared(msg.sender) euint64) {\n\
                   \x20       return fetch();\n\
                   \x20   }\n";
    let out = transpile(&[("t.fsol", &shared_unit(members))]);
    assert_eq!(out.failed_files, 0, "diags: {:?}", out.lower_diag_codes);
    let text = &out.files[0].1;
    assert!(
        text.contains("        return FHE.shareEuint64(fetch(), msg.sender);\n"),
        "output: {text}"
    );
    // Twice in the file: the declaration and the one call site.
    assert_eq!(text.matches("fetch()").count(), 2, "output: {text}");
    assert_eq!(
        text.matches("FHE.shareEuint64").count(),
        1,
        "output: {text}"
    );
}

#[test]
fn a_bodiless_shared_declaration_rewrites_its_signature_only() {
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         interface I {\n\
         \x20   function set(in shared euint32 amount) external;\n\
         \x20   function take() external returns (shared(msg.sender) euint64);\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         interface I {\n\
         \x20   function set(sharedEuint32 amount) external;\n\
         \x20   function take() external returns (sharedEuint64);\n\
         }\n",
    );
}

#[test]
fn a_bodiless_declaration_keeps_the_author_parameter_name() {
    // Spec §2.3 / §2.8: no local is generated, so the ABI-visible parameter
    // name must not change on a published interface.
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         interface I {\n\
         \x20   function deposit(in euint32 amount) external;\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         interface I {\n\
         \x20   function deposit(externalEuint32 amount, bytes memory inputProof) external;\n\
         }\n",
    );
}

#[test]
fn explicit_share_and_receive_calls_are_a_no_op() {
    // §1.4: plain CoFHE Solidity that crosses the boundary by hand carries no
    // dialect marker, so the output is the input byte for byte.
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        \n\
        contract Explicit {\n\
        \x20   euint64 balance;\n\
        \n\
        \x20   function set(sharedEuint64 amount_shared) public {\n\
        \x20       euint64 amount = FHE.receiveEuint64Param(amount_shared);\n\
        \x20       balance = amount;\n\
        \x20       FHE.allowThis(balance);\n\
        \x20       FHE.allowSender(balance);\n\
        \x20   }\n\
        \n\
        \x20   function take() public returns (sharedEuint64) {\n\
        \x20       return FHE.shareEuint64(balance, msg.sender);\n\
        \x20   }\n\
        }\n";
    let out = transpile(&[("t.fsol", src)]);
    assert_eq!(out.files[0].1, src);
    assert!(
        !out.any_patches,
        "a plain CoFHE source must produce no patch"
    );
}

#[test]
fn shared_stays_an_ordinary_identifier_through_lowering() {
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        \n\
        contract Shared {\n\
        \x20   uint256 shared;\n\
        \n\
        \x20   function bump(uint256 shared_) public returns (uint256) {\n\
        \x20       shared = shared + shared_;\n\
        \x20       return shared;\n\
        \x20   }\n\
        }\n";
    let out = transpile(&[("t.fsol", src)]);
    assert_eq!(out.files[0].1, src);
    assert!(!out.any_patches);
}

// ---------------------------------------------------------------------------
// `precondition` blocks (spec §2.7)
// ---------------------------------------------------------------------------

#[test]
fn precondition_moves_the_conversion_after_the_block() {
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   mapping(address => bool) operators;\n\
         \x20   error NotOperator(address who);\n\
         \x20   function isOperator(address who) public view returns (bool) {\n\
         \x20       return operators[who];\n\
         \x20   }\n\
         \x20   function setA(address from, in euint32 amount) external {\n\
         \x20       precondition {\n\
         \x20           if (!isOperator(from)) revert NotOperator(from);\n\
         \x20       }\n\
         \x20       a = amount;\n\
         \x20   }\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   mapping(address => bool) operators;\n\
         \x20   error NotOperator(address who);\n\
         \x20   function isOperator(address who) public view returns (bool) {\n\
         \x20       return operators[who];\n\
         \x20   }\n\
         \x20   function setA(address from, externalEuint32 amount_input, \
         bytes memory inputProof) external {\n\
         \x20       {\n\
         \x20           if (!isOperator(from)) revert NotOperator(from);\n\
         \x20       }\n\
         \x20       euint32 amount = FHE.asEuint32(amount_input, inputProof);\n\
         \x20       a = amount;\n\
         \x20       FHE.allowThis(a);\n\
         \x20   }\n\
         }\n",
    );
}

#[test]
fn precondition_batches_several_inputs_after_the_block() {
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   error Denied();\n\
         \x20   function setA(bool ok, in euint32 x, in euint32 y) external {\n\
         \x20       precondition {\n\
         \x20           require(ok, \"denied\");\n\
         \x20       }\n\
         \x20       a = x;\n\
         \x20       a = y;\n\
         \x20   }\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   error Denied();\n\
         \x20   function setA(bool ok, externalEuint32 x_input, externalEuint32 y_input, \
         bytes memory inputProof) external {\n\
         \x20       {\n\
         \x20           require(ok, \"denied\");\n\
         \x20       }\n\
         \x20       UnsignedEncryptedInput[] memory __fhe_inputs_0 = new UnsignedEncryptedInput[](2);\n\
         \x20       __fhe_inputs_0[0] = UnsignedEncryptedInput(uint256(externalEuint32.unwrap(x_input)), 0, Utils.EUINT32_TFHE);\n\
         \x20       __fhe_inputs_0[1] = UnsignedEncryptedInput(uint256(externalEuint32.unwrap(y_input)), 0, Utils.EUINT32_TFHE);\n\
         \x20       bytes32[] memory __fhe_hashes_1 = Impl.verifyBatchInputs(__fhe_inputs_0, inputProof);\n\
         \x20       euint32 x = euint32.wrap(__fhe_hashes_1[0]);\n\
         \x20       euint32 y = euint32.wrap(__fhe_hashes_1[1]);\n\
         \x20       a = x;\n\
         \x20       FHE.allowThis(a);\n\
         \x20       a = y;\n\
         \x20       FHE.allowThis(a);\n\
         \x20   }\n\
         }\n",
    );
}

#[test]
fn precondition_local_declarations_stay_inside_the_block() {
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   uint256 limit;\n\
         \x20   error TooBig();\n\
         \x20   function setA(uint256 n, in euint32 amount) external {\n\
         \x20       precondition {\n\
         \x20           uint256 cap = limit;\n\
         \x20           cap = cap + 1;\n\
         \x20           if (n > cap) revert TooBig();\n\
         \x20       }\n\
         \x20       uint256 cap = n;\n\
         \x20       cap;\n\
         \x20       a = amount;\n\
         \x20   }\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   uint256 limit;\n\
         \x20   error TooBig();\n\
         \x20   function setA(uint256 n, externalEuint32 amount_input, \
         bytes memory inputProof) external {\n\
         \x20       {\n\
         \x20           uint256 cap = limit;\n\
         \x20           cap = cap + 1;\n\
         \x20           if (n > cap) revert TooBig();\n\
         \x20       }\n\
         \x20       euint32 amount = FHE.asEuint32(amount_input, inputProof);\n\
         \x20       uint256 cap = n;\n\
         \x20       cap;\n\
         \x20       a = amount;\n\
         \x20       FHE.allowThis(a);\n\
         \x20   }\n\
         }\n",
    );
}

#[test]
fn precondition_moves_a_bound_conversion_after_the_block() {
    // The binder and the guard compose: the proof keeps its declared
    // position, and its verification still happens after the guard.
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   mapping(address => bool) operators;\n\
         \x20   error NotOperator(address who);\n\
         \x20   function isOperator(address who) public view returns (bool) {\n\
         \x20       return operators[who];\n\
         \x20   }\n\
         \x20   function setA(address from, in(sig) euint32 amount, bytes calldata sig)\n\
         \x20       external\n\
         \x20   {\n\
         \x20       precondition {\n\
         \x20           if (!isOperator(from)) revert NotOperator(from);\n\
         \x20       }\n\
         \x20       a = amount;\n\
         \x20   }\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   mapping(address => bool) operators;\n\
         \x20   error NotOperator(address who);\n\
         \x20   function isOperator(address who) public view returns (bool) {\n\
         \x20       return operators[who];\n\
         \x20   }\n\
         \x20   function setA(address from, externalEuint32 amount_input, bytes calldata sig)\n\
         \x20       external\n\
         \x20   {\n\
         \x20       {\n\
         \x20           if (!isOperator(from)) revert NotOperator(from);\n\
         \x20       }\n\
         \x20       euint32 amount = FHE.asEuint32(amount_input, sig);\n\
         \x20       a = amount;\n\
         \x20       FHE.allowThis(a);\n\
         \x20   }\n\
         }\n",
    );
}

#[test]
fn precondition_sits_between_modifier_prelude_and_body() {
    // Modifier preludes are solc's job: the generated conversions must still
    // land after the author's guard, and the modifier list is untouched.
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   uint256 guard;\n\
         \x20   error Denied();\n\
         \x20   modifier nonReentrant() {\n\
         \x20       guard = 1;\n\
         \x20       _;\n\
         \x20       guard = 0;\n\
         \x20   }\n\
         \x20   function setA(bool ok, in euint32 amount) external nonReentrant {\n\
         \x20       precondition {\n\
         \x20           if (!ok) revert Denied();\n\
         \x20       }\n\
         \x20       a = amount;\n\
         \x20   }\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   uint256 guard;\n\
         \x20   error Denied();\n\
         \x20   modifier nonReentrant() {\n\
         \x20       guard = 1;\n\
         \x20       _;\n\
         \x20       guard = 0;\n\
         \x20   }\n\
         \x20   function setA(bool ok, externalEuint32 amount_input, \
         bytes memory inputProof) external nonReentrant {\n\
         \x20       {\n\
         \x20           if (!ok) revert Denied();\n\
         \x20       }\n\
         \x20       euint32 amount = FHE.asEuint32(amount_input, inputProof);\n\
         \x20       a = amount;\n\
         \x20       FHE.allowThis(a);\n\
         \x20   }\n\
         }\n",
    );
}

#[test]
fn precondition_guards_a_constructor() {
    // A constructor is a legal host (spec §2.7 legality rule 3): the
    // materializers land after the guard there too.
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   error Denied();\n\
         \x20   constructor(bool ok, in euint32 seed) {\n\
         \x20       precondition {\n\
         \x20           if (!ok) revert Denied();\n\
         \x20       }\n\
         \x20       a = seed;\n\
         \x20   }\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   euint32 a;\n\
         \x20   error Denied();\n\
         \x20   constructor(bool ok, externalEuint32 seed_input, \
         bytes memory inputProof) {\n\
         \x20       {\n\
         \x20           if (!ok) revert Denied();\n\
         \x20       }\n\
         \x20       euint32 seed = FHE.asEuint32(seed_input, inputProof);\n\
         \x20       a = seed;\n\
         \x20       FHE.allowThis(a);\n\
         \x20   }\n\
         }\n",
    );
}

#[test]
fn precondition_refusals_produce_no_patches() {
    // A checker error refuses the whole unit: nothing is lowered.
    let out = transpile_with(&[("t.fsol", REFUSED_PRECONDITION)], AclMode::Insert);
    assert_eq!(out.check_error_codes, ["FHE3014"]);
    // The point of the test: a refused unit is not rewritten at all. Neither
    // the marker nor the `in` parameter may be touched.
    assert!(!out.any_patches, "a refused unit must produce no patches");
    assert_eq!(out.files[0].1, REFUSED_PRECONDITION);
}

/// The source of [`precondition_refusals_produce_no_patches`], so the test can
/// assert the output is byte-identical to it.
const REFUSED_PRECONDITION: &str = "pragma solidity ^0.8.25;\n\
                    import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
                    contract C {\n\
                    \x20   euint32 a;\n\
                    \x20   function setA(in euint32 amount) external {\n\
                    \x20       precondition { amount; }\n\
                    \x20       a = amount;\n\
                    \x20   }\n\
                    }\n";

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
         \x20           a = FHE.select(eb, FHE.add(a, FHE.asEuint32(1)), b);\n\
         \x20           FHE.allowThis(a);\n\
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
         \x20       }",
    );
}

#[test]
fn if_else_without_an_incoming_value_omits_pre() {
    golden_body(
        "        euint32 x;\n\
         \x20       if (eb) {\n\
         \x20           x = a;\n\
         \x20       } else {\n\
         \x20           x = b;\n\
         \x20       }\n\
         \x20       a = x;",
        "        euint32 x;\n\
         \x20       x = FHE.select(eb, a, b);\n\
         \x20       a = x;\n\
         \x20       FHE.allowThis(a);",
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
             \x20       }"
        )
    );
}

#[test]
fn if_merge_to_simple_var_warns_and_withholds_the_sender_grant() {
    // Issue #70: the same withholding R1 does for a direct write applies to
    // an encrypted-if merge write (`pass_if.rs`) — a simple state variable
    // has no key at all, so its owner is not provably `msg.sender` there
    // either.
    let out = transpile(&[(
        "t.fsol",
        &contract(
            "        if (eb) {\n\
             \x20           a = b;\n\
             \x20       }",
        ),
    )]);
    assert_eq!(out.failed_files, 0, "diags: {:?}", out.lower_diag_codes);
    assert!(
        out.lower_diag_codes
            .iter()
            .any(|d| d.starts_with("FHE4001")),
        "diags: {:?}",
        out.lower_diag_codes
    );
    assert_eq!(
        out.files[0].1,
        contract(
            "        {\n\
             \x20           ebool __fhe_cond_0 = eb;\n\
             \x20           euint32 __fhe_pre_1 = a;\n\
             \x20           euint32 __fhe_then_2;\n\
             \x20           {\n\
             \x20               __fhe_then_2 = b;\n\
             \x20           }\n\
             \x20           a = FHE.select(__fhe_cond_0, __fhe_then_2, __fhe_pre_1);\n\
             \x20           FHE.allowThis(a);\n\
             \x20       }"
        )
    );
}

#[test]
fn if_merge_shadowed_msg_param_withholds_the_sender_grant() {
    // Follow-up review finding: a parameter or local named `msg` shadows the
    // `msg.sender` builtin. The merge path must prove ownership by name
    // resolution (`fhec_check::is_msg_sender`), not by spelling, or it
    // false-safe grants the caller access based on a shadowed `msg` (the
    // same bug class as issue #61).
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        \n\
        contract C {\n\
        \x20   struct Msg {\n\
        \x20       address sender;\n\
        \x20   }\n\
        \x20   mapping(address => euint32) balances;\n\
        \x20   function f(Msg memory msg, ebool eb, euint32 v) public {\n\
        \x20       if (eb) {\n\
        \x20           balances[msg.sender] = v;\n\
        \x20       }\n\
        \x20   }\n\
        }\n";
    let out = transpile(&[("t.fsol", src)]);
    assert_eq!(out.failed_files, 0, "diags: {:?}", out.lower_diag_codes);
    assert!(
        out.lower_diag_codes
            .iter()
            .any(|d| d.starts_with("FHE4001")),
        "diags: {:?}",
        out.lower_diag_codes
    );
    let text = &out.files[0].1;
    assert!(
        text.contains("FHE.allowThis(balances[__fhe_key_1]);"),
        "output: {text}"
    );
    assert!(
        !text.contains("FHE.allowSender"),
        "a shadowed `msg` parameter must never prove sender ownership: {text}"
    );
}

#[test]
fn if_merge_parenthesized_msg_sender_still_receives_both_grants() {
    // The inverse of the shadowing case: `(msg).sender` is still exactly
    // `msg.sender` once parens are peeled, so it must still be provable —
    // the merge path's proof must not regress to a stricter spelling check
    // either.
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        \n\
        contract C {\n\
        \x20   mapping(address => euint32) balances;\n\
        \x20   function f(ebool eb, euint32 v) public {\n\
        \x20       if (eb) {\n\
        \x20           balances[(msg).sender] = v;\n\
        \x20       }\n\
        \x20   }\n\
        }\n";
    let out = transpile(&[("t.fsol", src)]);
    assert_eq!(out.failed_files, 0, "diags: {:?}", out.lower_diag_codes);
    assert!(
        !out.lower_diag_codes
            .iter()
            .any(|d| d.starts_with("FHE4001")),
        "diags: {:?}",
        out.lower_diag_codes
    );
    let text = &out.files[0].1;
    assert!(
        text.contains("FHE.allowThis(balances[__fhe_key_1]);"),
        "output: {text}"
    );
    assert!(
        text.contains("FHE.allowSender(balances[__fhe_key_1]);"),
        "output: {text}"
    );
}

#[test]
fn if_merge_nested_mapping_sender_key_at_top_level_receives_both_grants() {
    // `m[other][msg.sender]`: the sender key is the write's own top-level
    // key (spec §8.1), even though an outer key (`other`) is also present.
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        \n\
        contract C {\n\
        \x20   mapping(address => mapping(address => euint32)) m;\n\
        \x20   function f(address other, ebool eb, euint32 v) public {\n\
        \x20       if (eb) {\n\
        \x20           m[other][msg.sender] = v;\n\
        \x20       }\n\
        \x20   }\n\
        }\n";
    let out = transpile(&[("t.fsol", src)]);
    assert_eq!(out.failed_files, 0, "diags: {:?}", out.lower_diag_codes);
    assert!(
        !out.lower_diag_codes
            .iter()
            .any(|d| d.starts_with("FHE4001")),
        "diags: {:?}",
        out.lower_diag_codes
    );
    let text = &out.files[0].1;
    assert!(
        text.contains("FHE.allowThis(m[__fhe_key_1][__fhe_key_2]);"),
        "output: {text}"
    );
    assert!(
        text.contains("FHE.allowSender(m[__fhe_key_1][__fhe_key_2]);"),
        "output: {text}"
    );
}

#[test]
fn if_merge_struct_field_off_sender_keyed_mapping_withholds_the_sender_grant() {
    // `m[msg.sender].field`: the write's own top level is the struct field,
    // not the mapping index, so it carries no owner key of its own (spec
    // §8.1) even though the mapping underneath is sender-keyed.
    let src = "pragma solidity ^0.8.25;\n\
        import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
        \n\
        contract C {\n\
        \x20   struct Acct {\n\
        \x20       euint32 balance;\n\
        \x20   }\n\
        \x20   mapping(address => Acct) accts;\n\
        \x20   function f(ebool eb, euint32 v) public {\n\
        \x20       if (eb) {\n\
        \x20           accts[msg.sender].balance = v;\n\
        \x20       }\n\
        \x20   }\n\
        }\n";
    let out = transpile(&[("t.fsol", src)]);
    assert_eq!(out.failed_files, 0, "diags: {:?}", out.lower_diag_codes);
    assert!(
        out.lower_diag_codes
            .iter()
            .any(|d| d.starts_with("FHE4001")),
        "diags: {:?}",
        out.lower_diag_codes
    );
    let text = &out.files[0].1;
    assert!(
        text.contains("FHE.allowThis(accts[__fhe_key_1].balance);"),
        "output: {text}"
    );
    assert!(!text.contains("FHE.allowSender"), "output: {text}");
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
         \x20           byId[2] = FHE.select(__fhe_cond_0, __fhe_pre_2, __fhe_else_4);\n\
         \x20           FHE.allowThis(byId[2]);\n\
         \x20       }",
    );
}

#[test]
fn if_else_single_assign_matches_ternary() {
    // Issue #73: the trySub shape (plaintext early return, then one
    // assignment per arm of the same target) must lower like `?:`.
    golden(
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   function trySub(euint64 a, euint64 b) internal returns (ebool success, euint64 res) {\n\
         \x20       if (!FHE.isInitialized(b)) return (ebool(true), a);\n\
         \x20       euint64 difference = a - b;\n\
         \x20       success = difference <= a;\n\
         \x20       if (success) {\n\
         \x20           res = difference;\n\
         \x20       } else {\n\
         \x20           res = euint64(0);\n\
         \x20       }\n\
         \x20   }\n\
         }\n",
        "pragma solidity ^0.8.25;\n\
         import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
         \n\
         contract C {\n\
         \x20   function trySub(euint64 a, euint64 b) internal returns (ebool success, euint64 res) {\n\
         \x20       if (!FHE.isInitialized(b)) return (FHE.asEbool(true), a);\n\
         \x20       euint64 difference = FHE.sub(a, b);\n\
         \x20       success = FHE.lte(difference, a);\n\
         \x20       res = FHE.select(success, difference, FHE.asEuint64(0));\n\
         \x20   }\n\
         }\n",
    );
}

#[test]
fn if_else_multi_write_keeps_temps() {
    golden_body(
        "        if (eb) {\n\
         \x20           a = b;\n\
         \x20           a = a + 1;\n\
         \x20       } else {\n\
         \x20           a = b;\n\
         \x20       }",
        "        {\n\
         \x20           ebool __fhe_cond_0 = eb;\n\
         \x20           euint32 __fhe_then_2;\n\
         \x20           euint32 __fhe_then_3;\n\
         \x20           {\n\
         \x20               __fhe_then_2 = b;\n\
         \x20               __fhe_then_3 = FHE.add(__fhe_then_2, FHE.asEuint32(1));\n\
         \x20           }\n\
         \x20           euint32 __fhe_else_4;\n\
         \x20           {\n\
         \x20               __fhe_else_4 = b;\n\
         \x20           }\n\
         \x20           a = FHE.select(__fhe_cond_0, __fhe_then_3, __fhe_else_4);\n\
         \x20           FHE.allowThis(a);\n\
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

#[test]
fn braceless_branch_body_is_wrapped_before_r2_grants() {
    // Spec §8.0: the grant must not become the branch body and push the
    // guarded call out of the branch.
    let src = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               \n\
               interface IVault {\n\
               \x20   function deposit(euint32 x) external;\n\
               }\n\
               \n\
               contract C {\n\
               \x20   euint32 a;\n\
               \x20   IVault vault;\n\
               \x20   function f(bool notPaused) public {\n\
               \x20       if (notPaused) vault.deposit(a);\n\
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
               \x20   IVault vault;\n\
               \x20   function f(bool notPaused) public {\n\
               \x20       if (notPaused) { FHE.allowTransient(a, address(vault));\n\
               \x20       vault.deposit(a);\n\
               \x20       }\n\
               \x20   }\n\
               }\n";
    golden(src, expected);
}

#[test]
fn braceless_branch_body_is_wrapped_after_r1_grants() {
    // Mirror direction: R1 inserts after the write, which would otherwise
    // grant unconditionally.
    let src = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               \n\
               contract C {\n\
               \x20   mapping(address => euint32) bal;\n\
               \x20   function f(bool ok, euint32 amt) public {\n\
               \x20       if (ok) bal[msg.sender] = amt;\n\
               \x20   }\n\
               }\n";
    let expected = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               \n\
               contract C {\n\
               \x20   mapping(address => euint32) bal;\n\
               \x20   function f(bool ok, euint32 amt) public {\n\
               \x20       if (ok) { bal[msg.sender] = amt;\n\
               \x20       FHE.allowThis(bal[msg.sender]);\n\
               \x20       FHE.allowSender(bal[msg.sender]);\n\
               \x20       }\n\
               \x20   }\n\
               }\n";
    golden(src, expected);
}

#[test]
fn braceless_branch_body_with_every_grant_present_stays_byte_identical() {
    // §8.6 suppresses the insertion, so §1.4 must hold: no braces appear.
    let src = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               \n\
               interface IVault {\n\
               \x20   function deposit(euint32 x) external;\n\
               }\n\
               \n\
               contract C {\n\
               \x20   euint32 a;\n\
               \x20   IVault vault;\n\
               \x20   function f(bool notPaused) public {\n\
               \x20       if (notPaused) { FHE.allowTransient(a, address(vault)); vault.deposit(a); }\n\
               \x20   }\n\
               }\n";
    golden(src, src);
}

#[test]
fn acl_grant_in_a_for_header_rejects_with_fhe4004() {
    // A `for` initializer accepts no block and holds no statement list, so
    // the grant has nowhere legal to go (spec §8.0).
    let src = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               \n\
               contract C {\n\
               \x20   mapping(address => euint32) bal;\n\
               \x20   function f(euint32 amt) public {\n\
               \x20       for (bal[msg.sender] = amt; false; ) {}\n\
               \x20   }\n\
               }\n";
    let out = transpile(&[("t.fsol", src)]);
    assert!(
        out.lower_diag_codes
            .iter()
            .any(|d| d.starts_with("FHE4004")),
        "diags: {:?}",
        out.lower_diag_codes
    );
    assert_eq!(out.failed_files, 1);
    assert_eq!(out.files[0].1, src, "a refused file must stay untouched");
}

#[test]
fn r1_grants_land_inside_the_r3_return_rewrite() {
    // Spec §8.0: `return slot = value;` states both facts on one statement.
    // R1's insertion point is R3's replacement end, so R3 must emit the
    // storage grants itself or they would follow the `return`.
    let src = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               \n\
               contract C {\n\
               \x20   euint32 balance;\n\
               \x20   function set(euint32 amount) public returns (euint32) {\n\
               \x20       return balance = amount;\n\
               \x20   }\n\
               }\n";
    let expected = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               \n\
               contract C {\n\
               \x20   euint32 balance;\n\
               \x20   function set(euint32 amount) public returns (euint32) {\n\
               \x20       euint32 __fhe_ret_0 = balance = amount;\n\
               \x20       FHE.allowThis(balance);\n\
               \x20       FHE.allowTransient(__fhe_ret_0, msg.sender);\n\
               \x20       return __fhe_ret_0;\n\
               \x20   }\n\
               }\n";
    golden(src, expected);
}

#[test]
fn r1_write_inside_a_return_without_r3_rejects_with_fhe4004() {
    // No R3 fact on an internal function, so nothing owns the statement and
    // the grants would land after the `return`.
    let src = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               \n\
               contract C {\n\
               \x20   euint32 balance;\n\
               \x20   function set(euint32 amount) internal returns (euint32) {\n\
               \x20       return balance = amount;\n\
               \x20   }\n\
               }\n";
    let out = transpile(&[("t.fsol", src)]);
    assert!(
        out.lower_diag_codes
            .iter()
            .any(|d| d.starts_with("FHE4004")),
        "diags: {:?}",
        out.lower_diag_codes
    );
    assert_eq!(out.failed_files, 1);
    assert_eq!(out.files[0].1, src, "a refused file must stay untouched");
}

#[test]
fn r1_dedupe_accepts_a_grant_on_the_stored_local() {
    // Spec §8.6: CoFHE files permissions against the handle, so a grant on
    // the local the store copies already covers the slot.
    let src = contract(
        "        euint32 ptr = a;\n\
         \x20       FHE.allowThis(ptr);\n\
         \x20       FHE.allowSender(ptr);\n\
         \x20       balances[msg.sender] = ptr;",
    );
    let out = transpile(&[("t.fsol", &src)]);
    assert_eq!(out.files[0].1, src, "no grant may be appended");
}

#[test]
fn r1_dedupe_stops_at_a_reassignment_of_the_local() {
    let src = contract(
        "        euint32 ptr = a;\n\
         \x20       FHE.allowThis(ptr);\n\
         \x20       FHE.allowSender(ptr);\n\
         \x20       ptr = b;\n\
         \x20       balances[msg.sender] = ptr;",
    );
    let expected = contract(
        "        euint32 ptr = a;\n\
         \x20       FHE.allowThis(ptr);\n\
         \x20       FHE.allowSender(ptr);\n\
         \x20       ptr = b;\n\
         \x20       balances[msg.sender] = ptr;\n\
         \x20       FHE.allowThis(balances[msg.sender]);\n\
         \x20       FHE.allowSender(balances[msg.sender]);",
    );
    let out = transpile(&[("t.fsol", &src)]);
    assert_eq!(out.files[0].1, expected);
}

#[test]
fn r2_dedupe_path_owns_the_statement_it_rewrote() {
    // Spec §8.2: the fully-deduplicated path still rewrites the operator
    // argument, so pass 1 must not render the same expression again — the
    // two patches would overlap (FHE9001).
    let src = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               \n\
               interface IVault {\n\
               \x20   function deposit(euint32 x) external;\n\
               }\n\
               \n\
               contract C {\n\
               \x20   euint32 a;\n\
               \x20   euint32 b;\n\
               \x20   IVault vault;\n\
               \x20   function f() public {\n\
               \x20       FHE.allowTransient(a + b, address(vault));\n\
               \x20       vault.deposit(a + b);\n\
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
               \x20   euint32 b;\n\
               \x20   IVault vault;\n\
               \x20   function f() public {\n\
               \x20       FHE.allowTransient(FHE.add(a, b), address(vault));\n\
               \x20       vault.deposit(FHE.add(a, b));\n\
               \x20   }\n\
               }\n";
    golden(src, expected);
}

#[test]
fn r2_leaves_the_statement_to_pass_one_when_it_rewrote_nothing() {
    // A plain-identifier argument needs no rewrite, so the other operator of
    // the statement must still be lowered.
    let src = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               \n\
               interface IVault {\n\
               \x20   function ping(euint32 x) external returns (bytes32);\n\
               }\n\
               \n\
               contract C {\n\
               \x20   euint32 a;\n\
               \x20   euint32 b;\n\
               \x20   IVault vault;\n\
               \x20   function f() internal returns (euint32 out) {\n\
               \x20       out = euint32.wrap(vault.ping(a)) + b;\n\
               \x20   }\n\
               }\n";
    let expected = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               \n\
               interface IVault {\n\
               \x20   function ping(euint32 x) external returns (bytes32);\n\
               }\n\
               \n\
               contract C {\n\
               \x20   euint32 a;\n\
               \x20   euint32 b;\n\
               \x20   IVault vault;\n\
               \x20   function f() internal returns (euint32 out) {\n\
               \x20       FHE.allowTransient(a, address(vault));\n\
               \x20       out = FHE.add(euint32.wrap(vault.ping(a)), b);\n\
               \x20   }\n\
               }\n";
    golden(src, expected);
}

#[test]
fn r2_renders_a_site_that_straddles_a_hoisted_argument() {
    let src = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               \n\
               interface IVault {\n\
               \x20   function ping(euint32 x) external returns (bytes32);\n\
               }\n\
               \n\
               contract C {\n\
               \x20   euint32 a;\n\
               \x20   euint32 b;\n\
               \x20   IVault vault;\n\
               \x20   function f() internal returns (euint32 out) {\n\
               \x20       out = euint32.wrap(vault.ping(a + b)) + a;\n\
               \x20   }\n\
               }\n";
    let expected = "pragma solidity ^0.8.25;\n\
               import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";\n\
               \n\
               interface IVault {\n\
               \x20   function ping(euint32 x) external returns (bytes32);\n\
               }\n\
               \n\
               contract C {\n\
               \x20   euint32 a;\n\
               \x20   euint32 b;\n\
               \x20   IVault vault;\n\
               \x20   function f() internal returns (euint32 out) {\n\
               \x20       euint32 __fhe_val_0 = FHE.add(a, b);\n\
               \x20       FHE.allowTransient(__fhe_val_0, address(vault));\n\
               \x20       out = FHE.add(euint32.wrap(vault.ping(__fhe_val_0)), a);\n\
               \x20   }\n\
               }\n";
    golden(src, expected);
}
