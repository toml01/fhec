//! Tests for the `.fsol` encrypted-input parameter sugar (`in <type> <name>`, spec §2.3).

use fhec_syntax::{ast::FunctionKind, collect_in_sugar, with_parsed_source, InSugarPosition};

fn collect(src: &str) -> Vec<fhec_syntax::InSugarUse> {
    with_parsed_source("test.fsol", src, |p| {
        let uses = collect_in_sugar(p.ast);
        // Resolve snippets while the session is live so span exactness is
        // asserted where the source map is available.
        for u in &uses {
            assert_eq!(
                p.snippet(u.in_span).as_deref(),
                Some("in"),
                "in_span must cover exactly the `in` keyword"
            );
        }
        uses
    })
    .expect("source must parse")
}

#[test]
fn basic_function_param() {
    let uses = collect(
        "pragma solidity ^0.8.25;\n\
         contract C { function deposit(in euint32 amount) external {} }\n",
    );
    assert_eq!(uses.len(), 1);
    let u = &uses[0];
    assert_eq!(
        u.position,
        InSugarPosition::Parameters(FunctionKind::Function)
    );
    assert_eq!(u.name.as_deref(), Some("amount"));
    assert_eq!(u.function.as_deref(), Some("deposit"));
}

#[test]
fn param_span_starts_at_in_and_ty_span_follows() {
    let src = "contract C { function f(in euint32 amount) external {} }";
    with_parsed_source("t.fsol", src, |p| {
        let uses = collect_in_sugar(p.ast);
        assert_eq!(uses.len(), 1);
        let u = &uses[0];
        assert_eq!(p.snippet(u.in_span).as_deref(), Some("in"));
        assert_eq!(p.snippet(u.ty_span).as_deref(), Some("euint32"));
        assert_eq!(
            p.snippet(u.param_span).as_deref(),
            Some("in euint32 amount"),
            "param span must start at the `in` keyword"
        );
    })
    .unwrap();
}

#[test]
fn multiple_params_and_all_encrypted_types() {
    let uses = collect(
        "contract C {\n\
           function f(in euint32 a, uint256 plain, in ebool b, in eaddress who) external {}\n\
         }",
    );
    assert_eq!(uses.len(), 3);
    assert_eq!(uses[0].name.as_deref(), Some("a"));
    assert_eq!(uses[1].name.as_deref(), Some("b"));
    assert_eq!(uses[2].name.as_deref(), Some("who"));
    for u in &uses {
        assert_eq!(
            u.position,
            InSugarPosition::Parameters(FunctionKind::Function)
        );
    }
}

#[test]
fn constructor_param() {
    let uses = collect("contract C { constructor(in euint64 seed) {} }");
    assert_eq!(uses.len(), 1);
    assert_eq!(
        uses[0].position,
        InSugarPosition::Parameters(FunctionKind::Constructor)
    );
    assert_eq!(uses[0].function, None);
}

#[test]
fn non_encrypted_type_parses_restriction_is_checkers() {
    // `in uint32 x` parses; rejecting it (FHE1010) is the checker's job.
    let uses = collect("contract C { function f(in uint32 x) external {} }");
    assert_eq!(uses.len(), 1);
    assert_eq!(uses[0].name.as_deref(), Some("x"));
}

#[test]
fn flagged_positions_parse_and_are_distinguished() {
    // These positions parse (allow-and-flag) so the checker can emit FHE1012
    // instead of a generic parse error.
    let uses = collect(
        "contract C {\n\
           modifier m(in euint8 x) { _; }\n\
           event E(in euint8 x);\n\
           error Err(in euint8 x);\n\
           function g() external returns (in euint8 r) {}\n\
         }",
    );
    let positions: Vec<_> = uses.iter().map(|u| u.position).collect();
    assert_eq!(
        positions,
        vec![
            InSugarPosition::Parameters(FunctionKind::Modifier),
            InSugarPosition::Event,
            InSugarPosition::Error,
            InSugarPosition::Returns(FunctionKind::Function),
        ]
    );
}

#[test]
fn local_decl_multi_component_is_flagged_local() {
    // A tuple-declaration component parses through the same production as a
    // parameter; the occurrence is recorded as Local for the checker to reject.
    let uses = collect(
        "contract C {\n\
           function h() internal returns (uint256, uint256) { return (1, 2); }\n\
           function f() external { (uint256 a, in euint32 b) = (1, 2); a; b; }\n\
         }",
    );
    assert_eq!(uses.len(), 1);
    assert_eq!(uses[0].position, InSugarPosition::Local);
    assert_eq!(uses[0].function.as_deref(), Some("f"));
}

#[test]
fn explicit_proof_binder_is_recorded() {
    let src = "contract C {\n\
         \x20 function f(in(inputProof) euint32 a, in euint32 b, bytes calldata inputProof)\n\
         \x20   external {}\n\
         }";
    with_parsed_source("t.fsol", src, |p| {
        let uses = collect_in_sugar(p.ast);
        assert_eq!(uses.len(), 2);
        // Explicit: the binder is recorded, the marker span covers the parens,
        // and `in_span` still covers exactly the keyword.
        assert_eq!(uses[0].proof.as_deref(), Some("inputProof"));
        assert_eq!(p.snippet(uses[0].in_span).as_deref(), Some("in"));
        assert_eq!(
            p.snippet(uses[0].marker_span).as_deref(),
            Some("in(inputProof)")
        );
        assert_eq!(
            p.snippet(uses[0].param_span).as_deref(),
            Some("in(inputProof) euint32 a")
        );
        // Implicit: no binder, and the marker is the keyword alone. Mixing the
        // two forms parses; rejecting it (FHE1014) is the checker's job.
        assert_eq!(uses[1].proof, None);
        assert_eq!(p.snippet(uses[1].marker_span).as_deref(), Some("in"));
    })
    .expect("source must parse");
}

#[test]
fn plain_solidity_has_no_sugar() {
    let uses = collect(
        "contract C {\n\
           uint256 x;\n\
           function f(uint256 a, bool b) external returns (uint256) { return a; }\n\
         }",
    );
    assert!(uses.is_empty());
}

#[test]
fn upstream_negatives_still_fail() {
    // `in` in an expression.
    assert!(fhec_syntax::parse_source(
        "bad1.sol",
        "contract C { function f() external { uint256 x = 1 in 2; } }"
    )
    .is_err());
    // `in` after a type.
    assert!(fhec_syntax::parse_source(
        "bad2.sol",
        "contract C { function f(uint256 in x) external {} }"
    )
    .is_err());
    // `in` on a state variable declaration.
    assert!(fhec_syntax::parse_source("bad3.sol", "contract C { in euint32 x; }").is_err());
    // `in` in a single local declaration statement.
    assert!(fhec_syntax::parse_source(
        "bad4.sol",
        "contract C { function f() external { in euint32 x; } }"
    )
    .is_err());
    // `in` in a struct field.
    assert!(
        fhec_syntax::parse_source("bad5.sol", "contract C { struct S { in euint32 x; } }").is_err()
    );
    // `in` in a function-type parameter list.
    assert!(fhec_syntax::parse_source(
        "bad6.sol",
        "contract C { function(in euint32) internal g; }"
    )
    .is_err());
}

#[test]
fn with_parsed_source_reports_errors_without_calling_back() {
    let called = std::cell::Cell::new(false);
    let res = with_parsed_source("bad.fsol", "contract {", |_| called.set(true));
    assert!(res.is_err());
    assert!(!called.get(), "callback must not run on a failed parse");
}
