//! Tests for the `.fsol` `precondition { ... }` block (spec §2.7).
//!
//! Solar parses and marks the block in every statement position
//! (allow-and-flag); this collector only reports *where* each one occurred.
//! Legality (first statement, at most one, managed encrypted input present)
//! is the checker's job — see `fhec-check`.

use fhec_syntax::{
    ast::FunctionKind, collect_preconditions, with_parsed_source, PreconditionPosition,
    PreconditionUse,
};

fn collect(src: &str) -> Vec<PreconditionUse> {
    with_parsed_source("test.fsol", src, |p| {
        let uses = collect_preconditions(p.ast);
        for u in &uses {
            assert_eq!(
                p.snippet(u.keyword_span).as_deref(),
                Some("precondition"),
                "keyword_span must cover exactly the contextual keyword"
            );
            let block = p.snippet(u.block_span).expect("block span resolves");
            assert!(block.starts_with('{') && block.ends_with('}'));
            let stmt = p.snippet(u.stmt_span).expect("stmt span resolves");
            assert!(stmt.starts_with("precondition") && stmt.ends_with('}'));
        }
        uses
    })
    .expect("source must parse")
}

#[test]
fn first_body_statement() {
    let uses = collect(
        "pragma solidity ^0.8.25;\n\
         contract C {\n\
             function f(in euint32 a) external { precondition { require(true); } g(a); }\n\
         }\n",
    );
    assert_eq!(uses.len(), 1);
    let u = &uses[0];
    assert_eq!(
        u.position,
        PreconditionPosition::FirstStatement(FunctionKind::Function)
    );
    assert_eq!(u.function.as_deref(), Some("f"));
    assert_eq!(u.stmt_count, 1);
}

#[test]
fn marker_span_is_the_strippable_prefix() {
    let src = "contract C { function f() external { precondition { a = 1; } } }";
    with_parsed_source("t.fsol", src, |p| {
        let uses = collect_preconditions(p.ast);
        assert_eq!(uses.len(), 1);
        let u = &uses[0];
        // Deleting `marker_span` leaves a plain nested block behind: that is
        // exactly what the lowerer does (spec §2.7).
        assert_eq!(p.snippet(u.marker_span).as_deref(), Some("precondition "));
        assert_eq!(p.snippet(u.block_span).as_deref(), Some("{ a = 1; }"));
    })
    .unwrap();
}

#[test]
fn constructor_body() {
    let uses = collect("contract C { constructor(in euint32 a) { precondition {} h(a); } }");
    assert_eq!(uses.len(), 1);
    assert_eq!(
        uses[0].position,
        PreconditionPosition::FirstStatement(FunctionKind::Constructor)
    );
    assert_eq!(uses[0].stmt_count, 0);
}

#[test]
fn later_and_nested_positions_are_reported_not_rejected() {
    let uses = collect(
        "contract C {\n\
             function f() external {\n\
                 uint256 x = 1;\n\
                 precondition { x = 2; }\n\
                 if (x == 2) { precondition { x = 3; } }\n\
                 for (;;) precondition { x = 4; }\n\
             }\n\
         }\n",
    );
    assert_eq!(uses.len(), 3);
    assert_eq!(
        uses[0].position,
        PreconditionPosition::LaterStatement(FunctionKind::Function)
    );
    assert_eq!(uses[1].position, PreconditionPosition::Nested);
    assert_eq!(uses[2].position, PreconditionPosition::Nested);
}

#[test]
fn nested_precondition_inside_a_precondition() {
    let uses = collect("contract C { function f() external { precondition { precondition {} } } }");
    assert_eq!(uses.len(), 2);
    assert_eq!(
        uses[0].position,
        PreconditionPosition::FirstStatement(FunctionKind::Function)
    );
    assert_eq!(uses[1].position, PreconditionPosition::Nested);
}

#[test]
fn modifier_body_is_collected_too() {
    // The checker rejects this (a modifier has no dialect-managed encrypted
    // input), but the syntax layer must still report it.
    let uses = collect("contract C { modifier m() { precondition {} _; } }");
    assert_eq!(uses.len(), 1);
    assert_eq!(
        uses[0].position,
        PreconditionPosition::FirstStatement(FunctionKind::Modifier)
    );
    assert_eq!(uses[0].function.as_deref(), Some("m"));
}

#[test]
fn precondition_stays_an_ordinary_identifier() {
    // Spec §2.7: `precondition` is contextual, recognized only before `{`.
    // Plain Solidity that uses the word as a name must produce no occurrence.
    let uses = collect(
        "contract C {\n\
             uint256 precondition;\n\
             function precondition_(uint256 precondition) public returns (uint256 out) {\n\
                 out = precondition;\n\
                 precondition_(1);\n\
             }\n\
         }\n",
    );
    assert!(uses.is_empty(), "{uses:?}");
}

#[test]
fn free_function_body() {
    let uses = collect("function free(in euint32 a) { precondition {} use(a); }");
    assert_eq!(uses.len(), 1);
    assert_eq!(uses[0].function.as_deref(), Some("free"));
}
