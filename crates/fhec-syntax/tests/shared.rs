//! The shared-boundary marker collector (fhec spec §2.8) over the solar fork.
//!
//! These tests pin the *parser* contract the checker builds on: which shapes
//! record a marker, which position each records, and — critically for the
//! §1.4 no-op guarantee — that `shared` stays an ordinary identifier
//! everywhere else.

use fhec_syntax::{
    ast::FunctionKind, collect_shared, with_parsed_source, SharedPosition, SharedRecipient,
};

fn collect(src: &str) -> Vec<fhec_syntax::SharedUse> {
    with_parsed_source("t.fsol", src, |p| collect_shared(p.ast)).expect("must parse")
}

const HEAD: &str = "pragma solidity ^0.8.25;\n";

#[test]
fn input_form_records_a_bare_marker() {
    let uses = collect(&format!(
        "{HEAD}contract C {{ function f(in shared euint64 amount) external {{}} }}"
    ));
    assert_eq!(uses.len(), 1);
    let u = &uses[0];
    assert_eq!(u.recipient, None);
    assert!(u.has_in_marker);
    assert_eq!(u.proof, None);
    assert_eq!(u.name.as_deref(), Some("amount"));
    assert_eq!(u.function.as_deref(), Some("f"));
    assert_eq!(
        u.position,
        SharedPosition::Parameters(FunctionKind::Function)
    );
}

#[test]
fn return_form_records_the_recipient() {
    let uses = collect(&format!(
        "{HEAD}contract C {{ function f() external returns (shared(msg.sender) euint64) {{}} }}"
    ));
    assert_eq!(uses.len(), 1);
    let u = &uses[0];
    assert_eq!(u.recipient, Some(SharedRecipient::MsgSender));
    assert!(!u.has_in_marker);
    assert_eq!(u.name, None);
    assert_eq!(u.position, SharedPosition::Returns(FunctionKind::Function));
}

#[test]
fn a_recipient_other_than_msg_sender_is_classified_not_rejected() {
    // The parser accepts any expression; telling `msg.sender` apart is this
    // collector's job, and refusing the rest is the checker's (FHE1015).
    for recipient in ["owner", "tx.origin", "address(this)", "msg . sender()"] {
        let uses = collect(&format!(
            "{HEAD}contract C {{ address owner; \
             function f() external returns (shared({recipient}) euint64) {{}} }}"
        ));
        assert_eq!(uses.len(), 1, "{recipient}");
        assert!(
            matches!(uses[0].recipient, Some(SharedRecipient::Other(_))),
            "{recipient} must not classify as msg.sender"
        );
    }
}

#[test]
fn illegal_positions_still_parse_and_record() {
    // Allow-and-flag: every one of these must reach the checker as a marker,
    // not as a parse error, so FHE1015 can name the position.
    let cases = [
        (
            "function f(in shared euint64 a) internal {}",
            SharedPosition::Parameters(FunctionKind::Function),
        ),
        (
            "constructor(in shared euint64 a) {}",
            SharedPosition::Parameters(FunctionKind::Constructor),
        ),
        (
            "modifier m(in shared euint64 a) { _; }",
            SharedPosition::Parameters(FunctionKind::Modifier),
        ),
        (
            "event E(shared(msg.sender) euint64 a);",
            SharedPosition::Event,
        ),
        (
            "error Bad(shared(msg.sender) euint64 a);",
            SharedPosition::Error,
        ),
        ("shared(msg.sender) euint64 s;", SharedPosition::StateVar),
    ];
    for (member, position) in cases {
        let uses = collect(&format!("{HEAD}contract C {{ {member} }}"));
        assert_eq!(uses.len(), 1, "{member}");
        assert_eq!(uses[0].position, position, "{member}");
    }
}

#[test]
fn the_two_markers_compose_in_source_and_are_left_to_the_checker() {
    // `in(p) shared` and `in shared(...)` both parse; both are FHE1015.
    let uses = collect(&format!(
        "{HEAD}contract C {{ function f(in(p) shared euint64 a, bytes calldata p) external {{}} }}"
    ));
    assert_eq!(uses.len(), 1);
    assert!(uses[0].has_in_marker);
    assert_eq!(uses[0].proof.as_deref(), Some("p"));
    assert_eq!(uses[0].recipient, None);

    let uses = collect(&format!(
        "{HEAD}contract C {{ function f(in shared(msg.sender) euint64 a) external {{}} }}"
    ));
    assert_eq!(uses.len(), 1);
    assert!(uses[0].has_in_marker);
    assert_eq!(uses[0].recipient, Some(SharedRecipient::MsgSender));
}

#[test]
fn several_markers_come_back_in_source_order() {
    let uses = collect(&format!(
        "{HEAD}contract C {{ function f(in shared euint32 a, in shared euint64 b) external \
         returns (shared(msg.sender) euint8) {{}} }}"
    ));
    let names: Vec<Option<&str>> = uses.iter().map(|u| u.name.as_deref()).collect();
    assert_eq!(names, vec![Some("a"), Some("b"), None]);
}

#[test]
fn shared_stays_an_ordinary_identifier() {
    // The §1.4 no-op corpus depends on this: plain Solidity that uses
    // `shared` as a name must record no marker at all.
    let src = format!(
        "{HEAD}contract Shared {{\n\
         \x20   uint256 shared;\n\
         \x20   function shared_(uint256 shared) public returns (uint256 shared2) {{\n\
         \x20       shared = shared + 1;\n\
         \x20       shared2 = shared;\n\
         \x20   }}\n\
         }}\n"
    );
    assert!(collect(&src).is_empty());
}

#[test]
fn markers_are_absent_from_plain_in_sugar() {
    for src in [
        "function f(in euint64 a) external {}",
        "function f(in(p) euint64 a, bytes calldata p) external {}",
    ] {
        assert!(
            collect(&format!("{HEAD}contract C {{ {src} }}")).is_empty(),
            "{src}"
        );
    }
}
