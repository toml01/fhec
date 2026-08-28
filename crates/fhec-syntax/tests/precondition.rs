//! Parser-fork behavior for the `.fsol` `precondition { ... }` block (§2.7).
//!
//! This file pins what the *fork* does, and nothing else: solar parses the
//! block in every statement position (allow-and-flag) and keeps `precondition`
//! an ordinary identifier everywhere it is not followed by `{`. Which of those
//! positions is legal is a checker rule with its own coverage in
//! `fhec-check/tests/check.rs`; stating it twice would let the two drift.

use fhec_syntax::{ast, with_parsed_source};

/// The span of every `precondition` statement in a parsed unit, in source
/// order. A plain AST count — deliberately not a classification.
fn markers(src: &str) -> Vec<String> {
    with_parsed_source("test.fsol", src, |p| {
        use ast::visit::Visit;
        use std::ops::ControlFlow;

        struct Finder {
            spans: Vec<fhec_syntax::interface::Span>,
        }
        impl<'ast> Visit<'ast> for Finder {
            type BreakValue = std::convert::Infallible;
            fn visit_stmt(&mut self, stmt: &'ast ast::Stmt<'ast>) -> ControlFlow<Self::BreakValue> {
                if let ast::StmtKind::Precondition(_) = &stmt.kind {
                    self.spans.push(stmt.span);
                }
                self.walk_stmt(stmt)
            }
        }

        let mut f = Finder { spans: Vec::new() };
        let _ = f.visit_source_unit(p.ast);
        f.spans
            .iter()
            .map(|s| p.snippet(*s).expect("span resolves"))
            .collect()
    })
    .expect("source must parse")
}

#[test]
fn every_statement_position_parses() {
    // First statement, later statement, an `if` arm, a loop body, and nested
    // inside another `precondition`. The fork accepts all five; FHE1017 for
    // the illegal ones is the checker's call.
    let uses = markers(
        "pragma solidity ^0.8.25;\n\
         contract C {\n\
             function f(in euint32 a) external {\n\
                 precondition { require(true); precondition {} }\n\
                 uint256 x = 1;\n\
                 precondition { x = 2; }\n\
                 if (x == 2) { precondition { x = 3; } }\n\
                 for (;;) precondition { x = 4; }\n\
             }\n\
         }\n",
    );
    assert_eq!(uses.len(), 5, "{uses:?}");
    for u in &uses {
        assert!(u.starts_with("precondition") && u.ends_with('}'), "{u}");
    }
}

#[test]
fn constructors_modifiers_and_free_functions_parse_it_too() {
    assert_eq!(
        markers("contract C { constructor(in euint32 a) { precondition {} h(a); } }").len(),
        1
    );
    assert_eq!(
        markers("contract C { modifier m() { precondition {} _; } }").len(),
        1
    );
    assert_eq!(
        markers("function free(in euint32 a) { precondition {} use(a); }").len(),
        1
    );
}

#[test]
fn precondition_stays_an_ordinary_identifier() {
    // Spec §2.7: the keyword is contextual, recognized only before `{`. Plain
    // Solidity using the word as a name must parse with no marker at all —
    // this is what keeps the §1.4 no-op corpus safe.
    let uses = markers(
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
