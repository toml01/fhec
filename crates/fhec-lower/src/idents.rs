//! Collection of identifier texts for temp-name collision avoidance
//! (spec §2.4).
//!
//! The namer must avoid "any identifier visible in the enclosing function".
//! We collect a deterministic superset: every identifier that occurs anywhere
//! in the file (declarations, uses, member names). A superset only makes the
//! namer skip more candidates; it never produces a colliding name.

use solar_ast as ast;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::ops::ControlFlow;

/// Every identifier text occurring in the source unit, sorted (BTreeSet for
/// deterministic iteration).
pub(crate) fn file_idents<'ast>(unit: &'ast ast::SourceUnit<'ast>) -> BTreeSet<String> {
    use ast::visit::Visit;

    struct C {
        out: BTreeSet<String>,
    }

    impl<'ast> Visit<'ast> for C {
        type BreakValue = Infallible;

        fn visit_ident(&mut self, ident: &'ast solar_interface::Ident) -> ControlFlow<Infallible> {
            self.out.insert(ident.to_string());
            ControlFlow::Continue(())
        }
    }

    let mut c = C {
        out: BTreeSet::new(),
    };
    let _ = c.visit_source_unit(unit);
    c.out
}
