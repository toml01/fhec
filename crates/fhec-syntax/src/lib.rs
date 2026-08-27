//! forked solar-parse/-ast + dialect grammar extensions
//!
//! Thin wrapper over the [solar](https://github.com/toml01/solar) parser fork.
//! Downstream fhec crates should use the re-exports below instead of depending
//! on the solar crates directly, so the fork boundary stays in one place.

pub use solar_ast as ast;
pub use solar_parse as parse;
pub use solar_parse::interface;

use solar_parse::{
    interface::{source_map::FileName, ColorChoice, Session},
    Parser,
};
use std::path::Path;

/// Result of parsing one source: `Ok(())` on a clean parse, otherwise the rendered
/// diagnostics (one string per emitted diagnostic batch).
///
/// This entry point will grow richer (returning the AST + source map) as the pipeline
/// lands; for now it only answers "does this source parse cleanly?".
pub fn parse_source(name: &str, src: &str) -> Result<(), Vec<String>> {
    parse_inner(
        FileName::Custom(name.to_string()),
        SourceInput::Text(src.to_string()),
    )
}

/// Parse a file from disk. See [`parse_source`].
pub fn parse_path(path: &Path) -> Result<(), Vec<String>> {
    parse_inner(
        FileName::Real(path.to_path_buf()),
        SourceInput::File(path.to_path_buf()),
    )
}

/// A successfully parsed source, borrowed for the duration of a
/// [`with_parsed_source`] callback.
///
/// Lifetime pattern: solar allocates the AST in an arena and interns symbols in
/// session-globals that are only installed while the session is entered. Downstream
/// crates therefore consume the AST through the callback in [`with_parsed_source`];
/// anything that must outlive the callback has to be copied out (spans are `Copy`,
/// identifiers can be stringified).
pub struct Parsed<'ast> {
    /// The parsing session; gives access to the source map for span resolution.
    pub sess: &'ast Session,
    /// The parsed source unit.
    pub ast: &'ast ast::SourceUnit<'ast>,
}

impl Parsed<'_> {
    /// Returns the source text a span covers, if it resolves in the source map.
    pub fn snippet(&self, span: interface::Span) -> Option<String> {
        self.sess.source_map().span_to_snippet(span).ok()
    }
}

/// Parses `src` and hands the AST to `f` inside the live parse session.
///
/// Returns `Err` with rendered diagnostics if the source does not parse cleanly
/// (`f` is not called); otherwise returns `f`'s result.
pub fn with_parsed_source<R>(
    name: &str,
    src: &str,
    f: impl FnOnce(&Parsed<'_>) -> R,
) -> Result<R, Vec<String>> {
    let sess = Session::builder()
        .with_buffer_emitter(ColorChoice::Never)
        .build();
    let mut result = None;
    let _ = sess.enter_sequential(|| -> interface::Result<()> {
        let arena = ast::Arena::new();
        let mut parser =
            Parser::from_source_code(&sess, &arena, FileName::Custom(name.to_string()), src)?;
        let unit = parser.parse_file().map_err(|e| e.emit())?;
        // Move the source unit into the arena so its reference carries the arena
        // lifetime the `Visit` trait expects (`&'ast SourceUnit<'ast>`).
        let unit = &*arena.bump().alloc(unit);
        if sess.dcx.has_errors().is_ok() {
            result = Some(f(&Parsed {
                sess: &sess,
                ast: unit,
            }));
        }
        Ok(())
    });
    match sess.emitted_errors().expect("buffer emitter is set") {
        Ok(()) => Ok(result.expect("callback ran on clean parse")),
        Err(diags) => Err(diags.to_string().lines().map(str::to_string).collect()),
    }
}

/// Where an `in` encrypted-input sugar occurrence appeared (fhec spec §2.3).
///
/// Only `Parameters` on a `function` or `constructor` is legal; the checker maps the
/// other positions to FHE1012.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InSugarPosition {
    /// A parameter list of the given function kind (function, constructor, modifier,
    /// fallback, receive).
    Parameters(ast::FunctionKind),
    /// A `returns (...)` list of the given function kind.
    Returns(ast::FunctionKind),
    /// An event parameter list.
    Event,
    /// An error parameter list.
    Error,
    /// A local declaration inside a function body.
    Local,
    /// Any other variable-declaration position.
    Other,
}

/// One occurrence of the `in` encrypted-input parameter sugar.
#[derive(Clone, Debug)]
pub struct InSugarUse {
    /// Exact span of the `in` keyword itself.
    pub in_span: interface::Span,
    /// Span of the whole parameter declaration (starts at `in`).
    pub param_span: interface::Span,
    /// Span of the declared type.
    pub ty_span: interface::Span,
    /// Parameter name, if named.
    pub name: Option<String>,
    /// Enclosing function/modifier name, if any and named.
    pub function: Option<String>,
    /// Syntactic position; only function/constructor `Parameters` is legal.
    pub position: InSugarPosition,
}

/// Collects every `in` sugar occurrence in a parsed source unit.
///
/// Must be called inside a live session (i.e. from a [`with_parsed_source`] callback),
/// because identifier stringification needs the session's interner.
pub fn collect_in_sugar<'ast>(unit: &'ast ast::SourceUnit<'ast>) -> Vec<InSugarUse> {
    use ast::visit::Visit;
    use std::ops::ControlFlow;

    struct Collector {
        pos: InSugarPosition,
        function: Option<String>,
        out: Vec<InSugarUse>,
    }

    impl<'ast> Visit<'ast> for Collector {
        type BreakValue = std::convert::Infallible;

        fn visit_item_function(
            &mut self,
            f: &'ast ast::ItemFunction<'ast>,
        ) -> ControlFlow<Self::BreakValue> {
            let prev_fn = self.function.take();
            self.function = f.header.name.map(|i| i.to_string());
            let prev_pos = self.pos;
            self.pos = InSugarPosition::Parameters(f.kind);
            self.visit_parameter_list(&f.header.parameters)?;
            if let Some(returns) = &f.header.returns {
                self.pos = InSugarPosition::Returns(f.kind);
                self.visit_parameter_list(returns)?;
            }
            self.pos = InSugarPosition::Local;
            if let Some(body) = &f.body {
                self.visit_block(body)?;
            }
            self.pos = prev_pos;
            self.function = prev_fn;
            ControlFlow::Continue(())
        }

        fn visit_item_event(
            &mut self,
            e: &'ast ast::ItemEvent<'ast>,
        ) -> ControlFlow<Self::BreakValue> {
            let prev = self.pos;
            self.pos = InSugarPosition::Event;
            self.visit_parameter_list(&e.parameters)?;
            self.pos = prev;
            ControlFlow::Continue(())
        }

        fn visit_item_error(
            &mut self,
            e: &'ast ast::ItemError<'ast>,
        ) -> ControlFlow<Self::BreakValue> {
            let prev = self.pos;
            self.pos = InSugarPosition::Error;
            self.visit_parameter_list(&e.parameters)?;
            self.pos = prev;
            ControlFlow::Continue(())
        }

        fn visit_variable_definition(
            &mut self,
            var: &'ast ast::VariableDefinition<'ast>,
        ) -> ControlFlow<Self::BreakValue> {
            if let Some(in_sugar) = var.in_sugar {
                self.out.push(InSugarUse {
                    in_span: in_sugar.kw_span,
                    param_span: var.span,
                    ty_span: var.ty.span,
                    name: var.name.map(|i| i.to_string()),
                    function: self.function.clone(),
                    position: self.pos,
                });
            }
            ControlFlow::Continue(())
        }
    }

    let mut c = Collector {
        pos: InSugarPosition::Other,
        function: None,
        out: Vec::new(),
    };
    let _ = c.visit_source_unit(unit);
    c.out
}

enum SourceInput {
    Text(String),
    File(std::path::PathBuf),
}

fn parse_inner(filename: FileName, input: SourceInput) -> Result<(), Vec<String>> {
    let sess = Session::builder()
        .with_buffer_emitter(ColorChoice::Never)
        .build();
    let _ = sess.enter(|| -> interface::Result<()> {
        let arena = ast::Arena::new();
        let mut parser = match input {
            SourceInput::Text(src) => Parser::from_source_code(&sess, &arena, filename, src)?,
            SourceInput::File(path) => Parser::from_file(&sess, &arena, &path)?,
        };
        let _ast = parser.parse_file().map_err(|e| e.emit())?;
        Ok(())
    });
    match sess.emitted_errors().expect("buffer emitter is set") {
        Ok(()) => Ok(()),
        Err(diags) => Err(diags.to_string().lines().map(str::to_string).collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_contract() {
        parse_source(
            "test.sol",
            "pragma solidity ^0.8.25;\ncontract C { uint256 x; }\n",
        )
        .expect("minimal contract must parse");
    }

    #[test]
    fn reports_parse_errors() {
        let err = parse_source("bad.sol", "contract {").expect_err("must fail");
        assert!(!err.is_empty());
    }
}
