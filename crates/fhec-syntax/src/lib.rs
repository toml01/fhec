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
    /// Span of the whole marker: the `in` keyword alone in the implicit form,
    /// or `in` through the binder's closing `)` in the explicit form.
    pub marker_span: interface::Span,
    /// The identifier bound by `in(...)`, if the explicit proof-binder form
    /// was used. Whether it names a valid same-list `bytes` parameter is a
    /// checker rule (FHE1013), not a syntax one.
    pub proof: Option<String>,
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
                    marker_span: in_sugar.span,
                    proof: in_sugar.proof.map(|i| i.to_string()),
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

/// Where a shared-boundary marker appeared (fhec spec §2.8).
///
/// The parser records the marker wherever it can be written unambiguously; the
/// checker maps every position but the two legal ones to FHE1015.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedPosition {
    /// A parameter list of the given function kind. Only `in shared eT name`
    /// on a `function` is legal.
    Parameters(ast::FunctionKind),
    /// A `returns (...)` list of the given function kind. Only
    /// `shared(msg.sender) eT` on a `function` is legal.
    Returns(ast::FunctionKind),
    /// An event parameter list.
    Event,
    /// An error parameter list.
    Error,
    /// A state-variable declaration.
    StateVar,
    /// Any other variable-declaration position.
    Other,
}

/// The recipient of a `shared(...)` marker, classified for the checker.
///
/// The MVP accepts exactly `msg.sender`; the classification is structural, not
/// textual, so spacing and comments inside the marker do not matter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedRecipient {
    /// Exactly the member expression `msg.sender`.
    MsgSender,
    /// Any other expression. The span is the recipient expression's own.
    Other(interface::Span),
}

/// One occurrence of a shared-boundary marker.
#[derive(Clone, Debug)]
pub struct SharedUse {
    /// Span of the marker: `shared` alone (input form) or `shared` through the
    /// recipient's closing `)` (return form).
    pub marker_span: interface::Span,
    /// Span of the whole declaration the marker belongs to.
    pub decl_span: interface::Span,
    /// Span of the declared type that follows the marker.
    pub ty_span: interface::Span,
    /// The recipient, when the `shared(recipient)` form was used. `None` is
    /// the bare input-side marker `in shared eT name`.
    pub recipient: Option<SharedRecipient>,
    /// Whether the declaration also carries the §2.3 `in` marker. The bare
    /// form can only appear with it; the recipient form must appear without.
    pub has_in_marker: bool,
    /// The identifier bound by an accompanying `in(proof)` binder, if any.
    /// Binding a proof and sharing are mutually exclusive (FHE1015).
    pub proof: Option<String>,
    /// Declared name, if named.
    pub name: Option<String>,
    /// Enclosing function/modifier name, if any and named.
    pub function: Option<String>,
    /// Syntactic position.
    pub position: SharedPosition,
}

/// Whether an expression is exactly the member access `msg.sender`.
///
/// Structural on purpose: the checker must not accept a *different* expression
/// that happens to evaluate to the same address, because it cannot prove that.
pub fn is_msg_sender(e: &ast::Expr<'_>) -> bool {
    let ast::ExprKind::Member(base, member) = &e.kind else {
        return false;
    };
    let ast::ExprKind::Ident(id) = &base.kind else {
        return false;
    };
    id.as_str() == "msg" && member.as_str() == "sender"
}

/// Collects every shared-boundary marker occurrence in a parsed source unit.
///
/// Must be called inside a live session (see [`collect_in_sugar`]).
pub fn collect_shared<'ast>(unit: &'ast ast::SourceUnit<'ast>) -> Vec<SharedUse> {
    use ast::visit::Visit;
    use std::ops::ControlFlow;

    struct Collector {
        pos: SharedPosition,
        function: Option<String>,
        out: Vec<SharedUse>,
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
            self.pos = SharedPosition::Parameters(f.kind);
            self.visit_parameter_list(&f.header.parameters)?;
            if let Some(returns) = &f.header.returns {
                self.pos = SharedPosition::Returns(f.kind);
                self.visit_parameter_list(returns)?;
            }
            self.pos = SharedPosition::Other;
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
            self.pos = SharedPosition::Event;
            self.visit_parameter_list(&e.parameters)?;
            self.pos = prev;
            ControlFlow::Continue(())
        }

        fn visit_item_error(
            &mut self,
            e: &'ast ast::ItemError<'ast>,
        ) -> ControlFlow<Self::BreakValue> {
            let prev = self.pos;
            self.pos = SharedPosition::Error;
            self.visit_parameter_list(&e.parameters)?;
            self.pos = prev;
            ControlFlow::Continue(())
        }

        fn visit_item(&mut self, item: &'ast ast::Item<'ast>) -> ControlFlow<Self::BreakValue> {
            let prev = self.pos;
            if matches!(item.kind, ast::ItemKind::Variable(_)) {
                self.pos = SharedPosition::StateVar;
            }
            let r = self.walk_item(item);
            self.pos = prev;
            r
        }

        fn visit_variable_definition(
            &mut self,
            var: &'ast ast::VariableDefinition<'ast>,
        ) -> ControlFlow<Self::BreakValue> {
            if let Some(shared) = &var.shared {
                self.out.push(SharedUse {
                    marker_span: shared.span,
                    decl_span: var.span,
                    ty_span: var.ty.span,
                    recipient: shared.recipient.as_ref().map(|e| {
                        if is_msg_sender(e) {
                            SharedRecipient::MsgSender
                        } else {
                            SharedRecipient::Other(e.span)
                        }
                    }),
                    has_in_marker: var.in_sugar.is_some(),
                    proof: var.in_sugar.and_then(|s| s.proof).map(|i| i.to_string()),
                    name: var.name.map(|i| i.to_string()),
                    function: self.function.clone(),
                    position: self.pos,
                });
            }
            ControlFlow::Continue(())
        }
    }

    let mut c = Collector {
        pos: SharedPosition::Other,
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
