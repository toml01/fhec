# Vendored code: solar

- **Upstream:** https://github.com/paradigmxyz/solar
- **Tag:** `v0.2.0`
- **Commit:** `a1f81d071a85b2f6c36cd67fb2fd9d4503477169`
- **Vendored on:** 2026-08-17
- **License:** dual `MIT OR Apache-2.0` (see `LICENSE-MIT` and `LICENSE-APACHE` in this
  directory, copied from the upstream repository root). Copyright DaniPopes and the
  solar contributors.

## Vendored crates

| Directory | Upstream crate dir | Package |
|---|---|---|
| `solar-parse` | `crates/parse` | `solar-parse` 0.2.0 |
| `solar-ast` | `crates/ast` | `solar-ast` 0.2.0 |
| `solar-interface` | `crates/interface` | `solar-interface` 0.2.0 |
| `solar-data-structures` | `crates/data-structures` | `solar-data-structures` 0.2.0 |
| `solar-macros` | `crates/macros` | `solar-macros` 0.2.0 |
| `solar-config` | `crates/config` | `solar-config` 0.2.0 |

Not vendored: `solar-sema`, `solar-cli`, `solar-lsp`, `solar-codegen`, `solar-compiler`
facade, benches, tools — the parser does not need them.

## Local modifications

Source code (`src/`, `build.rs`) is byte-identical to upstream, with the exceptions
listed below. `Cargo.toml` manifests are rewritten.

1. **All six `Cargo.toml` manifests** — rewritten to be self-contained: workspace
   inheritance (`*.workspace = true` package fields and dependency entries) replaced
   with the concrete values from upstream's root `Cargo.toml` at the same tag;
   `solar-*` dependencies converted to `path = "../<dir>"` deps. Dependency versions
   and feature sets are unchanged. The `[lints] workspace = true` tables are kept;
   the upstream `[workspace.lints.*]` tables are replicated in this repo's root
   `Cargo.toml` so they resolve identically.
2. **`solar-parse/doc-examples/parser.rs`** — upstream is a symlink to
   `examples/src/parser.rs` (outside the vendored set); replaced by a regular file
   with that target's exact content (needed by an `include_str!` doc attribute).
3. **`solar-macros/src/symbols/tests.rs`** — one `include_str!` path adjusted from
   `../../../interface/src/symbol.rs` to `../../../solar-interface/src/symbol.rs`
   because the crate directory is named differently here (marked with an
   `fhec vendoring patch` comment at the site).
4. **`solar-ast/src/ast/item.rs`** — dialect grammar extension (fhec spec §2.3):
   `VariableDefinition` gains the field `in_sugar: Option<Span>` recording the exact
   span of the `in` keyword of the `.fsol` encrypted-input parameter sugar (`None`
   for plain Solidity).
5. **`solar-ast/src/visit.rs`** — the exhaustive `VariableDefinition` destructure in
   `visit_variable_definition` gains `in_sugar: _`.
6. **`solar-ast/src/ast/mod.rs`** — size snapshot for `VariableDefinition` updated
   72 → 88 (the new `Option<Span>` field).
7. **`solar-parse/src/parser/item.rs`** — dialect grammar extension: new
   `VarFlags::IN_SUGAR` bit, added to the `FUNCTION`, `EVENT`, and `ERROR` flag sets;
   `parse_variable_definition_with` optionally eats one `in` keyword before the type
   when the flag allows it and no type was pre-parsed, and records its span on the
   node. `in` is a reserved Solidity keyword, so no valid plain-Solidity program
   changes meaning; expression positions and single local declarations reject `in`
   exactly as upstream. Positional/type legality of the sugar is checked by fhec,
   not the parser. All sites marked with `fhec vendoring patch` comments.

## Policy

- Do not edit vendored code except to track upstream. Grammar extensions for the
  `.fsol` dialect live in `crates/fhec-syntax` wrappers where possible; if the fork
  must diverge, every divergence gets an entry in the list above.
- `cargo fmt` and `cargo clippy -D warnings` in CI are scoped to fhec crates only;
  vendored code is built and tested (`cargo test --workspace`) but not reformatted
  or linted by our configuration.
- To update: re-vendor from a newer tag, reapply the modifications above, update
  this file.
