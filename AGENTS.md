# AGENTS.md

`.fsol` → readable CoFHE Solidity. Dual workspace: Cargo `crates/*` (the compiler) + pnpm `packages/*` (npm wrapper + difftest). Normative behavior is `spec/spec.md` (RFC-2119); section numbers are stable — do not renumber.

## Commands

CI (`.github/workflows/ci.yml`):

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Keep `rust-toolchain.toml` (`1.98`) in sync with the CI `dtolnay/rust-toolchain` pin — the action ignores the toml.

Focused:

```
cargo test -p fhec-cli --test fixtures_runner
cargo test -p fhec-lower --test golden
cargo test -p fhec-check --test check
pnpm --filter difftest test          # transpiles then hardhat
pnpm --filter difftest run check:types
```

`fixtures_runner` is one `#[test]` per area (all cases). Iterate a single construct in `crates/fhec-{check,lower}/tests/*.rs`, not by hoping cargo will isolate one fixture directory.

`fhec` binary: `cargo build -p fhec-cli` → `target/debug/fhec`. Dogfood JS wrapper with `pnpm --filter fhec exec node bin/fhec.js …` — `pnpm exec fhec` does not resolve a package’s own bin.

## Pipeline (not obvious from filenames)

Stages, always in this order, inside **one** solar `Session` + `Arena` (AST is arena-borrowed; copy out anything that must outlive the session):

1. load (`fhec-cli`) — `fhec.toml` upward search, discover `.fsol`/`.sol`
2. parse (`fhec-syntax` + git-pinned solar fork)
3. bind (`fhec-bind`)
4–5. check (`fhec-check`) — types, rewrite sites, ACL facts, legality
6. lower (`fhec-lower`) — **ops → if/select → ACL**
7. emit (`fhec-emit`) — byte-range splice, re-parse guards, `generated/` mirror + `.fhec/manifest.json`
8. solc gate (`fhec-verify`) — `solc --standard-json`; **span remap to `.fsol` is CLI `gate.rs`**, not this crate

`fhec check` still runs the lowerer and discards output, so spec §7 rejects and spec §8 ACL diagnostics fire on check.

`fhec-ir` is a **rendering** IR (byte-range fragments), not an optimizer IR. Output = input bytes except inside non-overlapping patches. Only `.fsol` is rewritten; `.sol` is byte-identical except spec §2.6 import-specifier `.fsol` → `.sol`. Nested operator sites must be rendered recursively — never emit overlapping patches (FHE9001). Temps: `__fhe_<hint>_<n>`, one counter per function.

Solar is `git = https://github.com/toml01/solar` at a workspace-pinned rev (all four `solar-*` crates share it). Bump by hand after merging the `fhec` branch; Dependabot ignores these. `VariableDefinition.in_sugar` is a fork extension. Do not add crates.io `solar-*`. The stale `TODO(fhec-syntax)` in `fhec-bind` about a missing `in` marker is wrong — the marker already exists.

`fhec-ir`, `fhec-targets`, `fhec-lower`, `fhec-emit` use `#![warn(missing_docs)]`; CI denies warnings, so new public items need rustdoc.

## Invariants (refuse rather than guess)

- **Prime directive (spec §1.3):** never miscompile. Uncertainty → error + no patches for that file. Wrong FHE output is silent wrong ciphertexts, not reverts.
- **No-op / idempotence (spec §1.4):** plain CoFHE Solidity is byte-identical; `T(T(x)) == T(x)`. Hidden `--self-check` asserts this; fixture goldens run it.
- Encrypted `if` executes **both** branches and merges with `FHE.select`. No `return`/`revert`/`emit`/plaintext writes in those branches. Two indexed writes whose keys may alias → **FHE3011** (split into sequential `if`s; see EncryptedVault).
- No `euint256`. Profile types: `ebool`, `euint8/16/32/64/128`, `eaddress`.
- Existing FHE library calls the profile does not understand are left to solc — do not reject them.

Out of scope unless asked: Hardhat/Foundry plugins, decrypt/reveal, other FHE targets, LSP, formatter.

## Diagnostics

Codes are append-only (`FHE1xxx` load … `FHE9xxx` internal). Meaning never changes; retired codes are not reused. Adding a code means all of: spec §9, `fhec-cli` `explain.rs` `CATALOG`, the emitting crate’s `codes` module.

`--json` prints the spec §10.2 array on **stdout**; human form is stderr. Spans: 0-based half-open bytes; 1-based line/col; columns are UTF-8 bytes. Exit: `0` ok, `1` error diagnostics, `2` usage/internal.

`fhec.toml` uses `deny_unknown_fields` except reserved `[strictness]`. Defaults: `src = "contracts"`, `out = "generated"`, profile `cofhe` `0.1.x`, `solc = ">=0.8.25 <0.9.0"`, `evm_version = "cancun"`.

## Tests & fixtures

Conformance corpus: `fixtures/<area>/<case>/` (see `fixtures/README.md`). Goldens are **byte-exact**. A wrong golden freezes a bug — generate with `fhec build --json --self-check`, then review against the spec before committing. Areas the runner knows: `operators`, `select`, `acl`, `sugar`, `imports`, `contracts`, `typing`, `reject`, `noop`, `sourcemap`. New areas need a runner change. Markers: `fhec.toml`, `build-only`, `no-verify`.

Lowering changes usually need **both** `crates/fhec-lower/tests/golden.rs` and matching `fixtures/**/expected.sol`. Dialect output also regenerates `packages/difftest/contracts/generated/` (committed). `--frozen` fails if that tree would drift.

Tests that need a real compiler or CoFHE checkout **SKIP** (still green) when missing. The built-in default checkout path only exists on the original dev machine — everywhere else set:

- `FHEC_COFHE_CONTRACTS` — repo root containing `contracts/FHE.sol` (fixture/e2e/gate tests symlink it to `node_modules/@fhenixprotocol/cofhe-contracts`)
- `FHEC_CORPUS_DIRS` — colon-separated `.sol` trees for syntax/check corpus tests
- `FHEC_SOLC` — pin `solc` (else PATH, then svm-rs homes)

CI rust job does **not** install solc or CoFHE, so a green workspace test is not full gate coverage. Fixture/e2e linking is Unix `symlink`.

## `packages/`

- `fhec` — esbuild/biome-style binary shim. Resolution: `FHEC_BINARY_PATH` → platform package → `target/{release,debug}/fhec`. `build:native` only stages **darwin-arm64**; other hosts skip the smoke tests.
- `difftest` — Hardhat 2 harness (`node >= 22`). Exact version pins (no `^`/`~`). Do not bump Hardhat to 3 (Dependabot ignores that major). Compare plaintext, ACL `isAllowed`, and revert **identity** — **never ciphertext handles**. Mint encrypted inputs per side via `args: async (ctx) => …` (`encryptInput`). Write `*Ref.sol` independently; never copy fhec output as the oracle. Mock bootstrap lives in `src/mocks.ts` — do not reinvent it.

## Env (solc)

`FHEC_SOLC`, `FHEC_SVM_HOME`/`SVM_HOME`, `FHEC_NO_SOLC_INSTALL`. Discovery never networks; `ensure_solc` may, and is not on the compile path.
