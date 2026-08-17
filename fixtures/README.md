# Fixtures

This directory holds the golden-corpus fixtures used to test `fhec`. Each
fixture is a small directory with three files:

- `input.fsol` — the dialect source input.
- `expected.sol` — the expected transpiled, plain CoFHE Solidity output.
- `expected.diagnostics.json` — the expected diagnostics (stable codes such
  as `FHE1xxx`/`FHE2xxx`/`FHE3xxx`, source spans, and messages).

No fixtures exist yet (Phase 0 scaffold). This README documents the format
ahead of Phase 1, when the golden corpus is populated.

## What the corpus backs

- **Golden tests** — fixture pairs organized per rule ID; each snapshots the
  expected output and diagnostics for one rule.
- **Rejection suite** — one fixture per legality reject rule, asserting the
  exact error code produced.
- **Idempotence properties** — `T(T(x)) == T(x)` byte-exact, plus a
  plain-Solidity must-not-touch corpus asserting `T(y) == y`.
- **Conformance corpus** — de-lowered reference contracts as dialect inputs,
  checked for differential equivalence with the originals.

See `/Users/toml/dev/fhe-transpiler/PLAN.md` ("Verification" section) for the
full test strategy.
