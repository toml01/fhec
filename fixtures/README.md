# Fixtures — the conformance corpus

This directory is the golden-corpus conformance suite for `fhec` (spec §10).
The runner lives at `crates/fhec-cli/tests/fixtures_runner.rs` and drives the
real `fhec` binary over every fixture:

```
cargo test -p fhec-cli --test fixtures_runner
```

## Layout (spec §10.1)

```
fixtures/<area>/<case-name>/
    input.fsol                  # required (noop cases use input.sol)
    <Aux>.fsol / <Aux>.sol      # optional extra sources (multi-file cases)
    expected.sol                # single-output golden (byte-exact)
    expected/<name>.sol         # multi-output golden tree (byte-exact)
    expected.diagnostics.json   # required — [] when clean (§10.2 schema)
    fhec.toml                   # optional per-case config override
    build-only                  # marker: run `fhec build`, not `check`
    no-verify                   # marker: skip the solc gate for this case
```

## Areas

| Area | Kind | What it pins |
|---|---|---|
| `operators/` | golden | §4 operator lowering + §3.3 coercions |
| `select/` | golden | §5.2 if→select branch versioning |
| `acl/` | golden | §8 R1/R2/R3 insertion, dedupe, suggest mode |
| `sugar/` | golden | §2.3 `in` parameter expansion, §2.7 `precondition` blocks, §2.8 shared boundary |
| `imports/` | golden | §2.6 `.fsol` import-specifier rewriting |
| `contracts/` | golden | full-contract integration (EncryptedCounter) |
| `typing/` | rejection | one fixture per FHE2xxx code |
| `reject/` | rejection | FHE1xxx + FHE3xxx codes, exact spans |
| `noop/` | property | §10.4 no-op: byte-identical pass-through |
| `sourcemap/` | property | FHE6000 remapping to `.fsol` positions |

Golden cases also run with `--self-check`, which asserts the §10.4
idempotence property `T(T(x)) == T(x)` in-memory on every build.

`noop/` includes unmodified OpenZeppelin sources (see `noop/NOTICE`) and the
canonical already-lowered EncryptedCounter — plain CoFHE Solidity the
transpiler MUST reproduce byte-for-byte.

## Adding a fixture

1. Create `fixtures/<area>/<case-name>/input.fsol` (pick the area from the
   table; new areas are allowed by §10.1 — teach the runner about them).
2. Generate the expected files by running `fhec build --json --self-check`
   (or `fhec check --json` for rejection cases) in a temp project containing
   the inputs, then copy the generated output and the JSON diagnostics in.
3. REVIEW the generated output against the spec before committing — a golden
   pins the tool's contract, and a wrong golden freezes a bug.
4. Diagnostic matching is order-insensitive with exact spans; an expected
   entry may use `"message_prefix"` instead of `"message"` (§10.2), and
   `fixits`/`rule` are compared only when present in the expected entry.
