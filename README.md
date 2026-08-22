# fhec

`fhec` is a source-to-source compiler that transpiles `.fsol` — a Solidity
dialect (superset) — into plain, readable, auditable Solidity that calls the
[CoFHE](https://cofhe-docs.fhenix.zone) library. You write ordinary control
flow and operators over encrypted types (`if`, `+`, `<=`, `&&`, ternaries);
`fhec` lowers them to the `FHE.select` / `FHE.add` / ACL calls that CoFHE's
confidential-computing model requires — exactly the code a careful developer
would otherwise write and audit by hand.

Two guarantees govern every transform. The **prime directive**: `fhec` never
miscompiles — when it is not certain about a construct, it emits an error and
refuses, because a wrong patch produces wrong ciphertexts, not reverts. The
**no-op guarantee**: valid plain CoFHE Solidity passes through byte-identical,
and transpiling the output again changes nothing (`T(T(x)) == T(x)`), so a
codebase can adopt the dialect one file at a time.

## Quickstart

```console
$ cargo build --release -p fhec-cli     # or: pnpm --filter fhec run build:native
$ ./target/release/fhec init
created fhec.toml
created contracts/Counter.fsol
$ npm install @fhenixprotocol/cofhe-contracts   # solc-gate dependency
$ ./target/release/fhec check
$ ./target/release/fhec build
```

`fhec build` writes the generated Solidity to `generated/` (a 1:1 mirror of
`contracts/`, meant to be committed) plus a source-map manifest at
`generated/.fhec/manifest.json`, then compiles the output with real solc as a
verification gate. What the lowering does, on the sample contract:

**Input — `contracts/Counter.fsol`:**

```solidity
function increment(in euint32 amount) external {
    euint32 next = count + amount;
    if (next <= max) {
        count = next;
    }
}
```

**Output — `generated/Counter.sol`:**

```solidity
function increment(externalEuint32 amount_input, bytes memory inputProof) external {
    euint32 amount = FHE.asEuint32(amount_input, inputProof);
    euint32 next = FHE.add(count, amount);
    {
        ebool __fhe_cond_0 = FHE.lte(next, max);
        euint32 __fhe_pre_1 = count;
        euint32 __fhe_then_2;
        {
            __fhe_then_2 = next;
        }
        count = FHE.select(__fhe_cond_0, __fhe_then_2, __fhe_pre_1);
        FHE.allowThis(count);
        FHE.allowSender(count);
    }
}
```

Both branches of an encrypted `if` always execute; the write merges through
`FHE.select` against the pre-`if` value, and the required ACL grants are
inserted after the storage write. Everything outside the rewritten spans is
preserved byte-for-byte — comments, formatting, everything.

## CLI

| Command | What it does |
|---|---|
| `fhec init` | Scaffold `fhec.toml` and a sample dialect contract |
| `fhec check` | Run load → parse → bind → type-check → legality → lowering checks; report diagnostics |
| `fhec build` | `check`, then patch, write the `generated/` mirror + manifest, and compile with solc |
| `fhec explain FHEnnnn` | Explain a diagnostic code (full catalog from the spec) |
| `fhec clean` | Remove generated output |

| Flag | Meaning |
|---|---|
| `--json` | Machine-readable diagnostics (spec §10.2 schema) |
| `--frozen` | CI mode: fail if regeneration differs from the committed `generated/` tree |
| `--fix` | Apply safe fix-its to the source |
| `--acl=insert\|suggest` | Insert ACL grants (default) or downgrade them to fix-it notes |
| `--no-verify` | Skip the solc gate |

Diagnostics carry stable codes (`FHE1xxx` load/parse … `FHE9xxx` internal),
original-source spans, and fix-its; solc errors on generated code are remapped
back to `.fsol` positions through the manifest.

## Repository layout

| Path | Contents |
|---|---|
| `crates/fhec-syntax` | Parser wrapper + the `in euintX` grammar extension |
| `crates/fhec-bind` | Symbols, scopes, imports, C3 inheritance |
| `crates/fhec-check` | FHE-aware type checker, definite assignment, legality (stages 4–5) |
| `crates/fhec-ir` | Abstract FHE-IR + the rewrite-plan model |
| `crates/fhec-targets` | `TargetProfile` trait + the CoFHE profile signature tables |
| `crates/fhec-lower` | The three lowering passes: operators → if/select → ACL |
| `crates/fhec-emit` | Byte-range patcher, temp naming, re-parse guards, mirror tree, source maps |
| `crates/fhec-verify` | solc runner (standard JSON) + error forwarding |
| `crates/fhec-cli` | The `fhec` binary |
| `crates/vendor/` | Vendored [solar](https://github.com/paradigmxyz/solar) parser fork (see `VENDOR.md`) |
| `spec/` | The normative `.fsol` language specification |
| `fixtures/` | Conformance corpus: golden, rejection, no-op, and source-map suites |
| `packages/fhec` | npm wrapper (esbuild/biome-style platform-binary distribution) |
| `packages/difftest` | Differential-execution harness on the CoFHE mocks |

## Status

**Phase 1 (Core + CLI MVP) is complete.** Working today: all operators and
comparisons over encrypted types, encrypted `if`/ternary via select lowering
with branch versioning, plaintext/literal coercion and width widening,
automatic ACL insertion (R1/R2/R3) with dedupe, the `in euintX` parameter
sugar, stable diagnostics with fix-its, deterministic byte-range emission with
source maps, the solc compile gate, and a conformance corpus plus a
differential-execution suite that proves transpiled contracts equivalent to
hand-written references on the CoFHE mocks (plaintexts, ACL state, and revert
parity).

Explicitly not yet in scope (later phases): Hardhat/Foundry plugins,
decrypt/reveal syntax, ACL annotations, flow-based ACL, the Zama fhevm / Inco
/ COTI targets, LSP/editor tooling, and a formatter.

## Related work

OpenZeppelin's upgradeability transpiler (patch-based Solidity rewriting) and
zkay/ZeeStar (ETH Zurich; formal reference for privacy type systems) are the
closest prior art. Google's [HEIR](https://heir.dev) operates at a different
layer: it compiles numeric programs into FHE circuits for FHE libraries and
hardware, not smart contracts into library calls.

## License

MIT. The vendored solar parser is dual-licensed MIT/Apache-2.0 by Paradigm;
see `crates/vendor/VENDOR.md` for provenance and local modifications.
