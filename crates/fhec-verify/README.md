# fhec-verify

Stage 8 of the fhec pipeline: the **solc compile gate**.

After `fhec-emit` writes Solidity, this crate compiles that output with a real
`solc` and turns whatever the compiler says into structured diagnostics. If the
gate is red, the transpiler produced something that does not compile.

## What it does

- finds a `solc` binary and checks it against a semver requirement;
- builds a `--standard-json` request from an in-memory source map — the caller
  supplies **every** source, so solc never resolves an import from the
  filesystem;
- runs `solc --standard-json` as a subprocess and parses the response;
- exposes solc's `errors[]` both verbatim and wrapped as spec §9 `FHE6000`
  diagnostics.

## What it does not do

It does **not** remap spans back onto the original `.fsol`. That needs the
emitter's `generated/.fhec/manifest.json` and belongs to `fhec-emit`. What this
crate guarantees is that the remapping *can* be exact: solc's byte offsets are
carried through untouched on `SolcSourceLocation` (raw `i64`, `-1` sentinel
preserved) and on `Span` (`start_byte` / `end_byte`, plus derived 1-based
line/column).

## API

```rust
use fhec_verify::{CompileInput, CompileSettings, OutputSelection, Severity, SolcRunner};

let runner = SolcRunner::for_requirement(">=0.8.25, <0.9.0")?;

let input = CompileInput::new()
    .with_source("generated/Counter.sol", counter_source)
    .with_source("contracts/FHE.sol", fhe_library_source);

let output = runner.compile(&input)?;
if !output.is_success() {
    for diagnostic in output.fhe_diagnostics() {
        // diagnostic.code == "FHE6000"
        // diagnostic.solc carries solc's own code, severity and kind
    }
}
```

| Item | Purpose |
|---|---|
| `SolcRunner::compile(&CompileInput) -> Result<CompileOutput, VerifyError>` | the gate |
| `SolcRunner::discover_default` / `for_requirement` / `discover` / `at_path` | ways to get a runner |
| `CompileInput` / `CompileSettings` / `OutputSelection` / `Optimizer` | the request |
| `CompileOutput` | `diagnostics`, `errors`, `is_success`, `contracts`, `raw`, `fhe_diagnostics` |
| `SolcDiagnostic` / `SolcSourceLocation` / `SolcSeverity` | solc's output, verbatim |
| `Diagnostic` / `Span` / `Severity` / `ForwardedSolc` | the spec §10.2 shape |
| `discovery::ensure_solc` / `ensure_solc_with` | opt-in, best-effort installer |
| `VerifyError` | every failure mode, typed |

### Defaults

| Setting | Default | Note |
|---|---|---|
| `evmVersion` | `cancun` | per PLAN.md stage 8 |
| `optimizer` | off, `runs: 200` | the gate checks compilability, not gas |
| `outputSelection` | `{"*": {"": [], "*": []}}` | errors only |
| `viaIR` | off | |

`OutputSelection::Artifacts` additionally requests ABI, metadata and
creation/runtime bytecode, which populates `CompileOutput::contracts` for later
phases. Note that the errors-only default skips code generation, so
codegen-only diagnostics such as "stack too deep" only appear under
`Artifacts`.

## Diagnostics: the FHE6000 convention

Spec §9 reserves `FHE6xxx` for *forwarded solc diagnostics* and assigns exactly
one code in that range:

> | FHE6000 | (forwarded) | solc-diagnostic (carries solc's own code, severity, and the remapped `.fsol` span) |

So every solc diagnostic becomes one `Diagnostic` with `code == "FHE6000"`,
severity mapped onto the fhec ladder (`error` → `error`, `warning` → `warning`,
`info` → `note`), and a `solc` payload carrying solc's own code (`"6359"`),
severity, kind (`"TypeError"`), `formattedMessage` and every secondary location.

The JSON form matches the spec §10.2 schema. The `solc` key is additive and is
omitted for any other code, so the base schema is unchanged:

```json
{
  "code": "FHE6000",
  "severity": "error",
  "span": {
    "file": "generated/Broken.sol",
    "start_byte": 122, "end_byte": 126,
    "start_line": 6, "start_col": 16,
    "end_line": 6, "end_col": 20
  },
  "message": "Return argument type bool is not implicitly convertible …",
  "fixits": [],
  "solc": { "code": "6359", "severity": "error", "kind": "TypeError", "…": "…" }
}
```

Byte offsets are 0-based and half-open; lines and columns are 1-based, and
columns count UTF-8 bytes, per the spec §10.2 draft decision.

## Finding solc

Search order, first match wins:

1. an explicit path passed by the caller (`DiscoveryOptions::explicit_path`);
2. the `FHEC_SOLC` environment variable;
3. a `solc` executable on `PATH`;
4. a version directory under an svm-rs / Foundry home, laid out as
   `<svm-home>/<version>/solc-<version>`, newest matching version first.

Steps 1 and 2 are **assertions**: a binary named outright that reports the wrong
version fails with `VerifyError::VersionMismatch` rather than quietly falling
through to a different compiler. Steps 3 and 4 are **searches**: a mismatch is
recorded in the search trail and the next candidate is tried. When nothing is
found, `VerifyError::SolcNotFound` lists every place that was inspected and how
to install a compiler.

svm homes checked, in order:

- `$FHEC_SVM_HOME`
- `$SVM_HOME`
- `~/.svm` — the documented svm-rs layout
- `~/Library/Application Support/svm` — where svm-rs actually lands on macOS
- `$XDG_DATA_HOME/svm` and `~/.local/share/svm` — the Linux data-dir variants

`discover` and `compile` never touch the network.

### ensure_solc

`discovery::ensure_solc(&Version)` is an opt-in, best-effort installer that
**may access the network**. It is never called from `compile`. It tries, in
order: an already-installed copy, `svm install <version>`, and finally a
throwaway Foundry project pinned to that version built with `forge build`
(which makes Foundry fetch the compiler into its svm home). Every step is logged
through the `log` facade. `discovery::ensure_solc_with(version, false)`, or the
`FHEC_NO_SOLC_INSTALL` environment variable, reduces it to a pure lookup.

## Environment variables

| Variable | Effect |
|---|---|
| `FHEC_SOLC` | pins an exact binary, overriding the search |
| `FHEC_SVM_HOME` / `SVM_HOME` | where to look for svm-rs compilers |
| `FHEC_NO_SOLC_INSTALL` | forbids `ensure_solc` from downloading |
| `FHEC_COFHE_CONTRACTS` | (tests) the `cofhe-contracts` checkout to compile against |

## Tests

```
cargo test -p fhec-verify
```

- `tests/compile.rs` — a valid contract compiles clean; a deliberate type error
  surfaces with the right severity, solc code and byte range; warnings do not
  fail the gate; imports resolve only from the supplied source map; artifacts
  come back when requested; offsets stay UTF-8 byte offsets.
- `tests/discovery.rs` — version pinning, including rejection of a real binary
  against a fake `=0.4.0` requirement; typed errors for a missing binary, a
  binary with no version banner, and unparsable requirement text.
- `tests/cofhe.rs` — walks the transitive import closure of the real
  `cofhe-contracts` checkout (8 sources: `FHE.sol`, `ICofhe.sol` and the
  OpenZeppelin `Strings.sol` / `Math.sol` / `SafeCast.sol` / `SignedMath.sol` /
  `Bytes.sol` / `Panic.sol` dependencies) and compiles both the library alone
  and a wrapper contract that calls `FHE.add` / `FHE.allowThis`.

Every test that needs a compiler or the sibling checkout checks availability
first and, when it is missing, prints a `SKIP: …` message and returns, so CI
without solc stays green rather than failing.

### How solc got onto the development machine

The machine already had Foundry installed. On macOS, svm-rs (which Foundry
embeds) does **not** use `~/.svm`; it uses the platform data directory
`~/Library/Application Support/svm/<version>/solc-<version>`. That directory
already held 0.8.27, 0.8.30 and 0.8.33, and building a throwaway project with
`solc_version = "0.8.28"` pinned in `foundry.toml` made Foundry download 0.8.28
into the same tree — the same route `ensure_solc` takes as its last resort. No
manual download from `binaries.soliditylang.org` was needed.

Because discovery prefers the newest matching version, the tests run against
**solc 0.8.33** (`~/Library/Application Support/svm/0.8.33/solc-0.8.33`). Set
`FHEC_SOLC` to pin a different one.

This is why `svm_roots()` checks the macOS data directory as well as `~/.svm`:
on this platform, only the former exists.
