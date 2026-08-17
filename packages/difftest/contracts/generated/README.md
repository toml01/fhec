# `contracts/generated/`

Landing zone for `fhec` output.

The transpiler mirrors its source tree 1:1 into a `generated/` directory (see
"Emission: byte-range patching" in the repo's `PLAN.md`). Point that mirror here
and the files are compiled by the same `hardhat compile` run as the hand-written
references in `contracts/`, with no extra wiring: Hardhat globs `contracts/**`
and this package's `hardhat.config.ts` sets `paths.sources = 'contracts'`.

Convention:

| Path | Meaning |
|---|---|
| `contracts/<Name>Ref.sol` | hand-written reference, the differential oracle |
| `contracts/generated/<Name>.sol` | `fhec` output for `<Name>.fsol` |
| `scenarios/<name>.ts` | the transaction sequence and probes for that pair |
| `test/<name>.diff.test.ts` | deploys both and asserts equivalence |

Keep the two contracts ABI-compatible on the surface the scenario touches. The
harness compares behaviour, not source: the generated contract is free to use
different temporaries, a different handle layout, and a different internal
structure, as long as plaintexts, ACL state, and revert parity match.

Nothing in this directory is checked in yet — the transpiler does not exist. It
is a placeholder so the wiring is already proven when it does.
