# fhec

`fhec` is a source-to-source compiler that transpiles `.fsol` — a Solidity
dialect (superset) — into plain, readable, auditable Solidity that calls the
CoFHE library. Developers write ordinary control flow and operators over
encrypted types (`if`, `+`, `&&`, ...); `fhec` lowers these to the
`FHE.select` / `FHE.add` / ACL calls that CoFHE's confidential computing model
requires, so the generated Solidity is exactly what a human would otherwise
have to write and audit by hand.

The project is pre-alpha, in Phase 0: repo scaffolding is in progress and
there is no working compiler yet.

See `PLAN.md` for the full implementation plan (architecture, grammar,
phases, and verification strategy), and `spec/` for the normative language
specification, which lands separately.
