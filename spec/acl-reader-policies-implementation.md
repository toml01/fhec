# Implementing reader policies (spec §8.8–§8.13)

Status: spec merged on branch `spec/acl-reader-policies`, no code written yet.
Audience: an implementer starting with no prior context on this design.

## 1. Read these first, in order

1. `spec/spec.md` §8 in full — §8.1–§8.7 are the existing rules R1–R3, §8.8–§8.13 are new.
2. `spec/spec.md` §9 — codes FHE4005–FHE4009 and FHE4013 are reserved and defined.
3. `AGENTS.md` — pipeline stages, fixture layout, and the rule that a new code must land in three places.
4. The three commits: `a4be1be` (the feature), `43dcaf6` (merge + event resolution), `9edc77d` (key rename).

Do not redesign. Every question below was argued and closed; §7 lists what was deliberately left open.

## 2. What this feature is, in one paragraph

R1–R3 insert ACL grants only where the transpiler can *prove* who owns a value. Everything else — a balance owned by a mapping key, a compliance observer, a transfer amount both parties must read from an event — has to be hand-written, and §8.5 forbids the transpiler to guess it. In the reference port (`/Users/toml/dev/fhenix-confidential-contracts`) that is 22 of 35 grants. A **reader policy** lets the author state the claim once, at the declaration, in a NatSpec item; two new rules transcribe it. Nothing is inferred — R4 and R5 only ever emit what a policy says.

```solidity
/// @custom:storage-location erc7201:token.storage.Confidential
/// @custom:fhe-allow _balances: account
/// @custom:fhe-allow _totalSupply: this
struct ConfidentialStorage {
    mapping(address account => euint64) _balances;
    euint64 _totalSupply;
}

/// @custom:fhe-allow amount: from, to
event ConfidentialTransfer(address indexed from, address indexed to, euint64 indexed amount);
```

## 3. Settled decisions — do not reopen

| Question | Decision |
|---|---|
| Key spelling | `@custom:fhe-allow`. The `fhe-` prefix is load-bearing: §8.8 restriction 3 refuses any unrecognized `@custom:fhe-` key, which is the only thing stopping a typo from silently meaning "no policy". |
| Where a policy attaches | State variable, `struct`, or `event` — all three are `ast::Item`s and carry `docs`. **Not** a struct field or a function parameter: `VariableDefinition` has no `docs` field, which is exactly why the struct-level form exists. |
| Key binders | `key`/`key0`/`key1`… are policy-local placeholders for the index expression at each write site, available on every mapping. A Solidity named key (`mapping(address account => …)`) is an alias for the same binder. Both spellings stay legal. |
| Forward-only policies | A mapping/array policy naming mutable state is legal and grants correctly at every write; only re-application is impossible. FHE4007 **warning**, not a refusal. `public if` on such a target is the one error. |
| `public` emits no leading `allowThis` | Correct as specced. `allow` and `allowGlobal` gate on the *same* `isAllowed(handle, requester)` check (`MockACL.sol:110` and `:129`), so a leading `allowThis` cannot rescue a handle the contract is not allowed on — it fails identically. After `allowGlobal`, `isAllowed` is true for everyone including the contract. |
| Event redeclarations | A policy is read from the declaration the `emit` resolves to. Nothing propagates between an interface's copy and a library's copy. No diagnostic for an unannotated redeclaration — FHE4009 already reports the real harm against the value. |
| `--acl` default | Stays `suggest`. Flip to `insert` only after the reference port reproduces its committed `generated/` tree byte-for-byte with policies applied. |

## 4. Implementation map

Stage order is fixed (`AGENTS.md`): load → parse → bind → check → lower → emit → solc gate.

### Phase 0 — plumb doc comments through bind

Nothing in `crates/` reads NatSpec today; a repo-wide grep for `.docs` finds zero uses.

- Solar fork has what is needed already: `ast::Item.docs: DocComments` (`crates/ast/src/ast/item.rs:39`), `ItemKind::Variable` for state variables (`:84`), and structured NatSpec including `@custom:` in `crates/ast/src/ast/natspec.rs:8` (`DocComment`) and `:34` (`NatSpecItem`). **No fork change is required.**
- `crates/fhec-bind/src/binder.rs:119` `collect_item` already holds `item.docs`. Carry the parsed policies into `VarInfo` (`crates/fhec-bind/src/model.rs:138`) and add the struct/event equivalents.
- `crates/parse/src/parser/mod.rs:754` `bump_trivia` keeps doc comments and discards every ordinary comment. §8.8 restriction 1 therefore needs a **raw-source scan** of each `.fsol` unit for the literal `@custom:fhe-allow` in a non-doc comment. The `SourceMap` is on `Ctx`.

### Phase 1 — parse and validate policies (FHE4005)

New module in `fhec-check`. Implement the §8.8 grammar, the placement table, key binding, the five-step reader resolution, and all eight restrictions. Restriction 6 (`msg.sender`/`tx.origin`) must use resolution, not spelling — reuse the approach in `crates/fhec-check/src/ops.rs:1366` `is_msg_sender`, which requires `msg` to resolve to `Resolution::Builtin`. Issue #61 was caused by matching that name by spelling.

### Phase 2 — state policy facts

`crates/fhec-check/src/sites.rs` holds the fact types: `SlotKind` `:304`, `EncryptedStorageWrite` `:329`, `EncryptedArgCall` `:348`, `EncryptedReturn` `:379`, `AclFacts` `:409`. Attach the resolved policy (and its bound readers, as source text) to each storage-write fact, and add an event-emit fact for R5. The checker states facts; the lowerer decides insertions — keep that split.

R1's fact is pushed at `crates/fhec-check/src/ops.rs:1087` `finish_encrypted_write`; slot classification is in `analyze_lvalue` (mapping `:1186`, array `:1195`, struct field `:1237`, simple var `:1139`/`:1161`).

### Phase 3 — R4 at direct writes and at merges

- Direct writes: `crates/fhec-lower/src/pass_acl.rs:109` `rule_r1`. When a policy exists it replaces the `sender_provably_owns` decision at `:127` and suppresses FHE4001 at `:138-151`. Everything else — the forward window `:163`, the local-copy window `:165-169`, dedupe `:170-201`, brace wrap `:226`, the R1→R3 handover `:219-225` — applies unchanged.
- Merges: `crates/fhec-lower/src/pass_if.rs:625` `append_storage_acl` is a **second, separate** R1 implementation. It must get the same treatment; this is the path where #81 found a live disclosure. Per §8.9, reader paths bind to the merge's hoisted key temps (`__fhe_key_n`), **not** to the author's key expressions — re-rendering the source would evaluate the key twice and break §4.4. See `fixtures/acl/r1-if-merge-nested-key/expected.sol` for the exact shape.
- Emission order is `allowThis` first, then readers in policy order. A non-constant address reader is wrapped in `if (r != address(0))`.
- Suggest mode: FHE4013 note with a `safe: true` fix-it, mirroring FHE4010 at `pass_acl.rs:248`.

### Phase 4 — R5 at events

New rule alongside `rule_r1`/`rule_r2`/`rule_r3` in `pass_acl.rs`. Insert **before** the `emit`. Hoist a non-trivial argument to `__fhe_evt_n` (§2.4 naming; follow R3's hoist at `pass_acl.rs:635-651`). §8.0 brace wrapping applies. FHE4004 when no legal position exists.

### Phase 5 — re-application, gated disclosure (FHE4007)

A write to any variable a policy names, or names in its `public if` condition, re-emits that policy for the target's current handle. Only for bindable targets — a mapping or array target cannot be re-applied, which is the FHE4007 warning; `public if` on one is the FHE4007 error.

### Phase 6 — FHE4006, FHE4008, FHE4009

- **FHE4006**: refuse when a reader path cannot be bound at the write site. Must support the single-assignment ERC-7201 pointer shape (`Storage storage $ = _getStorage(); $.balances[k] = v;`) — that is 100% of the reference port's writes. `FHEC-FINDINGS.md:75-78` confirms fhec already recognizes this shape for R1.
- **FHE4008**: warn on a storage write whose RHS is a handle read from another slot with no intervening profile operation, where the two policies name different readers. A handle from any profile op — including a §5.2 `FHE.select` — is fresh and states no fact. Widening from a `this`-only policy is not a finding.
- **FHE4009**: warn when an encrypted value reaches an `emit` or `return` with a **known**-empty reader set. Transient grants do not count. An unknown set states no fact — same stance §8.2 takes for an `Unknown` callee. Getting this wrong makes the diagnostic useless: an encrypted parameter must never trigger it.

### Phase 7 — diagnostics wiring

Per `AGENTS.md`, each of FHE4005, FHE4006, FHE4007, FHE4008, FHE4009, FHE4013 needs all three of:
1. `spec/spec.md` §9 — **already done**;
2. `crates/fhec-cli/src/explain.rs` `CATALOG` — see the existing FHE4001–FHE4012 entries at `:68-74` for the shape;
3. the emitting crate's codes module (`crates/fhec-lower/src/lib.rs:46` has `FHE4004`'s const for reference).

FHE4007 carries two severities. `FHE2012` is the existing precedent for an `error / warning` code.

## 5. Test plan

- **Fixtures** under `fixtures/acl/`, byte-exact goldens generated with `fhec build --json --self-check` and reviewed against the spec before committing. A wrong golden freezes a bug. At minimum: a policy on a state variable, on a struct field, and on an event; the ERC-7201 pointer shape; a nested mapping with two binders; a merge write under an encrypted `if`; `public`; `public if`; forward-only warning; and one rejection case per new error code.
- **Unit iteration** in `crates/fhec-check/tests/check.rs` and `crates/fhec-lower/tests/golden.rs` — `fixtures_runner` cannot isolate a single fixture directory.
- **Idempotence** must hold: generated `.sol` carries the grants but not the policy, so a second pass reproduces the grants and inserts nothing (§8.6, §8.8 no-op).
- **Real corpus**: `/Users/toml/dev/fhenix-confidential-contracts`. Port `ERC20ConfidentialLib` and `FHERC20Core` to policies and require `--acl=insert` to reproduce the committed `generated/` tree byte-for-byte. That is the acceptance gate, and it is the evidence `PORT-PLAN.md:10-14`'s abandoned phase 4 never had.
- `packages/difftest` compares ACL `isAllowed` directly, so a policy's effect is testable end to end. Never compare ciphertext handles.

## 6. Hazards

- **Fail-open inversion.** Today a missing grant fails closed and loudly. Auto-granting removes that signal, which is why FHE4008 exists and why FHE4006 refuses instead of skipping. A silent skip anywhere in this feature is a defect.
- **`allow` reverts on an uninitialized handle.** Nobody is allowed on handle 0 (`MockACL.sol:109`). The reference port guards with `FHE.isInitialized` for this reason. Pre-existing for R1's `allowThis`, but do not make it worse.
- **Trivially encrypted handles are deterministic and public.** `FHE.asEuint64(k)` yields the same handle for the same `k` everywhere, and CoFHE makes `allow` a no-op on that path. A policy grant there is not a grant.
- **Grants are permanent.** CoFHE has no revoke anywhere (§8.13). Nothing this feature emits may imply otherwise.
- **Trust gate.** Dedupe must keep using `crates/fhec-check/src/trust.rs:269` `is_profile_library_function`; issues #60/#79/#87/#100 are all over-trust in this area. Issue **#100 is still open**.
- **`FHE.unwrap` into `bytes32` storage** escapes the model entirely (`ERC20ConfidentialLib.fsol:481-483`). §8.12 states this limit; no diagnostic in this revision.

## 7. Deliberately out of scope

Unbounded delegate sets (they need a grant loop, which is what `ERC20ConfidentialLib.grantPast` is); backfilling past handles, which is only possible from off-chain; any revoke or re-mint the transpiler performs on its own; a diagnostic for `FHE.unwrap`; flipping the `--acl` default.

## 8. Commands

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

cargo test -p fhec-check --test check
cargo test -p fhec-lower --test golden
cargo test -p fhec-cli --test fixtures_runner
```

Keep `rust-toolchain.toml` (1.98) in sync with CI. Work on a feature branch, commit, never push.
