# `difftest` — differential-execution harness for `fhec`

This package implements the **Differential execution** lane described in
`PLAN.md` → *Verification*:

> hardhat harness with `@cofhe/mock-contracts` (MockTaskManager/MockACL) +
> `mock_getPlaintext`/`mock_expectPlaintext`; identical tx sequences against
> transpiled vs hand-written reference contracts; plaintexts and `isAllowed`
> state must match.

It is the safety net for the transpiler's two silent-failure classes. Golden
tests compare *bytes*, and the solc gate proves the output *compiles* — neither
notices when `FHE.select` swallows an uninitialised handle or when the ACL pass
under-grants. Only running the code does.

The runner itself does not depend on the transpiler. Generated contracts are
compiled beside independently written references, including the FHERC20
dialect output and the unmodified upstream FHERC20 implementation.

```
pnpm --filter difftest test
```

## What it compares

`runDifferential(env, A, B, scenario)` executes the same step list against two
contracts and compares three axes:

| Axis | Source | Catches |
|---|---|---|
| **(a) plaintext** | `MockTaskManager.mockStorage(handle)` behind each designated encrypted getter | wrong arithmetic, wrong select merge, wrong constant, cross-branch read-after-write |
| **(b) ACL** | `MockTaskManager.isAllowed(handle, account)` for each `(getter, account)` probe | dropped or over-broad `allowThis` / `allowSender` / `allowTransient` / `allowPublic` |
| **(c) revert parity** | success/failure and the revert *identity* per step | a legality or lowering bug that turns a working call into a revert, or vice versa |

Plain (unencrypted) state is compared too, via `valueProbes`.

**Ciphertext handles are deliberately never compared.** A handle is a keccak
hash over its operands plus a salt, so two *correct* implementations can produce
different handles for the same plaintext. Comparing them would fail on correct
output. Handles are recorded in each snapshot for the report only.

Revert *identity* means the custom-error name (or panic code, or the 4-byte
selector when the error is not in the called contract's ABI) — never the error
arguments, because errors such as `ACLNotAllowed(uint256 handle, address)` carry
a handle.

### Snapshot discipline

Both runs start from an identical chain snapshot (`evm_snapshot` /
`evm_revert`, via `hardhat-network-helpers`), and the chain is restored again
afterwards. Without this the second run would see the first run's nonces,
`MockZkVerifier`'s advanced salt, and its leftover storage. `runDifferential`
leaves the chain exactly as it found it, so a mocha file can run several
comparisons against the same deployment set.

## The mock bootstrap ritual

This is the part that is easy to get subtly wrong, so it is written down.
Transcribed from `@cofhe/hardhat-plugin@0.7.0` (`src/deploy.ts`, `src/utils.ts`)
and implemented in [`src/mocks.ts`](src/mocks.ts) as `deployMockEnvironment()`.

**Step 0 — compile the mocks into this project.**
`@cofhe/mock-contracts` ≥ 0.5 no longer ships bytecode: its JS artifacts carry
only `contractName`, `abi`, `isFixed` and `fixedAddress`. The Solidity sources
must therefore be compiled by the consuming project.
[`contracts/mocks/CofheMocksImports.sol`](contracts/mocks/CofheMocksImports.sol)
is a barrel file that imports all of them, which also registers the artifacts
with Hardhat so it can decode reverts raised inside the mock coprocessor. (The
official plugin does the same thing by generating this file into the Hardhat
cache and injecting it through a `TASK_COMPILE_SOLIDITY_GET_SOURCE_PATHS`
subtask override; a checked-in source file is the same thing without the magic.)

**Step 1 — MockTaskManager at a fixed address.**
`FHE.sol` hard-codes `TASK_MANAGER_ADDRESS = 0xeA30c4B8b44078Bbf8a6ef5b9f1eC1626C7848D9`.
Every FHE op is an external call to that literal address, so the TaskManager
cannot be deployed normally — it is installed with `hardhat_setCode`, using the
`deployedBytecode` from `hre.artifacts.readArtifact('MockTaskManager')`.
`hardhat_setCode` also sidesteps EIP-170 (the contract is ~37 KB).

**Step 2 — initialise it by hand.**
`hardhat_setCode` does not run constructors, so `initialize(deployer)` must be
called explicitly. Skipping it leaves `owner == address(0)` and every
`onlyOwner` setter below reverts. Assert `exists()`.

**Step 3 — MockACL as a real deployment.**
`MockACLArtifact.isFixed === false`. It is deployed through an ethers factory
*specifically so its constructor runs* — `MockPermissioned` is `EIP712("ACL","1")`
and needs its domain separator built. Assert `exists()`.

**Step 4 — the ACP contracts (new in mock-contracts 0.7.0).**
0.7.0 replaced permits with scoped, revocable ACPs, and ships two plain
(non-fixed-address) contracts the ACL points at: `ACPTimestampRevoker`, linked
with `acl.setDefaultRevokerContract(...)`, answers `disabled(issuer, id)` during
ACP validation; `ACPShareRegistry`, linked with `acl.setShareRegistry(...)`, is
the on-chain hand-off for shared ACPs. Neither sits on the FHE-op path, so the
harness's own probes work without them — but the plugin deploys both, so this
does too, and an ACP-authenticated read would revert if either were unset.

**Step 5 — link the ACL: `taskManager.setACLContract(aclAddress)`.**
Missing this link makes every single FHE op revert inside the TaskManager.

**Step 6 — set the two signer authorities.**
`setVerifierSigner(0x6E12D8C8…)` and `setDecryptResultSigner(0x70997970…)`.
Both keys are file-level constants in `MockCoFHE.sol`. This is not optional
housekeeping: leaving either at `address(0)` makes the mock **skip signature
verification entirely**, which would silently weaken the harness.
`assertMockConstants()` re-derives both addresses from their private keys at
startup, so a version bump that rotates them fails loudly.

**Step 7 — fund the ZK verifier signer** with `hardhat_setBalance`.

**Step 8 — MockZkVerifier (`0x…5001`) and MockThresholdNetwork (`0x…5002`)**
via `hardhat_setCode`, then `thresholdNetwork.initialize(taskManager, acl)`.

**Step 9 — `taskManager.setLogOps(false)`.**
The mock coprocessor `console.log`s every FHE operation. A differential run
executes the scenario twice; pass `{ logOps: true }` when debugging.

### Encrypted inputs without the SDK

External encrypted inputs require the harness to mint
verified inputs itself. cofhe-contracts 0.2.0 **removed the `InEuintXX`
structs**: an encrypted argument is now a *pair* — an `externalEuintXX` handle
(a plain `bytes32`) in the parameter's own position, plus **one** `bytes` proof,
shared by every encrypted input of that call. Legacy `in eT` sugar appends that
proof; canonical interfaces such as ERC-7984's AndCall overloads may place it
before a following `bytes data` argument.

```solidity
function setCount(externalEuint32 _inCount, bytes memory inputProof) external {
    count = FHE.asEuint32(_inCount, inputProof);
    …
}
```

`env.encryptInput(value, type, sender, consumingContract, securityZone = 0)`
mints one, with no `@cofhe/sdk` dependency, and returns
`{ handle, ctHash, utype, securityZone, signature }`:

1. `zkVerifier.zkVerifyCalcCtHash.staticCall(...)` — read the handle **first**;
   `insertCtHash` bumps the verifier's internal salt, which would change it.
2. `zkVerifier.insertCtHash(ctHash, value)` — store the plaintext.
3. Sign the **batch** digest with the verifier key. mock-contracts 0.7.0
   authenticates a whole batch with one signature, and binds each input to the
   contract that will consume it (`MockTaskManager.extractBatchSigner`):

   ```
   h_i    = keccak256(abi.encodePacked(
              uint256 ctHash, uint8 utype, uint8 securityZone,
              address sender, uint256 chainid, address consumingContract))
   digest = keccak256(h_0 ‖ h_1 ‖ … ‖ h_n)
   ```

   `ECDSA.recover` runs **raw** on `digest`, so sign it directly — an EIP-191
   `personal_sign` prefix produces `InvalidSigner`.

Two bindings matter, and both are enforced: `sender` is `msg.sender` as the
consuming contract sees it, and `consumingContract` is `msg.sender` as
`batchVerifyInputs` sees it — the contract whose code runs `FHE.asEuintXX`.
An input signed for one contract is rejected by any other (this closed a replay
path). Since the two sides of a comparison live at different addresses, **each
side must mint its own input**, with `ctx.address` as the consuming contract.
That is what the `args` factory form is for:

```ts
{
  fn: 'setCount',
  args: async (ctx) => {
    const input = await ctx.env.encryptInput(1000, 'euint32', ctx.sender, ctx.address);
    return [input.handle, input.signature];
  },
}
```

`env.encryptInputs(specs, sender, consumingContract)` is the batch form,
returning `{ handles, ctHashes, signature }`. It is needed whenever one call
carries more than one encrypted argument: the signature covers the whole batch,
so per-argument `FHE.asEuintXX(h, proof)` calls would each rebuild a one-element
digest and fail — such a contract must verify them together
(`FHE.asEuintXXs` / `Impl.verifyBatchInputs`), in the same order.

One 0.7.0 mock semantic worth recording: `MockACL` transient allowances now use
real EIP-1153 transient storage, so a transient grant expires at the end of its
own **transaction**, not at the end of the block. Nothing here relied on the old
behaviour — the R2/R3 grants are used inside the granting transaction, and the
`isAllowed` probes read permanent grants — but a scenario that granted
transiently in one step and asserted in a later one would now read `false`.

## Writing a scenario

```ts
export const scenario: Scenario = {
  name: 'EncryptedCounter: increment, encrypted set, public allow, bad reveal',
  steps: [
    { fn: 'incrementCount', label: 'increment #1' },
    { fn: 'incrementCount', from: 1, expectRevert: 'OnlyOwnerAllowed' },
    {
      fn: 'setCount',
      args: async (ctx) => {
        const input = await ctx.env.encryptInput(1000, 'euint32', ctx.sender, ctx.address);
        return [input.handle, input.signature];
      },
    },
  ],
  plaintextProbes: [{ name: 'count', getter: 'getCount' }],
  aclProbes: [
    { name: 'count', getter: 'getCount', account: 'self' },   // FHE.allowThis
    { name: 'count', getter: 'getCount', account: 0 },        // FHE.allowSender
    { name: 'count', getter: 'getCount', account: 2 },        // must stay denied
  ],
  valueProbes: [{ name: 'decrypted', getter: 'decrypted' }],
};
```

Probes are read once before the first step and again after every step
(`probeAfterEachStep`, default `true`), so a divergence is reported at the exact
step that introduced it:

```
Differential mismatch in scenario "EncryptedCounter: …"
  A = EncryptedCounterRef @ 0xa513E6E4…
  B = EncryptedCounterMissingAcl @ 0x2279B7A0…
  4 divergence(s):

  [acl] after step 0 (increment #1) / isAllowed count@signer0
      ACL state for count@signer0 differs
      A: true
      B: false
```

## Fixtures shipped today

| Contract | Role |
|---|---|
| `EncryptedCounterRef` | verbatim copy of the canonical `EncryptedCounter.sol` from the CoFHE docs; the reference oracle |
| `EncryptedCounterWrongConstant` | increments by 2 — models an operator-lowering bug; caught on axis (a) |
| `EncryptedCounterMissingAcl` | drops one `FHE.allowSender` — models an ACL rule-R1 under-grant; caught on axis (b) **only** |

`EncryptedCounterMissingAcl` is the fixture that justifies the whole ACL probe
set: its arithmetic is perfect, so plaintext comparison alone would declare it
equivalent to the reference.

The suite proves both directions. `A == A` must pass; both divergent twins must
**fail**, and the tests assert that they fail with the expected divergence kind,
at the expected step, with the expected values. A harness that cannot detect
divergence is worse than no harness.

## The transpiler is plugged in

This package is itself a `fhec` project: [`fhec.toml`](fhec.toml) points
`src` at [`contracts-dialect/`](contracts-dialect/) and `out` at
`contracts/generated/`, which sits inside hardhat's `paths.sources` — so the
same `hardhat compile` run builds fhec's output next to the hand-written
references. `pnpm test` transpiles first (`scripts/build-dialect.mjs`: cargo
when available, an existing `target/release/fhec` otherwise), then runs the
suite. The generated mirror is **committed**, per `PLAN.md`; `fhec build
--frozen` in this directory proves it matches regeneration.

| Path | Meaning |
|---|---|
| `contracts-dialect/<Name>.fsol` | dialect input, the transpile target |
| `contracts/<Name>Ref.sol` | hand-written reference, the differential oracle |
| `contracts/generated/<Name>.sol` | `fhec` output for `<Name>.fsol` |
| `scenarios/<name>.ts` | the transaction sequence and probes for that pair |
| `test/<name>.diff.test.ts` | deploys both and asserts equivalence |

Current pairs:

- **EncryptedCounterDialect** — `in euint32` sugar, `+`/`<=` operators, a
  literal operand, and a capped encrypted `if` crossed from both sides of the
  boundary. Zero manual ACL in the dialect source; every grant is rule R1's.
- **EncryptedVaultDialect** — `mapping(address => euint64)` slots updated
  through encrypted `if`s (accepted and rejected transfers), R1 on both the
  sender-keyed and recipient-keyed slot (the FHE4001 warning case), R3 (an
  encrypted return called as a transaction), and R2 (a transient grant to an
  `AuditorSink` that immediately *uses* the handle, so a dropped grant would
  break revert parity).
- **FHERC20** — all eight canonical IERC7984 transfer overloads across external
  and directed-shared inputs; valid, self, unauthorized, and expired operators;
  EOA/accept/reject/revert callbacks and full rejection refunds; saturating
  mint/transfer arithmetic and burn; balance/supply ACL and indicator views.
  Hand-written callback receivers and paired shared-call drivers keep each
  share/create/call/receive chain inside one transaction. The ABI test fails
  closed on all eight signatures/selectors, one `bytes32` result each, required
  events/errors, and Solidity-computed IFHERC20/IERC7984/IERC20 interface IDs.

The current PR #26 baseline has one deliberately isolated characterization,
not a relaxed comparison rule: an unauthorized basic external
`confidentialTransferFrom` carrying a valid proof bound to the wrong consumer
reverts `FHERC20UnauthorizedSpender` upstream but reaches `InvalidSigner` in the
generated proof-first lowering. Every other FHERC20 scenario, including
external FromAndCall and shared From compound-invalid ordering, is strict.

One shape is deliberately absent: writing `balances[msg.sender]` **and**
`balances[to]` inside a *single* encrypted `if` is rejected by spec §5.2's
aliasing rule (FHE3011 — two syntactically different non-literal keys). The
vault therefore splits the transfer into two sequential encrypted `if`s on the
same `ebool`, made sound by the plaintext self-transfer guard. The rejection
was verified against the real CLI before restructuring.

The reference contracts are written independently from the spec's semantics —
never copied from fhec output. The two sides only need to agree on the surface
the scenario touches; temporaries, handles, and internal structure are free to
differ. That is the point.

Planned follow-ons, in `PLAN.md` order: the conformance corpus (de-lowered
`TestBed.sol` / `EncryptedCounter.sol` as dialect inputs, differentially
equivalent to the originals) and property-based inputs for the aliasing and
merge-order bug classes, which fit as generated `Scenario` objects.

## Dependencies

`@cofhe/mock-contracts` **is published** on the public npm registry under
exactly the name `PLAN.md` uses, so this package depends on the published
release, not on a `file:` link to `/Users/toml/dev/cofhesdk/packages/mock-contracts`.
No `file:` fallback was needed.

Two long-standing consequences of the published line are worth recording:

- **`TestBed.sol` is gone** since 0.6.0. It is not needed here — this harness
  uses its own fixture contracts — but `PLAN.md` names TestBed as conformance-
  corpus material, so that seed will have to come from the 0.4.x sources or
  from the cofhesdk repo.
- **Artifacts no longer carry bytecode**, hence the compile-the-mocks step
  above. The 0.4.x flow (`hardhat_setCode` straight from
  `MockTaskManagerArtifact.deployedBytecode`) no longer exists.

All versions are pinned exactly — no `^`, no `~`. The pins that matter:

| Package | Pin | Why |
|---|---|---|
| `@cofhe/mock-contracts` | `0.7.0` | the mock coprocessor; batch input verification, inputs bound to the consuming contract, EIP-1153 transient allowances, the two ACP contracts |
| `@fhenixprotocol/cofhe-contracts` | `0.2.0` | matches the mock package's own dependency; `InEuintXX` removed in favour of `externalEuintXX` + trailing `bytes` proof |
| `hardhat` | `2.29.1` | Hardhat 2 is what `@cofhe/hardhat-plugin` peer-depends on (`^2.0.0`) and what its own test project runs |
| `ethers` | `6.17.0` | v6, as in the cofhesdk test project |
| solc | `0.8.28`, `evmVersion: cancun` | CoFHE requires cancun; `cofhe-contracts` has a 0.8.25 pragma floor |

`allowUnlimitedContractSize` is on for the in-process Hardhat network: the mock
TaskManager is ~37 KB.

## Layout

```
packages/difftest/
  contracts/
    EncryptedCounterRef.sol         reference oracle
    EncryptedCounterDivergent.sol   two deliberately-wrong twins
    FHERC20Receiver.sol             independent IERC7984 callback receiver
    FHERC20SharedDriver.sol         paired directed-share driver and ABI ID probe
    generated/                      landing zone for fhec output (see its README)
    mocks/CofheMocksImports.sol     pulls @cofhe/mock-contracts into compilation
  src/
    constants.ts                    mock addresses, keys, utype table
    mocks.ts                        deployMockEnvironment() + encryptInput()
    differential.ts                 Scenario/Step types, runner, comparison
    index.ts
  scenarios/encrypted-counter.ts
  test/encrypted-counter.diff.test.ts
```
