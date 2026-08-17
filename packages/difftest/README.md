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

Nothing here depends on the transpiler. The harness is a library plus a working
fixture pair, so it is already green today and the generated contracts drop in
later without touching it.

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
Transcribed from `@cofhe/hardhat-plugin@0.6.1` (`src/deploy.ts`, `src/utils.ts`)
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

**Step 4 — link them: `taskManager.setACLContract(aclAddress)`.**
Missing this link makes every single FHE op revert inside the TaskManager.

**Step 5 — set the two signer authorities.**
`setVerifierSigner(0x6E12D8C8…)` and `setDecryptResultSigner(0x70997970…)`.
Both keys are file-level constants in `MockCoFHE.sol`. This is not optional
housekeeping: leaving either at `address(0)` makes the mock **skip signature
verification entirely**, which would silently weaken the harness.
`assertMockConstants()` re-derives both addresses from their private keys at
startup, so a version bump that rotates them fails loudly.

**Step 6 — fund the ZK verifier signer** with `hardhat_setBalance`.

**Step 7 — MockZkVerifier (`0x…5001`) and MockThresholdNetwork (`0x…5002`)**
via `hardhat_setCode`, then `thresholdNetwork.initialize(taskManager, acl)`.

**Step 8 — `taskManager.setLogOps(false)`.**
The mock coprocessor `console.log`s every FHE operation. A differential run
executes the scenario twice; pass `{ logOps: true }` when debugging.

### Encrypted inputs without the SDK

`in euint32` sugar is a v1 transpiler feature, so the harness has to build
signed `InEuintXX` values. `env.encryptInput(value, 'euint32', sender)` does it
with no `@cofhe/sdk` dependency:

1. `zkVerifier.zkVerifyCalcCtHash.staticCall(...)` — read the handle **first**;
   `insertCtHash` bumps the verifier's internal salt, which would change it.
2. `zkVerifier.insertCtHash(ctHash, value)` — store the plaintext.
3. Sign `keccak256(abi.encodePacked(ctHash, utype, securityZone, sender, chainid))`
   with the verifier key. `MockTaskManager.extractSigner` uses a **raw**
   `ECDSA.recover`, so sign the digest directly — an EIP-191 `personal_sign`
   prefix produces `InvalidSigner`.

Handles are bound to their sender and to the salt, so each side of a comparison
mints its own input. That is what the `args` factory form is for:

```ts
{
  fn: 'setCount',
  args: async (ctx) => [await ctx.env.encryptInput(1000, 'euint32', ctx.sender)],
}
```

## Writing a scenario

```ts
export const scenario: Scenario = {
  name: 'EncryptedCounter: increment, encrypted set, public allow, bad reveal',
  steps: [
    { fn: 'incrementCount', label: 'increment #1' },
    { fn: 'incrementCount', from: 1, expectRevert: 'OnlyOwnerAllowed' },
    { fn: 'setCount', args: async (ctx) => [await ctx.env.encryptInput(1000, 'euint32', ctx.sender)] },
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

## Plugging the transpiler in later

Nothing about the runner is transpiler-specific — it takes two deployed
contracts. When `fhec` exists:

1. Point the transpiler's mirror tree at `contracts/generated/`. It is compiled
   by the same `hardhat compile` run, no config change needed (`paths.sources`
   is `contracts`, and Hardhat globs recursively).
2. Keep the hand-written oracle at `contracts/<Name>Ref.sol`.
3. Add `scenarios/<name>.ts` — one scenario per fixture pair.
4. Add `test/<name>.diff.test.ts`: deploy both, call
   `assertDifferentiallyEquivalent`.

```ts
const reference = await hre.ethers.deployContract('VaultRef', args);
const generated = await hre.ethers.deployContract('Vault', args); // contracts/generated/Vault.sol
await assertDifferentiallyEquivalent(env, reference, generated, vaultScenario);
```

The two contracts only need to agree on the surface the scenario touches. The
generated contract is free to use different temporaries, different handles, and
a different internal structure — that is the point.

Planned follow-ons, in `PLAN.md` order: the conformance corpus (de-lowered
`TestBed.sol` / `EncryptedCounter.sol` as dialect inputs, differentially
equivalent to the originals) and property-based inputs for the aliasing and
merge-order bug classes, which fit as generated `Scenario` objects.

## Dependencies

`@cofhe/mock-contracts` **is published** on the public npm registry under
exactly the name `PLAN.md` uses. This package therefore depends on the
**published `0.6.1`**, not on a `file:` link to
`/Users/toml/dev/cofhesdk/packages/mock-contracts` (which is `0.4.0` locally).
No `file:` fallback was needed.

Two consequences of taking 0.6.1 over the local 0.4.0 are worth recording:

- **`TestBed.sol` is gone** from 0.6.x. It is not needed here — this harness
  uses its own fixture contracts — but `PLAN.md` names TestBed as conformance-
  corpus material, so that seed will have to come from the 0.4.x sources or
  from the cofhesdk repo.
- **Artifacts no longer carry bytecode**, hence the compile-the-mocks step
  above. The 0.4.x flow (`hardhat_setCode` straight from
  `MockTaskManagerArtifact.deployedBytecode`) no longer exists.

All versions are pinned exactly — no `^`, no `~`. The pins that matter:

| Package | Pin | Why |
|---|---|---|
| `@cofhe/mock-contracts` | `0.6.1` | the mock coprocessor |
| `@fhenixprotocol/cofhe-contracts` | `0.1.4` | matches the mock package's own dependency; encrypted handles are `bytes32` here (they were `uint256` before 0.1.0) |
| `hardhat` | `2.26.3` | Hardhat 2 is what `@cofhe/hardhat-plugin` peer-depends on (`^2.0.0`) and what its own test project runs |
| `ethers` | `6.13.5` | v6, as in the cofhesdk test project |
| solc | `0.8.28`, `evmVersion: cancun` | CoFHE requires cancun; `cofhe-contracts` has a 0.8.25 pragma floor |

`allowUnlimitedContractSize` is on for the in-process Hardhat network: the mock
TaskManager is ~37 KB.

## Layout

```
packages/difftest/
  contracts/
    EncryptedCounterRef.sol         reference oracle
    EncryptedCounterDivergent.sol   two deliberately-wrong twins
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
