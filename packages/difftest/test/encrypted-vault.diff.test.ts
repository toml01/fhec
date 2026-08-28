import hre from 'hardhat';
import type { Contract } from 'ethers';
import { expect } from 'chai';

import { deployMockEnvironment, type MockEnvironment } from '../src/mocks';
import { assertDifferentiallyEquivalent } from '../src/differential';
import { EXPECTED_FINAL_BALANCES, makeEncryptedVaultScenario } from '../scenarios/encrypted-vault';

/**
 * The mapping/if-heavy pair: `contracts/generated/EncryptedVaultDialect.sol`
 * (fhec output for `contracts-dialect/EncryptedVaultDialect.fsol`) vs the
 * independently hand-written `EncryptedVaultDialectRef`.
 *
 * Each side calls its own AuditorSink instance for the rule-R2 step; the sink
 * immediately uses the received handle in an FHE op, so a missing
 * `FHE.allowTransient` grant surfaces as a revert-parity divergence.
 */
describe('differential :: transpiled EncryptedVaultDialect vs hand-written reference', () => {
  let env: MockEnvironment;

  before(async function () {
    this.timeout(180_000);
    env = await deployMockEnvironment(hre);
  });

  it('transpiled output is differentially equivalent to the reference', async function () {
    this.timeout(240_000);

    const signers = await hre.ethers.getSigners();
    const holder = await signers[0].getAddress();
    const recipient = await signers[1].getAddress();

    const reference = (await hre.ethers.deployContract('EncryptedVaultDialectRef')) as unknown as Contract;
    const generated = (await hre.ethers.deployContract('EncryptedVaultDialect')) as unknown as Contract;
    const sinkA = (await hre.ethers.deployContract('AuditorSink')) as unknown as Contract;
    const sinkB = (await hre.ethers.deployContract('AuditorSink')) as unknown as Contract;

    const scenario = makeEncryptedVaultScenario({
      holder,
      recipient,
      sink: { A: await sinkA.getAddress(), B: await sinkB.getAddress() },
    });

    const result = await assertDifferentiallyEquivalent(env, reference, generated, scenario, {
      labelA: 'EncryptedVaultDialectRef (hand-written)',
      labelB: 'EncryptedVaultDialect (fhec output)',
    });

    // Every step (including the R2/R3 transactions) succeeded or reverted per
    // the scenario's expectations, on both sides.
    expect(result.a.steps.every((s) => s.expectationMet)).to.equal(true);
    expect(result.b.steps.every((s) => s.expectationMet)).to.equal(true);

    // Pin the plaintext semantics: 100 − 30 / 50 + 30, then the insufficient
    // transfer and the guarded self-transfer must change nothing.
    const final = result.a.snapshots[result.a.snapshots.length - 1];
    expect(final.plaintexts.holderBalance).to.equal(EXPECTED_FINAL_BALANCES.holder);
    expect(final.plaintexts.recipientBalance).to.equal(EXPECTED_FINAL_BALANCES.recipient);

    // The insufficient transfer (step index 3; snapshot index 4 counting the
    // initial snapshot) kept both slots at their post-step-2 values.
    const afterInsufficient = result.a.snapshots[4];
    expect(afterInsufficient.plaintexts.holderBalance).to.equal(EXPECTED_FINAL_BALANCES.holder);
    expect(afterInsufficient.plaintexts.recipientBalance).to.equal(EXPECTED_FINAL_BALANCES.recipient);

    // R1 ACL semantics, pinned explicitly (see the scenario factory's note):
    // `holderBalance` is keyed by `msg.sender` in every write that touches it
    // (holder transfers their own balance), so it is provably owned by the
    // transferer and both grants hold. `recipientBalance` is written by
    // `transfer()` as `balances[to]` — keyed by the recipient, not
    // `msg.sender` — so it is NOT provably owned by the transferer (issue
    // #70): the fresh handle is granted to the contract only, and the
    // transferer must not gain read access to the recipient's balance.
    expect(final.acl['holderBalance@self']).to.equal(true);
    expect(final.acl['holderBalance@signer0']).to.equal(true);
    expect(final.acl['holderBalance@signer2']).to.equal(false);
    expect(final.acl['recipientBalance@self']).to.equal(true);
    expect(final.acl['recipientBalance@signer0']).to.equal(false, 'the transferer must not gain access to the recipient balance');
    expect(final.acl['recipientBalance@signer1']).to.equal(false);

    // ...but right after the recipient's own deposit (step 1 → snapshot 2)
    // they DID hold access to their slot's then-current handle.
    const afterRecipientDeposit = result.a.snapshots[2];
    expect(afterRecipientDeposit.acl['recipientBalance@signer1']).to.equal(true);
  });
});
