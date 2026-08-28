import hre from 'hardhat';
import type { Contract } from 'ethers';
import { expect } from 'chai';

import { deployMockEnvironment, type MockEnvironment } from '../src/mocks';
import { assertDifferentiallyEquivalent } from '../src/differential';
import {
  CAP,
  EXPECTED_FINAL_COUNT,
  INITIAL_COUNT,
  encryptedCounterDialectScenario,
} from '../scenarios/encrypted-counter-dialect';

/**
 * The first REAL transpiler proof: `contracts/generated/EncryptedCounterDialect.sol`
 * is fhec output (produced by `pnpm run build:dialect` from
 * `contracts-dialect/EncryptedCounterDialect.fsol`), and it must be
 * differentially equivalent to the independently hand-written
 * `EncryptedCounterDialectRef` — plaintexts, ACL state, and revert parity.
 */
describe('differential :: transpiled EncryptedCounterDialect vs hand-written reference', () => {
  let env: MockEnvironment;

  before(async function () {
    this.timeout(180_000);
    env = await deployMockEnvironment(hre);
  });

  it('transpiled output is differentially equivalent to the reference', async function () {
    this.timeout(180_000);

    const reference = (await hre.ethers.deployContract('EncryptedCounterDialectRef', [
      INITIAL_COUNT,
      CAP,
    ])) as unknown as Contract;
    const generated = (await hre.ethers.deployContract('EncryptedCounterDialect', [
      INITIAL_COUNT,
      CAP,
    ])) as unknown as Contract;

    const result = await assertDifferentiallyEquivalent(env, reference, generated, encryptedCounterDialectScenario, {
      labelA: 'EncryptedCounterDialectRef (hand-written)',
      labelB: 'EncryptedCounterDialect (fhec output)',
    });

    // Pin the semantics so an inert scenario cannot pass as equivalent.
    const final = result.a.snapshots[result.a.snapshots.length - 1];
    expect(final.plaintexts.count).to.equal(EXPECTED_FINAL_COUNT);
    expect(final.acl['count@self']).to.equal(true, 'R1 allowThis must hold');
    // `count` is a simple state variable (no key at all), so its owner is not
    // provably `msg.sender` (issue #70): R1 withholds the sender grant rather
    // than guess it, even though signer0 (the owner) is the one calling
    // increment/incrementByOne.
    expect(final.acl['count@signer0']).to.equal(false, 'R1 must withhold allowSender for an unkeyed slot');
    expect(final.acl['count@signer2']).to.equal(false, 'unrelated account must stay denied');

    // The encrypted-if boundary really was crossed in both directions: the
    // step that would exceed the cap left the plaintext unchanged.
    const afterOverCap = result.a.snapshots[4];
    expect(afterOverCap.plaintexts.count).to.equal(EXPECTED_FINAL_COUNT);
    const afterExactCap = result.a.snapshots[3];
    expect(afterExactCap.plaintexts.count).to.equal(String(CAP));

    // Owner gate reverted identically on both sides.
    expect(result.a.steps[4].revertKey).to.equal('OnlyOwnerAllowed');
    expect(result.b.steps[4].revertKey).to.equal('OnlyOwnerAllowed');
  });
});
