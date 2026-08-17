import hre from 'hardhat';
import type { Contract } from 'ethers';
import { expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import { deployMockEnvironment, type MockEnvironment } from '../src/mocks';
import {
  DifferentialMismatchError,
  assertDifferentiallyEquivalent,
  runDifferential,
  type Divergence,
} from '../src/differential';
import { EXPECTED_FINAL_COUNT, INITIAL_COUNT, encryptedCounterScenario } from '../scenarios/encrypted-counter';

use(chaiAsPromised);

const deploy = async (name: string): Promise<Contract> =>
  (await hre.ethers.deployContract(name, [INITIAL_COUNT])) as unknown as Contract;

const kinds = (divergences: Divergence[]) => new Set(divergences.map((d) => d.kind));

describe('differential harness :: EncryptedCounter', () => {
  let env: MockEnvironment;

  before(async function () {
    this.timeout(180_000);
    env = await deployMockEnvironment(hre);
  });

  it('bootstraps the mock coprocessor', async () => {
    expect(await env.taskManager.exists()).to.equal(true);
    expect(await env.acl.exists()).to.equal(true);
    expect(await env.zkVerifier.exists()).to.equal(true);
    expect(await env.thresholdNetwork.exists()).to.equal(true);
    // The ACL must be linked into the TaskManager, or every FHE op reverts.
    expect((await env.taskManager.acl()).toLowerCase()).to.equal((await env.acl.getAddress()).toLowerCase());
  });

  it('A == A: the reference matches an identical twin', async () => {
    const a = await deploy('EncryptedCounterRef');
    const b = await deploy('EncryptedCounterRef');

    const result = await assertDifferentiallyEquivalent(env, a, b, encryptedCounterScenario, {
      labelA: 'EncryptedCounterRef',
      labelB: 'EncryptedCounterRef (twin)',
    });

    expect(result.equivalent).to.equal(true);
    expect(result.divergences).to.have.length(0);

    // Guard against a scenario that silently stopped doing anything: two
    // contracts that both do nothing would also compare equal.
    const final = result.a.snapshots[result.a.snapshots.length - 1];
    expect(final.plaintexts.count).to.equal(EXPECTED_FINAL_COUNT);
    expect(final.acl['count@self']).to.equal(true);
    expect(final.acl['count@signer0']).to.equal(true);
    // allowCountPublicly must have opened the handle to an unrelated account.
    expect(final.acl['count@signer2']).to.equal(true);

    // The owner gate and the malformed reveal must both have reverted, on both
    // sides, and both must have matched their declared expectation.
    expect(result.a.steps[2].reverted).to.equal(true);
    expect(result.a.steps[2].revertKey).to.equal('OnlyOwnerAllowed');
    expect(result.a.steps[6].reverted).to.equal(true);
    expect(result.a.steps.every((s) => s.expectationMet)).to.equal(true);
    expect(result.b.steps.every((s) => s.expectationMet)).to.equal(true);
  });

  it('detects a wrong constant (plaintext divergence)', async () => {
    const reference = await deploy('EncryptedCounterRef');
    const divergent = await deploy('EncryptedCounterWrongConstant');

    const result = await runDifferential(env, reference, divergent, encryptedCounterScenario, {
      labelA: 'EncryptedCounterRef',
      labelB: 'EncryptedCounterWrongConstant',
    });

    expect(result.equivalent).to.equal(false);
    expect(kinds(result.divergences)).to.include('plaintext');

    // The bug is in incrementCount, so the very first step must already differ:
    // 5 + 1 on the reference, 5 + 2 on the twin.
    const first = result.divergences.find((d) => d.kind === 'plaintext');
    expect(first?.where).to.contain('step 0');
    expect(first?.a).to.equal('6');
    expect(first?.b).to.equal('7');

    // The throwing API must surface the same thing.
    await expect(
      assertDifferentiallyEquivalent(env, reference, divergent, encryptedCounterScenario)
    ).to.be.rejectedWith(DifferentialMismatchError, /plaintext/);
  });

  it('detects a dropped FHE.allowSender (ACL divergence only)', async () => {
    const reference = await deploy('EncryptedCounterRef');
    const divergent = await deploy('EncryptedCounterMissingAcl');

    const result = await runDifferential(env, reference, divergent, encryptedCounterScenario, {
      labelA: 'EncryptedCounterRef',
      labelB: 'EncryptedCounterMissingAcl',
    });

    expect(result.equivalent).to.equal(false);

    // This is the point of probing the ACL separately: the arithmetic is
    // correct, so plaintext comparison alone would call these two equivalent.
    expect(kinds(result.divergences)).to.include('acl');
    expect(kinds(result.divergences)).to.not.include('plaintext');

    const acl = result.divergences.find((d) => d.kind === 'acl');
    expect(acl?.where).to.contain('count@signer0');
    expect(acl?.a).to.equal('true');
    expect(acl?.b).to.equal('false');

    await expect(
      assertDifferentiallyEquivalent(env, reference, divergent, encryptedCounterScenario)
    ).to.be.rejectedWith(DifferentialMismatchError, /acl/);
  });

  it('leaves the chain restored after a differential run', async () => {
    const a = await deploy('EncryptedCounterRef');
    const b = await deploy('EncryptedCounterRef');

    const before = await env.getPlaintext(await a.getCount());
    await runDifferential(env, a, b, encryptedCounterScenario);
    const after = await env.getPlaintext(await a.getCount());

    expect(before).to.equal(BigInt(INITIAL_COUNT));
    expect(after).to.equal(BigInt(INITIAL_COUNT));
  });
});
