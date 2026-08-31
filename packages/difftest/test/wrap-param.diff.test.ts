import hre from 'hardhat';
import type { Contract } from 'ethers';
import { expect } from 'chai';

import { deployMockEnvironment, type MockEnvironment } from '../src/mocks';
import { assertDifferentiallyEquivalent } from '../src/differential';
import { wrapParamScenario } from '../scenarios/wrap-param';

/**
 * Issue #103 regression: a `.wrap`-derived zero sentinel passed through a
 * function parameter and written to storage. The transpiler's inserted
 * grants must sit behind `FHE.isInitialized`, so the sentinel write executes
 * instead of reverting with `SenderNotAllowed` — validated here by actually
 * deploying and calling the generated contract against the CoFHE mocks.
 */
describe('differential :: transpiled WrapParamDialect vs hand-written reference', () => {
  let env: MockEnvironment;

  before(async function () {
    this.timeout(180_000);
    env = await deployMockEnvironment(hre);
  });

  it('wrap-derived sentinel writes execute; grants land only on initialized handles', async function () {
    this.timeout(180_000);

    const reference = (await hre.ethers.deployContract('WrapParamDialectRef')) as unknown as Contract;
    const generated = (await hre.ethers.deployContract('WrapParamDialect')) as unknown as Contract;

    const result = await assertDifferentiallyEquivalent(env, reference, generated, wrapParamScenario, {
      labelA: 'WrapParamDialectRef (hand-written)',
      labelB: 'WrapParamDialect (fhec output)',
    });

    // Pin the semantics so an inert scenario cannot pass as equivalent.
    // Step 1 (`reset`) is the #103 shape itself: it MUST succeed. The
    // differential harness compares revert identity, so also assert the
    // absolute expectation here — both sides reverting identically would
    // otherwise still count as "equivalent".
    for (const side of [result.a, result.b]) {
      for (const step of side.steps) {
        expect(step.reverted).to.equal(false, `${side.label}: "${step.label}" must not revert`);
      }
    }

    // After the final reset, `spent` is the zero sentinel again: no mock
    // plaintext, no grant for anyone.
    const final = result.a.snapshots[result.a.snapshots.length - 1];
    expect(final.plaintexts.spent).to.equal(null, 'the sentinel has no plaintext');
    expect(final.acl['spent@self']).to.equal(false, 'no grant may exist on the zero sentinel');

    // After `bump(7)` (snapshot 3: initial + step count ordering), the
    // handle is real: the guarded R1 grant must have landed.
    const afterBump = result.a.snapshots[3];
    expect(afterBump.plaintexts.spent).to.equal('7');
    expect(afterBump.acl['spent@self']).to.equal(true, 'R1 allowThis must hold after bump');
    expect(afterBump.acl['spent@signer0']).to.equal(false, 'the sender grant stays withheld');
  });
});
