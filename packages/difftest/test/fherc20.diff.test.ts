import hre from 'hardhat';
import type { Contract } from 'ethers';
import { expect } from 'chai';

import { deployMockEnvironment, type MockEnvironment } from '../src/mocks';
import { assertDifferentiallyEquivalent } from '../src/differential';
import { EXPECTED_FINAL, makeFherc20Scenario } from '../scenarios/fherc20';

/**
 * The flagship pair: `contracts/generated-fherc20/FHERC20.sol` (fhec output
 * for `contracts-dialect-fherc20/FHERC20.fsol`) vs the UNMODIFIED upstream
 * `fhenix-confidential-contracts` FHERC20, both behind identical mint/burn
 * harnesses.
 *
 * The dialect side was written with `in euint64` input sugar, encrypted
 * operators, and encrypted ternaries (FHESafeMath inlined); ACL grants stay
 * explicit (suggest mode). Equivalence here means the transpiled token and
 * the audited upstream token agree on every plaintext, every indicator value,
 * every ACL grant, and every revert across the scenario.
 */
describe('differential :: transpiled FHERC20 (dialect) vs upstream fhenix-confidential-contracts', () => {
  let env: MockEnvironment;

  before(async function () {
    this.timeout(180_000);
    env = await deployMockEnvironment(hre);
  });

  it('transpiled output is differentially equivalent to the upstream reference', async function () {
    this.timeout(240_000);

    const signers = await hre.ethers.getSigners();
    const alice = await signers[0].getAddress();
    const bob = await signers[1].getAddress();
    const carol = await signers[2].getAddress();

    const constructorArgs = ['Confidential Token', 'CTOK', 6, 'https://example.com/ctok'] as const;
    const reference = (await hre.ethers.deployContract('FHERC20RefHarness', [...constructorArgs])) as unknown as Contract;
    const generated = (await hre.ethers.deployContract('FHERC20Harness', [...constructorArgs])) as unknown as Contract;

    const scenario = makeFherc20Scenario({ alice, bob, carol });

    const result = await assertDifferentiallyEquivalent(env, reference, generated, scenario, {
      labelA: 'FHERC20RefHarness (upstream fhenix-confidential-contracts)',
      labelB: 'FHERC20Harness (fhec output)',
    });

    // Every step succeeded or reverted per the scenario's expectations, on
    // both sides (the unauthorized-spender, disclosure-ACL, and ERC-20-compat
    // steps all reverted with the declared errors).
    expect(result.a.steps.every((s) => s.expectationMet)).to.equal(true);
    expect(result.b.steps.every((s) => s.expectationMet)).to.equal(true);

    // Pin the plaintext semantics (identical on both sides by the assertion
    // above; pinned here against hand-derived values so a *jointly* wrong
    // implementation cannot slip through).
    const final = result.a.snapshots[result.a.snapshots.length - 1];
    expect(final.plaintexts.aliceBalance).to.equal(EXPECTED_FINAL.alice);
    expect(final.plaintexts.bobBalance).to.equal(EXPECTED_FINAL.bob);
    expect(final.plaintexts.carolBalance).to.equal(EXPECTED_FINAL.carol);
    expect(final.plaintexts.totalSupply).to.equal(EXPECTED_FINAL.totalSupply);

    // The saturated transfer (step 3; snapshot index 4 counting 'initial')
    // moved nothing: alice still at 900, carol initialized at 0.
    const afterSaturated = result.a.snapshots[4];
    expect(afterSaturated.plaintexts.aliceBalance).to.equal('900');
    expect(afterSaturated.plaintexts.carolBalance).to.equal('0');

    // ACL policy: balance handles belong to the contract and the account.
    // Bob's operator (carol) and other signers never gain access to bob's
    // balance handle; alice's final handle is publicly allowed after her
    // disclosure request.
    expect(final.acl['bobBalance@self']).to.equal(true);
    expect(final.acl['bobBalance@signer1']).to.equal(true);
    expect(final.acl['bobBalance@signer0']).to.equal(false);
    expect(final.acl['bobBalance@signer2']).to.equal(false);
    expect(final.acl['aliceBalance@self']).to.equal(true);
    expect(final.acl['aliceBalance@signer0']).to.equal(true);
    expect(final.acl['aliceBalance@signer2']).to.equal(true); // allowPublic after disclosure
    expect(final.acl['totalSupply@self']).to.equal(true);

    // Indicator layer: alice reset hers to 0 in the second-to-last step.
    expect(final.values.indicatedAlice).to.equal('0');
    expect(final.values.balanceOfIsIndicator).to.equal('true');
    expect(final.values.carolIsOperatorForBob).to.equal('true');

    // Before the disclosure request, carol had no access to alice's handle.
    const afterBurn = result.a.snapshots[8];
    expect(afterBurn.acl['aliceBalance@signer2']).to.equal(false);
  });
});
