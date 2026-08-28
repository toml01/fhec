import hre from 'hardhat';
import type { Contract, ErrorFragment, EventFragment, FunctionFragment, InterfaceAbi } from 'ethers';
import { Interface } from 'ethers';
import { expect } from 'chai';

import { deployMockEnvironment, type MockEnvironment } from '../src/mocks';
import {
  assertDifferentiallyEquivalent,
  type DifferentialResult,
  type RunResult,
  type Scenario,
} from '../src/differential';
import {
  EXPECTED_ARITHMETIC_FINAL,
  EXPECTED_CALLBACK_FINAL,
  EXPECTED_CORE_FINAL,
  EXPECTED_SHARED_FINAL,
  CALLBACK_ACCEPT_DATA,
  OPERATOR_UNTIL,
  makeFherc20ArithmeticScenario,
  makeFherc20CallbackScenario,
  makeFherc20CompoundInvalidOrderingScenario,
  makeFherc20CoreScenario,
  makeFherc20SharedScenario,
  type Fherc20Accounts,
} from '../scenarios/fherc20';

const LABELS = {
  a: 'FHERC20RefHarness (upstream fhenix-confidential-contracts)',
  b: 'FHERC20Harness (fhec output)',
} as const;

interface ProbeManifest {
  plaintexts: string[];
  acl: string[];
  values: string[];
}

function declaredAclKey(probe: NonNullable<Scenario['aclProbes']>[number]): string {
  const account = probe.account === 'self' ? 'self' : typeof probe.account === 'number' ? `signer${probe.account}` : probe.account;
  return `${probe.name}@${account}`;
}

function expectedSnapshotLabels(scenario: Scenario): string[] {
  const steps = scenario.steps.map((step, index) => `step ${index} (${step.label ?? step.fn})`);
  return scenario.probeAfterEachStep === false ? ['initial', steps[steps.length - 1]] : ['initial', ...steps];
}

/** Fail closed on scenario structure, expectations, divergences, and every configured probe. */
function assertStrictResult(result: DifferentialResult, scenario: Scenario, manifest: ProbeManifest): void {
  const labels = scenario.steps.map((step) => step.label ?? step.fn);

  expect(result.equivalent).to.equal(true);
  expect(result.divergences).to.deep.equal([]);
  expect(result.a.steps).to.have.length(labels.length);
  expect(result.b.steps).to.have.length(labels.length);
  expect(result.a.steps.map((step) => step.label)).to.deep.equal(labels);
  expect(result.b.steps.map((step) => step.label)).to.deep.equal(labels);
  expect(result.a.steps.every((step) => step.expectationMet)).to.equal(true);
  expect(result.b.steps.every((step) => step.expectationMet)).to.equal(true);

  expect((scenario.plaintextProbes ?? []).map((probe) => probe.name)).to.deep.equal(manifest.plaintexts);
  expect((scenario.aclProbes ?? []).map(declaredAclKey)).to.deep.equal(manifest.acl);
  expect((scenario.valueProbes ?? []).map((probe) => probe.name)).to.deep.equal(manifest.values);

  const snapshotLabels = expectedSnapshotLabels(scenario);
  for (const run of [result.a, result.b]) {
    expect(run.snapshots.map((snapshot) => snapshot.after)).to.deep.equal(snapshotLabels);
    for (const snapshot of run.snapshots) {
      expect(Object.keys(snapshot.plaintexts)).to.deep.equal(manifest.plaintexts);
      expect(Object.keys(snapshot.acl)).to.deep.equal(manifest.acl);
      expect(Object.keys(snapshot.values)).to.deep.equal(manifest.values);
    }
  }
}

function snapshotAfter(run: RunResult, label: string) {
  const step = run.steps.find((candidate) => candidate.label === label);
  expect(step, `missing step label ${label}`).not.to.equal(undefined);
  const after = `step ${step!.index} (${label})`;
  const snapshot = run.snapshots.find((candidate) => candidate.after === after);
  expect(snapshot, `missing snapshot ${after}`).not.to.equal(undefined);
  return snapshot!;
}

async function deployTokenPair(): Promise<{ reference: Contract; generated: Contract }> {
  const constructorArgs = ['Confidential Token', 'CTOK', 6, 'https://example.com/ctok'] as const;
  const reference = (await hre.ethers.deployContract('FHERC20RefHarness', [...constructorArgs])) as unknown as Contract;
  const generated = (await hre.ethers.deployContract('FHERC20Harness', [...constructorArgs])) as unknown as Contract;
  await Promise.all([reference.waitForDeployment(), generated.waitForDeployment()]);
  return { reference, generated };
}

/**
 * The flagship pair is the current fhec output versus the unmodified upstream
 * FHERC20. Every scenario is strict: it compares plaintexts, ACL, indicators,
 * and revert identity without comparing ciphertext handles. No divergence
 * remains — the `precondition` block closed the last ordering gap, so all eight
 * transfer overloads now agree on error identity as well as on effect.
 */
describe('differential :: transpiled FHERC20 (dialect) vs upstream fhenix-confidential-contracts', () => {
  let env: MockEnvironment;
  let accounts: Fherc20Accounts;

  before(async function () {
    this.timeout(180_000);
    env = await deployMockEnvironment(hre);
    const signers = await hre.ethers.getSigners();
    accounts = {
      alice: await signers[0].getAddress(),
      bob: await signers[1].getAddress(),
      carol: await signers[2].getAddress(),
      dave: await signers[3].getAddress(),
    };
  });

  it('matches external transfers, the complete operator matrix, ACL, and indicators', async function () {
    this.timeout(300_000);
    const { reference, generated } = await deployTokenPair();
    const scenario = makeFherc20CoreScenario(accounts);
    const result = await assertDifferentiallyEquivalent(env, reference, generated, scenario, {
      labelA: LABELS.a,
      labelB: LABELS.b,
    });

    assertStrictResult(result, scenario, {
      plaintexts: ['aliceBalance', 'bobBalance', 'totalSupply'],
      acl: [
        'aliceBalance@self',
        'aliceBalance@signer0',
        'aliceBalance@signer2',
        'bobBalance@self',
        'bobBalance@signer1',
        'bobBalance@signer2',
        'totalSupply@self',
        'totalSupply@signer0',
      ],
      values: [
        'indicatedSupply',
        'indicatedAlice',
        'indicatedBob',
        'indicatorTick',
        'balanceOfIsIndicator',
        'carolIsOperator',
        'daveIsOperator',
        'bobIsSelfOperator',
      ],
    });

    const afterOperator = snapshotAfter(result.a, 'valid operator moves 50 from alice to bob');
    expect(afterOperator.acl['aliceBalance@signer2']).to.equal(false);
    expect(afterOperator.acl['bobBalance@signer2']).to.equal(false);

    const beforeDisclosure = snapshotAfter(result.a, 'operator has no ACL to disclose alice balance');
    expect(beforeDisclosure.acl['aliceBalance@signer2']).to.equal(false);

    const final = result.a.snapshots[result.a.snapshots.length - 1];
    expect(final.plaintexts.aliceBalance).to.equal(EXPECTED_CORE_FINAL.alice);
    expect(final.plaintexts.bobBalance).to.equal(EXPECTED_CORE_FINAL.bob);
    expect(final.plaintexts.totalSupply).to.equal(EXPECTED_CORE_FINAL.totalSupply);
    expect(final.acl['aliceBalance@signer2']).to.equal(true); // explicitly public after disclosure
    expect(final.acl['bobBalance@signer2']).to.equal(false);
    expect(final.values.indicatedAlice).to.equal('0');
    expect(final.values.indicatorTick).to.equal('100');
    expect(final.values.balanceOfIsIndicator).to.equal('true');
    expect(final.values.carolIsOperator).to.equal('true');
    expect(final.values.daveIsOperator).to.equal('false');
    expect(final.values.bobIsSelfOperator).to.equal('true');
  });

  it('matches EOA, accepting, rejecting, and empty-reverting callback behavior', async function () {
    this.timeout(300_000);
    const { reference, generated } = await deployTokenPair();
    const accepting = (await hre.ethers.deployContract('FHERC20Receiver', [0])) as unknown as Contract;
    const rejecting = (await hre.ethers.deployContract('FHERC20Receiver', [1])) as unknown as Contract;
    const reverting = (await hre.ethers.deployContract('FHERC20Receiver', [2])) as unknown as Contract;
    await Promise.all([accepting.waitForDeployment(), rejecting.waitForDeployment(), reverting.waitForDeployment()]);

    const scenario = makeFherc20CallbackScenario({
      ...accounts,
      acceptingReceiver: await accepting.getAddress(),
      rejectingReceiver: await rejecting.getAddress(),
      revertingReceiver: await reverting.getAddress(),
    });
    const result = await assertDifferentiallyEquivalent(env, reference, generated, scenario, {
      labelA: LABELS.a,
      labelB: LABELS.b,
    });

    assertStrictResult(result, scenario, {
      plaintexts: [
        'aliceBalance',
        'bobBalance',
        'acceptingBalance',
        'rejectingBalance',
        'revertingBalance',
        'totalSupply',
      ],
      acl: ['aliceBalance@signer0', `acceptingBalance@${await accepting.getAddress()}`, `rejectingBalance@${await rejecting.getAddress()}`],
      values: ['indicatedAlice', 'indicatedRejecting'],
    });

    const afterReject = snapshotAfter(result.a, 'rejecting callback refunds all 30');
    expect(afterReject.plaintexts.aliceBalance).to.equal('170');
    expect(afterReject.plaintexts.rejectingBalance).to.equal('0');

    for (const token of [reference, generated]) {
      const receiver = (await hre.ethers.deployContract('FHERC20Receiver', [0])) as unknown as Contract;
      await receiver.waitForDeployment();
      const tokenAddress = await token.getAddress();
      await (await token.mint(accounts.alice, 20n)).wait();
      await (await (token.connect((await hre.ethers.getSigners())[0]) as Contract).setOperator(accounts.carol, OPERATOR_UNTIL)).wait();
      const input = await env.encryptInput(20n, 'euint64', accounts.carol, tokenAddress);
      await (
        await (token.connect((await hre.ethers.getSigners())[2]) as Contract)[
          'confidentialTransferFromAndCall(address,address,bytes32,bytes,bytes)'
        ](accounts.alice, await receiver.getAddress(), input.handle, input.signature, CALLBACK_ACCEPT_DATA)
      ).wait();

      expect(await receiver.lastOperator()).to.equal(accounts.carol);
      expect(await receiver.lastFrom()).to.equal(accounts.alice);
      expect(await receiver.lastDataHash()).to.equal(hre.ethers.keccak256(CALLBACK_ACCEPT_DATA));
      expect((await env.getPlaintext(await receiver.lastAmount()))?.toString()).to.equal('20');
    }

    const final = result.a.snapshots[result.a.snapshots.length - 1];
    expect(final.plaintexts.aliceBalance).to.equal(EXPECTED_CALLBACK_FINAL.alice);
    expect(final.plaintexts.bobBalance).to.equal(EXPECTED_CALLBACK_FINAL.bob);
    expect(final.plaintexts.acceptingBalance).to.equal(EXPECTED_CALLBACK_FINAL.accepting);
    expect(final.plaintexts.rejectingBalance).to.equal(EXPECTED_CALLBACK_FINAL.rejecting);
    expect(final.plaintexts.revertingBalance).to.equal(EXPECTED_CALLBACK_FINAL.reverting);
    expect(final.plaintexts.totalSupply).to.equal(EXPECTED_CALLBACK_FINAL.totalSupply);
  });

  it('matches saturating mint, insufficient transfer, and burn arithmetic', async function () {
    this.timeout(300_000);
    const { reference, generated } = await deployTokenPair();
    const scenario = makeFherc20ArithmeticScenario(accounts);
    const result = await assertDifferentiallyEquivalent(env, reference, generated, scenario, {
      labelA: LABELS.a,
      labelB: LABELS.b,
    });

    assertStrictResult(result, scenario, {
      plaintexts: ['aliceBalance', 'bobBalance', 'carolBalance', 'totalSupply'],
      acl: ['aliceBalance@signer0', 'bobBalance@signer1', 'carolBalance@signer2', 'totalSupply@self'],
      values: ['indicatedSupply', 'indicatedAlice', 'indicatedBob', 'indicatedCarol'],
    });

    const afterOverflow = snapshotAfter(result.a, 'overflowing mint to bob saturates to zero');
    expect(afterOverflow.plaintexts.bobBalance).to.equal('0');
    expect(afterOverflow.plaintexts.totalSupply).to.equal((2n ** 64n - 1n).toString());

    const afterInsufficient = snapshotAfter(result.a, 'insufficient alice transfer saturates to zero');
    expect(afterInsufficient.plaintexts.aliceBalance).to.equal('0');
    expect(afterInsufficient.plaintexts.carolBalance).to.equal('0');

    const final = result.a.snapshots[result.a.snapshots.length - 1];
    expect(final.plaintexts.aliceBalance).to.equal(EXPECTED_ARITHMETIC_FINAL.alice);
    expect(final.plaintexts.bobBalance).to.equal(EXPECTED_ARITHMETIC_FINAL.bob);
    expect(final.plaintexts.carolBalance).to.equal(EXPECTED_ARITHMETIC_FINAL.carol);
    expect(final.plaintexts.totalSupply).to.equal(EXPECTED_ARITHMETIC_FINAL.totalSupply);
  });

  it('matches all shared overloads, directed results, and receive-first compound failures', async function () {
    this.timeout(360_000);
    const signers = await hre.ethers.getSigners();
    const { reference, generated } = await deployTokenPair();
    const referenceDriver = (await hre.ethers.deployContract('FHERC20SharedDriver', [
      await reference.getAddress(),
    ])) as unknown as Contract;
    const generatedDriver = (await hre.ethers.deployContract('FHERC20SharedDriver', [
      await generated.getAddress(),
    ])) as unknown as Contract;
    const accepting = (await hre.ethers.deployContract('FHERC20Receiver', [0])) as unknown as Contract;
    await Promise.all([
      referenceDriver.waitForDeployment(),
      generatedDriver.waitForDeployment(),
      accepting.waitForDeployment(),
    ]);

    const referenceDriverAddress = await referenceDriver.getAddress();
    const generatedDriverAddress = await generatedDriver.getAddress();
    await (await reference.mint(referenceDriverAddress, 500n)).wait();
    await (await generated.mint(generatedDriverAddress, 500n)).wait();
    await (await reference.mint(accounts.alice, 300n)).wait();
    await (await generated.mint(accounts.alice, 300n)).wait();
    await (await (reference.connect(signers[0]) as Contract).setOperator(referenceDriverAddress, OPERATOR_UNTIL)).wait();
    await (await (generated.connect(signers[0]) as Contract).setOperator(generatedDriverAddress, OPERATOR_UNTIL)).wait();

    const scenario = makeFherc20SharedScenario({
      ...accounts,
      acceptingReceiver: await accepting.getAddress(),
    });
    const result = await assertDifferentiallyEquivalent(env, referenceDriver, generatedDriver, scenario, {
      labelA: 'reference-token shared driver',
      labelB: 'generated-token shared driver',
    });

    assertStrictResult(result, scenario, {
      plaintexts: ['driverBalance', 'aliceBalance', 'bobBalance', 'acceptingBalance', 'totalSupply', 'lastResult'],
      acl: [
        'driverBalance@self',
        'driverBalance@signer0',
        'aliceBalance@signer0',
        'aliceBalance@self',
        'bobBalance@signer1',
        'bobBalance@self',
        'lastResult@self',
        'lastResult@signer0',
      ],
      values: ['driverIsOperator'],
    });

    expect(snapshotAfter(result.a, 'shared transfer moves 50 from driver to bob').plaintexts.lastResult).to.equal('50');
    expect(snapshotAfter(result.a, 'shared From uses driver operator for 40').plaintexts.lastResult).to.equal('40');
    expect(snapshotAfter(result.a, 'shared AndCall sends 30 to accepting receiver').plaintexts.lastResult).to.equal('30');
    expect(snapshotAfter(result.a, 'shared FromAndCall sends 20 as operator').plaintexts.lastResult).to.equal('20');

    for (const label of [
      'shared From missing share fails before unauthorized operator',
      'shared From wrong recipient fails before unauthorized operator',
    ]) {
      const step = result.a.steps.find((candidate) => candidate.label === label)!;
      expect(step.revertKey).to.equal('NotShared');
    }
    expect(
      result.a.steps.find(
        (candidate) => candidate.label === 'shared FromAndCall wrong sharer fails before unauthorized operator'
      )!.revertKey
    ).to.equal('UnexpectedSharer');

    const final = result.a.snapshots[result.a.snapshots.length - 1];
    expect(final.plaintexts.driverBalance).to.equal(EXPECTED_SHARED_FINAL.driver);
    expect(final.plaintexts.aliceBalance).to.equal(EXPECTED_SHARED_FINAL.alice);
    expect(final.plaintexts.bobBalance).to.equal(EXPECTED_SHARED_FINAL.bob);
    expect(final.plaintexts.acceptingBalance).to.equal(EXPECTED_SHARED_FINAL.accepting);
    expect(final.plaintexts.totalSupply).to.equal(EXPECTED_SHARED_FINAL.totalSupply);
    expect(final.plaintexts.lastResult).to.equal(EXPECTED_SHARED_FINAL.lastResult);
    expect(final.acl['aliceBalance@self']).to.equal(false); // the driver operator never gains holder balance ACL
    expect(final.acl['bobBalance@self']).to.equal(false);
    expect(final.acl['lastResult@self']).to.equal(true);
    expect(final.values.driverIsOperator).to.equal('true');
  });

  it('matches basic From compound-invalid ordering, operator error first on both sides', async function () {
    this.timeout(240_000);
    const { reference, generated } = await deployTokenPair();
    const scenario = makeFherc20CompoundInvalidOrderingScenario(accounts);
    const result = await assertDifferentiallyEquivalent(env, reference, generated, scenario, {
      labelA: LABELS.a,
      labelB: LABELS.b,
    });

    assertStrictResult(result, scenario, { plaintexts: [], acl: [], values: [] });

    // The `precondition` block keeps the operator check ahead of proof
    // verification, so both sides report the operator error, not `InvalidSigner`.
    expect(result.a.steps[0].revertKey).to.equal('FHERC20UnauthorizedSpender');
    expect(result.b.steps[0].revertKey).to.equal('FHERC20UnauthorizedSpender');
    expect(result.a.snapshots[0].plaintexts).to.deep.equal({});
    expect(result.a.snapshots[0].acl).to.deep.equal({});
    expect(result.a.snapshots[0].values).to.deep.equal({});
  });

  it('pins the canonical eight-transfer ABI, selectors, surface, and interface support', async function () {
    this.timeout(180_000);
    const expectedTransfers = new Map<string, string>([
      ['confidentialTransfer(address,bytes32,bytes)', '0x2fb74e62'],
      ['confidentialTransfer(address,bytes32)', '0x5bebed7e'],
      ['confidentialTransferFrom(address,address,bytes32,bytes)', '0xe064b9bb'],
      ['confidentialTransferFrom(address,address,bytes32)', '0xeb3155b5'],
      ['confidentialTransferAndCall(address,bytes32,bytes,bytes)', '0xde642119'],
      ['confidentialTransferAndCall(address,bytes32,bytes)', '0x537d3c50'],
      ['confidentialTransferFromAndCall(address,address,bytes32,bytes,bytes)', '0x34c45743'],
      ['confidentialTransferFromAndCall(address,address,bytes32,bytes)', '0xc7b8a75e'],
    ]);
    const requiredEvents = [
      'OperatorSet(address indexed holder, address indexed operator, uint48 until)',
      'ConfidentialTransfer(address indexed from, address indexed to, bytes32 indexed amount)',
      'AmountDisclosed(bytes32 indexed encryptedAmount, uint64 amount)',
      'Transfer(address indexed from, address indexed to, uint256 value)',
      'AmountDiscloseRequested(bytes32 indexed encryptedAmount, address indexed requester)',
    ];
    const requiredErrors = [
      'FHERC20InvalidReceiver(address receiver)',
      'FHERC20InvalidSender(address sender)',
      'FHERC20UnauthorizedSpender(address holder, address spender)',
      'FHERC20ZeroBalance(address holder)',
      'FHERC20UnauthorizedUseOfEncryptedAmount(bytes32 amount, address user)',
      'FHERC20IncompatibleFunction()',
    ];

    for (const [signature, selector] of expectedTransfers) {
      expect(hre.ethers.id(signature).slice(0, 10)).to.equal(selector);
    }

    for (const artifactName of ['FHERC20RefHarness', 'FHERC20Harness']) {
      const artifact = await hre.artifacts.readArtifact(artifactName);
      const iface = new Interface(artifact.abi as InterfaceAbi);
      const transfers = iface.fragments
        .filter((fragment): fragment is FunctionFragment => fragment.type === 'function')
        .filter((fragment) => fragment.name.startsWith('confidentialTransfer'));
      const signatures = transfers.map((fragment) => fragment.format('sighash'));
      expect(signatures).to.have.length(8);
      expect(new Set(signatures)).to.deep.equal(new Set(expectedTransfers.keys()));

      for (const [signature, selector] of expectedTransfers) {
        const fn = iface.getFunction(signature);
        expect(fn, `${artifactName} missing ${signature}`).not.to.equal(null);
        expect(fn!.selector).to.equal(selector);
        expect(fn!.outputs).to.have.length(1);
        expect(fn!.outputs[0].type).to.equal('bytes32');
      }

      const eventSignatures = new Set(
        iface.fragments
          .filter((fragment): fragment is EventFragment => fragment.type === 'event')
          .map((fragment) => fragment.format('full'))
      );
      const errorSignatures = new Set(
        iface.fragments
          .filter((fragment): fragment is ErrorFragment => fragment.type === 'error')
          .map((fragment) => fragment.format('full'))
      );
      for (const signature of requiredEvents) expect(eventSignatures.has(`event ${signature}`), `${artifactName} event ${signature}`).to.equal(true);
      for (const signature of requiredErrors) {
        const error = iface.getError(signature);
        expect(error, `${artifactName} error ${signature}`).not.to.equal(null);
        expect(error!.format('full')).to.equal(`error ${signature}`);
        expect(error!.selector).to.equal(hre.ethers.id(error!.format('sighash')).slice(0, 10));
        expect(errorSignatures.has(`error ${signature}`), `${artifactName} error ${signature}`).to.equal(true);
      }
    }

    const { reference, generated } = await deployTokenPair();
    const ids = (await hre.ethers.deployContract('FHERC20InterfaceIds')) as unknown as Contract;
    await ids.waitForDeployment();
    const interfaceIds = [await ids.fherc20(), await ids.ierc7984(), await ids.ierc20()];
    expect(new Set(interfaceIds).size).to.equal(3);

    for (const token of [reference, generated]) {
      for (const interfaceId of interfaceIds) expect(await token.supportsInterface(interfaceId)).to.equal(true);
      expect(await token.supportsInterface('0xffffffff')).to.equal(false);
    }
  });
});
