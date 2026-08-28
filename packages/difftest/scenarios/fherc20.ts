import type { Contract } from 'ethers';

import type { Scenario, StepContext } from '../src/differential';

export const UINT64_MAX = (1n << 64n) - 1n;
export const OPERATOR_UNTIL = 1n << 40n;
export const CALLBACK_ACCEPT_DATA = '0xaabb';

export const EXPECTED_CORE_FINAL = {
  alice: '855',
  bob: '245',
  totalSupply: '1100',
} as const;

export const EXPECTED_CALLBACK_FINAL = {
  alice: '170',
  bob: '10',
  accepting: '20',
  rejecting: '0',
  reverting: null,
  totalSupply: '200',
} as const;

export const EXPECTED_ARITHMETIC_FINAL = {
  alice: '0',
  bob: (UINT64_MAX - 5n).toString(),
  carol: '0',
  totalSupply: (UINT64_MAX - 5n).toString(),
} as const;

export const EXPECTED_SHARED_FINAL = {
  driver: '420',
  alice: '240',
  bob: '90',
  accepting: '50',
  totalSupply: '800',
  lastResult: '20',
} as const;

export interface Fherc20Accounts {
  alice: string;
  bob: string;
  carol: string;
  dave: string;
}

export interface CallbackWiring extends Fherc20Accounts {
  acceptingReceiver: string;
  rejectingReceiver: string;
  revertingReceiver: string;
}

export interface SharedWiring extends Fherc20Accounts {
  acceptingReceiver: string;
}

/** A token-consumed encrypted input: EOA sender and token consumer are both bound. */
async function tokenAmountArgs(
  ctx: StepContext,
  amount: bigint | number,
  leading: unknown[] = [],
  trailing: unknown[] = []
): Promise<unknown[]> {
  const input = await ctx.env.encryptInput(amount, 'euint64', ctx.sender, ctx.address);
  return [...leading, input.handle, input.signature, ...trailing];
}

/** A driver-consumed encrypted input, using the same per-side consumer rule. */
async function driverAmountArgs(
  ctx: StepContext,
  amount: bigint | number,
  leading: unknown[] = [],
  trailing: unknown[] = []
): Promise<unknown[]> {
  const input = await ctx.env.encryptInput(amount, 'euint64', ctx.sender, ctx.address);
  return [...leading, input.handle, input.signature, ...trailing];
}

/** A valid input signed for the wrong consumer, rather than arbitrary proof bytes. */
async function wrongConsumerArgs(
  ctx: StepContext,
  amount: bigint | number,
  wrongConsumer: string,
  leading: unknown[] = [],
  trailing: unknown[] = []
): Promise<unknown[]> {
  const input = await ctx.env.encryptInput(amount, 'euint64', ctx.sender, wrongConsumer);
  return [...leading, input.handle, input.signature, ...trailing];
}

/** Current per-side balance handle, used without ever comparing the handle itself. */
async function balanceHandleArg(ctx: StepContext, account: string): Promise<unknown[]> {
  const handle = await (ctx.contract as Contract).confidentialBalanceOf(account);
  return [handle];
}

/**
 * Strict external-input/operator/ACL coverage. This includes valid, self,
 * unauthorized, and expired operators, plus the operator-first compound-invalid
 * FromAndCall path. The basic From compound-invalid ordering case is isolated
 * elsewhere (also strict — no divergence remains).
 */
export function makeFherc20CoreScenario(wiring: Fherc20Accounts): Scenario {
  return {
    name: 'FHERC20 external transfers, operators, ACL, and indicators',
    steps: [
      { fn: 'mint', label: 'mint 1000 to alice', args: [wiring.alice, 1000n] },
      { fn: 'mint', label: 'mint 100 to bob', args: [wiring.bob, 100n] },
      {
        fn: 'confidentialTransfer(address,bytes32,bytes)',
        label: 'external transfer moves 100 from alice to bob',
        args: (ctx) => tokenAmountArgs(ctx, 100n, [wiring.bob]),
      },
      {
        fn: 'setOperator',
        label: 'alice authorizes carol as operator',
        args: [wiring.carol, OPERATOR_UNTIL],
      },
      {
        fn: 'confidentialTransferFrom(address,address,bytes32,bytes)',
        from: 2,
        label: 'valid operator moves 50 from alice to bob',
        args: (ctx) => tokenAmountArgs(ctx, 50n, [wiring.alice, wiring.bob]),
      },
      {
        fn: 'confidentialTransferFrom(address,address,bytes32,bytes)',
        from: 1,
        label: 'self operator moves 25 from bob to alice',
        args: (ctx) => tokenAmountArgs(ctx, 25n, [wiring.bob, wiring.alice]),
      },
      {
        fn: 'confidentialTransferFrom(address,address,bytes32,bytes)',
        from: 3,
        label: 'unauthorized dave cannot move alice balance',
        args: (ctx) => tokenAmountArgs(ctx, 10n, [wiring.alice, wiring.bob]),
        expectRevert: 'FHERC20UnauthorizedSpender',
      },
      {
        fn: 'setOperator',
        label: 'alice records an already expired dave operator',
        args: [wiring.dave, 0n],
      },
      {
        fn: 'confidentialTransferFrom(address,address,bytes32,bytes)',
        from: 3,
        label: 'expired operator cannot move alice balance',
        args: (ctx) => tokenAmountArgs(ctx, 10n, [wiring.alice, wiring.bob]),
        expectRevert: 'FHERC20UnauthorizedSpender',
      },
      {
        fn: 'confidentialTransferFromAndCall(address,address,bytes32,bytes,bytes)',
        from: 2,
        label: 'external FromAndCall operator moves 20 to EOA bob',
        args: (ctx) => tokenAmountArgs(ctx, 20n, [wiring.alice, wiring.bob], ['0x1234']),
      },
      {
        fn: 'confidentialTransferFromAndCall(address,address,bytes32,bytes,bytes)',
        from: 3,
        label: 'external FromAndCall stays operator-first with wrong-consumer proof',
        args: (ctx) => wrongConsumerArgs(ctx, 1n, wiring.bob, [wiring.alice, wiring.bob], ['0x']),
        expectRevert: 'FHERC20UnauthorizedSpender',
      },
      {
        fn: 'requestDiscloseEncryptedAmount',
        from: 2,
        label: 'operator has no ACL to disclose alice balance',
        args: (ctx) => balanceHandleArg(ctx, wiring.alice),
        expectRevert: 'FHERC20UnauthorizedUseOfEncryptedAmount',
      },
      {
        fn: 'requestDiscloseEncryptedAmount',
        label: 'alice makes her balance publicly allowed',
        args: (ctx) => balanceHandleArg(ctx, wiring.alice),
      },
      { fn: 'resetIndicatedBalance', label: 'alice resets her indicated balance' },
      {
        fn: 'transfer',
        label: 'cleartext ERC20 transfer remains incompatible',
        args: [wiring.bob, 1n],
        expectRevert: 'FHERC20IncompatibleFunction',
      },
    ],
    plaintextProbes: [
      { name: 'aliceBalance', getter: 'confidentialBalanceOf', args: [wiring.alice] },
      { name: 'bobBalance', getter: 'confidentialBalanceOf', args: [wiring.bob] },
      { name: 'totalSupply', getter: 'confidentialTotalSupply' },
    ],
    aclProbes: [
      { name: 'aliceBalance', getter: 'confidentialBalanceOf', args: [wiring.alice], account: 'self' },
      { name: 'aliceBalance', getter: 'confidentialBalanceOf', args: [wiring.alice], account: 0 },
      { name: 'aliceBalance', getter: 'confidentialBalanceOf', args: [wiring.alice], account: 2 },
      { name: 'bobBalance', getter: 'confidentialBalanceOf', args: [wiring.bob], account: 'self' },
      { name: 'bobBalance', getter: 'confidentialBalanceOf', args: [wiring.bob], account: 1 },
      { name: 'bobBalance', getter: 'confidentialBalanceOf', args: [wiring.bob], account: 2 },
      { name: 'totalSupply', getter: 'confidentialTotalSupply', account: 'self' },
      { name: 'totalSupply', getter: 'confidentialTotalSupply', account: 0 },
    ],
    valueProbes: [
      { name: 'indicatedSupply', getter: 'totalSupply' },
      { name: 'indicatedAlice', getter: 'balanceOf', args: [wiring.alice] },
      { name: 'indicatedBob', getter: 'balanceOf', args: [wiring.bob] },
      { name: 'indicatorTick', getter: 'indicatorTick' },
      { name: 'balanceOfIsIndicator', getter: 'balanceOfIsIndicator' },
      { name: 'carolIsOperator', getter: 'isOperator', args: [wiring.alice, wiring.carol] },
      { name: 'daveIsOperator', getter: 'isOperator', args: [wiring.alice, wiring.dave] },
      { name: 'bobIsSelfOperator', getter: 'isOperator', args: [wiring.bob, wiring.bob] },
    ],
  };
}

/** Strict callback coverage for an EOA and accept/reject/empty-revert receivers. */
export function makeFherc20CallbackScenario(wiring: CallbackWiring): Scenario {
  return {
    name: 'FHERC20 external callbacks and rejection refunds',
    steps: [
      { fn: 'mint', label: 'mint 200 to alice for callbacks', args: [wiring.alice, 200n] },
      {
        fn: 'confidentialTransferAndCall(address,bytes32,bytes,bytes)',
        label: 'AndCall to EOA bob transfers without callback',
        args: (ctx) => tokenAmountArgs(ctx, 10n, [wiring.bob], ['0x01']),
      },
      {
        fn: 'setOperator',
        label: 'alice authorizes carol for accepting callback',
        args: [wiring.carol, OPERATOR_UNTIL],
      },
      {
        fn: 'confidentialTransferFromAndCall(address,address,bytes32,bytes,bytes)',
        from: 2,
        label: 'accepting callback keeps 20 and receives operator payload',
        args: (ctx) => tokenAmountArgs(ctx, 20n, [wiring.alice, wiring.acceptingReceiver], [CALLBACK_ACCEPT_DATA]),
      },
      {
        fn: 'confidentialTransferAndCall(address,bytes32,bytes,bytes)',
        label: 'rejecting callback refunds all 30',
        args: (ctx) => tokenAmountArgs(ctx, 30n, [wiring.rejectingReceiver], ['0xcc']),
      },
      {
        fn: 'confidentialTransferAndCall(address,bytes32,bytes,bytes)',
        label: 'empty-reverting callback becomes invalid receiver',
        args: (ctx) => tokenAmountArgs(ctx, 40n, [wiring.revertingReceiver], ['0xdd']),
        expectRevert: 'FHERC20InvalidReceiver',
      },
    ],
    plaintextProbes: [
      { name: 'aliceBalance', getter: 'confidentialBalanceOf', args: [wiring.alice] },
      { name: 'bobBalance', getter: 'confidentialBalanceOf', args: [wiring.bob] },
      { name: 'acceptingBalance', getter: 'confidentialBalanceOf', args: [wiring.acceptingReceiver] },
      { name: 'rejectingBalance', getter: 'confidentialBalanceOf', args: [wiring.rejectingReceiver] },
      { name: 'revertingBalance', getter: 'confidentialBalanceOf', args: [wiring.revertingReceiver] },
      { name: 'totalSupply', getter: 'confidentialTotalSupply' },
    ],
    aclProbes: [
      { name: 'aliceBalance', getter: 'confidentialBalanceOf', args: [wiring.alice], account: 0 },
      {
        name: 'acceptingBalance',
        getter: 'confidentialBalanceOf',
        args: [wiring.acceptingReceiver],
        account: wiring.acceptingReceiver,
      },
      {
        name: 'rejectingBalance',
        getter: 'confidentialBalanceOf',
        args: [wiring.rejectingReceiver],
        account: wiring.rejectingReceiver,
      },
    ],
    valueProbes: [
      { name: 'indicatedAlice', getter: 'balanceOf', args: [wiring.alice] },
      { name: 'indicatedRejecting', getter: 'balanceOf', args: [wiring.rejectingReceiver] },
    ],
  };
}

/** Strict saturating uint64 arithmetic and burn behavior. */
export function makeFherc20ArithmeticScenario(wiring: Fherc20Accounts): Scenario {
  return {
    name: 'FHERC20 saturating arithmetic and burn',
    steps: [
      { fn: 'mint', label: 'mint uint64 max to alice', args: [wiring.alice, UINT64_MAX] },
      { fn: 'mint', label: 'overflowing mint to bob saturates to zero', args: [wiring.bob, 1n] },
      {
        fn: 'confidentialTransfer(address,bytes32,bytes)',
        label: 'alice transfers uint64 max to bob',
        args: (ctx) => tokenAmountArgs(ctx, UINT64_MAX, [wiring.bob]),
      },
      {
        fn: 'confidentialTransfer(address,bytes32,bytes)',
        label: 'insufficient alice transfer saturates to zero',
        args: (ctx) => tokenAmountArgs(ctx, 1n, [wiring.carol]),
      },
      { fn: 'burn', label: 'burn 5 from bob', args: [wiring.bob, 5n] },
    ],
    plaintextProbes: [
      { name: 'aliceBalance', getter: 'confidentialBalanceOf', args: [wiring.alice] },
      { name: 'bobBalance', getter: 'confidentialBalanceOf', args: [wiring.bob] },
      { name: 'carolBalance', getter: 'confidentialBalanceOf', args: [wiring.carol] },
      { name: 'totalSupply', getter: 'confidentialTotalSupply' },
    ],
    aclProbes: [
      { name: 'aliceBalance', getter: 'confidentialBalanceOf', args: [wiring.alice], account: 0 },
      { name: 'bobBalance', getter: 'confidentialBalanceOf', args: [wiring.bob], account: 1 },
      { name: 'carolBalance', getter: 'confidentialBalanceOf', args: [wiring.carol], account: 2 },
      { name: 'totalSupply', getter: 'confidentialTotalSupply', account: 'self' },
    ],
    valueProbes: [
      { name: 'indicatedSupply', getter: 'totalSupply' },
      { name: 'indicatedAlice', getter: 'balanceOf', args: [wiring.alice] },
      { name: 'indicatedBob', getter: 'balanceOf', args: [wiring.bob] },
      { name: 'indicatedCarol', getter: 'balanceOf', args: [wiring.carol] },
    ],
  };
}

/**
 * Strict shared-input/result coverage. The scenario target is a paired driver,
 * whose wrapper views expose the paired token without address-dependent probes.
 */
export function makeFherc20SharedScenario(wiring: SharedWiring): Scenario {
  return {
    name: 'FHERC20 directed shared inputs and results',
    steps: [
      {
        fn: 'transferShared',
        label: 'shared transfer moves 50 from driver to bob',
        args: (ctx) => driverAmountArgs(ctx, 50n, [wiring.bob]),
      },
      {
        fn: 'transferFromShared',
        label: 'shared From uses driver operator for 40',
        args: (ctx) => driverAmountArgs(ctx, 40n, [wiring.alice, wiring.bob]),
      },
      {
        fn: 'transferAndCallShared',
        label: 'shared AndCall sends 30 to accepting receiver',
        args: (ctx) => driverAmountArgs(ctx, 30n, [wiring.acceptingReceiver], ['0x1234']),
      },
      {
        fn: 'transferFromAndCallShared',
        label: 'shared FromAndCall sends 20 as operator',
        args: (ctx) => driverAmountArgs(ctx, 20n, [wiring.alice, wiring.acceptingReceiver], ['0x5678']),
      },
      {
        fn: 'transferFromMissingShare',
        label: 'shared From missing share fails before unauthorized operator',
        args: (ctx) => driverAmountArgs(ctx, 1n, [wiring.carol, wiring.bob]),
        expectRevert: 'NotShared',
      },
      {
        fn: 'transferFromWrongRecipient',
        label: 'shared From wrong recipient fails before unauthorized operator',
        args: (ctx) => driverAmountArgs(ctx, 1n, [wiring.carol, wiring.bob]),
        expectRevert: 'NotShared',
      },
      {
        fn: 'transferFromAndCallWrongSharer',
        label: 'shared FromAndCall wrong sharer fails before unauthorized operator',
        args: (ctx) => driverAmountArgs(ctx, 1n, [wiring.carol, wiring.acceptingReceiver], ['0x']),
        expectRevert: 'UnexpectedSharer',
      },
      {
        fn: 'transferWrongResultRecipient',
        label: 'shared result cannot be consumed by wrong recipient',
        args: (ctx) => driverAmountArgs(ctx, 5n, [wiring.bob]),
        expectRevert: 'NotShared',
      },
    ],
    plaintextProbes: [
      { name: 'driverBalance', getter: 'driverBalance' },
      { name: 'aliceBalance', getter: 'tokenBalanceOf', args: [wiring.alice] },
      { name: 'bobBalance', getter: 'tokenBalanceOf', args: [wiring.bob] },
      { name: 'acceptingBalance', getter: 'tokenBalanceOf', args: [wiring.acceptingReceiver] },
      { name: 'totalSupply', getter: 'tokenTotalSupply' },
      { name: 'lastResult', getter: 'lastResult' },
    ],
    aclProbes: [
      { name: 'driverBalance', getter: 'driverBalance', account: 'self' },
      { name: 'driverBalance', getter: 'driverBalance', account: 0 },
      { name: 'aliceBalance', getter: 'tokenBalanceOf', args: [wiring.alice], account: 0 },
      { name: 'aliceBalance', getter: 'tokenBalanceOf', args: [wiring.alice], account: 'self' },
      { name: 'bobBalance', getter: 'tokenBalanceOf', args: [wiring.bob], account: 1 },
      { name: 'bobBalance', getter: 'tokenBalanceOf', args: [wiring.bob], account: 'self' },
      { name: 'lastResult', getter: 'lastResult', account: 'self' },
      { name: 'lastResult', getter: 'lastResult', account: 0 },
    ],
    valueProbes: [{ name: 'driverIsOperator', getter: 'driverIsOperator', args: [wiring.alice] }],
  };
}

/**
 * Basic external From with BOTH an unauthorized operator and a proof bound to
 * the wrong consumer. The order of the two failures is observable, so this
 * pinned the one old baseline divergence: generated output used to verify the
 * proof first and report `InvalidSigner`. A `precondition` block now keeps the
 * operator check first, and both sides report `FHERC20UnauthorizedSpender`.
 *
 * A second step repeats the wrong-consumer proof with an AUTHORIZED operator,
 * so the precondition passes and proof verification is actually reached. This
 * proves the ordering test isn't tautological: the operator check firing
 * first in step 0 isn't masking a proof check that would always pass anyway.
 */
export function makeFherc20CompoundInvalidOrderingScenario(wiring: Fherc20Accounts): Scenario {
  return {
    name: 'FHERC20 basic From unauthorized plus wrong-consumer proof ordering',
    steps: [
      {
        fn: 'confidentialTransferFrom(address,address,bytes32,bytes)',
        from: 1,
        label: 'unauthorized basic From with proof bound to wrong consumer',
        args: (ctx) => wrongConsumerArgs(ctx, 1n, wiring.dave, [wiring.alice, wiring.carol]),
        expectRevert: true,
      },
      {
        fn: 'setOperator',
        label: 'alice authorizes carol as operator',
        args: [wiring.carol, OPERATOR_UNTIL],
      },
      {
        fn: 'confidentialTransferFrom(address,address,bytes32,bytes)',
        from: 2,
        label: 'authorized basic From still fails on a proof bound to the wrong consumer',
        args: (ctx) => wrongConsumerArgs(ctx, 1n, wiring.dave, [wiring.alice, wiring.carol]),
        expectRevert: 'InvalidSigner',
      },
    ],
    probeAfterEachStep: false,
  };
}
