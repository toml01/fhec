import type { Contract } from 'ethers';

import type { Scenario, StepContext } from '../src/differential';

/** Hand-derived plaintext expectations for the FHERC20 scenario. */
export const EXPECTED_FINAL = {
  alice: '730', // 1000 − 100 (transfer) − 0 (saturated) + 30 (operator) − 200 (burn)
  bob: '120', // 50 + 100 − 30
  carol: '0', // initialized by the saturated transfer, which moved 0
  totalSupply: '850', // 1000 + 50 − 200
} as const;

export interface Fherc20ScenarioWiring {
  /** signer0 — deployer, mint/burn caller, primary holder. */
  alice: string;
  /** signer1 — transfer recipient. */
  bob: string;
  /** signer2 — bob's operator. */
  carol: string;
}

/**
 * Scenario factory for the FHERC20 pair: the fhec-transpiled dialect token vs
 * the unmodified upstream implementation.
 *
 * Coverage: mint (tryIncrease path, first-mint handle adoption and the
 * initialized path), encrypted-input transfers through the `in euint64`
 * sugar, the saturating trySpend path (insufficient balance transfers 0 but
 * still shifts indicators), operator-based transferFrom, unauthorized-spender
 * and ERC-20-compat reverts, burn, disclosure request ACL, and the indicator
 * view layer.
 */
export function makeFherc20Scenario(wiring: Fherc20ScenarioWiring): Scenario {
  /**
   * Encrypted `euint64` argument for the `in euint64` sugar surface: handle in
   * the parameter's own position, batch signature trailing. Minted per run
   * and per step: the verifier signature binds sender AND consuming contract.
   */
  const amountArgs = async (ctx: StepContext, amount: number, leading: unknown[] = []): Promise<unknown[]> => {
    const input = await ctx.env.encryptInput(amount, 'euint64', ctx.sender, ctx.address);
    return [...leading, input.handle, input.signature];
  };

  /** The current (per-side) balance handle of `account`. */
  const balanceHandleArg = async (ctx: StepContext, account: string): Promise<unknown[]> => {
    const handle = await (ctx.contract as Contract).confidentialBalanceOf(account);
    return [handle];
  };

  const OPERATOR_UNTIL = 2n ** 40n; // far future, fits uint48

  return {
    name: 'FHERC20: mint, encrypted transfers, operator flow, burn, disclosure',

    steps: [
      { fn: 'mint', label: 'mint 1000 to alice (first mint adopts the handle)', args: [wiring.alice, 1000] },
      { fn: 'mint', label: 'mint 50 to bob (initialized tryIncrease path)', args: [wiring.bob, 50] },
      {
        fn: 'confidentialTransfer(address,bytes32,bytes)',
        label: 'alice transfers 100 to bob (in-euint64 sugar)',
        args: async (ctx) => amountArgs(ctx, 100, [wiring.bob]),
      },
      {
        fn: 'confidentialTransfer(address,bytes32,bytes)',
        label: 'alice transfers 5000 to carol (insufficient: saturates to 0)',
        args: async (ctx) => amountArgs(ctx, 5000, [wiring.carol]),
      },
      {
        fn: 'setOperator',
        from: 1,
        label: 'bob sets carol as operator',
        args: [wiring.carol, OPERATOR_UNTIL],
      },
      {
        fn: 'confidentialTransferFrom(address,address,bytes32,bytes)',
        from: 2,
        label: 'carol (operator) moves 30 from bob to alice',
        args: async (ctx) => amountArgs(ctx, 30, [wiring.bob, wiring.alice]),
      },
      {
        fn: 'confidentialTransferFrom(address,address,bytes32,bytes)',
        from: 1,
        label: 'bob (not an operator for alice) tries to move 10',
        args: async (ctx) => amountArgs(ctx, 10, [wiring.alice, wiring.carol]),
        expectRevert: 'FHERC20UnauthorizedSpender',
      },
      { fn: 'burn', label: 'burn 200 from alice', args: [wiring.alice, 200] },
      {
        fn: 'requestDiscloseEncryptedAmount',
        from: 2,
        label: 'carol requests disclosure of alice’s balance (no access)',
        args: async (ctx) => balanceHandleArg(ctx, wiring.alice),
        expectRevert: 'FHERC20UnauthorizedUseOfEncryptedAmount',
      },
      {
        fn: 'requestDiscloseEncryptedAmount',
        label: 'alice requests disclosure of her own balance',
        args: async (ctx) => balanceHandleArg(ctx, wiring.alice),
      },
      { fn: 'resetIndicatedBalance', label: 'alice resets her indicated balance' },
      {
        fn: 'transfer',
        label: 'ERC-20 transfer() reverts on a confidential token',
        args: [wiring.bob, 1],
        expectRevert: 'FHERC20IncompatibleFunction',
      },
    ],

    plaintextProbes: [
      { name: 'aliceBalance', getter: 'confidentialBalanceOf', args: [wiring.alice] },
      { name: 'bobBalance', getter: 'confidentialBalanceOf', args: [wiring.bob] },
      { name: 'carolBalance', getter: 'confidentialBalanceOf', args: [wiring.carol] },
      { name: 'totalSupply', getter: 'confidentialTotalSupply' },
    ],

    aclProbes: [
      // Balance handles: granted to the contract and the ACCOUNT — never to
      // an operator or an unrelated signer.
      { name: 'aliceBalance', getter: 'confidentialBalanceOf', args: [wiring.alice], account: 'self' },
      { name: 'aliceBalance', getter: 'confidentialBalanceOf', args: [wiring.alice], account: 0 },
      { name: 'aliceBalance', getter: 'confidentialBalanceOf', args: [wiring.alice], account: 2 },
      { name: 'bobBalance', getter: 'confidentialBalanceOf', args: [wiring.bob], account: 'self' },
      { name: 'bobBalance', getter: 'confidentialBalanceOf', args: [wiring.bob], account: 1 },
      { name: 'bobBalance', getter: 'confidentialBalanceOf', args: [wiring.bob], account: 0 },
      { name: 'bobBalance', getter: 'confidentialBalanceOf', args: [wiring.bob], account: 2 },
      { name: 'totalSupply', getter: 'confidentialTotalSupply', account: 'self' },
      { name: 'totalSupply', getter: 'confidentialTotalSupply', account: 0 },
    ],

    valueProbes: [
      { name: 'indicatedSupply', getter: 'totalSupply' },
      { name: 'indicatedAlice', getter: 'balanceOf', args: [wiring.alice] },
      { name: 'indicatedBob', getter: 'balanceOf', args: [wiring.bob] },
      { name: 'indicatedCarol', getter: 'balanceOf', args: [wiring.carol] },
      { name: 'indicatorTick', getter: 'indicatorTick' },
      { name: 'balanceOfIsIndicator', getter: 'balanceOfIsIndicator' },
      { name: 'carolIsOperatorForBob', getter: 'isOperator', args: [wiring.bob, wiring.carol] },
    ],
  };
}
