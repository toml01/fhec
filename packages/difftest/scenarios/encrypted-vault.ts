import type { Scenario, StepContext } from '../src/differential';

/** Hand-derived plaintext expectations for the vault scenario. */
export const EXPECTED_FINAL_BALANCES = { holder: '70', recipient: '80' } as const;

export interface VaultScenarioWiring {
  /** signer0's address — the depositing / transferring account. */
  holder: string;
  /** signer1's address — the transfer recipient (also deposits once). */
  recipient: string;
  /** Per-side AuditorSink addresses, keyed by run side. */
  sink: { A: string; B: string };
}

/**
 * Scenario factory for the `EncryptedVaultDialect` pair. A factory rather than
 * a constant because the probes need concrete addresses and the rule-R2 step
 * needs a per-side sink (each side must call its own AuditorSink instance so
 * neither run observes the other's state).
 *
 * Coverage: mapping-slot updates through two sequential encrypted `if`s
 * (accepted and rejected transfers), R1 grants on both the sender-keyed and
 * the recipient-keyed slot (the FHE4001 case), R3 (encrypted return as a
 * transaction), R2 (transient grant to an external callee that actually uses
 * the handle), and plaintext revert parity for the self-transfer guard.
 *
 * A deliberate R1 semantic this pins down (issue #70): after a transfer, the
 * recipient's slot holds a NEW handle whose only grant is allowThis — the
 * recipient's slot is keyed by the recipient, not `msg.sender`, so its owner
 * is not provably the transferer, and the transferer must NOT gain read
 * access to it. The recipient also loses handle access until their next own
 * interaction. Both sides must agree on that; the test asserts it explicitly.
 */
export function makeEncryptedVaultScenario(wiring: VaultScenarioWiring): Scenario {
  /**
   * `deposit(externalEuint64 amount, bytes inputProof)` and
   * `transfer(address to, externalEuint64 amount, bytes inputProof)`: the
   * handle sits in the encrypted parameter's own position, the batch signature
   * is always the trailing argument. Minted per run, because the signature
   * binds the input to the consuming contract (`ctx.address`).
   */
  const amountArgs = async (ctx: StepContext, amount: number, leading: unknown[] = []): Promise<unknown[]> => {
    const input = await ctx.env.encryptInput(amount, 'euint64', ctx.sender, ctx.address);
    return [...leading, input.handle, input.signature];
  };

  return {
    name: 'EncryptedVaultDialect: deposits, guarded transfers, R2/R3 grants',

    steps: [
      {
        fn: 'deposit',
        label: 'holder deposits 100',
        args: async (ctx) => amountArgs(ctx, 100),
      },
      {
        fn: 'deposit',
        from: 1,
        label: 'recipient deposits 50',
        args: async (ctx) => amountArgs(ctx, 50),
      },
      {
        fn: 'transfer',
        label: 'transfer 30 (sufficient balance; both slots move)',
        args: async (ctx) => amountArgs(ctx, 30, [wiring.recipient]),
      },
      {
        fn: 'transfer',
        label: 'transfer 500 (insufficient; select keeps both pre-values)',
        args: async (ctx) => amountArgs(ctx, 500, [wiring.recipient]),
      },
      {
        fn: 'transfer',
        label: 'self-transfer (plaintext guard)',
        args: async (ctx) => amountArgs(ctx, 5, [ctx.sender]),
        expectRevert: 'SelfTransfer',
      },
      {
        fn: 'getBalance',
        label: 'getBalance as a transaction (rule R3 transient grant)',
      },
      {
        fn: 'reportBalance',
        label: 'reportBalance to the auditor sink (rule R2 transient grant)',
        args: async (ctx) => [wiring.sink[ctx.side]],
      },
    ],

    plaintextProbes: [
      { name: 'holderBalance', getter: 'balanceOf', args: [wiring.holder] },
      { name: 'recipientBalance', getter: 'balanceOf', args: [wiring.recipient] },
    ],

    aclProbes: [
      // R1 on the sender-keyed slot.
      { name: 'holderBalance', getter: 'balanceOf', args: [wiring.holder], account: 'self' },
      { name: 'holderBalance', getter: 'balanceOf', args: [wiring.holder], account: 0 },
      // Unrelated account: must stay denied.
      { name: 'holderBalance', getter: 'balanceOf', args: [wiring.holder], account: 2 },
      // R1 on the recipient-keyed slot (the FHE4001 warning case): after a
      // transfer the only grant is to the contract — the transferer is not
      // provably the recipient's owner, so the sender grant is withheld.
      { name: 'recipientBalance', getter: 'balanceOf', args: [wiring.recipient], account: 'self' },
      { name: 'recipientBalance', getter: 'balanceOf', args: [wiring.recipient], account: 0 },
      { name: 'recipientBalance', getter: 'balanceOf', args: [wiring.recipient], account: 1 },
    ],
  };
}
