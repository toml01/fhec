import type { Scenario } from '../src/differential';

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
 * A deliberate R1 semantic this pins down: after a transfer, the recipient's
 * slot holds a NEW handle whose grants are allowThis + allowSender(transferer)
 * — the recipient loses handle access until their next own interaction. Both
 * sides must agree on that; the test asserts it explicitly.
 */
export function makeEncryptedVaultScenario(wiring: VaultScenarioWiring): Scenario {
  return {
    name: 'EncryptedVaultDialect: deposits, guarded transfers, R2/R3 grants',

    steps: [
      {
        fn: 'deposit',
        label: 'holder deposits 100',
        args: async (ctx) => [await ctx.env.encryptInput(100, 'euint64', ctx.sender)],
      },
      {
        fn: 'deposit',
        from: 1,
        label: 'recipient deposits 50',
        args: async (ctx) => [await ctx.env.encryptInput(50, 'euint64', ctx.sender)],
      },
      {
        fn: 'transfer',
        label: 'transfer 30 (sufficient balance; both slots move)',
        args: async (ctx) => [wiring.recipient, await ctx.env.encryptInput(30, 'euint64', ctx.sender)],
      },
      {
        fn: 'transfer',
        label: 'transfer 500 (insufficient; select keeps both pre-values)',
        args: async (ctx) => [wiring.recipient, await ctx.env.encryptInput(500, 'euint64', ctx.sender)],
      },
      {
        fn: 'transfer',
        label: 'self-transfer (plaintext guard)',
        args: async (ctx) => [ctx.sender, await ctx.env.encryptInput(5, 'euint64', ctx.sender)],
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
      // transfer the grants go to the contract and the *transferer*.
      { name: 'recipientBalance', getter: 'balanceOf', args: [wiring.recipient], account: 'self' },
      { name: 'recipientBalance', getter: 'balanceOf', args: [wiring.recipient], account: 0 },
      { name: 'recipientBalance', getter: 'balanceOf', args: [wiring.recipient], account: 1 },
    ],
  };
}
