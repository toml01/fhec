import type { Scenario } from '../src/differential';

/** Constructor args shared by the dialect pair: initial count and the cap. */
export const INITIAL_COUNT = 5;
export const CAP = 1000;

/**
 * Expected final plaintext, derived by hand:
 *   5 → +10 = 15 (within cap) → +1 = 16 → +984 = 1000 (== cap, `lte` accepts)
 *     → +1 would be 1001 > cap, select keeps 1000
 *     → non-owner increment reverts, still 1000.
 *
 * The differential comparison never needs this number; the tests assert it so
 * a scenario that silently stops doing anything cannot pass as "equivalent".
 */
export const EXPECTED_FINAL_COUNT = '1000';

/**
 * Scenario for the first transpiled pair: `EncryptedCounterDialect`
 * (fhec output) vs `EncryptedCounterDialectRef` (hand-written oracle).
 *
 * Exercises the encrypted-if boundary from both sides (below / exactly at /
 * above the cap), the literal-encrypt path, the R1 grants after the select
 * merge, and owner-gate revert parity.
 */
export const encryptedCounterDialectScenario: Scenario = {
  name: 'EncryptedCounterDialect: capped increments across the boundary',

  steps: [
    {
      fn: 'increment',
      label: 'increment by 10 (below cap)',
      args: async (ctx) => [await ctx.env.encryptInput(10, 'euint32', ctx.sender)],
    },
    { fn: 'incrementByOne', label: 'incrementByOne (literal lowering)' },
    {
      fn: 'increment',
      label: 'increment by 984 (lands exactly on the cap; lte accepts)',
      args: async (ctx) => [await ctx.env.encryptInput(984, 'euint32', ctx.sender)],
    },
    {
      fn: 'increment',
      label: 'increment by 1 (would exceed cap; select keeps the old value)',
      args: async (ctx) => [await ctx.env.encryptInput(1, 'euint32', ctx.sender)],
    },
    {
      fn: 'incrementByOne',
      from: 1,
      label: 'increment as non-owner',
      expectRevert: 'OnlyOwnerAllowed',
    },
  ],

  plaintextProbes: [{ name: 'count', getter: 'getCount' }],

  aclProbes: [
    // FHE.allowThis — inserted by rule R1 after the select merge.
    { name: 'count', getter: 'getCount', account: 'self' },
    // FHE.allowSender — the R1 grant this harness exists to catch when dropped.
    { name: 'count', getter: 'getCount', account: 0 },
    // Unrelated account: must stay denied throughout.
    { name: 'count', getter: 'getCount', account: 2 },
  ],

  valueProbes: [{ name: 'owner', getter: 'owner' }],
};
