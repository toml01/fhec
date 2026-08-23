import type { Scenario } from '../src/differential';

/** Value both counters are constructed with. */
export const INITIAL_COUNT = 5;

/** Value pushed through `setCount` as a verified `externalEuint32` + proof. */
export const SET_COUNT_VALUE = 1000;

/**
 * Expected final plaintext of `count`, derived by hand:
 *   5 -> 6 -> 7 -> (non-owner increment reverts, still 7)
 *     -> 1000 (setCount) -> 1001 (increment).
 *
 * The harness never needs this number — it compares the two runs against each
 * other, not against an oracle. The tests assert it anyway, so that a scenario
 * which silently stops doing anything cannot pass as "equivalent".
 */
export const EXPECTED_FINAL_COUNT = '1001';

/**
 * Scenario for the `EncryptedCounter` fixture pair.
 *
 * It deliberately exercises all three comparison axes:
 *   - plaintext: `count` changes through a trivial encrypt, an FHE.add, and a
 *     verified encrypted input;
 *   - ACL: `allowThis` / `allowSender` after every write, then `allowPublic`,
 *     which must flip an unrelated account from denied to allowed;
 *   - revert parity: one owner-gated call from the wrong sender, and one
 *     decrypt verification with a malformed signature.
 */
export const encryptedCounterScenario: Scenario = {
  name: 'EncryptedCounter: increment, encrypted set, public allow, bad reveal',

  steps: [
    { fn: 'incrementCount', label: 'increment #1' },
    { fn: 'incrementCount', label: 'increment #2' },

    // Owner gate. The error is declared on the counter itself, so ethers
    // decodes it and both sides must reject identically.
    {
      fn: 'incrementCount',
      from: 1,
      label: 'increment as non-owner',
      expectRevert: 'OnlyOwnerAllowed',
    },

    // Encrypted input. Args are built per run: the verifier signature is bound
    // to the sender AND to the consuming contract (`ctx.address`, which differs
    // per side), and minting consumes a salt inside MockZkVerifier — so each
    // side mints its own even though both encode the same plaintext.
    {
      fn: 'setCount',
      label: 'setCount(encrypted 1000)',
      args: async (ctx) => {
        const input = await ctx.env.encryptInput(SET_COUNT_VALUE, 'euint32', ctx.sender, ctx.address);
        return [input.handle, input.signature];
      },
    },

    { fn: 'incrementCount', label: 'increment #3' },

    // FHE.allowPublic: after this, isAllowed must be true for every account.
    { fn: 'allowCountPublicly', label: 'allowCountPublicly' },

    // Reverts inside MockTaskManager, not in the counter's own ABI. Exercises
    // the harness's fallback revert-key extraction.
    {
      fn: 'revealCount',
      label: 'revealCount with a malformed signature',
      args: [1001, '0x'],
      expectRevert: 'InvalidSignature',
    },
  ],

  plaintextProbes: [{ name: 'count', getter: 'getCount' }],

  aclProbes: [
    // The contract itself: FHE.allowThis.
    { name: 'count', getter: 'getCount', account: 'self' },
    // The owner: FHE.allowSender. This probe is what catches a dropped R1 grant.
    { name: 'count', getter: 'getCount', account: 0 },
    // An unrelated account: must stay denied until allowCountPublicly runs.
    { name: 'count', getter: 'getCount', account: 2 },
  ],

  valueProbes: [
    { name: 'owner', getter: 'owner' },
    { name: 'decrypted', getter: 'decrypted' },
    { name: 'decryptedCount', getter: 'decryptedCount' },
  ],
};
