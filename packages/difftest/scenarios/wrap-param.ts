import type { Scenario } from '../src/differential';

/**
 * Scenario for the issue #103 regression pair: `WrapParamDialect` (fhec
 * output) vs `WrapParamDialectRef` (hand-written oracle).
 *
 * The heart of the test is step 1: before the initialization guard, the
 * transpiled side reverted with `SenderNotAllowed` on `reset()` — the
 * inserted `FHE.allowThis` ran on a `.wrap`-derived zero handle that carries
 * no CoFHE permission for anyone. With the guard, both sides succeed, skip
 * the grant, and stay differentially equivalent.
 */
export const wrapParamScenario: Scenario = {
  name: 'WrapParamDialect: wrap-derived sentinel through a parameter (issue #103)',

  steps: [
    {
      fn: 'reset',
      label: 'reset to the wrap-derived zero sentinel (must NOT revert)',
    },
    {
      fn: 'getSpent',
      label: 'getSpent on the zero sentinel (guarded R3 grant must skip, not revert)',
    },
    {
      fn: 'bump',
      label: 'bump to an initialized handle (guard passes, grant lands)',
      args: async () => [7n],
    },
    {
      fn: 'getSpent',
      label: 'getSpent on the initialized handle (R3 grant fires)',
    },
    {
      fn: 'reset',
      label: 'reset again after a real value (back to the sentinel, still no revert)',
    },
  ],

  plaintextProbes: [{ name: 'spent', getter: 'spent' }],

  aclProbes: [
    // R1 allowThis: false while `spent` is the zero sentinel, true after bump.
    { name: 'spent', getter: 'spent', account: 'self' },
    // `spent` is a simple state variable (no key), so the sender grant is
    // withheld (FHE4001) — the caller must stay denied even after bump.
    { name: 'spent', getter: 'spent', account: 0 },
  ],
};
