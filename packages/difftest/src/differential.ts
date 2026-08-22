import type { HardhatEthersSigner } from '@nomicfoundation/hardhat-ethers/signers';
import type { Contract, Signer } from 'ethers';

import type { MockEnvironment } from './mocks';
import { toHandle } from './mocks';

/**
 * HardhatEthersSigner is not a structural subtype of ethers 6.17 `Signer`
 * (`populateAuthorization` / `authorize` were added later). The harness only
 * calls `getAddress` and `Contract.connect`.
 */
export type AnySigner = Signer | HardhatEthersSigner;

/*
 * Differential execution.
 *
 * Run the same transaction sequence against two contracts that share the
 * ABI-relevant surface — normally `fhec`'s generated output and the
 * hand-written reference it must be equivalent to — and compare three things:
 *
 *   (a) the plaintexts behind designated encrypted-state getters, read out of
 *       MockTaskManager's `mockStorage`;
 *   (b) `isAllowed(handle, account)` for designated (getter, account) probes;
 *   (c) revert/success parity, step by step.
 *
 * Handles themselves are deliberately NOT compared. Ciphertext handles are
 * keccak hashes over operands and a salt, so two correct implementations can
 * produce different handles for the same value. Comparing handles would make
 * the harness fail on correct output.
 *
 * The two runs execute from an identical chain snapshot, so each side sees the
 * same nonces, the same mock salt, and the same block timestamps.
 */

// ---------------------------------------------------------------------------
// Scenario description
// ---------------------------------------------------------------------------

export interface StepContext {
  env: MockEnvironment;
  /** The contract this run is executing against. */
  contract: Contract;
  /** The address of that contract. */
  address: string;
  signers: AnySigner[];
  /** Address of the signer sending this step. */
  sender: string;
  side: RunSide;
  stepIndex: number;
}

/**
 * Arguments computed per run. Required for encrypted inputs: an `InEuintXX` is
 * bound to a sender and consumes a mock-verifier salt, so each side must mint
 * its own.
 */
export type ArgsFactory = (ctx: StepContext) => unknown[] | Promise<unknown[]>;

export interface Step {
  /** Contract function name. */
  fn: string;
  args?: unknown[] | ArgsFactory;
  /** Index into the signer list. Defaults to 0. */
  from?: number;
  value?: bigint;
  /**
   * Declare that this step must revert. `true` accepts any revert; a string
   * must be a substring of the revert key (custom error name or reason).
   */
  expectRevert?: boolean | string;
  /** Human-readable name for reports. Defaults to `fn`. */
  label?: string;
}

/** A view getter returning an encrypted handle; its plaintext is compared. */
export interface PlaintextProbe {
  name: string;
  getter: string;
  args?: unknown[];
  /** Signer index used to make the `view` call. Defaults to 0. */
  from?: number;
}

/** A view getter returning an encrypted handle; ACL state is compared. */
export interface AclProbe {
  name: string;
  getter: string;
  args?: unknown[];
  /** Signer index, a literal address, or `'self'` for the contract itself. */
  account: number | string;
  from?: number;
}

/** A plain (unencrypted) view getter; the returned value is compared as-is. */
export interface ValueProbe {
  name: string;
  getter: string;
  args?: unknown[];
  from?: number;
}

export interface Scenario {
  name: string;
  steps: Step[];
  plaintextProbes?: PlaintextProbe[];
  aclProbes?: AclProbe[];
  valueProbes?: ValueProbe[];
  /**
   * Snapshot the probes after every step instead of only at the end. Default
   * `true` — it costs a few extra view calls and localises a divergence to the
   * exact step that introduced it.
   */
  probeAfterEachStep?: boolean;
}

// ---------------------------------------------------------------------------
// Run results
// ---------------------------------------------------------------------------

export type RunSide = 'A' | 'B';

export interface StepOutcome {
  index: number;
  label: string;
  fn: string;
  reverted: boolean;
  /** Custom-error name, panic code, or revert reason. Compared across sides. */
  revertKey: string | null;
  /** Full decoded revert, including arguments. Reported, never compared. */
  revertDetail: string | null;
  /** False when `expectRevert` was declared and not honoured. */
  expectationMet: boolean;
  expectationNote: string | null;
}

export interface ProbeSnapshot {
  /** `'initial'`, or the label of the step this snapshot follows. */
  after: string;
  /** Probe name -> decimal plaintext, or `null` when the mock has none. */
  plaintexts: Record<string, string | null>;
  /** `"<probe>@<account>"` -> isAllowed. */
  acl: Record<string, boolean>;
  /** Probe name -> normalised plain value. */
  values: Record<string, string>;
  /** Probe name -> handle. Recorded for the report only; never compared. */
  handles: Record<string, string>;
}

export interface RunResult {
  side: RunSide;
  label: string;
  address: string;
  steps: StepOutcome[];
  snapshots: ProbeSnapshot[];
}

export type DivergenceKind = 'plaintext' | 'acl' | 'value' | 'revert' | 'expectation' | 'structure';

export interface Divergence {
  kind: DivergenceKind;
  /** Where it showed up, e.g. `step 2 (incrementCount) / plaintext "count"`. */
  where: string;
  a: string;
  b: string;
  message: string;
}

export interface DifferentialResult {
  scenario: string;
  a: RunResult;
  b: RunResult;
  divergences: Divergence[];
  equivalent: boolean;
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

function normaliseValue(value: unknown, selfAddress: string): string {
  if (value === null || value === undefined) return String(value);
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') {
    // The two sides live at different addresses; collapse self-references so a
    // getter returning `address(this)` is not a false divergence.
    if (value.toLowerCase() === selfAddress.toLowerCase()) return '<self>';
    return /^0x[0-9a-fA-F]+$/.test(value) ? value.toLowerCase() : value;
  }
  if (Array.isArray(value)) return `[${value.map((v) => normaliseValue(v, selfAddress)).join(', ')}]`;
  return JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
}

/**
 * Reduce an ethers error to a stable key plus a human-readable detail.
 *
 * The key deliberately excludes error arguments. Errors such as
 * `ACLNotAllowed(uint256 handle, address account)` carry a handle, and handles
 * legitimately differ between two correct implementations.
 */
function describeRevert(error: unknown): { key: string; detail: string } {
  const err = error as {
    revert?: { name?: string; args?: unknown[] } | null;
    reason?: string | null;
    shortMessage?: string;
    message?: string;
    code?: string;
  };

  // Errors declared by the contract under test: ethers decodes them.
  if (err?.revert?.name) {
    const args = (err.revert.args ?? []).map((a) => (typeof a === 'bigint' ? a.toString() : String(a)));
    return { key: err.revert.name, detail: `${err.revert.name}(${args.join(', ')})` };
  }

  const message = err?.shortMessage ?? err?.message ?? String(error);

  // Errors raised deeper down (MockTaskManager, MockACL) are not in the called
  // contract's ABI, so they arrive as Hardhat's rendered message instead.
  const named = /custom error '([A-Za-z_][A-Za-z0-9_]*)\(/.exec(message);
  if (named) return { key: named[1], detail: message };

  const panic = /panic code (0x[0-9a-fA-F]+)/.exec(message);
  if (panic) return { key: `Panic(${panic[1]})`, detail: message };

  if (typeof err?.reason === 'string' && err.reason.length > 0) {
    return { key: err.reason, detail: err.reason };
  }

  // Unrecognised custom error: the 4-byte selector still identifies it, and —
  // unlike the full return data — it carries no handles or addresses, so it is
  // safe to compare across two implementations.
  const raw = /(?:return data|data):\s*"?(0x[0-9a-fA-F]{8})/.exec(message);
  if (raw) return { key: `custom-error:${raw[1].toLowerCase()}`, detail: message };

  return { key: err?.code ?? 'UNKNOWN_REVERT', detail: message };
}

async function readProbes(
  env: MockEnvironment,
  contract: Contract,
  signers: AnySigner[],
  scenario: Scenario,
  after: string
): Promise<ProbeSnapshot> {
  const address = await contract.getAddress();
  const snapshot: ProbeSnapshot = { after, plaintexts: {}, acl: {}, values: {}, handles: {} };

  const call = async (getter: string, args: unknown[], from?: number) => {
    const connected = contract.connect(signers[from ?? 0]) as Contract;
    return connected[getter](...args);
  };

  for (const probe of scenario.plaintextProbes ?? []) {
    const handle = await call(probe.getter, probe.args ?? [], probe.from);
    snapshot.handles[probe.name] = toHandle(handle as never).toString();
    const plaintext = await env.getPlaintext(handle as never);
    snapshot.plaintexts[probe.name] = plaintext === null ? null : plaintext.toString();
  }

  for (const probe of scenario.aclProbes ?? []) {
    const handle = await call(probe.getter, probe.args ?? [], probe.from);
    const account =
      probe.account === 'self'
        ? address
        : typeof probe.account === 'number'
          ? await signers[probe.account].getAddress()
          : probe.account;
    const accountLabel = probe.account === 'self' ? 'self' : typeof probe.account === 'number' ? `signer${probe.account}` : probe.account;
    snapshot.acl[`${probe.name}@${accountLabel}`] = await env.isAllowed(handle as never, account);
  }

  for (const probe of scenario.valueProbes ?? []) {
    const value = await call(probe.getter, probe.args ?? [], probe.from);
    snapshot.values[probe.name] = normaliseValue(value, address);
  }

  return snapshot;
}

/**
 * Execute a scenario against one contract and capture every probe.
 *
 * Never throws on a contract revert: a revert is data, and the comparison
 * decides whether it is a divergence.
 */
export async function runScenario(
  env: MockEnvironment,
  contract: Contract,
  scenario: Scenario,
  options: { side?: RunSide; label?: string; signers?: AnySigner[] } = {}
): Promise<RunResult> {
  const side = options.side ?? 'A';
  const signers: AnySigner[] = options.signers ?? (await env.hre.ethers.getSigners());
  const address = await contract.getAddress();
  const probeEachStep = scenario.probeAfterEachStep !== false;

  const result: RunResult = {
    side,
    label: options.label ?? side,
    address,
    steps: [],
    snapshots: [],
  };

  result.snapshots.push(await readProbes(env, contract, signers, scenario, 'initial'));

  for (let index = 0; index < scenario.steps.length; index += 1) {
    const step = scenario.steps[index];
    const label = step.label ?? step.fn;
    const signer = signers[step.from ?? 0];
    const connected = contract.connect(signer) as Contract;

    const ctx: StepContext = {
      env,
      contract,
      address,
      signers,
      sender: await signer.getAddress(),
      side,
      stepIndex: index,
    };
    const args = typeof step.args === 'function' ? await step.args(ctx) : (step.args ?? []);
    const overrides = step.value === undefined ? [] : [{ value: step.value }];

    const outcome: StepOutcome = {
      index,
      label,
      fn: step.fn,
      reverted: false,
      revertKey: null,
      revertDetail: null,
      expectationMet: true,
      expectationNote: null,
    };

    try {
      const sent = await connected[step.fn](...args, ...overrides);
      if (sent && typeof (sent as { wait?: unknown }).wait === 'function') {
        await (sent as { wait: () => Promise<unknown> }).wait();
      }
    } catch (error) {
      const { key, detail } = describeRevert(error);
      outcome.reverted = true;
      outcome.revertKey = key;
      outcome.revertDetail = detail;
    }

    if (step.expectRevert !== undefined && step.expectRevert !== false) {
      if (!outcome.reverted) {
        outcome.expectationMet = false;
        outcome.expectationNote = 'expected a revert, the call succeeded';
      } else if (typeof step.expectRevert === 'string' && !(outcome.revertKey ?? '').includes(step.expectRevert)) {
        outcome.expectationMet = false;
        outcome.expectationNote = `expected revert matching "${step.expectRevert}", got "${outcome.revertKey}"`;
      }
    } else if (outcome.reverted) {
      outcome.expectationMet = false;
      outcome.expectationNote = `unexpected revert: ${outcome.revertDetail}`;
    }

    result.steps.push(outcome);

    if (probeEachStep || index === scenario.steps.length - 1) {
      result.snapshots.push(await readProbes(env, contract, signers, scenario, `step ${index} (${label})`));
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

function pushDivergence(
  out: Divergence[],
  kind: DivergenceKind,
  where: string,
  a: unknown,
  b: unknown,
  message: string
): void {
  out.push({ kind, where, a: String(a), b: String(b), message });
}

/** Compare two runs. An empty array means the two contracts are equivalent. */
export function compareRuns(a: RunResult, b: RunResult): Divergence[] {
  const divergences: Divergence[] = [];

  if (a.steps.length !== b.steps.length) {
    pushDivergence(
      divergences,
      'structure',
      'step count',
      a.steps.length,
      b.steps.length,
      'the two runs executed a different number of steps'
    );
  }

  const stepCount = Math.min(a.steps.length, b.steps.length);
  for (let i = 0; i < stepCount; i += 1) {
    const sa = a.steps[i];
    const sb = b.steps[i];
    const where = `step ${i} (${sa.label})`;

    if (sa.reverted !== sb.reverted) {
      pushDivergence(
        divergences,
        'revert',
        where,
        sa.reverted ? `reverted: ${sa.revertDetail}` : 'succeeded',
        sb.reverted ? `reverted: ${sb.revertDetail}` : 'succeeded',
        'revert/success parity broken'
      );
    } else if (sa.reverted && sa.revertKey !== sb.revertKey) {
      pushDivergence(divergences, 'revert', where, sa.revertDetail, sb.revertDetail, 'both reverted, but with different errors');
    }

    for (const [run, outcome] of [
      [a, sa],
      [b, sb],
    ] as const) {
      if (!outcome.expectationMet) {
        pushDivergence(
          divergences,
          'expectation',
          `${where} on ${run.label}`,
          run === a ? outcome.expectationNote : 'n/a',
          run === b ? outcome.expectationNote : 'n/a',
          `scenario expectation violated on ${run.label}: ${outcome.expectationNote}`
        );
      }
    }
  }

  if (a.snapshots.length !== b.snapshots.length) {
    pushDivergence(
      divergences,
      'structure',
      'snapshot count',
      a.snapshots.length,
      b.snapshots.length,
      'the two runs produced a different number of probe snapshots'
    );
  }

  const snapCount = Math.min(a.snapshots.length, b.snapshots.length);
  for (let i = 0; i < snapCount; i += 1) {
    const sa = a.snapshots[i];
    const sb = b.snapshots[i];
    const at = `after ${sa.after}`;

    const plaintextNames = new Set([...Object.keys(sa.plaintexts), ...Object.keys(sb.plaintexts)]);
    for (const name of plaintextNames) {
      const va = sa.plaintexts[name] ?? '<no plaintext>';
      const vb = sb.plaintexts[name] ?? '<no plaintext>';
      if (va !== vb) {
        pushDivergence(
          divergences,
          'plaintext',
          `${at} / plaintext "${name}"`,
          va,
          vb,
          `decrypted value of "${name}" differs`
        );
      }
    }

    const aclKeys = new Set([...Object.keys(sa.acl), ...Object.keys(sb.acl)]);
    for (const key of aclKeys) {
      const va = sa.acl[key];
      const vb = sb.acl[key];
      if (va !== vb) {
        pushDivergence(divergences, 'acl', `${at} / isAllowed ${key}`, va, vb, `ACL state for ${key} differs`);
      }
    }

    const valueNames = new Set([...Object.keys(sa.values), ...Object.keys(sb.values)]);
    for (const name of valueNames) {
      const va = sa.values[name];
      const vb = sb.values[name];
      if (va !== vb) {
        pushDivergence(divergences, 'value', `${at} / value "${name}"`, va, vb, `plain state "${name}" differs`);
      }
    }
  }

  return divergences;
}

/** Render a divergence list as an assertion message. */
export function formatDivergences(result: DifferentialResult): string {
  const { scenario, a, b, divergences } = result;
  const lines: string[] = [];
  lines.push(`Differential mismatch in scenario "${scenario}"`);
  lines.push(`  A = ${a.label} @ ${a.address}`);
  lines.push(`  B = ${b.label} @ ${b.address}`);
  lines.push(`  ${divergences.length} divergence(s):`);
  for (const d of divergences) {
    lines.push('');
    lines.push(`  [${d.kind}] ${d.where}`);
    lines.push(`      ${d.message}`);
    lines.push(`      A: ${d.a}`);
    lines.push(`      B: ${d.b}`);
  }
  return lines.join('\n');
}

export class DifferentialMismatchError extends Error {
  readonly result: DifferentialResult;

  constructor(result: DifferentialResult) {
    super(formatDivergences(result));
    this.name = 'DifferentialMismatchError';
    this.result = result;
  }
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

export interface DifferentialOptions {
  labelA?: string;
  labelB?: string;
  signers?: AnySigner[];
}

/**
 * Run `scenario` against both contracts from an identical chain snapshot and
 * compare the results.
 *
 * Snapshot discipline matters. Encrypted inputs derive their handle from a
 * salt held in MockZkVerifier, and any state the first run leaves behind would
 * otherwise leak into the second. Restoring between runs — and again at the end
 * — makes each run see the exact same starting chain.
 */
export async function runDifferential(
  env: MockEnvironment,
  contractA: Contract,
  contractB: Contract,
  scenario: Scenario,
  options: DifferentialOptions = {}
): Promise<DifferentialResult> {
  // Required lazily: hardhat-network-helpers reads the injected HRE on import.
  const { takeSnapshot } = await import('@nomicfoundation/hardhat-network-helpers');
  const snapshot = await takeSnapshot();

  const signers: AnySigner[] = options.signers ?? (await env.hre.ethers.getSigners());

  const a = await runScenario(env, contractA, scenario, {
    side: 'A',
    label: options.labelA ?? 'A',
    signers,
  });
  await snapshot.restore();

  const b = await runScenario(env, contractB, scenario, {
    side: 'B',
    label: options.labelB ?? 'B',
    signers,
  });
  await snapshot.restore();

  const divergences = compareRuns(a, b);
  return { scenario: scenario.name, a, b, divergences, equivalent: divergences.length === 0 };
}

/** `runDifferential`, but throws a formatted `DifferentialMismatchError`. */
export async function assertDifferentiallyEquivalent(
  env: MockEnvironment,
  contractA: Contract,
  contractB: Contract,
  scenario: Scenario,
  options: DifferentialOptions = {}
): Promise<DifferentialResult> {
  const result = await runDifferential(env, contractA, contractB, scenario, options);
  if (!result.equivalent) {
    throw new DifferentialMismatchError(result);
  }
  return result;
}
