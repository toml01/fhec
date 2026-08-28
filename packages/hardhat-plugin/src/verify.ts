import type { HardhatRuntimeEnvironment, RunTaskFunction, TaskArguments, TaskIdentifier } from "hardhat/types";

import { translateFsolFqn } from "./fqn";
import { loadManifest } from "./remap";

/**
 * `@nomicfoundation/hardhat-verify`'s subtask name. Kept as a literal
 * because we cannot depend on that (optional, third-party) package's own
 * exported constant.
 */
const TASK_VERIFY_VERIFY = "verify:verify";

function taskNameOf(identifier: TaskIdentifier): string | undefined {
  if (typeof identifier === "string") {
    return identifier;
  }
  if (
    typeof identifier === "object" &&
    identifier !== null &&
    typeof identifier.task === "string" &&
    identifier.scope === undefined
  ) {
    return identifier.task;
  }
  return undefined;
}

/**
 * Translates `args.contract` — a `path:Contract` fully-qualified name — from
 * the fhec source path to the generated path, when it names a `.fsol` file
 * the manifest knows about. Etherscan (or another block explorer) must
 * receive the source that actually produced the bytecode, which is the
 * generated `.sol`, so this direction is deliberate. Anything we cannot
 * confidently translate is passed through untouched.
 */
function translateVerifyArgs(hre: HardhatRuntimeEnvironment, args: TaskArguments): TaskArguments {
  if (args === undefined || args === null || typeof args !== "object" || typeof args.contract !== "string") {
    return args;
  }
  const fhec = hre.config.fhec;
  if (!fhec.enabled) {
    return args;
  }
  const manifest = loadManifest(hre.config.paths.sources);
  if (manifest === undefined) {
    return args;
  }
  const translated = translateFsolFqn(args.contract, fhec.srcDir, fhec.outDir, manifest);
  if (translated === undefined) {
    return args;
  }
  return { ...args, contract: translated };
}

/**
 * Wraps `hre.run` so a call that targets `verify:verify` — whether from
 * `npx hardhat verify` (which calls it internally) or a script's own
 * `hre.run("verify:verify", ...)` — has its `args.contract` translated.
 *
 * This wraps `hre.run` itself, not the task definition, so it does not
 * depend on whether `@fhec/hardhat-plugin` or `@nomicfoundation/hardhat-verify`
 * is `require`d first in the user's Hardhat config: task registration (and
 * so require order) only matters for `task()`/`subtask()` calls, and those
 * are all resolved by the time any `extendEnvironment` callback (this one
 * included) runs. If the task the third-party plugin defines is absent —
 * that plugin is not installed, or the user's version does not register it
 * under this name — nothing is registered: there would be nothing for a
 * broken override's `runSuper` to call.
 */
export function installVerifyOverride(hre: HardhatRuntimeEnvironment): void {
  if (!hre.config.fhec.enabled) {
    return;
  }
  if (hre.tasks[TASK_VERIFY_VERIFY] === undefined) {
    return;
  }

  const original: RunTaskFunction = hre.run;
  const wrapped: RunTaskFunction = (taskIdentifier, taskArguments, subtaskArguments) => {
    const args =
      taskNameOf(taskIdentifier) === TASK_VERIFY_VERIFY
        ? translateVerifyArgs(hre, taskArguments)
        : taskArguments;
    return original(taskIdentifier, args, subtaskArguments);
  };
  (hre as { run: RunTaskFunction }).run = wrapped;
}
