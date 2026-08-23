import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";

import type { HardhatRuntimeEnvironment } from "hardhat/types";
import { HardhatPluginError } from "hardhat/plugins";

import { resolveTomlPath } from "./toml";
import { PLUGIN_NAME } from "./types";
import { readInstalledCofheVersion, versionSatisfies } from "./version";

const nodeRequire = createRequire(__filename);

interface ResolveModule {
  resolveBinary: () => { binaryPath: string };
}

/**
 * Runs `fhec build` in the Hardhat project, optionally checking the installed
 * `@fhenixprotocol/cofhe-contracts` version (FHE5003).
 */
export function runFhecBuild(hre: HardhatRuntimeEnvironment): void {
  const fhec = hre.config.fhec;
  if (!fhec.enabled) {
    return;
  }

  const projectRoot = hre.config.paths.root;
  const tomlPath = resolveExistingToml(projectRoot, fhec.config, fhec.tomlPath);

  let binaryPath: string;
  try {
    ({ binaryPath } = (nodeRequire("fhec/resolve") as ResolveModule).resolveBinary());
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new HardhatPluginError(PLUGIN_NAME, message);
  }

  assertCofheVersion(projectRoot, fhec.profileVersion);

  const args = ["build"];
  if (!fhec.verify) {
    args.push("--no-verify");
  }
  if (fhec.acl !== undefined) {
    args.push(`--acl=${fhec.acl}`);
  }
  args.push("--config", tomlPath);

  const result = spawnSync(binaryPath, args, {
    cwd: projectRoot,
    stdio: "inherit",
  });

  if (result.error !== undefined) {
    throw new HardhatPluginError(
      PLUGIN_NAME,
      `failed to run ${binaryPath}: ${result.error.message}`,
    );
  }
  if (result.signal !== null && result.signal !== undefined) {
    throw new HardhatPluginError(
      PLUGIN_NAME,
      `fhec build terminated by signal ${result.signal}`,
    );
  }
  if (result.status !== 0) {
    throw new HardhatPluginError(PLUGIN_NAME, "fhec build failed");
  }
}

function resolveExistingToml(
  projectRoot: string,
  explicit: string | undefined,
  cached: string | undefined,
): string {
  if (cached !== undefined && existsSync(cached)) {
    return cached;
  }
  const found = resolveTomlPath(projectRoot, explicit);
  if (found === undefined || !existsSync(found)) {
    throw new HardhatPluginError(
      PLUGIN_NAME,
      "No fhec.toml found. Run `fhec init` to create one, or set `fhec.enabled: false` in your Hardhat config.",
    );
  }
  return found;
}

function assertCofheVersion(projectRoot: string, profileVersion: string): void {
  const installed = readInstalledCofheVersion(projectRoot);
  if (installed === undefined) {
    return;
  }
  if (versionSatisfies(profileVersion, installed)) {
    return;
  }
  throw new HardhatPluginError(
    PLUGIN_NAME,
    `Installed @fhenixprotocol/cofhe-contracts@${installed} does not satisfy the pinned profile version ${profileVersion} (FHE5003).`,
  );
}
