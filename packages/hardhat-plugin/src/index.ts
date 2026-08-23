import { existsSync } from "node:fs";
import path from "node:path";

import {
  TASK_COMPILE,
  TASK_COMPILE_SOLIDITY_RUN_SOLC,
  TASK_COMPILE_SOLIDITY_RUN_SOLCJS,
} from "hardhat/builtin-tasks/task-names";
import { extendConfig, subtask, task } from "hardhat/config";
import { HardhatPluginError } from "hardhat/plugins";
import type { HardhatConfig, HardhatUserConfig } from "hardhat/types";

import { runFhecBuild } from "./build";
import { loadManifest, remapSolcOutput, type RemapContext } from "./remap";
import { loadFhecToml, resolveTomlPath } from "./toml";
import {
  DEFAULT_OUT,
  DEFAULT_PROFILE_VERSION,
  DEFAULT_SRC,
  PLUGIN_NAME,
  type FhecConfig,
} from "./types";

import "./type-extensions";

export type { FhecConfig, FhecUserConfig, ParsedFhecToml } from "./types";
export { parseFhecToml, findConfig, resolveTomlPath } from "./toml";
export { remapRange, matchManifestFile, displaySourcePath, remapSolcOutput } from "./remap";
export { versionSatisfies, parseSemver } from "./version";

extendConfig((config: HardhatConfig, userConfig: Readonly<HardhatUserConfig>) => {
  const user = userConfig.fhec ?? {};
  const resolved: FhecConfig = {
    enabled: user.enabled ?? true,
    verify: user.verify ?? false,
    acl: user.acl,
    config: user.config,
    srcDir: DEFAULT_SRC,
    outDir: DEFAULT_OUT,
    profileVersion: DEFAULT_PROFILE_VERSION,
  };

  if (resolved.enabled) {
    const tomlPath = resolveTomlPath(config.paths.root, resolved.config);
    if (tomlPath !== undefined && existsSync(tomlPath)) {
      let parsed;
      try {
        parsed = loadFhecToml(tomlPath);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        throw new HardhatPluginError(
          PLUGIN_NAME,
          `invalid fhec.toml at ${tomlPath}: ${message}`,
        );
      }
      resolved.tomlPath = tomlPath;
      resolved.srcDir = parsed.src;
      resolved.outDir = parsed.out;
      resolved.profileVersion = parsed.version;
      config.paths.sources = path.resolve(config.paths.root, parsed.out);
    }
  }

  config.fhec = resolved;
});

task(TASK_COMPILE, async (args, hre, runSuper) => {
  runFhecBuild(hre);
  return runSuper(args);
});

function remapAfterSolc(output: unknown, hre: { config: HardhatConfig }): unknown {
  const fhec = hre.config.fhec;
  if (!fhec.enabled) {
    return output;
  }
  const manifest = loadManifest(hre.config.paths.sources);
  if (manifest === undefined) {
    return output;
  }
  const ctx: RemapContext = {
    manifest,
    outDir: fhec.outDir,
    srcDir: fhec.srcDir,
    projectRoot: hre.config.paths.root,
    sourcesDir: hre.config.paths.sources,
  };
  return remapSolcOutput(output as { errors?: never[] }, ctx);
}

subtask(TASK_COMPILE_SOLIDITY_RUN_SOLC, async (args, hre, runSuper) => {
  const output: unknown = await runSuper(args);
  return remapAfterSolc(output, hre);
});

subtask(TASK_COMPILE_SOLIDITY_RUN_SOLCJS, async (args, hre, runSuper) => {
  const output: unknown = await runSuper(args);
  return remapAfterSolc(output, hre);
});
