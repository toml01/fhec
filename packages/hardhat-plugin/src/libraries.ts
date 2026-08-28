import type { HardhatRuntimeEnvironment } from "hardhat/types";

import { translateFsolFqn } from "./fqn";
import { loadManifest } from "./remap";
import type { Manifest } from "./types";

/**
 * `hardhat-ethers` methods whose `FactoryOptions` (or `DeployContractOptions`)
 * may include a `libraries` map. Keys of that map are matched against solc
 * `linkReferences`, which use the generated `.sol` source name — so a `.fsol`
 * fully-qualified name has to be translated before it reaches them.
 */
const LIBRARY_METHODS: ReadonlySet<string> = new Set([
  "getContractFactory",
  "getContractFactoryFromArtifact",
  "deployContract",
]);

const WRAPPED = Symbol.for("@fhec/hardhat-plugin.wrapEthers");

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Translates `.fsol` keys in a `libraries` link map to the generated `.sol`
 * fully-qualified names recorded in the manifest. Other keys — bare library
 * names, `generated/*.sol` FQNs, unknown paths — are left unchanged.
 *
 * Returns the original object when nothing changed. If both a `.fsol` key and
 * its generated form are present, the generated entry is kept (same "do not
 * clobber" rule as `solidity.overrides` rewriting).
 */
export function translateLibrariesMap(
  libraries: Record<string, unknown>,
  srcDir: string,
  outDir: string,
  manifest: Manifest | undefined,
): Record<string, unknown> {
  if (manifest === undefined) {
    return libraries;
  }

  let changed = false;
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(libraries)) {
    const next = translateFsolFqn(key, srcDir, outDir, manifest) ?? key;
    if (next !== key) {
      changed = true;
    }
    if (next !== key && Object.prototype.hasOwnProperty.call(out, next)) {
      continue;
    }
    out[next] = value;
  }
  return changed ? out : libraries;
}

/**
 * If `value` looks like hardhat-ethers `FactoryOptions` / `DeployContractOptions`
 * (a plain object with a `libraries` map, not a Signer), rewrite `.fsol` keys
 * in that map. Anything else is returned as-is.
 *
 * A Signer is detected the same way hardhat-ethers does: `"provider" in value`.
 */
export function translateFactoryOptionsArg(
  hre: HardhatRuntimeEnvironment,
  value: unknown,
): unknown {
  if (!isRecord(value) || !isRecord(value.libraries)) {
    return value;
  }
  if ("provider" in value) {
    return value;
  }
  const fhec = hre.config.fhec;
  if (!fhec.enabled) {
    return value;
  }
  const manifest = loadManifest(hre.config.paths.sources);
  const libraries = translateLibrariesMap(
    value.libraries,
    fhec.srcDir,
    fhec.outDir,
    manifest,
  );
  if (libraries === value.libraries) {
    return value;
  }
  return { ...value, libraries };
}

function wrapEthers(hre: HardhatRuntimeEnvironment, ethers: object): object {
  if (WRAPPED in ethers) {
    return ethers;
  }
  return new Proxy(ethers, {
    get(target, prop, receiver) {
      if (prop === WRAPPED) {
        return true;
      }
      if (typeof prop === "string" && LIBRARY_METHODS.has(prop)) {
        const fn = Reflect.get(target, prop, receiver);
        if (typeof fn === "function") {
          return (...args: unknown[]) =>
            fn.call(
              target,
              ...args.map((arg) => translateFactoryOptionsArg(hre, arg)),
            );
        }
      }
      const value = Reflect.get(target, prop, receiver);
      return typeof value === "function" ? value.bind(target) : value;
    },
    has(target, prop) {
      return prop === WRAPPED || Reflect.has(target, prop);
    },
  });
}

type HreWithEthers = HardhatRuntimeEnvironment & { ethers?: unknown };

/**
 * Wraps `hre.ethers` so `getContractFactory`, `getContractFactoryFromArtifact`,
 * and `deployContract` translate `.fsol` keys in their `libraries` map before
 * `hardhat-ethers` validates them against `linkReferences`.
 *
 * This intercepts assignment of `hre.ethers`, not a task definition, so it
 * does not depend on whether `@fhec/hardhat-plugin` or `@nomicfoundation/hardhat-ethers`
 * is `require`d first: `extendEnvironment` callbacks run after every plugin has
 * registered, but they still run in require order, and `hardhat-ethers` assigns
 * `hre.ethers` from its own callback. A getter/setter on the property catches
 * that assignment either before or after this function runs. If hardhat-ethers
 * is not installed, the property stays unset until something assigns it.
 */
export function installLibrariesTranslation(hre: HardhatRuntimeEnvironment): void {
  if (!hre.config.fhec.enabled) {
    return;
  }

  const env = hre as HreWithEthers;
  const descriptor = Object.getOwnPropertyDescriptor(env, "ethers");
  let current: unknown = env.ethers;

  const wrapIfObject = (value: unknown): unknown => {
    if (value === undefined || value === null || typeof value !== "object") {
      return value;
    }
    return wrapEthers(hre, value);
  };

  if (current !== undefined) {
    current = wrapIfObject(current);
  }

  Object.defineProperty(env, "ethers", {
    configurable: true,
    enumerable: descriptor?.enumerable ?? true,
    get() {
      return current;
    },
    set(value: unknown) {
      current = wrapIfObject(value);
    },
  });
}
