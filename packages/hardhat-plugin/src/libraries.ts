import type { EnvironmentExtender, HardhatRuntimeEnvironment } from "hardhat/types";

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

/**
 * Outer proxies created by {@link wrapEthers}. Used instead of an `in` check
 * on the wrapped object: `hre.ethers` is a `lazyObject` Proxy whose `has`
 * trap forces construction.
 */
const wrappedEthers = new WeakSet<object>();

/**
 * Environment extenders already replaced by
 * {@link wrapRemainingEnvironmentExtenders}. The wrapper is stored too so a
 * second install in the same process does not stack wrappers.
 */
const wrappedEnvironmentExtenders = new WeakSet<EnvironmentExtender>();

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

/**
 * Index of the `signerOrOptions` slot for each wrapped method, matching
 * `@nomicfoundation/hardhat-ethers` 3.x:
 * - `getContractFactory(name, signerOrOptions?)` — not the ABI+bytecode form
 * - `getContractFactoryFromArtifact(artifact, signerOrOptions?)`
 * - `deployContract(name, args?, signerOrOptions?)` — options are arg 1 unless
 *   arg 1 is the constructor-args array, in which case they are arg 2
 */
function factoryOptionsArgIndex(method: string, args: unknown[]): number | undefined {
  switch (method) {
    case "getContractFactory":
      return typeof args[0] === "string" ? 1 : undefined;
    case "getContractFactoryFromArtifact":
      return 1;
    case "deployContract":
      return Array.isArray(args[1]) ? 2 : 1;
    default:
      return undefined;
  }
}

function translateMethodArgs(hre: HardhatRuntimeEnvironment, method: string, args: unknown[]): unknown[] {
  const index = factoryOptionsArgIndex(method, args);
  if (index === undefined || index >= args.length) {
    return args;
  }
  const translated = translateFactoryOptionsArg(hre, args[index]);
  if (translated === args[index]) {
    return args;
  }
  const next = args.slice();
  next[index] = translated;
  return next;
}

function wrapEthers(hre: HardhatRuntimeEnvironment, ethers: object): object {
  if (wrappedEthers.has(ethers)) {
    return ethers;
  }
  const proxy = new Proxy(ethers, {
    get(target, prop, receiver) {
      if (typeof prop === "string" && LIBRARY_METHODS.has(prop)) {
        const fn = Reflect.get(target, prop, receiver);
        if (typeof fn === "function") {
          return (...args: unknown[]) => fn.apply(target, translateMethodArgs(hre, prop, args));
        }
      }
      return Reflect.get(target, prop, receiver);
    },
  });
  wrappedEthers.add(proxy);
  return proxy;
}

type HreWithEthers = HardhatRuntimeEnvironment & { ethers?: unknown };

function wrapIfObject(hre: HardhatRuntimeEnvironment, value: unknown): unknown {
  if (value === undefined || value === null || typeof value !== "object") {
    return value;
  }
  return wrapEthers(hre, value);
}

function readOwnEthers(env: HreWithEthers): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(env, "ethers");
  if (descriptor === undefined) {
    return undefined;
  }
  if (descriptor.get !== undefined) {
    return descriptor.get.call(env);
  }
  return descriptor.value;
}

/**
 * Replaces `hre.ethers` with a getter/setter that wraps the current value and
 * any later assignment. Caller must only invoke this when the property already
 * exists, or in unit tests that simulate a later `hre.ethers = …` assignment.
 */
function installEthersAccessor(hre: HardhatRuntimeEnvironment, env: HreWithEthers): void {
  const descriptor = Object.getOwnPropertyDescriptor(env, "ethers");
  let current: unknown = wrapIfObject(hre, readOwnEthers(env));

  Object.defineProperty(env, "ethers", {
    configurable: true,
    enumerable: descriptor?.enumerable ?? true,
    get() {
      return current;
    },
    set(value: unknown) {
      current = wrapIfObject(hre, value);
    },
  });
}

function isExtenderArray(value: unknown): value is EnvironmentExtender[] {
  return Array.isArray(value);
}

/**
 * The extender list the Environment constructor is iterating. Hardhat 2
 * assigns the same array to `this._environmentExtenders` (a TypeScript
 * `private` field, still present at runtime) and walks it with `forEach`.
 */
function environmentExtendersOf(hre: HardhatRuntimeEnvironment): EnvironmentExtender[] | undefined {
  const fromHre = (hre as { _environmentExtenders?: unknown })._environmentExtenders;
  if (isExtenderArray(fromHre)) {
    return fromHre;
  }
  try {
    const { HardhatContext } = require("hardhat/internal/context") as {
      HardhatContext: {
        getHardhatContext: () => { environmentExtenders: unknown };
      };
    };
    const fromCtx = HardhatContext.getHardhatContext().environmentExtenders;
    if (isExtenderArray(fromCtx)) {
      return fromCtx;
    }
  } catch {
    // No Hardhat context (unit tests).
  }
  return undefined;
}

/**
 * If hardhat-ethers has not assigned `hre.ethers` yet, wrap the remaining
 * `environmentExtenders` in place so we install the accessor after a later
 * plugin assigns it — without pre-defining `ethers` (which would make
 * `'ethers' in hre` true).
 *
 * Hardhat 2 walks that array with `Array.prototype.forEach`, which does
 * not visit elements pushed during the loop. Replacing later slots is
 * visible to the in-flight `forEach`; pushing is not. There is no
 * "run after every extender" hook.
 */
function wrapRemainingEnvironmentExtenders(hre: HardhatRuntimeEnvironment): boolean {
  const extenders = environmentExtendersOf(hre);
  if (extenders === undefined) {
    return false;
  }
  for (let i = 0; i < extenders.length; i++) {
    const original = extenders[i];
    if (typeof original !== "function" || wrappedEnvironmentExtenders.has(original)) {
      continue;
    }
    const wrapped: EnvironmentExtender = (later) => {
      original(later);
      if (!Object.prototype.hasOwnProperty.call(later, "ethers")) {
        return;
      }
      installEthersAccessor(later, later as HreWithEthers);
    };
    wrappedEnvironmentExtenders.add(original);
    wrappedEnvironmentExtenders.add(wrapped);
    extenders[i] = wrapped;
  }
  return true;
}

/**
 * Wraps `hre.ethers` so `getContractFactory`, `getContractFactoryFromArtifact`,
 * and `deployContract` translate `.fsol` keys in their `libraries` map before
 * `hardhat-ethers` validates them against `linkReferences`.
 *
 * Only those three methods are wrapped. The rest of the ethers namespace
 * (`Contract`, `Interface`, `Wallet`, …) is forwarded unchanged: binding
 * constructors breaks statics (`Interface.from`, `Wallet.createRandom`) and
 * identity (`hre.ethers.Contract === hre.ethers.Contract`).
 *
 * `hardhat-ethers` assigns `hre.ethers = lazyObject(...)`. This intercepts
 * that assignment rather than a task, so require order does not matter:
 * if the lazy object is already present it is wrapped immediately; if a
 * later extender will assign it, that extender is wrapped in place so the
 * assignment is intercepted after it runs. If hardhat-ethers is not
 * installed, `ethers` is never defined, so `'ethers' in hre` stays false.
 */
export function installLibrariesTranslation(hre: HardhatRuntimeEnvironment): void {
  if (!hre.config.fhec.enabled) {
    return;
  }

  const env = hre as HreWithEthers;
  if (Object.prototype.hasOwnProperty.call(env, "ethers")) {
    installEthersAccessor(hre, env);
    return;
  }

  if (wrapRemainingEnvironmentExtenders(hre)) {
    return;
  }

  // No extender list (unit tests): install the accessor so a later
  // `hre.ethers = …` assignment is still wrapped.
  installEthersAccessor(hre, env);
}
