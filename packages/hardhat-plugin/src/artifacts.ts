import type { Artifacts, HardhatRuntimeEnvironment } from "hardhat/types";

import { translateFsolFqn } from "./fqn";
import { loadManifest } from "./remap";

/**
 * `Artifacts` methods whose first argument is a contract name or fully
 * qualified name, and so are worth resolving through the manifest. This is
 * the real Hardhat 2.29 method set (checked against the installed
 * `hardhat/types/artifacts.d.ts`), not the task's suggested names verbatim:
 * `getArtifactPath`/`getArtifactPathSync` do not exist on `Artifacts` — the
 * closest public equivalent is `formArtifactPathFromFullyQualifiedName`,
 * which is covered here, along with `getBuildInfo`/`getBuildInfoSync`
 * (same shape of argument, same benefit).
 */
const TRANSLATED_METHODS: ReadonlySet<string> = new Set([
  "readArtifact",
  "readArtifactSync",
  "artifactExists",
  "getBuildInfo",
  "getBuildInfoSync",
  "formArtifactPathFromFullyQualifiedName",
]);

/**
 * Resolves `fqn` against the manifest, per-call (the manifest may not exist
 * until after `hardhat compile` has run `fhec build`, and can change between
 * calls in the same process). Falls through to `fqn` unchanged when the
 * plugin is disabled, no manifest is on disk yet, or `fqn` does not name a
 * `.fsol` file under `srcDir`.
 */
function resolveFqn(hre: HardhatRuntimeEnvironment, fqn: string): string {
  const fhec = hre.config.fhec;
  if (!fhec.enabled) {
    return fqn;
  }
  const manifest = loadManifest(hre.config.paths.sources);
  if (manifest === undefined) {
    return fqn;
  }
  return translateFsolFqn(fqn, fhec.srcDir, fhec.outDir, manifest) ?? fqn;
}

/**
 * Wraps `hre.artifacts` so a fully-qualified (or bare) name that still uses
 * the `.fsol` source path — `contracts/Path/File.fsol:Name` — resolves to
 * the generated artifact, on {@link TRANSLATED_METHODS}.
 *
 * This is a `Proxy` over the original `Artifacts` implementation, not a
 * plain object copy: Hardhat's own `builtin-tasks/compile.ts` calls
 * `artifacts.addValidArtifacts(...)`, a method the concrete `Artifacts`
 * class exposes but the public `Artifacts` *type* does not declare. A
 * hand-written replacement object — even one that binds and forwards every
 * documented method — silently drops methods like that one, breaking
 * `hardhat compile`. The `Proxy` instead forwards every property it does
 * not explicitly translate straight through to the original instance, with
 * function properties bound to it so their internal `this` still works.
 */
export function wrapArtifacts(hre: HardhatRuntimeEnvironment): Artifacts {
  const original = hre.artifacts;
  return new Proxy(original, {
    get(target, prop, receiver) {
      if (typeof prop === "string" && TRANSLATED_METHODS.has(prop)) {
        const fn = Reflect.get(target, prop, receiver);
        if (typeof fn === "function") {
          return (name: string, ...rest: unknown[]) => fn.call(target, resolveFqn(hre, name), ...rest);
        }
      }
      const value = Reflect.get(target, prop, receiver);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}
