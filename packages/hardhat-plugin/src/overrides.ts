import { PLUGIN_NAME } from "./types";

/**
 * One `solidity.overrides` key that still used the fhec source directory
 * after the plugin repointed Hardhat `paths.sources` at `out`.
 */
export interface OverrideNotice {
  /** Original key, as written in the Hardhat config. */
  from: string;
  /** Key Hardhat will match after `paths.sources` is `out`. */
  to: string;
  /**
   * `rewritten` — the entry was moved to `to`.
   * `skipped` — `to` already had an entry; the source key is left in place
   * (Hardhat will ignore it) so the existing destination is not overwritten.
   */
  action: "rewritten" | "skipped";
}

/**
 * If `key` is a Hardhat source name under `srcDir`, return the same name
 * under `outDir`. Otherwise return `undefined` (leave the key alone).
 *
 * Keys are project-root-relative (Hardhat's `solidity.overrides` form). A
 * `:Contract` suffix is preserved so a fully-qualified name is rewritten
 * too, even though overrides usually omit it.
 */
export function mapSrcKeyToOut(
  key: string,
  srcDir: string,
  outDir: string,
): string | undefined {
  const src = normalizeDir(srcDir);
  const out = normalizeDir(outDir);
  if (src === "" || out === "" || src === out) {
    return undefined;
  }

  const normalized = normalizePathKey(key);
  if (normalized === out || normalized.startsWith(`${out}/`)) {
    return undefined;
  }
  if (normalized === src) {
    return out;
  }
  const srcPrefix = `${src}/`;
  if (normalized.startsWith(srcPrefix)) {
    return `${out}/${normalized.slice(srcPrefix.length)}`;
  }
  return undefined;
}

/**
 * Moves `solidity.overrides` entries from `srcDir/...` to `outDir/...` in
 * place. Returns a notice for every key that matched the source directory.
 *
 * Safe: never overwrites an overrides entry that already uses the `out`
 * path. In that case the source key is left as a no-op and `action` is
 * `skipped`.
 */
export function rewriteSolidityOverrides<T>(
  overrides: Record<string, T>,
  srcDir: string,
  outDir: string,
): OverrideNotice[] {
  const notices: OverrideNotice[] = [];
  for (const key of Object.keys(overrides)) {
    const to = mapSrcKeyToOut(key, srcDir, outDir);
    if (to === undefined || to === key) {
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(overrides, to)) {
      notices.push({ from: key, to, action: "skipped" });
      continue;
    }
    overrides[to] = overrides[key];
    delete overrides[key];
    notices.push({ from: key, to, action: "rewritten" });
  }
  return notices;
}

/**
 * Human-readable warning for rewritten or skipped `solidity.overrides` keys.
 */
export function formatOverrideWarning(
  notices: OverrideNotice[],
  srcDir: string,
  outDir: string,
): string {
  const src = normalizeDir(srcDir);
  const out = normalizeDir(outDir);
  const lines = [
    `${PLUGIN_NAME}: Hardhat compiles '${out}/', not '${src}/', so artifact fully-qualified names use the '${out}/' prefix.`,
  ];

  const rewritten = notices.filter((n) => n.action === "rewritten");
  const skipped = notices.filter((n) => n.action === "skipped");

  if (rewritten.length > 0) {
    lines.push("Rewrote solidity.overrides keys:");
    for (const notice of rewritten) {
      lines.push(`  - "${notice.from}" -> "${notice.to}"`);
    }
  }
  if (skipped.length > 0) {
    lines.push(
      "Did not rewrite these solidity.overrides keys (destination already set):",
    );
    for (const notice of skipped) {
      lines.push(`  - "${notice.from}" (would become "${notice.to}")`);
    }
  }

  lines.push(
    `Also update getContractFactory, deployments.deploy({ contract }), and verify:verify to the '${out}/' form.`,
  );
  return lines.join("\n");
}

function normalizePathKey(key: string): string {
  return key.replace(/\\/g, "/").replace(/^\.\//, "");
}

function normalizeDir(dir: string): string {
  return dir.replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+$/, "");
}
