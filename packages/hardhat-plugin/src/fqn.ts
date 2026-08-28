import type { Manifest } from "./types";

/**
 * Splits a Hardhat fully-qualified name (`path/File.sol:Contract`) into its
 * file and contract-name parts. A bare contract name (no `:`) has no file
 * part. The contract name never contains `:`, so splitting on the *last*
 * `:` is unambiguous even though POSIX paths could in principle contain one.
 */
function splitFqn(fqn: string): { file: string; name: string | undefined } {
  const idx = fqn.lastIndexOf(":");
  if (idx === -1) {
    return { file: fqn, name: undefined };
  }
  return { file: fqn.slice(0, idx), name: fqn.slice(idx + 1) };
}

function normalize(value: string): string {
  return value.replace(/\\/g, "/");
}

function normalizeDir(dir: string): string {
  return normalize(dir).replace(/^\.\/+/, "").replace(/\/+$/, "");
}

/**
 * Strips `dir/` (or an exact match on `dir`) from the front of `value`.
 * Returns `undefined` when `value` is not under `dir`.
 */
function stripDir(value: string, dir: string): string | undefined {
  const normalizedDir = normalizeDir(dir);
  const normalizedValue = normalize(value);
  if (normalizedDir.length === 0) {
    return normalizedValue;
  }
  if (normalizedValue === normalizedDir) {
    return "";
  }
  const prefix = `${normalizedDir}/`;
  if (normalizedValue.startsWith(prefix)) {
    return normalizedValue.slice(prefix.length);
  }
  return undefined;
}

/**
 * Translates a Hardhat fully-qualified name (or bare source-relative path)
 * naming a `.fsol` file under `srcDir` to the same file's manifest `output`
 * under `outDir`. The `:Contract` suffix, if present, is preserved as-is.
 *
 * Returns `undefined` — meaning "leave the input unchanged" — when:
 * - the FQN has no file part under `srcDir`,
 * - the file does not end in `.fsol` (a pass-through `.sol` file keeps its
 *   own name and needs no alias), or
 * - no manifest entry matches (an unknown FQN passes through unchanged).
 */
export function translateFsolFqn(
  fqn: string,
  srcDir: string,
  outDir: string,
  manifest: Manifest,
): string | undefined {
  const { file, name } = splitFqn(fqn);
  const rel = stripDir(file, srcDir);
  if (rel === undefined || !rel.endsWith(".fsol")) {
    return undefined;
  }
  const entry = manifest.files.find((candidate) => normalize(candidate.source) === rel);
  if (entry === undefined) {
    return undefined;
  }
  const out = normalizeDir(outDir);
  const outPath = out.length > 0 ? `${out}/${entry.output}` : entry.output;
  return name !== undefined ? `${outPath}:${name}` : outPath;
}
