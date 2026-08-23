import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import type { Manifest, ManifestFile } from "./types";

/**
 * Maps `[start, end)` in output coordinates onto source coordinates using a
 * manifest file's mappings (sorted by output range).
 *
 * Port of `crates/fhec-cli/src/gate.rs` `remap_range`:
 * - A position inside a mapping's output range blames the whole source range
 *   of that mapping and sets `insideGenerated = true`.
 * - Otherwise shift by the last mapping whose `output_range[1] <= start`
 *   using `delta = output_end - source_end`.
 */
export function remapRange(
  file: ManifestFile,
  start: number,
  end: number,
): { start: number; end: number; insideGenerated: boolean } {
  for (const mapping of file.mappings) {
    const outStart = mapping.output_range[0];
    const outEnd = mapping.output_range[1];
    if (start >= outStart && start < Math.max(outEnd, outStart + 1)) {
      return {
        start: mapping.source_range[0],
        end: mapping.source_range[1],
        insideGenerated: true,
      };
    }
  }

  let delta = 0;
  for (const mapping of file.mappings) {
    if (mapping.output_range[1] <= start) {
      delta = mapping.output_range[1] - mapping.source_range[1];
    } else {
      break;
    }
  }
  const shift = (value: number): number => Math.max(0, value - delta);
  return { start: shift(start), end: shift(end), insideGenerated: false };
}

/**
 * Loads `generated/.fhec/manifest.json` from the (already-repointed) Hardhat
 * sources directory. Returns `undefined` when the file is missing or invalid.
 */
export function loadManifest(sourcesDir: string): Manifest | undefined {
  const manifestPath = path.join(sourcesDir, ".fhec", "manifest.json");
  if (!existsSync(manifestPath)) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(readFileSync(manifestPath, "utf8")) as Manifest;
    if (!Array.isArray(parsed.files)) {
      return undefined;
    }
    return parsed;
  } catch {
    return undefined;
  }
}

/**
 * Matches a Hardhat/solc source name (`generated/Counter.sol`) to a manifest
 * `output` (`Counter.sol`) by stripping the out-dir prefix.
 */
export function matchManifestFile(
  solcFile: string,
  outDir: string,
  manifest: Manifest,
): ManifestFile | undefined {
  const normalized = solcFile.replace(/\\/g, "/");
  const prefix = outDir.replace(/\\/g, "/").replace(/^\.\/+/, "").replace(/\/+$/, "");
  let rel = normalized;
  if (prefix.length > 0 && (normalized === prefix || normalized.startsWith(`${prefix}/`))) {
    rel = normalized === prefix ? "" : normalized.slice(prefix.length + 1);
  }
  return manifest.files.find((file) => file.output.replace(/\\/g, "/") === rel);
}

/**
 * Project-relative path shown to the user, e.g. `contracts/Counter.fsol`.
 */
export function displaySourcePath(srcDir: string, source: string): string {
  const src = srcDir.replace(/\\/g, "/").replace(/\/+$/, "");
  const rel = source.replace(/\\/g, "/");
  if (src.length === 0 || src === ".") {
    return rel;
  }
  return `${src}/${rel}`;
}

interface SolcLocation {
  file: string;
  start: number;
  end: number;
  message?: string;
}

interface SolcError {
  sourceLocation?: SolcLocation;
  secondarySourceLocations?: SolcLocation[];
  formattedMessage?: string;
}

interface SolcOutput {
  errors?: SolcError[];
}

export interface RemapContext {
  manifest: Manifest;
  outDir: string;
  srcDir: string;
  projectRoot: string;
  sourcesDir: string;
}

/**
 * Rewrites `output.errors[]` so paths and byte ranges point at the original
 * `.fsol` (or pass-through `.sol`) instead of `generated/*.sol`.
 *
 * Errors that do not match a manifest file, or that have no usable range,
 * are left unchanged.
 */
export function remapSolcOutput<T extends SolcOutput>(output: T, ctx: RemapContext): T {
  if (output.errors === undefined || output.errors.length === 0) {
    return output;
  }
  for (const error of output.errors) {
    remapError(error, ctx);
  }
  return output;
}

function remapError(error: SolcError, ctx: RemapContext): void {
  if (error.sourceLocation !== undefined) {
    const remapped = remapLocation(error.sourceLocation, ctx);
    if (remapped !== undefined) {
      if (error.formattedMessage !== undefined) {
        error.formattedMessage = rewriteFormattedMessage(
          error.formattedMessage,
          error.sourceLocation,
          remapped,
          ctx,
        );
      }
      error.sourceLocation = remapped;
    }
  }
  if (error.secondarySourceLocations !== undefined) {
    error.secondarySourceLocations = error.secondarySourceLocations.map((loc) => {
      return remapLocation(loc, ctx) ?? loc;
    });
  }
}

function remapLocation(loc: SolcLocation, ctx: RemapContext): SolcLocation | undefined {
  const file = matchManifestFile(loc.file, ctx.outDir, ctx.manifest);
  if (file === undefined) {
    return undefined;
  }
  const display = displaySourcePath(ctx.srcDir, file.source);
  if (loc.start < 0) {
    return { ...loc, file: display };
  }
  const remapped = remapRange(file, loc.start, loc.end);
  return { ...loc, file: display, start: remapped.start, end: remapped.end };
}

/**
 * Rewrites solc's pretty-printed `formattedMessage` so the path (and, when
 * we can compute them, the line/column) name the original source.
 */
export function rewriteFormattedMessage(
  formatted: string,
  original: SolcLocation,
  remapped: SolcLocation,
  ctx: RemapContext,
): string {
  let next = replaceAll(formatted, original.file, remapped.file);
  if (original.start < 0 || remapped.start < 0) {
    return next;
  }
  const generatedText = readUtf8(path.join(ctx.sourcesDir, manifestRelFromSolc(original.file, ctx.outDir)));
  const sourceText = readUtf8(path.join(ctx.projectRoot, remapped.file));
  if (generatedText === undefined || sourceText === undefined) {
    return next;
  }
  const oldLoc = byteOffsetToLineCol(generatedText, original.start);
  const newLoc = byteOffsetToLineCol(sourceText, remapped.start);
  if (oldLoc.line !== newLoc.line || oldLoc.column !== newLoc.column) {
    next = replaceAll(
      next,
      `${remapped.file}:${oldLoc.line}:${oldLoc.column}`,
      `${remapped.file}:${newLoc.line}:${newLoc.column}`,
    );
  }
  return next;
}

function manifestRelFromSolc(solcFile: string, outDir: string): string {
  const normalized = solcFile.replace(/\\/g, "/");
  const prefix = outDir.replace(/\\/g, "/").replace(/^\.\/+/, "").replace(/\/+$/, "");
  if (prefix.length > 0 && normalized.startsWith(`${prefix}/`)) {
    return normalized.slice(prefix.length + 1);
  }
  return normalized;
}

function readUtf8(filePath: string): string | undefined {
  try {
    return readFileSync(filePath, "utf8");
  } catch {
    return undefined;
  }
}

/**
 * Converts a UTF-8 byte offset to a 1-based line/column (columns count
 * UTF-8 bytes), matching spec §10.2 / AGENTS.md.
 */
export function byteOffsetToLineCol(source: string, offset: number): { line: number; column: number } {
  const bytes = Buffer.from(source, "utf8");
  const end = Math.max(0, Math.min(offset, bytes.length));
  let line = 1;
  let column = 1;
  for (let i = 0; i < end; i++) {
    if (bytes[i] === 0x0a) {
      line += 1;
      column = 1;
    } else {
      column += 1;
    }
  }
  return { line, column };
}

function replaceAll(haystack: string, needle: string, replacement: string): string {
  if (needle.length === 0) {
    return haystack;
  }
  return haystack.split(needle).join(replacement);
}
