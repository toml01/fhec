import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import { parse } from "smol-toml";

import {
  CONFIG_FILE_NAME,
  DEFAULT_OUT,
  DEFAULT_PROFILE_VERSION,
  DEFAULT_SRC,
  type ParsedFhecToml,
} from "./types";

/**
 * Searches for `fhec.toml` upward from `start`, returning the first hit.
 * Mirrors `fhec-cli` `find_config`.
 */
export function findConfig(start: string): string | undefined {
  let dir = path.resolve(start);
  for (;;) {
    const candidate = path.join(dir, CONFIG_FILE_NAME);
    if (existsSync(candidate)) {
      return candidate;
    }
    const parent = path.dirname(dir);
    if (parent === dir) {
      return undefined;
    }
    dir = parent;
  }
}

/**
 * Resolves the config path: an explicit `fhec.config` value, otherwise an
 * upward search from the Hardhat project root.
 */
export function resolveTomlPath(projectRoot: string, explicit?: string): string | undefined {
  if (explicit !== undefined && explicit !== "") {
    return path.isAbsolute(explicit) ? explicit : path.resolve(projectRoot, explicit);
  }
  return findConfig(projectRoot);
}

/**
 * Parses only the `fhec.toml` keys this plugin needs. Missing tables fall
 * back to the same defaults as `fhec-cli` (`src`, `out`, `target.version`).
 */
export function parseFhecToml(text: string): ParsedFhecToml {
  const data = parse(text) as {
    project?: { src?: unknown; out?: unknown };
    target?: { version?: unknown };
  };
  return {
    src: stringOrDefault(data.project?.src, DEFAULT_SRC),
    out: stringOrDefault(data.project?.out, DEFAULT_OUT),
    version: stringOrDefault(data.target?.version, DEFAULT_PROFILE_VERSION),
  };
}

/**
 * Reads and parses `fhec.toml` from disk.
 */
export function loadFhecToml(tomlPath: string): ParsedFhecToml {
  const text = readFileSync(tomlPath, "utf8");
  return parseFhecToml(text);
}

function stringOrDefault(value: unknown, fallback: string): string {
  return typeof value === "string" && value.length > 0 ? value : fallback;
}
