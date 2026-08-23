/**
 * User-facing Hardhat config for `@fhec/hardhat-plugin`.
 */
export interface FhecUserConfig {
  /** Run `fhec build` before compile. Default `true`. */
  enabled?: boolean;
  /**
   * When `false` (default), pass `--no-verify` so Hardhat is the only solc.
   * When `true`, let fhec run its own solc gate as well.
   */
  verify?: boolean;
  /** Override the ACL mode from `fhec.toml`. */
  acl?: "insert" | "suggest";
  /** Path to `fhec.toml` (relative to the Hardhat project root, or absolute). */
  config?: string;
}

/**
 * Resolved plugin config stored on `HardhatConfig.fhec`.
 */
export interface FhecConfig {
  enabled: boolean;
  verify: boolean;
  acl?: "insert" | "suggest";
  config?: string;
  /** Absolute path of the `fhec.toml` discovered at config-load time, if any. */
  tomlPath?: string;
  /** `[project].src`, default `contracts`. */
  srcDir: string;
  /** `[project].out`, default `generated`. */
  outDir: string;
  /** `[target].version`, default `0.2.x`. */
  profileVersion: string;
}

/**
 * The keys of `fhec.toml` this plugin reads. Unknown tables are ignored.
 */
export interface ParsedFhecToml {
  src: string;
  out: string;
  version: string;
}

/**
 * One output-range → source-range mapping from `generated/.fhec/manifest.json`.
 */
export interface ManifestMapping {
  output_range: [number, number];
  source_range: [number, number];
  rule: string;
  code?: string;
}

/**
 * Source-map data for one emitted file.
 */
export interface ManifestFile {
  output: string;
  source: string;
  no_op: boolean;
  mappings: ManifestMapping[];
}

/**
 * The whole-run sidecar manifest (`generated/.fhec/manifest.json`).
 */
export interface Manifest {
  tool: string;
  version: string;
  files: ManifestFile[];
}

export const PLUGIN_NAME = "@fhec/hardhat-plugin";

export const DEFAULT_SRC = "contracts";
export const DEFAULT_OUT = "generated";
export const DEFAULT_PROFILE_VERSION = "0.2.x";
export const CONFIG_FILE_NAME = "fhec.toml";
