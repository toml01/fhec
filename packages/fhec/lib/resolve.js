// Resolves the native `fhec` binary in this order:
//   1. FHEC_BINARY_PATH env var, if set (used as-is, existence-checked).
//   2. The optional platform package for the current platform+arch, e.g.
//      `@fhec/cli-darwin-arm64`, resolved via require.resolve and expected
//      to ship the binary at <pkg>/bin/fhec.
//   3. A dev fallback: ../../../target/release/fhec then
//      ../../../target/debug/fhec, resolved relative to this file (i.e. a
//      cargo build done directly in this monorepo checkout).
//
// This mirrors the platform-package distribution model used by esbuild and
// biome: a thin JS shim spawns a prebuilt native binary chosen for the
// current platform/arch.
//
// Require as `fhec/resolve` (or `../lib/resolve` from bin/fhec.js).

"use strict";

const path = require("node:path");
const fs = require("node:fs");

const BINARY_NAME = process.platform === "win32" ? "fhec.exe" : "fhec";

// process.platform/process.arch -> platform package suffix, following the
// same naming convention as esbuild/biome's per-platform packages.
const PLATFORM_PACKAGES = {
  "darwin-arm64": "@fhec/cli-darwin-arm64",
  "darwin-x64": "@fhec/cli-darwin-x64",
  "linux-x64": "@fhec/cli-linux-x64",
  "linux-arm64": "@fhec/cli-linux-arm64",
  "win32-x64": "@fhec/cli-win32-x64",
  "win32-arm64": "@fhec/cli-win32-arm64",
};

/**
 * Builds the "could not find the native binary" error text, including every
 * location that was tried and the same fix hints the CLI wrapper prints.
 * @param {string[]} tried
 * @returns {string}
 */
function formatResolveFailure(tried) {
  return [
    "fhec: could not find the native binary. Tried, in order:",
    ...tried.map((t) => `  - ${t}`),
    "",
    "To fix this:",
    "  - set FHEC_BINARY_PATH to an existing fhec binary, or",
    "  - install the platform package for your platform/arch, or",
    "  - run `pnpm --filter fhec run build:native` in this checkout to build one locally.",
  ].join("\n");
}

/**
 * Attempts every resolution strategy in order, recording what was tried.
 * Returns `{ binaryPath }` on success, or throws with a message listing every
 * location that was tried.
 * @returns {{ binaryPath: string }}
 */
function resolveBinary() {
  const tried = [];

  // (a) explicit override.
  const override = process.env.FHEC_BINARY_PATH;
  if (override) {
    tried.push(`FHEC_BINARY_PATH=${override}`);
    if (fs.existsSync(override)) {
      return { binaryPath: override };
    }
  }

  // (b) platform package for the current platform+arch.
  const platformKey = `${process.platform}-${process.arch}`;
  const pkgName = PLATFORM_PACKAGES[platformKey];
  if (pkgName) {
    let pkgJsonPath;
    try {
      pkgJsonPath = require.resolve(`${pkgName}/package.json`);
    } catch {
      tried.push(`platform package ${pkgName} (not installed)`);
    }
    if (pkgJsonPath) {
      const candidate = path.join(path.dirname(pkgJsonPath), "bin", BINARY_NAME);
      tried.push(candidate);
      if (fs.existsSync(candidate)) {
        return { binaryPath: candidate };
      }
    }
  } else {
    tried.push(`platform package (no mapping for ${platformKey})`);
  }

  // (c) dev fallback: a local cargo build in this checkout.
  // this file lives at packages/fhec/lib/resolve.js → repo root is ../../..
  for (const profile of ["release", "debug"]) {
    const candidate = path.resolve(__dirname, "..", "..", "..", "target", profile, BINARY_NAME);
    tried.push(candidate);
    if (fs.existsSync(candidate)) {
      return { binaryPath: candidate };
    }
  }

  throw new Error(formatResolveFailure(tried));
}

module.exports = {
  resolveBinary,
  formatResolveFailure,
  PLATFORM_PACKAGES,
  BINARY_NAME,
};
