#!/usr/bin/env node
// `fhec` npm wrapper entry point.
//
// Resolves the native `fhec` binary in this order:
//   1. FHEC_BINARY_PATH env var, if set (used as-is, existence-checked).
//   2. The optional platform package for the current platform+arch, e.g.
//      `@fhec/cli-darwin-arm64`, resolved via require.resolve and expected
//      to ship the binary at <pkg>/bin/fhec.
//   3. A dev fallback: ../../target/release/fhec then
//      ../../target/debug/fhec, resolved relative to this script (i.e. a
//      cargo build done directly in this monorepo checkout).
//
// This mirrors the platform-package distribution model used by esbuild and
// biome: a thin JS shim spawns a prebuilt native binary chosen for the
// current platform/arch.

"use strict";

const path = require("node:path");
const fs = require("node:fs");
const { spawnSync } = require("node:child_process");

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
 * Attempts every resolution strategy in order, recording what was tried.
 * Returns { binaryPath } on success, or throws with a message listing every
 * location that was tried.
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
  for (const profile of ["release", "debug"]) {
    const candidate = path.resolve(__dirname, "..", "..", "..", "target", profile, BINARY_NAME);
    tried.push(candidate);
    if (fs.existsSync(candidate)) {
      return { binaryPath: candidate };
    }
  }

  const lines = [
    "fhec: could not find the native binary. Tried, in order:",
    ...tried.map((t) => `  - ${t}`),
    "",
    "To fix this:",
    "  - set FHEC_BINARY_PATH to an existing fhec binary, or",
    "  - install the platform package for your platform/arch, or",
    "  - run `pnpm --filter fhec run build:native` in this checkout to build one locally.",
  ];
  throw new Error(lines.join("\n"));
}

function main() {
  let binaryPath;
  try {
    ({ binaryPath } = resolveBinary());
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }

  const args = process.argv.slice(2);
  const result = spawnSync(binaryPath, args, { stdio: "inherit" });

  if (result.error) {
    console.error(`fhec: failed to run ${binaryPath}: ${result.error.message}`);
    process.exit(1);
  }
  if (result.signal) {
    console.error(`fhec: ${binaryPath} terminated by signal ${result.signal}`);
    process.exit(1);
  }
  process.exit(result.status === null ? 1 : result.status);
}

main();
