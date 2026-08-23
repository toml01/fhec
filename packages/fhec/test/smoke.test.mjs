// Smoke tests for the `fhec` npm wrapper (packages/fhec/bin/fhec.js).
//
// These exercise the real resolution + spawn path against the actual
// native binary, building it once via `build:native` if it is missing and
// cargo is available. If cargo is not available, the binary-dependent
// tests skip gracefully instead of failing.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkgRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(pkgRoot, "..", "..");
const cliJs = path.join(pkgRoot, "bin", "fhec.js");

// Kept in sync with the mapping in lib/resolve.js / scripts/build-native.mjs.
const PLATFORM_DIRS = {
  "darwin-arm64": "fhec-darwin-arm64",
};
const binaryName = process.platform === "win32" ? "fhec.exe" : "fhec";
const platformDir = PLATFORM_DIRS[`${process.platform}-${process.arch}`];
const platformBinary = platformDir
  ? path.join(repoRoot, "packages", platformDir, "bin", binaryName)
  : null;

function haveCargo() {
  const result = spawnSync("cargo", ["--version"]);
  return !result.error && result.status === 0;
}

// Resolved once, up front, so every test shares the same skip decision
// instead of each re-running (and re-building) independently.
// NOTE: must stay `undefined` (not `null`) when nothing needs skipping —
// node:test's `skip` option treats any defined value, including `null`, as
// "skip this test".
let skipReason;

if (!platformBinary) {
  skipReason = `no platform package wired up for ${process.platform}-${process.arch} in this test`;
} else if (!existsSync(platformBinary)) {
  if (haveCargo()) {
    console.error("smoke: platform binary missing, running `build:native` once...");
    const build = spawnSync(
      process.execPath,
      [path.join(pkgRoot, "scripts", "build-native.mjs")],
      {
        cwd: pkgRoot,
        stdio: "inherit",
        timeout: 10 * 60 * 1000, // cargo build --release can be slow the first time
      },
    );
    if (build.status !== 0 || !existsSync(platformBinary)) {
      skipReason = "build:native did not produce the platform binary";
    }
  } else {
    skipReason = "cargo is not available; skipping native-binary smoke tests";
  }
}

test("fhec explain FHE1002 exits 0 with non-empty stdout", { skip: skipReason }, () => {
  const result = spawnSync(process.execPath, [cliJs, "explain", "FHE1002"], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0, `stderr: ${result.stderr}`);
  assert.ok(result.stdout.trim().length > 0, "expected non-empty stdout");
});

test("fhec check exits 1 (passthrough) in a dir without fhec.toml", { skip: skipReason }, () => {
  const tmpDir = mkdtempSync(path.join(os.tmpdir(), "fhec-smoke-"));
  try {
    const result = spawnSync(process.execPath, [cliJs, "check"], {
      cwd: tmpDir,
      encoding: "utf8",
    });
    assert.equal(result.status, 1, `stderr: ${result.stderr}`);
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("FHEC_BINARY_PATH override is respected", { skip: skipReason }, () => {
  const result = spawnSync(process.execPath, [cliJs, "explain", "FHE1002"], {
    encoding: "utf8",
    env: { ...process.env, FHEC_BINARY_PATH: platformBinary },
  });
  assert.equal(result.status, 0, `stderr: ${result.stderr}`);
  assert.ok(result.stdout.trim().length > 0, "expected non-empty stdout");
});
