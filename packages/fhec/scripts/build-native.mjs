#!/usr/bin/env node
// Builds the `fhec-cli` crate in release mode and stages the resulting
// binary into the darwin-arm64 platform package, so local dogfooding works
// without publishing anything: `fhec` (the JS wrapper) picks the binary up
// from `@fhec/cli-darwin-arm64` via require.resolve.
//
// This only stages the current machine's platform package (darwin-arm64).
// Other platform packages would get their own equivalent staging step when
// they are added.

"use strict";

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, copyFileSync, chmodSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..", "..", "..");

const platformDir = {
  "darwin-arm64": "fhec-darwin-arm64",
}[`${process.platform}-${process.arch}`];

if (!platformDir) {
  console.error(
    `build:native: no platform package wired up for ${process.platform}-${process.arch} yet (only darwin-arm64 today).`,
  );
  process.exit(1);
}

console.error("build:native: cargo build --release -p fhec-cli");
const build = spawnSync("cargo", ["build", "--release", "-p", "fhec-cli"], {
  cwd: repoRoot,
  stdio: "inherit",
});

if (build.error) {
  console.error(`build:native: failed to run cargo: ${build.error.message}`);
  process.exit(1);
}
if (build.status !== 0) {
  process.exit(build.status === null ? 1 : build.status);
}

const binaryName = process.platform === "win32" ? "fhec.exe" : "fhec";
const builtBinary = path.join(repoRoot, "target", "release", binaryName);
if (!existsSync(builtBinary)) {
  console.error(`build:native: expected cargo to produce ${builtBinary}, but it is missing`);
  process.exit(1);
}

const destDir = path.join(repoRoot, "packages", platformDir, "bin");
const destBinary = path.join(destDir, binaryName);
mkdirSync(destDir, { recursive: true });
copyFileSync(builtBinary, destBinary);
chmodSync(destBinary, 0o755);

console.error(`build:native: staged ${destBinary}`);
