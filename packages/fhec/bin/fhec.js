#!/usr/bin/env node
// `fhec` npm wrapper entry point.
//
// Resolves the native binary via `fhec/resolve` (`../lib/resolve.js`) and
// execs it, forwarding args and the exit code. See that module for the
// resolution order (FHEC_BINARY_PATH → platform package → cargo target/).

"use strict";

const { spawnSync } = require("node:child_process");
const { resolveBinary } = require("../lib/resolve");

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
