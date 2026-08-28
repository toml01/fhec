"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const pluginRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(pluginRoot, "..", "..");
const pluginEntry = path.join(pluginRoot, "dist", "index.js");
const binaryName = process.platform === "win32" ? "fhec.exe" : "fhec";

// NOTE: must stay `undefined` (not `null`) when nothing needs skipping —
// node:test's `skip` option treats any defined value, including `null`, as
// "skip this test". Same trap as packages/fhec/test/smoke.test.mjs.
let skipReason;

function findNativeBinary() {
  const override = process.env.FHEC_BINARY_PATH;
  if (override && fs.existsSync(override)) {
    return override;
  }
  for (const profile of ["release", "debug"]) {
    const candidate = path.join(repoRoot, "target", profile, binaryName);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

const nativeBinary = findNativeBinary();
if (nativeBinary === undefined) {
  skipReason =
    "no native fhec binary (set FHEC_BINARY_PATH or cargo build -p fhec-cli)";
}

function hardhatCli() {
  return require.resolve("hardhat/internal/cli/cli.js", { paths: [pluginRoot] });
}

function linkLocalHardhat(dir) {
  const hardhatDir = path.dirname(
    require.resolve("hardhat/package.json", { paths: [pluginRoot] }),
  );
  const nm = path.join(dir, "node_modules");
  fs.mkdirSync(nm, { recursive: true });
  fs.symlinkSync(hardhatDir, path.join(nm, "hardhat"));
}

function writeProject(dir, { sourceName, sourceBody }) {
  fs.mkdirSync(path.join(dir, "contracts"), { recursive: true });
  linkLocalHardhat(dir);
  fs.writeFileSync(
    path.join(dir, "hardhat.config.js"),
    `'use strict';
require(${JSON.stringify(pluginEntry)});
module.exports = {
  solidity: {
    version: "0.8.28",
    settings: { evmVersion: "cancun" },
  },
};
`,
  );
  fs.writeFileSync(
    path.join(dir, "fhec.toml"),
    `[project]
src = "contracts"
out = "generated"
`,
  );
  fs.writeFileSync(path.join(dir, "contracts", sourceName), sourceBody);
}

function runCompile(dir, binary) {
  return spawnSync(process.execPath, [hardhatCli(), "compile"], {
    cwd: dir,
    encoding: "utf8",
    env: {
      ...process.env,
      FHEC_BINARY_PATH: binary,
      HARDHAT_DISABLE_TELEMETRY: "true",
    },
    timeout: 180_000,
  });
}

function artifactExists(dir, contractFile, contractName) {
  const candidates = [
    path.join(dir, "artifacts", "generated", contractFile, `${contractName}.json`),
    path.join(dir, "artifacts", contractFile, `${contractName}.json`),
  ];
  return candidates.some((p) => fs.existsSync(p));
}

function writeReadArtifactTaskProject(dir) {
  fs.mkdirSync(path.join(dir, "contracts", "Nested"), { recursive: true });
  linkLocalHardhat(dir);
  fs.writeFileSync(
    path.join(dir, "hardhat.config.js"),
    `'use strict';
const { task } = require("hardhat/config");
require(${JSON.stringify(pluginEntry)});
task("fhec-test-read-artifact", async (args, hre) => {
  const artifact = await hre.artifacts.readArtifact("contracts/Nested/D.fsol:D");
  console.log(
    "FHEC_TEST_RESULT:" +
      JSON.stringify({ contractName: artifact.contractName, sourceName: artifact.sourceName }),
  );
});
module.exports = {
  solidity: {
    version: "0.8.28",
    settings: { evmVersion: "cancun" },
  },
};
`,
  );
  fs.writeFileSync(
    path.join(dir, "fhec.toml"),
    `[project]
src = "contracts"
out = "generated"
`,
  );
  fs.writeFileSync(
    path.join(dir, "contracts", "Nested", "D.fsol"),
    "pragma solidity ^0.8.25; contract D { uint public x; }\n",
  );
}

function runTask(dir, binary, taskName) {
  return spawnSync(process.execPath, [hardhatCli(), taskName], {
    cwd: dir,
    encoding: "utf8",
    env: {
      ...process.env,
      FHEC_BINARY_PATH: binary,
      HARDHAT_DISABLE_TELEMETRY: "true",
    },
    timeout: 180_000,
  });
}

test(
  "hardhat compile transpiles a no-FHE .fsol and writes artifacts",
  { skip: skipReason, timeout: 180_000 },
  () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-hh-ok-"));
    try {
      writeProject(dir, {
        sourceName: "C.fsol",
        sourceBody: "pragma solidity ^0.8.25; contract C { uint public x; }\n",
      });
      const result = runCompile(dir, nativeBinary);
      assert.equal(
        result.status,
        0,
        `compile failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
      );
      assert.ok(fs.existsSync(path.join(dir, "generated", "C.sol")), "expected generated/C.sol");
      assert.ok(artifactExists(dir, "C.sol", "C"), "expected Hardhat artifact for C");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "hre.artifacts.readArtifact resolves a .fsol FQN end-to-end",
  { skip: skipReason, timeout: 180_000 },
  () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-hh-fqn-"));
    try {
      writeReadArtifactTaskProject(dir);
      const compileResult = runCompile(dir, nativeBinary);
      assert.equal(
        compileResult.status,
        0,
        `compile failed\nstdout:\n${compileResult.stdout}\nstderr:\n${compileResult.stderr}`,
      );
      const taskResult = runTask(dir, nativeBinary, "fhec-test-read-artifact");
      assert.equal(
        taskResult.status,
        0,
        `task failed\nstdout:\n${taskResult.stdout}\nstderr:\n${taskResult.stderr}`,
      );
      const match = taskResult.stdout.match(/FHEC_TEST_RESULT:(.+)/);
      assert.ok(match, `expected FHEC_TEST_RESULT marker in stdout:\n${taskResult.stdout}`);
      const parsed = JSON.parse(match[1]);
      assert.equal(parsed.contractName, "D");
      assert.equal(parsed.sourceName, "generated/Nested/D.sol");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "solc errors mention Broken.fsol, not only generated/Broken.sol",
  { skip: skipReason, timeout: 180_000 },
  () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-hh-broken-"));
    try {
      writeProject(dir, {
        sourceName: "Broken.fsol",
        sourceBody:
          "pragma solidity ^0.8.25;\ncontract Broken {\n    function f() public {\n        notDefined();\n    }\n}\n",
      });
      const result = runCompile(dir, nativeBinary);
      assert.notEqual(result.status, 0, "expected Hardhat compile to fail");
      const combined = `${result.stdout}\n${result.stderr}`;
      assert.match(
        combined,
        /Broken\.fsol/,
        `expected remapped .fsol path in compiler output\n${combined}`,
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  },
);
