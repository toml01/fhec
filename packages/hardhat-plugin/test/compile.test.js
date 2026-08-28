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

function writeLibrariesTaskProject(dir) {
  fs.mkdirSync(path.join(dir, "contracts", "Path"), { recursive: true });
  linkLocalHardhat(dir);
  fs.writeFileSync(
    path.join(dir, "hardhat.config.js"),
    `'use strict';
const { task } = require("hardhat/config");
require(${JSON.stringify(pluginEntry)});
const { translateLibrariesMap } = require(${JSON.stringify(path.join(pluginRoot, "dist", "libraries.js"))});
const { loadManifest } = require(${JSON.stringify(path.join(pluginRoot, "dist", "remap.js"))});
task("fhec-test-libraries", async (args, hre) => {
  const artifact = await hre.artifacts.readArtifact("contracts/Path/User.fsol:User");
  const fsolKey = "contracts/Path/Lib.fsol:Lib";
  const translated = translateLibrariesMap(
    { [fsolKey]: "0x" + "11".repeat(20) },
    hre.config.fhec.srcDir,
    hre.config.fhec.outDir,
    loadManifest(hre.config.paths.sources),
  );
  const generatedKey = Object.keys(translated)[0];
  const colon = generatedKey.lastIndexOf(":");
  const sourceName = generatedKey.slice(0, colon);
  const libName = generatedKey.slice(colon + 1);
  const hit =
    artifact.linkReferences[sourceName] !== undefined &&
    artifact.linkReferences[sourceName][libName] !== undefined;
  console.log(
    "FHEC_TEST_RESULT:" +
      JSON.stringify({
        generatedKey,
        hit,
        linkReferenceFiles: Object.keys(artifact.linkReferences),
      }),
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
    path.join(dir, "contracts", "Path", "Lib.fsol"),
    "pragma solidity ^0.8.25; library Lib { function add(uint256 a, uint256 b) public pure returns (uint256) { return a + b; } }\n",
  );
  fs.writeFileSync(
    path.join(dir, "contracts", "Path", "User.fsol"),
    'pragma solidity ^0.8.25; import "./Lib.fsol"; contract User { function add(uint256 a, uint256 b) public pure returns (uint256) { return Lib.add(a, b); } }\n',
  );
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

function writeOverrideCompileProject(dir) {
  fs.mkdirSync(path.join(dir, "contracts"), { recursive: true });
  linkLocalHardhat(dir);
  fs.writeFileSync(
    path.join(dir, "hardhat.config.js"),
    `'use strict';
const { task } = require("hardhat/config");
require(${JSON.stringify(pluginEntry)});
task("fhec-test-overrides-after-compile", async (args, hre) => {
  const atLoad = Object.keys(hre.config.solidity.overrides);
  await hre.run("compile");
  console.log(
    "FHEC_OVERRIDES_JSON:" +
      JSON.stringify({
        atLoad,
        afterCompile: Object.keys(hre.config.solidity.overrides),
        pinVersion: hre.config.solidity.overrides["generated/Pin.sol"]
          ? hre.config.solidity.overrides["generated/Pin.sol"].version
          : null,
      }),
  );
});
module.exports = {
  solidity: {
    compilers: [
      { version: "0.8.28", settings: { evmVersion: "cancun" } },
    ],
    overrides: {
      "contracts/Pin.fsol": {
        version: "0.8.26",
        settings: { optimizer: { enabled: true, runs: 1 }, evmVersion: "cancun" },
      },
    },
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
    path.join(dir, "contracts", "Pin.fsol"),
    "pragma solidity ^0.8.25; contract Pin { uint public x; }\n",
  );
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
  "a .fsol libraries key translates to a solc linkReferences entry",
  { skip: skipReason, timeout: 180_000 },
  () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-hh-libs-"));
    try {
      writeLibrariesTaskProject(dir);
      const compileResult = runCompile(dir, nativeBinary);
      assert.equal(
        compileResult.status,
        0,
        `compile failed\nstdout:\n${compileResult.stdout}\nstderr:\n${compileResult.stderr}`,
      );
      const taskResult = runTask(dir, nativeBinary, "fhec-test-libraries");
      assert.equal(
        taskResult.status,
        0,
        `task failed\nstdout:\n${taskResult.stdout}\nstderr:\n${taskResult.stderr}`,
      );
      const match = taskResult.stdout.match(/FHEC_TEST_RESULT:(.+)/);
      assert.ok(match, `expected FHEC_TEST_RESULT marker in stdout:\n${taskResult.stdout}`);
      const parsed = JSON.parse(match[1]);
      assert.equal(parsed.generatedKey, "generated/Path/Lib.sol:Lib");
      assert.equal(parsed.hit, true, `linkReferences files: ${JSON.stringify(parsed.linkReferenceFiles)}`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "TASK_COMPILE rewrites a .fsol solidity.overrides key after fhec build",
  { skip: skipReason, timeout: 180_000 },
  () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-hh-ov-compile-"));
    try {
      writeOverrideCompileProject(dir);
      const result = runTask(dir, nativeBinary, "fhec-test-overrides-after-compile");
      assert.equal(
        result.status,
        0,
        `task failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
      );
      const match = result.stdout.match(/FHEC_OVERRIDES_JSON:(.+)/);
      assert.ok(match, `expected FHEC_OVERRIDES_JSON marker in stdout:\n${result.stdout}`);
      const parsed = JSON.parse(match[1]);
      assert.deepEqual(parsed.atLoad, ["contracts/Pin.fsol"]);
      assert.deepEqual(parsed.afterCompile, ["generated/Pin.sol"]);
      assert.equal(parsed.pinVersion, "0.8.26");
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
