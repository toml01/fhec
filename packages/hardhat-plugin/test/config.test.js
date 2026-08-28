"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { spawnSync } = require("node:child_process");

const { parseFhecToml, findConfig } = require("../dist/toml");
const { versionSatisfies, parseSemver } = require("../dist/version");
const {
  mapOverrideKey,
  rewriteSolidityOverrides,
  formatOverrideWarning,
} = require("../dist/overrides");

const pluginRoot = path.resolve(__dirname, "..");
const pluginEntry = path.join(pluginRoot, "dist", "index.js");

test("empty toml uses defaults", () => {
  assert.deepEqual(parseFhecToml(""), {
    src: "contracts",
    out: "generated",
    version: "0.2.x",
  });
});

test("parses [project].out and leaves other defaults", () => {
  const parsed = parseFhecToml(`[project]\nout = "build/out"\n`);
  assert.equal(parsed.out, "build/out");
  assert.equal(parsed.src, "contracts");
  assert.equal(parsed.version, "0.2.x");
});

test("parses src, out, and target.version together", () => {
  const parsed = parseFhecToml(`
[project]
src = "src"
out = "out"

[target]
profile = "cofhe"
version = "0.2.x"
`);
  assert.deepEqual(parsed, { src: "src", out: "out", version: "0.2.x" });
});

test("0.2.x satisfies 0.2.0 and rejects 0.1.5", () => {
  assert.equal(versionSatisfies("0.2.x", "0.2.0"), true);
  assert.equal(versionSatisfies("0.2.x", "0.2.9"), true);
  assert.equal(versionSatisfies("0.2.x", "0.1.5"), false);
  assert.equal(versionSatisfies("0.2.x", "0.3.0"), false);
});

test("parseSemver reads a leading X.Y.Z", () => {
  assert.deepEqual(parseSemver("0.2.0"), { major: 0, minor: 2, patch: 0 });
  assert.deepEqual(parseSemver("v1.4.8-rc.1"), { major: 1, minor: 4, patch: 8 });
  assert.equal(parseSemver("not-a-version"), undefined);
});

test("findConfig walks upward and returns the nearest fhec.toml", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-hh-cfg-"));
  try {
    const nested = path.join(root, "a", "b");
    fs.mkdirSync(nested, { recursive: true });
    const toml = path.join(root, "fhec.toml");
    fs.writeFileSync(toml, "");
    assert.equal(findConfig(nested), toml);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("mapOverrideKey rewrites a source-tree override key to out/", () => {
  assert.equal(
    mapOverrideKey("contracts/Foo.sol", "contracts", "generated", undefined),
    "generated/Foo.sol",
  );
  assert.equal(
    mapOverrideKey("contracts/Path/File.sol", "contracts", "generated", undefined),
    "generated/Path/File.sol",
  );
  assert.equal(
    mapOverrideKey("contracts/Lib.sol:Lib", "contracts", "generated", undefined),
    "generated/Lib.sol:Lib",
  );
  assert.equal(
    mapOverrideKey("./contracts/Foo.sol", "contracts", "generated", undefined),
    "generated/Foo.sol",
  );
});

test("mapOverrideKey leaves keys that are not under srcDir", () => {
  assert.equal(
    mapOverrideKey("generated/Foo.sol", "contracts", "generated", undefined),
    undefined,
  );
  assert.equal(
    mapOverrideKey("other/Foo.sol", "contracts", "generated", undefined),
    undefined,
  );
  assert.equal(
    mapOverrideKey("contracts-extra/Foo.sol", "contracts", "generated", undefined),
    undefined,
  );
  assert.equal(
    mapOverrideKey("contracts/Foo.sol", "contracts", "contracts", undefined),
    undefined,
  );
});

test("rewriteSolidityOverrides moves source keys and does not overwrite out keys", () => {
  const overrides = {
    "contracts/Pin.sol": { version: "0.8.26" },
    "generated/Keep.sol": { version: "0.8.28" },
    "lib/Other.sol": { version: "0.8.25" },
  };
  const notices = rewriteSolidityOverrides(overrides, "contracts", "generated");
  assert.deepEqual(overrides, {
    "generated/Pin.sol": { version: "0.8.26" },
    "generated/Keep.sol": { version: "0.8.28" },
    "lib/Other.sol": { version: "0.8.25" },
  });
  assert.deepEqual(notices, [
    { from: "contracts/Pin.sol", to: "generated/Pin.sol", action: "rewritten" },
  ]);
});

test("rewriteSolidityOverrides skips when the out key already exists", () => {
  const overrides = {
    "contracts/Pin.sol": { version: "0.8.26" },
    "generated/Pin.sol": { version: "0.8.28" },
  };
  const notices = rewriteSolidityOverrides(overrides, "contracts", "generated");
  assert.deepEqual(overrides, {
    "contracts/Pin.sol": { version: "0.8.26" },
    "generated/Pin.sol": { version: "0.8.28" },
  });
  assert.deepEqual(notices, [
    { from: "contracts/Pin.sol", to: "generated/Pin.sol", action: "skipped" },
  ]);
});

test("formatOverrideWarning names each rewritten key and the generated form", () => {
  const text = formatOverrideWarning(
    [{ from: "contracts/Pin.sol", to: "generated/Pin.sol", action: "rewritten" }],
    "contracts",
    "generated",
  );
  assert.match(text, /@fhec\/hardhat-plugin/);
  assert.match(text, /"contracts\/Pin\.sol" -> "generated\/Pin\.sol"/);
  assert.match(text, /getContractFactory/);
});

function packageRoot(name, fromRoot) {
  const resolved = require.resolve(name, { paths: [fromRoot] });
  let dir = path.dirname(resolved);
  while (!fs.existsSync(path.join(dir, "package.json")) && dir !== path.dirname(dir)) {
    dir = path.dirname(dir);
  }
  return dir;
}

function linkLocalHardhat(dir) {
  const hardhatDir = path.dirname(
    require.resolve("hardhat/package.json", { paths: [pluginRoot] }),
  );
  const nm = path.join(dir, "node_modules");
  fs.mkdirSync(nm, { recursive: true });
  fs.symlinkSync(hardhatDir, path.join(nm, "hardhat"));
}

function linkLocalHardhatEthers(dir) {
  const searchRoots = [
    path.resolve(pluginRoot, "../difftest"),
    pluginRoot,
    path.resolve(pluginRoot, "../.."),
  ];
  let lastErr;
  for (const root of searchRoots) {
    try {
      const pkgDir = packageRoot("@nomicfoundation/hardhat-ethers", root);
      const dest = path.join(dir, "node_modules", "@nomicfoundation", "hardhat-ethers");
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.symlinkSync(pkgDir, dest);
      return;
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr;
}

function writeMinimalConfig(dir, requires) {
  fs.writeFileSync(
    path.join(dir, "fhec.toml"),
    `[project]\nsrc = "contracts"\nout = "generated"\n`,
  );
  fs.writeFileSync(
    path.join(dir, "hardhat.config.js"),
    `'use strict';
${requires}
module.exports = {
  solidity: { version: "0.8.28", settings: { evmVersion: "cancun" } },
};
`,
  );
}

function spawnHreProbe(dir, script) {
  return spawnSync(process.execPath, ["-e", script], {
    cwd: dir,
    encoding: "utf8",
    env: { ...process.env, HARDHAT_DISABLE_TELEMETRY: "true" },
  });
}

test("plugin load rewrites solidity.overrides and warns", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-hh-ov-"));
  try {
    linkLocalHardhat(dir);
    fs.writeFileSync(
      path.join(dir, "fhec.toml"),
      `[project]\nsrc = "contracts"\nout = "generated"\n`,
    );
    fs.writeFileSync(
      path.join(dir, "hardhat.config.js"),
      `'use strict';
require(${JSON.stringify(pluginEntry)});
module.exports = {
  solidity: {
    compilers: [
      { version: "0.8.28", settings: { evmVersion: "cancun" } },
    ],
    overrides: {
      "contracts/Pin.sol": {
        version: "0.8.26",
        settings: { optimizer: { enabled: true, runs: 1 }, evmVersion: "cancun" },
      },
    },
  },
};
`,
    );
    const result = spawnSync(
      process.execPath,
      [
        "-e",
        `const hre = require("hardhat");
         console.log("FHEC_OVERRIDES_JSON:" + JSON.stringify({
           overrideKeys: Object.keys(hre.config.solidity.overrides),
           pinVersion: hre.config.solidity.overrides["generated/Pin.sol"]
             ? hre.config.solidity.overrides["generated/Pin.sol"].version
             : null,
           sources: hre.config.paths.sources,
         }));`,
      ],
      {
        cwd: dir,
        encoding: "utf8",
        env: { ...process.env, HARDHAT_DISABLE_TELEMETRY: "true" },
      },
    );
    assert.equal(
      result.status,
      0,
      `hardhat load failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
    const jsonLine = result.stdout
      .split(/\r?\n/)
      .find((line) => line.startsWith("FHEC_OVERRIDES_JSON:"));
    assert.ok(
      jsonLine,
      `missing FHEC_OVERRIDES_JSON line\nstdout:\n${result.stdout}`,
    );
    const payload = JSON.parse(jsonLine.slice("FHEC_OVERRIDES_JSON:".length));
    assert.deepEqual(payload.overrideKeys, ["generated/Pin.sol"]);
    assert.equal(payload.pinVersion, "0.8.26");
    assert.equal(path.basename(payload.sources), "generated");
    assert.match(
      result.stderr,
      /"contracts\/Pin\.sol" -> "generated\/Pin\.sol"/,
      `expected rewrite warning\n${result.stderr}`,
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("hre.ethers constructors stay unbound when hardhat-ethers loads after this plugin", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-hh-eth-after-"));
  try {
    linkLocalHardhat(dir);
    linkLocalHardhatEthers(dir);
    writeMinimalConfig(
      dir,
      `require(${JSON.stringify(pluginEntry)});
require("@nomicfoundation/hardhat-ethers");`,
    );
    const result = spawnHreProbe(
      dir,
      `const hre = require("hardhat");
       const C1 = hre.ethers.Contract;
       console.log("FHEC_ETHERS_WRAP:" + JSON.stringify({
         present: "ethers" in hre,
         same: C1 === hre.ethers.Contract,
         hasFrom: typeof hre.ethers.Interface.from === "function",
         hasCreateRandom: typeof hre.ethers.Wallet.createRandom === "function",
       }));`,
    );
    assert.equal(
      result.status,
      0,
      `hardhat load failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
    const jsonLine = result.stdout
      .split(/\r?\n/)
      .find((line) => line.startsWith("FHEC_ETHERS_WRAP:"));
    assert.ok(jsonLine, `missing FHEC_ETHERS_WRAP line\nstdout:\n${result.stdout}`);
    const payload = JSON.parse(jsonLine.slice("FHEC_ETHERS_WRAP:".length));
    assert.equal(payload.present, true);
    assert.equal(payload.same, true);
    assert.equal(payload.hasFrom, true);
    assert.equal(payload.hasCreateRandom, true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("hre.ethers constructors stay unbound when hardhat-ethers loads before this plugin", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-hh-eth-before-"));
  try {
    linkLocalHardhat(dir);
    linkLocalHardhatEthers(dir);
    writeMinimalConfig(
      dir,
      `require("@nomicfoundation/hardhat-ethers");
require(${JSON.stringify(pluginEntry)});`,
    );
    const result = spawnHreProbe(
      dir,
      `const hre = require("hardhat");
       const C1 = hre.ethers.Contract;
       console.log("FHEC_ETHERS_WRAP:" + JSON.stringify({
         present: "ethers" in hre,
         same: C1 === hre.ethers.Contract,
         hasFrom: typeof hre.ethers.Interface.from === "function",
         hasCreateRandom: typeof hre.ethers.Wallet.createRandom === "function",
       }));`,
    );
    assert.equal(
      result.status,
      0,
      `hardhat load failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
    const jsonLine = result.stdout
      .split(/\r?\n/)
      .find((line) => line.startsWith("FHEC_ETHERS_WRAP:"));
    assert.ok(jsonLine, `missing FHEC_ETHERS_WRAP line\nstdout:\n${result.stdout}`);
    const payload = JSON.parse(jsonLine.slice("FHEC_ETHERS_WRAP:".length));
    assert.equal(payload.present, true);
    assert.equal(payload.same, true);
    assert.equal(payload.hasFrom, true);
    assert.equal(payload.hasCreateRandom, true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("'ethers' in hre is false when hardhat-ethers is not installed", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-hh-no-ethers-"));
  try {
    linkLocalHardhat(dir);
    fs.writeFileSync(
      path.join(dir, "fhec.toml"),
      `[project]\nsrc = "contracts"\nout = "generated"\n`,
    );
    fs.writeFileSync(
      path.join(dir, "hardhat.config.js"),
      `'use strict';
require(${JSON.stringify(pluginEntry)});
module.exports = {
  solidity: { version: "0.8.28", settings: { evmVersion: "cancun" } },
};
`,
    );
    const result = spawnSync(
      process.execPath,
      [
        "-e",
        `const hre = require("hardhat");
         console.log("FHEC_ETHERS_IN_HRE:" + JSON.stringify({
           present: "ethers" in hre,
           own: Object.prototype.hasOwnProperty.call(hre, "ethers"),
         }));`,
      ],
      {
        cwd: dir,
        encoding: "utf8",
        env: { ...process.env, HARDHAT_DISABLE_TELEMETRY: "true" },
      },
    );
    assert.equal(
      result.status,
      0,
      `hardhat load failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
    const jsonLine = result.stdout
      .split(/\r?\n/)
      .find((line) => line.startsWith("FHEC_ETHERS_IN_HRE:"));
    assert.ok(jsonLine, `missing FHEC_ETHERS_IN_HRE line\nstdout:\n${result.stdout}`);
    const payload = JSON.parse(jsonLine.slice("FHEC_ETHERS_IN_HRE:".length));
    assert.equal(payload.present, false);
    assert.equal(payload.own, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a .fsol solidity.overrides key on a clean tree is rewritten after the manifest appears", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-hh-fsol-ov-"));
  try {
    linkLocalHardhat(dir);
    fs.writeFileSync(
      path.join(dir, "fhec.toml"),
      `[project]\nsrc = "contracts"\nout = "generated"\n`,
    );
    fs.writeFileSync(
      path.join(dir, "hardhat.config.js"),
      `'use strict';
require(${JSON.stringify(pluginEntry)});
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
    const overridesJs = path.join(pluginRoot, "dist", "overrides.js");
    const remapJs = path.join(pluginRoot, "dist", "remap.js");
    const result = spawnSync(
      process.execPath,
      [
        "-e",
        `const fs = require("node:fs");
         const path = require("node:path");
         const hre = require("hardhat");
         const { rewriteSolidityOverrides } = require(${JSON.stringify(overridesJs)});
         const { loadManifest } = require(${JSON.stringify(remapJs)});
         const atLoad = Object.keys(hre.config.solidity.overrides);
         const sources = hre.config.paths.sources;
         fs.mkdirSync(path.join(sources, ".fhec"), { recursive: true });
         fs.writeFileSync(
           path.join(sources, ".fhec", "manifest.json"),
           JSON.stringify({
             tool: "fhec",
             version: "0.0.0",
             files: [{ output: "Pin.sol", source: "Pin.fsol", no_op: false, mappings: [] }],
           }),
         );
         rewriteSolidityOverrides(
           hre.config.solidity.overrides,
           hre.config.fhec.srcDir,
           hre.config.fhec.outDir,
           loadManifest(sources),
         );
         console.log("FHEC_OVERRIDES_JSON:" + JSON.stringify({
           atLoad,
           afterBuild: Object.keys(hre.config.solidity.overrides),
           pinVersion: hre.config.solidity.overrides["generated/Pin.sol"]
             ? hre.config.solidity.overrides["generated/Pin.sol"].version
             : null,
         }));`,
      ],
      {
        cwd: dir,
        encoding: "utf8",
        env: { ...process.env, HARDHAT_DISABLE_TELEMETRY: "true" },
      },
    );
    assert.equal(
      result.status,
      0,
      `hardhat load failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
    const jsonLine = result.stdout
      .split(/\r?\n/)
      .find((line) => line.startsWith("FHEC_OVERRIDES_JSON:"));
    assert.ok(jsonLine, `missing FHEC_OVERRIDES_JSON line\nstdout:\n${result.stdout}`);
    const payload = JSON.parse(jsonLine.slice("FHEC_OVERRIDES_JSON:".length));
    assert.deepEqual(payload.atLoad, ["contracts/Pin.fsol"]);
    assert.deepEqual(payload.afterBuild, ["generated/Pin.sol"]);
    assert.equal(payload.pinVersion, "0.8.26");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
