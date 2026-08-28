"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { installVerifyOverride } = require("../dist/verify");

function writeManifest(sourcesDir, manifest) {
  const dir = path.join(sourcesDir, ".fhec");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "manifest.json"), JSON.stringify(manifest));
}

function sampleManifest() {
  return {
    tool: "fhec",
    version: "0.0.0",
    files: [
      {
        output: "ERC20Confidential/ERC20ConfidentialLib.sol",
        source: "ERC20Confidential/ERC20ConfidentialLib.fsol",
        no_op: false,
        mappings: [],
      },
    ],
  };
}

function makeHre({ sourcesDir, hasVerifyTask, enabled = true }) {
  const calls = [];
  const originalRun = async (taskIdentifier, taskArguments, subtaskArguments) => {
    calls.push({ taskIdentifier, taskArguments, subtaskArguments });
    return "result";
  };
  const hre = {
    config: {
      fhec: { enabled, srcDir: "contracts", outDir: "generated" },
      paths: { sources: sourcesDir },
    },
    tasks: hasVerifyTask ? { "verify:verify": {} } : {},
    run: originalRun,
  };
  return { hre, calls, originalRun };
}

test("registers nothing when verify:verify is not a known task", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-verify-"));
  try {
    const { hre, originalRun } = makeHre({ sourcesDir: dir, hasVerifyTask: false });
    installVerifyOverride(hre);
    assert.equal(hre.run, originalRun);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("translates args.contract for a verify:verify run() call", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-verify-"));
  try {
    writeManifest(dir, sampleManifest());
    const { hre, calls } = makeHre({ sourcesDir: dir, hasVerifyTask: true });
    installVerifyOverride(hre);
    assert.notEqual(hre.run, undefined);
    await hre.run("verify:verify", {
      address: "0xabc",
      contract: "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol:ERC20ConfidentialLib",
    });
    assert.equal(calls.length, 1);
    assert.equal(
      calls[0].taskArguments.contract,
      "generated/ERC20Confidential/ERC20ConfidentialLib.sol:ERC20ConfidentialLib",
    );
    assert.equal(calls[0].taskArguments.address, "0xabc");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("also translates when the task identifier is an object form", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-verify-"));
  try {
    writeManifest(dir, sampleManifest());
    const { hre, calls } = makeHre({ sourcesDir: dir, hasVerifyTask: true });
    installVerifyOverride(hre);
    await hre.run(
      { task: "verify:verify" },
      { contract: "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol:ERC20ConfidentialLib" },
    );
    assert.equal(
      calls[0].taskArguments.contract,
      "generated/ERC20Confidential/ERC20ConfidentialLib.sol:ERC20ConfidentialLib",
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("leaves args.contract untouched when it is not a string", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-verify-"));
  try {
    writeManifest(dir, sampleManifest());
    const { hre, calls } = makeHre({ sourcesDir: dir, hasVerifyTask: true });
    installVerifyOverride(hre);
    await hre.run("verify:verify", { contract: 42 });
    assert.equal(calls[0].taskArguments.contract, 42);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("leaves args.contract untouched when it is absent", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-verify-"));
  try {
    writeManifest(dir, sampleManifest());
    const { hre, calls } = makeHre({ sourcesDir: dir, hasVerifyTask: true });
    installVerifyOverride(hre);
    await hre.run("verify:verify", { address: "0xabc" });
    assert.deepEqual(calls[0].taskArguments, { address: "0xabc" });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("does not touch args for an unrelated task", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-verify-"));
  try {
    writeManifest(dir, sampleManifest());
    const { hre, calls } = makeHre({ sourcesDir: dir, hasVerifyTask: true });
    installVerifyOverride(hre);
    await hre.run("compile", {
      contract: "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol:ERC20ConfidentialLib",
    });
    assert.equal(
      calls[0].taskArguments.contract,
      "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol:ERC20ConfidentialLib",
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("does not wrap run when the plugin is disabled", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-verify-"));
  try {
    const { hre, originalRun } = makeHre({ sourcesDir: dir, hasVerifyTask: true, enabled: false });
    installVerifyOverride(hre);
    assert.equal(hre.run, originalRun);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("with no manifest present, args.contract passes through unchanged", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-verify-"));
  try {
    const { hre, calls } = makeHre({ sourcesDir: dir, hasVerifyTask: true });
    installVerifyOverride(hre);
    await hre.run("verify:verify", {
      contract: "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol:ERC20ConfidentialLib",
    });
    assert.equal(
      calls[0].taskArguments.contract,
      "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol:ERC20ConfidentialLib",
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
