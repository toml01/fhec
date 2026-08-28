"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { wrapArtifacts } = require("../dist/artifacts");

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

function fakeOriginalArtifacts(recorder) {
  return {
    readArtifact: async (name) => {
      recorder.push(["readArtifact", name]);
      return { contractName: name };
    },
    readArtifactSync: (name) => {
      recorder.push(["readArtifactSync", name]);
      return { contractName: name };
    },
    artifactExists: async (name) => {
      recorder.push(["artifactExists", name]);
      return true;
    },
    getAllFullyQualifiedNames: async () => ["untouched"],
    getBuildInfo: async (name) => {
      recorder.push(["getBuildInfo", name]);
      return undefined;
    },
    getBuildInfoSync: (name) => {
      recorder.push(["getBuildInfoSync", name]);
      return undefined;
    },
    getArtifactPaths: async () => [],
    getDebugFilePaths: async () => [],
    getBuildInfoPaths: async () => [],
    saveArtifactAndDebugFile: async () => {},
    saveBuildInfo: async () => "id",
    formArtifactPathFromFullyQualifiedName: (name) => {
      recorder.push(["formArtifactPathFromFullyQualifiedName", name]);
      return `/artifacts/${name}`;
    },
  };
}

function makeHre(sourcesDir, recorder, enabled = true) {
  return {
    config: {
      fhec: { enabled, srcDir: "contracts", outDir: "generated" },
      paths: { sources: sourcesDir },
    },
    artifacts: fakeOriginalArtifacts(recorder),
  };
}

test("readArtifact resolves a .fsol FQN to the manifest output before delegating", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-artifacts-"));
  try {
    writeManifest(dir, sampleManifest());
    const recorder = [];
    const hre = makeHre(dir, recorder);
    const wrapped = wrapArtifacts(hre);
    await wrapped.readArtifact("contracts/ERC20Confidential/ERC20ConfidentialLib.fsol:ERC20ConfidentialLib");
    assert.deepEqual(recorder, [
      ["readArtifact", "generated/ERC20Confidential/ERC20ConfidentialLib.sol:ERC20ConfidentialLib"],
    ]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("an unknown FQN passes through unchanged", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-artifacts-"));
  try {
    writeManifest(dir, sampleManifest());
    const recorder = [];
    const hre = makeHre(dir, recorder);
    const wrapped = wrapArtifacts(hre);
    await wrapped.readArtifact("contracts/DoesNotExist.fsol:Name");
    assert.deepEqual(recorder, [["readArtifact", "contracts/DoesNotExist.fsol:Name"]]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("with no manifest present, names pass through unchanged", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-artifacts-"));
  try {
    const recorder = [];
    const hre = makeHre(dir, recorder);
    const wrapped = wrapArtifacts(hre);
    wrapped.readArtifactSync("contracts/ERC20Confidential/ERC20ConfidentialLib.fsol:ERC20ConfidentialLib");
    assert.deepEqual(recorder, [
      [
        "readArtifactSync",
        "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol:ERC20ConfidentialLib",
      ],
    ]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("formArtifactPathFromFullyQualifiedName translates too", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-artifacts-"));
  try {
    writeManifest(dir, sampleManifest());
    const recorder = [];
    const hre = makeHre(dir, recorder);
    const wrapped = wrapArtifacts(hre);
    wrapped.formArtifactPathFromFullyQualifiedName(
      "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol:ERC20ConfidentialLib",
    );
    assert.deepEqual(recorder, [
      [
        "formArtifactPathFromFullyQualifiedName",
        "generated/ERC20Confidential/ERC20ConfidentialLib.sol:ERC20ConfidentialLib",
      ],
    ]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("methods with no name argument still delegate", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-artifacts-"));
  try {
    const recorder = [];
    const hre = makeHre(dir, recorder);
    const wrapped = wrapArtifacts(hre);
    assert.deepEqual(await wrapped.getAllFullyQualifiedNames(), ["untouched"]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
