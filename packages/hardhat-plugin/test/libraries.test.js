"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  translateLibrariesMap,
  translateFactoryOptionsArg,
  installLibrariesTranslation,
} = require("../dist/libraries");

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

const FSOL_FQN =
  "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol:ERC20ConfidentialLib";
const GENERATED_FQN =
  "generated/ERC20Confidential/ERC20ConfidentialLib.sol:ERC20ConfidentialLib";
const LIB_ADDRESS = "0x" + "11".repeat(20);

test("translateLibrariesMap rewrites a .fsol FQN to the manifest output", () => {
  const result = translateLibrariesMap(
    { [FSOL_FQN]: LIB_ADDRESS },
    "contracts",
    "generated",
    sampleManifest(),
  );
  assert.deepEqual(result, { [GENERATED_FQN]: LIB_ADDRESS });
});

test("translateLibrariesMap leaves a generated FQN unchanged", () => {
  const libraries = { [GENERATED_FQN]: LIB_ADDRESS };
  const result = translateLibrariesMap(libraries, "contracts", "generated", sampleManifest());
  assert.equal(result, libraries);
  assert.deepEqual(result, { [GENERATED_FQN]: LIB_ADDRESS });
});

test("translateLibrariesMap leaves a bare library name unchanged", () => {
  const libraries = { ERC20ConfidentialLib: LIB_ADDRESS };
  const result = translateLibrariesMap(libraries, "contracts", "generated", sampleManifest());
  assert.equal(result, libraries);
});

test("translateLibrariesMap leaves an unknown .fsol FQN unchanged", () => {
  const libraries = { "contracts/Missing.fsol:Name": LIB_ADDRESS };
  const result = translateLibrariesMap(libraries, "contracts", "generated", sampleManifest());
  assert.equal(result, libraries);
});

test("translateLibrariesMap leaves keys unchanged when there is no manifest", () => {
  const libraries = { [FSOL_FQN]: LIB_ADDRESS };
  const result = translateLibrariesMap(libraries, "contracts", "generated", undefined);
  assert.equal(result, libraries);
});

test("translateLibrariesMap keeps a generated entry when both spellings are present", () => {
  const generatedAddress = "0x" + "22".repeat(20);
  const result = translateLibrariesMap(
    {
      [GENERATED_FQN]: generatedAddress,
      [FSOL_FQN]: LIB_ADDRESS,
    },
    "contracts",
    "generated",
    sampleManifest(),
  );
  assert.deepEqual(result, { [GENERATED_FQN]: generatedAddress });
});

test("translateFactoryOptionsArg rewrites libraries on FactoryOptions", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    writeManifest(dir, sampleManifest());
    const hre = {
      config: {
        fhec: { enabled: true, srcDir: "contracts", outDir: "generated" },
        paths: { sources: dir },
      },
    };
    const translated = translateFactoryOptionsArg(hre, {
      libraries: { [FSOL_FQN]: LIB_ADDRESS },
    });
    assert.deepEqual(translated, { libraries: { [GENERATED_FQN]: LIB_ADDRESS } });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("translateFactoryOptionsArg does not treat a Signer as FactoryOptions", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    writeManifest(dir, sampleManifest());
    const hre = {
      config: {
        fhec: { enabled: true, srcDir: "contracts", outDir: "generated" },
        paths: { sources: dir },
      },
    };
    const signer = { provider: {}, libraries: { [FSOL_FQN]: LIB_ADDRESS } };
    assert.equal(translateFactoryOptionsArg(hre, signer), signer);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

function fakeEthers(recorder) {
  return {
    getContractFactory: async (...args) => {
      recorder.push(["getContractFactory", args]);
      return { name: "factory" };
    },
    getContractFactoryFromArtifact: async (...args) => {
      recorder.push(["getContractFactoryFromArtifact", args]);
      return { name: "fromArtifact" };
    },
    deployContract: async (...args) => {
      recorder.push(["deployContract", args]);
      return { name: "deployed" };
    },
    getSigners: async () => {
      recorder.push(["getSigners"]);
      return [];
    },
  };
}

function makeHre({ sourcesDir, enabled = true, ethers }) {
  return {
    config: {
      fhec: { enabled, srcDir: "contracts", outDir: "generated" },
      paths: { sources: sourcesDir },
    },
    ethers,
  };
}

test("getContractFactory translates a .fsol libraries key before delegating", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    writeManifest(dir, sampleManifest());
    const recorder = [];
    const hre = makeHre({ sourcesDir: dir, ethers: fakeEthers(recorder) });
    installLibrariesTranslation(hre);
    await hre.ethers.getContractFactory("MyToken", {
      libraries: { [FSOL_FQN]: LIB_ADDRESS },
    });
    assert.equal(recorder.length, 1);
    assert.equal(recorder[0][0], "getContractFactory");
    assert.deepEqual(recorder[0][1], [
      "MyToken",
      { libraries: { [GENERATED_FQN]: LIB_ADDRESS } },
    ]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("deployContract translates a .fsol libraries key too", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    writeManifest(dir, sampleManifest());
    const recorder = [];
    const hre = makeHre({ sourcesDir: dir, ethers: fakeEthers(recorder) });
    installLibrariesTranslation(hre);
    await hre.ethers.deployContract("MyToken", [], {
      libraries: { [FSOL_FQN]: LIB_ADDRESS },
    });
    assert.deepEqual(recorder[0][1], [
      "MyToken",
      [],
      { libraries: { [GENERATED_FQN]: LIB_ADDRESS } },
    ]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("getContractFactoryFromArtifact translates a .fsol libraries key too", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    writeManifest(dir, sampleManifest());
    const recorder = [];
    const hre = makeHre({ sourcesDir: dir, ethers: fakeEthers(recorder) });
    installLibrariesTranslation(hre);
    const artifact = { contractName: "MyToken" };
    await hre.ethers.getContractFactoryFromArtifact(artifact, {
      libraries: { [FSOL_FQN]: LIB_ADDRESS },
    });
    assert.deepEqual(recorder[0][1], [
      artifact,
      { libraries: { [GENERATED_FQN]: LIB_ADDRESS } },
    ]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a generated/*.sol libraries key is left unchanged", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    writeManifest(dir, sampleManifest());
    const recorder = [];
    const hre = makeHre({ sourcesDir: dir, ethers: fakeEthers(recorder) });
    installLibrariesTranslation(hre);
    await hre.ethers.getContractFactory("MyToken", {
      libraries: { [GENERATED_FQN]: LIB_ADDRESS },
    });
    assert.deepEqual(recorder[0][1], [
      "MyToken",
      { libraries: { [GENERATED_FQN]: LIB_ADDRESS } },
    ]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("getContractFactory with a signer (no libraries) is left unchanged", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    writeManifest(dir, sampleManifest());
    const recorder = [];
    const hre = makeHre({ sourcesDir: dir, ethers: fakeEthers(recorder) });
    installLibrariesTranslation(hre);
    const signer = { provider: {}, getAddress: async () => LIB_ADDRESS };
    await hre.ethers.getContractFactory("MyToken", signer);
    assert.deepEqual(recorder[0][1], ["MyToken", signer]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("methods with no libraries argument still delegate", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    const recorder = [];
    const hre = makeHre({ sourcesDir: dir, ethers: fakeEthers(recorder) });
    installLibrariesTranslation(hre);
    await hre.ethers.getSigners();
    assert.deepEqual(recorder, [["getSigners"]]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("ethers assigned after install is still wrapped (plugin require order)", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    writeManifest(dir, sampleManifest());
    const recorder = [];
    const hre = makeHre({ sourcesDir: dir });
    installLibrariesTranslation(hre);
    hre.ethers = fakeEthers(recorder);
    await hre.ethers.getContractFactory("MyToken", {
      libraries: { [FSOL_FQN]: LIB_ADDRESS },
    });
    assert.deepEqual(recorder[0][1], [
      "MyToken",
      { libraries: { [GENERATED_FQN]: LIB_ADDRESS } },
    ]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("does not wrap ethers when the plugin is disabled", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    const original = fakeEthers([]);
    const hre = makeHre({ sourcesDir: dir, enabled: false, ethers: original });
    installLibrariesTranslation(hre);
    assert.equal(hre.ethers, original);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("with no manifest present, libraries keys pass through unchanged", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    const recorder = [];
    const hre = makeHre({ sourcesDir: dir, ethers: fakeEthers(recorder) });
    installLibrariesTranslation(hre);
    await hre.ethers.getContractFactory("MyToken", {
      libraries: { [FSOL_FQN]: LIB_ADDRESS },
    });
    assert.deepEqual(recorder[0][1], [
      "MyToken",
      { libraries: { [FSOL_FQN]: LIB_ADDRESS } },
    ]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
