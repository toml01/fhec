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
  function Contract() {}
  Contract.from = () => "contract-from";
  function Wallet() {}
  Wallet.createRandom = () => "random-wallet";
  function Interface() {}
  Interface.from = () => "interface-from";
  return {
    Contract,
    Wallet,
    Interface,
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

function requireHardhatEthersHelpers() {
  const roots = [
    path.resolve(__dirname, "../../difftest"),
    path.resolve(__dirname, ".."),
    path.resolve(__dirname, "../../.."),
  ];
  let lastErr;
  for (const root of roots) {
    try {
      return require(
        require.resolve("@nomicfoundation/hardhat-ethers/internal/helpers", { paths: [root] }),
      );
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr;
}

function linkedUserArtifact() {
  return {
    contractName: "User",
    sourceName: "generated/Path/User.sol",
    abi: [],
    bytecode: "0x00" + "00".repeat(20) + "ff",
    deployedBytecode: "0x",
    linkReferences: {
      "generated/Path/Lib.sol": {
        Lib: [{ start: 1, length: 20 }],
      },
    },
    deployedLinkReferences: {},
  };
}

function pathLibManifest() {
  return {
    tool: "fhec",
    version: "0.0.0",
    files: [
      {
        output: "Path/Lib.sol",
        source: "Path/Lib.fsol",
        no_op: false,
        mappings: [],
      },
    ],
  };
}

const PATH_FSOL_FQN = "contracts/Path/Lib.fsol:Lib";
const PATH_GENERATED_FQN = "generated/Path/Lib.sol:Lib";

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

test("FactoryOptions with signer and libraries together is rewritten", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    writeManifest(dir, sampleManifest());
    const recorder = [];
    const hre = makeHre({ sourcesDir: dir, ethers: fakeEthers(recorder) });
    installLibrariesTranslation(hre);
    const signer = { provider: {}, getAddress: async () => LIB_ADDRESS };
    await hre.ethers.getContractFactory("MyToken", {
      signer,
      libraries: { [FSOL_FQN]: LIB_ADDRESS },
    });
    assert.deepEqual(recorder[0][1], [
      "MyToken",
      { signer, libraries: { [GENERATED_FQN]: LIB_ADDRESS } },
    ]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("class constructors on hre.ethers are not bound", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    const original = fakeEthers([]);
    const hre = makeHre({ sourcesDir: dir, ethers: original });
    installLibrariesTranslation(hre);
    assert.equal(hre.ethers.Contract, original.Contract);
    assert.equal(hre.ethers.Wallet, original.Wallet);
    assert.equal(hre.ethers.Interface, original.Interface);
    assert.equal(hre.ethers.Contract, hre.ethers.Contract);
    assert.equal(hre.ethers.Wallet.createRandom(), "random-wallet");
    assert.equal(hre.ethers.Interface.from(), "interface-from");
    assert.equal(hre.ethers.Contract.from(), "contract-from");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("wrapping ethers does not trip a lazyObject has/get trap", () => {
  const { lazyObject } = require("hardhat/plugins");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    let constructed = 0;
    const inner = fakeEthers([]);
    const lazy = lazyObject(() => {
      constructed += 1;
      return inner;
    });
    const hre = makeHre({ sourcesDir: dir, ethers: lazy });
    installLibrariesTranslation(hre);
    assert.equal(constructed, 0);
    assert.equal(hre.ethers.Wallet.createRandom(), "random-wallet");
    assert.equal(constructed, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("getContractFactoryFromArtifact does not rewrite the artifact argument", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    writeManifest(dir, sampleManifest());
    const recorder = [];
    const hre = makeHre({ sourcesDir: dir, ethers: fakeEthers(recorder) });
    installLibrariesTranslation(hre);
    const artifact = { contractName: "MyToken", libraries: { [FSOL_FQN]: LIB_ADDRESS } };
    await hre.ethers.getContractFactoryFromArtifact(artifact, {
      libraries: { [FSOL_FQN]: LIB_ADDRESS },
    });
    assert.equal(recorder[0][1][0], artifact);
    assert.deepEqual(recorder[0][1][0].libraries, { [FSOL_FQN]: LIB_ADDRESS });
    assert.deepEqual(recorder[0][1][1], { libraries: { [GENERATED_FQN]: LIB_ADDRESS } });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("deployContract does not rewrite constructor args that look like a libraries map", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    writeManifest(dir, sampleManifest());
    const recorder = [];
    const hre = makeHre({ sourcesDir: dir, ethers: fakeEthers(recorder) });
    installLibrariesTranslation(hre);
    const ctorArg = { libraries: { [FSOL_FQN]: LIB_ADDRESS } };
    await hre.ethers.deployContract("MyToken", [ctorArg]);
    assert.equal(recorder[0][1][1][0], ctorArg);
    assert.deepEqual(ctorArg, { libraries: { [FSOL_FQN]: LIB_ADDRESS } });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("getContractFactory ABI form does not rewrite a bytecode-slot object", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    writeManifest(dir, sampleManifest());
    const recorder = [];
    const hre = makeHre({ sourcesDir: dir, ethers: fakeEthers(recorder) });
    installLibrariesTranslation(hre);
    const abi = [{ type: "constructor", inputs: [] }];
    const bytecodeOrOptions = { libraries: { [FSOL_FQN]: LIB_ADDRESS } };
    await hre.ethers.getContractFactory(abi, bytecodeOrOptions);
    assert.equal(recorder[0][1][0], abi);
    assert.equal(recorder[0][1][1], bytecodeOrOptions);
    assert.deepEqual(bytecodeOrOptions, { libraries: { [FSOL_FQN]: LIB_ADDRESS } });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("deployContract options slot is rewritten when constructor args are present", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    writeManifest(dir, sampleManifest());
    const recorder = [];
    const hre = makeHre({ sourcesDir: dir, ethers: fakeEthers(recorder) });
    installLibrariesTranslation(hre);
    await hre.ethers.deployContract("MyToken", ["arg0"], {
      libraries: { [FSOL_FQN]: LIB_ADDRESS },
    });
    assert.deepEqual(recorder[0][1], [
      "MyToken",
      ["arg0"],
      { libraries: { [GENERATED_FQN]: LIB_ADDRESS } },
    ]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("hardhat-ethers linking accepts a translated .fsol libraries key", async () => {
  const helpers = requireHardhatEthersHelpers();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fhec-libs-"));
  try {
    writeManifest(dir, pathLibManifest());
    const artifact = linkedUserArtifact();
    const signer = { provider: {} };
    const innerHre = {
      artifacts: { readArtifact: async () => artifact },
      ethers: { getSigners: async () => [signer] },
    };

    await assert.rejects(
      () =>
        helpers.getContractFactoryFromArtifact(innerHre, artifact, {
          libraries: { [PATH_FSOL_FQN]: LIB_ADDRESS },
          signer,
        }),
      (err) => /which is not one of its libraries/.test(String(err && err.message)),
    );

    const ethersObj = {
      getContractFactory: (name, opts) => helpers.getContractFactory(innerHre, name, opts),
      getContractFactoryFromArtifact: (art, opts) =>
        helpers.getContractFactoryFromArtifact(innerHre, art, opts),
    };
    const hre = makeHre({ sourcesDir: dir, ethers: ethersObj });
    installLibrariesTranslation(hre);

    const fromArtifact = await hre.ethers.getContractFactoryFromArtifact(artifact, {
      libraries: { [PATH_FSOL_FQN]: LIB_ADDRESS },
      signer,
    });
    assert.match(fromArtifact.bytecode, /11111111/);

    const fromName = await hre.ethers.getContractFactory("User", {
      libraries: { [PATH_FSOL_FQN]: LIB_ADDRESS },
      signer,
    });
    assert.match(fromName.bytecode, /11111111/);

    const fromGenerated = await hre.ethers.getContractFactory("User", {
      libraries: { [PATH_GENERATED_FQN]: LIB_ADDRESS },
      signer,
    });
    assert.match(fromGenerated.bytecode, /11111111/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
