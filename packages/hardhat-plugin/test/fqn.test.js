"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { translateFsolFqn } = require("../dist/fqn");

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
      {
        output: "B.sol",
        source: "B.sol",
        no_op: true,
        mappings: [],
      },
    ],
  };
}

test("translates a .fsol FQN under srcDir to the manifest output under outDir", () => {
  const result = translateFsolFqn(
    "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol:ERC20ConfidentialLib",
    "contracts",
    "generated",
    sampleManifest(),
  );
  assert.equal(result, "generated/ERC20Confidential/ERC20ConfidentialLib.sol:ERC20ConfidentialLib");
});

test("translates a bare .fsol source path with no :Contract suffix", () => {
  const result = translateFsolFqn(
    "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol",
    "contracts",
    "generated",
    sampleManifest(),
  );
  assert.equal(result, "generated/ERC20Confidential/ERC20ConfidentialLib.sol");
});

test("an unknown FQN passes through unchanged (returns undefined)", () => {
  assert.equal(
    translateFsolFqn("contracts/DoesNotExist.fsol:Name", "contracts", "generated", sampleManifest()),
    undefined,
  );
});

test("a plain .sol file under srcDir needs no alias", () => {
  assert.equal(
    translateFsolFqn("contracts/B.sol:B", "contracts", "generated", sampleManifest()),
    undefined,
  );
});

test("an FQN outside srcDir passes through unchanged", () => {
  assert.equal(
    translateFsolFqn("node_modules/lib/X.sol:X", "contracts", "generated", sampleManifest()),
    undefined,
  );
});

test("a bare contract name (no path) passes through unchanged", () => {
  assert.equal(
    translateFsolFqn("ERC20ConfidentialLib", "contracts", "generated", sampleManifest()),
    undefined,
  );
});
