"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { mapOverrideKey, rewriteSolidityOverrides, formatOverrideWarning } = require("../dist/overrides");

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

test("mapOverrideKey rewrites a plain .sol key without needing a manifest", () => {
  assert.equal(mapOverrideKey("contracts/B.sol", "contracts", "generated", undefined), "generated/B.sol");
});

test("mapOverrideKey rewrites a .fsol key via the manifest", () => {
  assert.equal(
    mapOverrideKey(
      "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol",
      "contracts",
      "generated",
      sampleManifest(),
    ),
    "generated/ERC20Confidential/ERC20ConfidentialLib.sol",
  );
});

test("mapOverrideKey preserves a :Contract suffix on a .fsol key", () => {
  assert.equal(
    mapOverrideKey(
      "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol:ERC20ConfidentialLib",
      "contracts",
      "generated",
      sampleManifest(),
    ),
    "generated/ERC20Confidential/ERC20ConfidentialLib.sol:ERC20ConfidentialLib",
  );
});

test("mapOverrideKey leaves a .fsol key alone when there is no manifest", () => {
  assert.equal(
    mapOverrideKey(
      "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol",
      "contracts",
      "generated",
      undefined,
    ),
    undefined,
  );
});

test("mapOverrideKey leaves a .fsol key alone when the manifest has no matching entry", () => {
  assert.equal(
    mapOverrideKey("contracts/Missing.fsol", "contracts", "generated", sampleManifest()),
    undefined,
  );
});

test("mapOverrideKey leaves a key already under outDir alone", () => {
  assert.equal(mapOverrideKey("generated/B.sol", "contracts", "generated", undefined), undefined);
});

test("mapOverrideKey leaves a key outside srcDir alone", () => {
  assert.equal(mapOverrideKey("lib/B.sol", "contracts", "generated", undefined), undefined);
});

test("rewriteSolidityOverrides moves matching keys in place and reports notices", () => {
  const overrides = {
    "contracts/B.sol": { version: "0.8.26" },
    "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol": { version: "0.8.26" },
    "lib/Other.sol": { version: "0.8.20" },
  };
  const notices = rewriteSolidityOverrides(overrides, "contracts", "generated", sampleManifest());
  assert.deepEqual(Object.keys(overrides).sort(), [
    "generated/B.sol",
    "generated/ERC20Confidential/ERC20ConfidentialLib.sol",
    "lib/Other.sol",
  ]);
  assert.equal(overrides["generated/B.sol"].version, "0.8.26");
  assert.equal(notices.length, 2);
  assert.ok(notices.every((n) => n.action === "rewritten"));
});

test("a .fsol override key is rewritten only after a manifest appears", () => {
  const overrides = {
    "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol": { version: "0.8.26" },
  };
  const before = rewriteSolidityOverrides(overrides, "contracts", "generated", undefined);
  assert.deepEqual(before, []);
  assert.deepEqual(Object.keys(overrides), [
    "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol",
  ]);

  const after = rewriteSolidityOverrides(overrides, "contracts", "generated", sampleManifest());
  assert.deepEqual(after, [
    {
      from: "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol",
      to: "generated/ERC20Confidential/ERC20ConfidentialLib.sol",
      action: "rewritten",
    },
  ]);
  assert.deepEqual(Object.keys(overrides), ["generated/ERC20Confidential/ERC20ConfidentialLib.sol"]);
  assert.equal(overrides["generated/ERC20Confidential/ERC20ConfidentialLib.sol"].version, "0.8.26");
});

test("rewriteSolidityOverrides skips a rewrite that would clobber an existing destination", () => {
  const overrides = {
    "contracts/B.sol": { version: "0.8.26" },
    "generated/B.sol": { version: "0.8.20" },
  };
  const notices = rewriteSolidityOverrides(overrides, "contracts", "generated", undefined);
  assert.deepEqual(notices, [{ from: "contracts/B.sol", to: "generated/B.sol", action: "skipped" }]);
  assert.equal(overrides["contracts/B.sol"].version, "0.8.26");
  assert.equal(overrides["generated/B.sol"].version, "0.8.20");
});

test("formatOverrideWarning mentions both rewritten and skipped keys", () => {
  const message = formatOverrideWarning(
    [
      { from: "contracts/B.sol", to: "generated/B.sol", action: "rewritten" },
      { from: "contracts/C.sol", to: "generated/C.sol", action: "skipped" },
    ],
    "contracts",
    "generated",
  );
  assert.match(message, /Rewrote solidity\.overrides keys/);
  assert.match(message, /"contracts\/B\.sol" -> "generated\/B\.sol"/);
  assert.match(message, /Did not rewrite/);
  assert.match(message, /"contracts\/C\.sol"/);
});
