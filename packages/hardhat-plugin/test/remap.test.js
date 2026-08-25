"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  remapRange,
  matchManifestFile,
  displaySourcePath,
  remapSolcOutput,
  byteOffsetToLineCol,
} = require("../dist/remap");

// Sample from crates/fhec-emit/src/manifest.rs tests.
function sampleManifest() {
  return {
    tool: "fhec",
    version: "0.0.0",
    files: [
      {
        output: "A.sol",
        source: "A.fsol",
        no_op: false,
        mappings: [
          {
            output_range: [120, 155],
            source_range: [120, 131],
            rule: "operator-lowering",
          },
          {
            output_range: [200, 245],
            source_range: [180, 180],
            rule: "§8.1 R1",
            code: "FHE4001",
          },
        ],
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

test("start inside first mapping blames the whole source range", () => {
  const file = sampleManifest().files[0];
  assert.deepEqual(remapRange(file, 120, 130), {
    start: 120,
    end: 131,
    insideGenerated: true,
  });
});

test("start after mappings shifts by the last mapping delta", () => {
  const file = sampleManifest().files[0];
  // last mapping with output_end <= 250 is [200, 245] → delta = 245 - 180 = 65
  assert.deepEqual(remapRange(file, 250, 260), {
    start: 185,
    end: 195,
    insideGenerated: false,
  });
});

test("start between mappings uses the previous mapping's delta", () => {
  const file = sampleManifest().files[0];
  // last mapping with output_end <= 180 is [120, 155] → delta = 155 - 131 = 24
  assert.deepEqual(remapRange(file, 180, 190), {
    start: 156,
    end: 166,
    insideGenerated: false,
  });
});

test("no-op file with empty mappings leaves offsets unchanged", () => {
  const file = sampleManifest().files[1];
  assert.deepEqual(remapRange(file, 40, 55), {
    start: 40,
    end: 55,
    insideGenerated: false,
  });
});

test("position before the first mapping is identity", () => {
  const file = sampleManifest().files[0];
  assert.deepEqual(remapRange(file, 10, 20), {
    start: 10,
    end: 20,
    insideGenerated: false,
  });
});

test("matchManifestFile strips the out-dir prefix", () => {
  const manifest = sampleManifest();
  const hit = matchManifestFile("generated/A.sol", "generated", manifest);
  assert.equal(hit && hit.source, "A.fsol");
  assert.equal(matchManifestFile("contracts/A.sol", "generated", manifest), undefined);
});

test("displaySourcePath joins src dir and manifest source", () => {
  assert.equal(displaySourcePath("contracts", "Counter.fsol"), "contracts/Counter.fsol");
  assert.equal(displaySourcePath("contracts", "nested/C.fsol"), "contracts/nested/C.fsol");
});

test("remapSolcOutput rewrites file, range, and formattedMessage path", () => {
  const manifest = sampleManifest();
  const output = {
    errors: [
      {
        sourceLocation: { file: "generated/A.sol", start: 120, end: 140 },
        formattedMessage: "TypeError: nope\n --> generated/A.sol:6:1:\n",
      },
    ],
  };
  remapSolcOutput(output, {
    manifest,
    outDir: "generated",
    srcDir: "contracts",
    projectRoot: path.join(__dirname, "does-not-exist"),
    sourcesDir: path.join(__dirname, "does-not-exist"),
  });
  assert.equal(output.errors[0].sourceLocation.file, "contracts/A.fsol");
  assert.equal(output.errors[0].sourceLocation.start, 120);
  assert.equal(output.errors[0].sourceLocation.end, 131);
  assert.match(output.errors[0].formattedMessage, /contracts\/A\.fsol/);
  assert.doesNotMatch(output.errors[0].formattedMessage, /generated\/A\.sol/);
});

test("remapSolcOutput leaves unmatched files unchanged", () => {
  const output = {
    errors: [
      {
        sourceLocation: { file: "node_modules/lib/X.sol", start: 4, end: 8 },
        formattedMessage: " --> node_modules/lib/X.sol:1:5:\n",
      },
    ],
  };
  remapSolcOutput(output, {
    manifest: sampleManifest(),
    outDir: "generated",
    srcDir: "contracts",
    projectRoot: "/tmp",
    sourcesDir: "/tmp/generated",
  });
  assert.equal(output.errors[0].sourceLocation.file, "node_modules/lib/X.sol");
  assert.equal(output.errors[0].sourceLocation.start, 4);
});

test("byteOffsetToLineCol is 1-based and counts UTF-8 bytes", () => {
  assert.deepEqual(byteOffsetToLineCol("ab\ncd", 0), { line: 1, column: 1 });
  assert.deepEqual(byteOffsetToLineCol("ab\ncd", 3), { line: 2, column: 1 });
});
