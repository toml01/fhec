"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { parseFhecToml, findConfig } = require("../dist/toml");
const { versionSatisfies, parseSemver } = require("../dist/version");

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
