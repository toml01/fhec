#!/usr/bin/env node
/**
 * Transpile `contracts-dialect/*.fsol` into `contracts/generated/` with the
 * real fhec CLI (see ../fhec.toml for the src/out wiring).
 *
 * Prefers `cargo run --release` so a stale binary can never be tested by
 * accident — cargo rebuilds only what changed, so the fresh-build case costs
 * ~2s. Falls back to an existing `target/release/fhec` when cargo is not
 * installed (e.g. a JS-only checkout), and fails loudly when neither exists.
 */
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkgDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(pkgDir, '../..');
const releaseBinary = join(repoRoot, 'target', 'release', 'fhec');

const run = (cmd, args) => spawnSync(cmd, args, { cwd: pkgDir, stdio: 'inherit' });

const haveCargo = spawnSync('cargo', ['--version'], { stdio: 'ignore' }).status === 0;

let result;
if (haveCargo) {
  result = run('cargo', [
    'run',
    '--release',
    '--quiet',
    '-p',
    'fhec-cli',
    '--manifest-path',
    join(repoRoot, 'Cargo.toml'),
    '--',
    'build',
  ]);
} else if (existsSync(releaseBinary)) {
  result = run(releaseBinary, ['build']);
} else {
  console.error('build-dialect: neither cargo nor a prebuilt target/release/fhec is available.');
  console.error('Install rust (rustup) or build the CLI once on a machine that has it.');
  process.exit(1);
}

process.exit(result.status ?? 1);
