#!/usr/bin/env node
/**
 * Transpile both dialect projects with the real fhec CLI:
 *   - `contracts-dialect/*.fsol` -> `contracts/generated/` (../fhec.toml,
 *     ACL mode insert);
 *   - `contracts-dialect-fherc20/*.fsol` -> `contracts/generated-fherc20/`
 *     (../fhec.fherc20.toml, ACL mode suggest — FHERC20's account-directed
 *     grants are explicit in the source).
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

/** One `fhec build` for the given config file (undefined = default fhec.toml). */
function build(configFile) {
  const configArgs = configFile ? ['--config', configFile] : [];
  if (haveCargo) {
    return run('cargo', [
      'run',
      '--release',
      '--quiet',
      '-p',
      'fhec-cli',
      '--manifest-path',
      join(repoRoot, 'Cargo.toml'),
      '--',
      ...configArgs,
      'build',
    ]);
  }
  if (existsSync(releaseBinary)) {
    return run(releaseBinary, [...configArgs, 'build']);
  }
  console.error('build-dialect: neither cargo nor a prebuilt target/release/fhec is available.');
  console.error('Install rust (rustup) or build the CLI once on a machine that has it.');
  process.exit(1);
}

for (const configFile of [undefined, 'fhec.fherc20.toml']) {
  const result = build(configFile);
  if ((result.status ?? 1) !== 0) process.exit(result.status ?? 1);
}

process.exit(0);
