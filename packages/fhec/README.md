# fhec

npm wrapper for the `fhec` native binary (the Rust CLI in `crates/fhec-cli`),
following the platform-package distribution model used by esbuild and
biome: this package is a thin JS entry point (`bin/fhec.js`) that finds a
prebuilt native binary for the current platform/arch and execs it,
forwarding args and exit code. Resolution lives in `lib/resolve.js` and
is exported as `fhec/resolve` for the Hardhat plugin and other tooling.

This package is the published JS wrapper (`fhec` on npm). Platform packages
(`@fhec/cli-<platform>`) are not published yet, so a registry or `file:`
install still needs `FHEC_BINARY_PATH` (or a local `cargo build`) until
those packages ship a binary. See [`RELEASING.md`](../../RELEASING.md).

## Binary resolution order

`fhec/resolve` looks for the native binary in this order, stopping at the
first one it finds:

1. **`FHEC_BINARY_PATH`** — if set, used as-is (existence-checked).
2. **The platform package** for the current `process.platform`/`process.arch`,
   e.g. `@fhec/cli-darwin-arm64`. Resolved via `require.resolve`, with the
   binary expected at `<package>/bin/fhec`.
3. **Dev fallback** — `../../../target/release/fhec`, then
   `../../../target/debug/fhec`, resolved relative to `lib/resolve.js`
   (this file lives at `packages/fhec/lib/resolve.js`, so the repo root is
   three levels up). This layout exists only when the package sits in this
   checkout (a workspace install or `link:`). A `file:` or registry copy
   does not keep it; use `FHEC_BINARY_PATH` or a platform package.

If none of these resolve, `fhec.js` exits 1 and prints every location it
tried.

## Dogfooding locally

From the repo root:

```sh
pnpm --filter fhec run build:native
pnpm --filter fhec exec node bin/fhec.js --help
```

(`pnpm exec fhec` does not resolve here — pnpm does not symlink a package's
own `bin` entry into its own `node_modules/.bin`; running the entry point
with `node` directly works the same way `fhec` would once it is actually
installed as a dependency somewhere.)

`build:native` runs `cargo build --release -p fhec-cli` and copies the
resulting binary into `packages/fhec-darwin-arm64/bin/fhec` (today this only
covers darwin-arm64; the binary itself is never committed, see that
package's `.gitignore`).

## Tests

```sh
pnpm --filter fhec run test
```

`test/smoke.test.mjs` builds the native binary via `build:native` if it is
missing (skipping gracefully if `cargo` is not available), then checks
`fhec explain`, `fhec check`, and the `FHEC_BINARY_PATH` override against
the real binary.
