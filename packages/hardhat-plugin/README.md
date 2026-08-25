# @fhec/hardhat-plugin

Hardhat 2 plugin for [`fhec`](https://github.com/toml01/fhec). It transpiles
`.fsol` before `hardhat compile`, points Hardhat `paths.sources` at the fhec
output directory (`generated/` by default), and remaps solc diagnostics from
generated `.sol` spans back to the original `.fsol` through
`generated/.fhec/manifest.json`.

Hardhat 3 is out of scope. CoFHE mock deployment is still provided by
[`@cofhe/hardhat-plugin`](https://www.npmjs.com/package/@cofhe/hardhat-plugin);
this package does not bootstrap mocks.

## Install

```sh
npm install --save-dev @fhec/hardhat-plugin
# or
pnpm add -D @fhec/hardhat-plugin
```

The plugin resolves the native `fhec` binary the same way the `fhec` npm
wrapper does (`fhec/resolve`): `FHEC_BINARY_PATH`, then a platform package,
then a local `target/{release,debug}/fhec` in a monorepo checkout.

Also install `@fhenixprotocol/cofhe-contracts` for any contract that imports
it. If that package is installed but its version does not satisfy the
`[target].version` pin in `fhec.toml` (for example `0.2.x` → `>=0.2.0 <0.3.0`),
the plugin hard-fails with **FHE5003**. If it is not installed, the check is
skipped and solc will fail on the import as usual.

## Usage

```js
// hardhat.config.js
require("@fhec/hardhat-plugin");
// Optional: CoFHE mocks for tests / `hardhat node`.
// require("@cofhe/hardhat-plugin");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.28",
    settings: { evmVersion: "cancun" },
  },
  fhec: {
    // enabled: true,
    // verify: false,
    // acl: "insert",
    // config: "./fhec.toml",
  },
};
```

TypeScript:

```ts
import { HardhatUserConfig } from "hardhat/config";
import "@fhec/hardhat-plugin";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.28",
    settings: { evmVersion: "cancun" },
  },
};

export default config;
```

Run `fhec init` (or write a `fhec.toml`) in the Hardhat project root. On
load, if the plugin is enabled and a config file is found, `paths.sources`
is set to `<root>/<out>` so Hardhat compiles the generated tree. On
`hardhat compile` the plugin runs `fhec build --no-verify` first.

If no `fhec.toml` is present at compile time, the plugin throws and tells
you to run `fhec init` (or set `fhec.enabled: false`).

## Config keys

| Key | Default | Meaning |
|---|---|---|
| `fhec.enabled` | `true` | Run `fhec build` before compile and repoint `paths.sources`. |
| `fhec.verify` | `false` | When `false`, pass `--no-verify` (Hardhat is the solc). When `true`, fhec also runs its solc gate. |
| `fhec.acl` | (unset) | Pass `--acl=insert` or `--acl=suggest`. Unset leaves `fhec.toml` in charge. |
| `fhec.config` | (search) | Path to `fhec.toml`. Relative paths are resolved from the Hardhat project root. |

`[project].src` / `[project].out` / `[target].version` are read from
`fhec.toml`. Defaults match the CLI: `contracts`, `generated`, `0.2.x`.

## Compatibility

- Hardhat **2** only (`peerDependencies.hardhat: ^2.0.0`). Do not use with Hardhat 3.
- Compatible with `@cofhe/hardhat-plugin`: that plugin appends mock sources
  via `GET_SOURCE_PATHS` and deploys mocks on `test` / `node`. This plugin
  does not touch those tasks.
