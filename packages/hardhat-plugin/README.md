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

Hardhat then names artifacts `<out>/Path/File.sol:Name` (default
`generated/...`), not `contracts/Path/File.sol:Name`. `solidity.overrides`
keys that still use the source path are rewritten to the `<out>/` form at
plugin load, with a warning. Test and deploy scripts are not rewritten —
name the `.fsol` file instead, as below.

## Naming a `.fsol` file directly

You can name the `.fsol` file you actually edit — the one under `src`, not
`out` — in a fully-qualified name, and it resolves to the generated
artifact:

```ts
const LIB_FQN =
  "contracts/ERC20Confidential/ERC20ConfidentialLib.fsol:ERC20ConfidentialLib";

const lib = await (await ethers.getContractFactory(LIB_FQN)).deploy();
await ethers.getContractFactory("MyToken", {
  libraries: { [LIB_FQN]: await lib.getAddress() },
});
```

This works for `hre.artifacts.readArtifact` / `readArtifactSync` /
`artifactExists` / `getBuildInfo` / `getBuildInfoSync` /
`formArtifactPathFromFullyQualifiedName`; for `libraries` keys passed to
`getContractFactory` / `getContractFactoryFromArtifact` / `deployContract`;
and for `solidity.overrides` keys (rewritten in place at config load and
again after `fhec build` on `hardhat compile`, with a console warning). The
lookup uses `generated/.fhec/manifest.json`. Artifact reads and `libraries`
keys need a compile first (the manifest is written there); before that, or
for a path the manifest does not know about, the name you gave is passed
straight through to Hardhat unchanged — you get Hardhat's normal "contract
not found" / "not one of its libraries" error, not a silent miss. A
`.fsol` `solidity.overrides` key is rewritten on the first compile as well,
once `fhec build` has written the manifest.

A plain pass-through `.sol` file (one with no dialect features, copied
byte-identical into `out`) is not translated by this alias: it already
keeps its own name, so name it with the `<out>/` prefix directly, as
before.

**`verify:verify` is covered too**, when
[`@nomicfoundation/hardhat-verify`](https://www.npmjs.com/package/@nomicfoundation/hardhat-verify)
is installed — both `npx hardhat verify --contract <fqn> ...` and a
script's own `run("verify:verify", { contract: <fqn>, ... })`. A `.fsol`
`--contract` argument is translated to the generated `.sol` path before
Etherscan (or another explorer) sees it, since it must receive the source
that produced the bytecode. This does not depend on whether
`hardhat-verify` or `@fhec/hardhat-plugin` is `require`d first in your
Hardhat config. If `hardhat-verify` is not installed, nothing is
registered.

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

## Local checkout

These packages are not on the npm registry yet. `pnpm add -D
@fhec/hardhat-plugin` therefore cannot work from a project outside this
monorepo: the plugin depends on `fhec` via `workspace:^0.1.0`, and the
`fhec` wrapper looks for `target/{release,debug}/fhec` relative to the
cargo checkout.

Until the first publish (see [`RELEASING.md`](../../RELEASING.md)), wire a
Hardhat 2 project to this checkout as follows.

1. Add the plugin as a `file:` dependency:

   ```sh
   pnpm add -D file:/abs/path/to/fhec/packages/hardhat-plugin
   ```

2. pnpm materialises that `file:` dependency in its store, so `fhec@workspace:`
   is not visible. Override it to the wrapper package:

   ```json
   {
     "pnpm": {
       "overrides": {
         "fhec": "file:/abs/path/to/fhec/packages/fhec"
       }
     }
   }
   ```

3. The wrapper's cargo fallback (`../../../target/{release,debug}/fhec`
   relative to `packages/fhec/lib/resolve.js`) no longer reaches this
   checkout after the store copy. Point it at a binary you built:

   ```sh
   cargo build --release -p fhec-cli
   export FHEC_BINARY_PATH=/abs/path/to/fhec/target/release/fhec
   ```

Both the override and `FHEC_BINARY_PATH` are required. Neither is enough
on its own.
