# Releasing npm packages

Do not publish until platform binaries exist and an npm account is ready.
This file is the order of operations. It does not configure CI credentials.

Keep package versions in lockstep (`0.1.0` today):

| Package | Directory | Depends on |
|---|---|---|
| `@fhec/cli-<platform>` | `packages/fhec-darwin-arm64` (and later platform dirs) | nothing |
| `fhec` | `packages/fhec` | optional `@fhec/cli-*` |
| `@fhec/hardhat-plugin` | `packages/hardhat-plugin` | `fhec` |

pnpm rewrites `workspace:^x.y.z` in `package.json` to `^x.y.z` on publish.

## Preconditions

1. Bump `version` in each package you will publish. Keep the numbers equal.
2. Run `pnpm install` so `pnpm-lock.yaml` matches.
3. Run `pnpm -r run --if-present build`.
4. Run `pnpm --filter @fhec/hardhat-plugin test`.
5. Stage a native binary into each `@fhec/cli-*` package at `bin/fhec`.
   `pnpm --filter fhec run build:native` only stages **darwin-arm64** on that
   host.

Platform packages stay `"private": true` until a binary is in `bin/`. Drop
that flag on a platform package only when you are ready to publish it.

## Publish order

From the repository root, logged in to npm (`npm whoami`):

```sh
# 1. Every platform package that has a binary (skip while private).
pnpm --filter @fhec/cli-darwin-arm64 publish --access public

# 2. The JS wrapper. Optional platform deps must already be on the registry,
#    or a published `fhec` install has no native binary.
pnpm --filter fhec publish --access public

# 3. The Hardhat plugin.
pnpm --filter @fhec/hardhat-plugin publish --access public
```

Do not add npm tokens to CI in this change.

## Until the first publish

Consumers cannot `pnpm add -D @fhec/hardhat-plugin` from the registry. Use
the `file:` override plus `FHEC_BINARY_PATH` in
[`packages/hardhat-plugin/README.md`](packages/hardhat-plugin/README.md)
(Local checkout).
