# fhec

This package is currently a stub entry point for the `fhec` CLI.

Once the native toolchain is wired up, this package will dispatch to a
platform-specific native Rust binary, distributed as an optional
per-platform npm package, following the same model used by esbuild and
biome: a thin JS entry point selects and execs/requires the right
prebuilt binary for the current `process.platform` / `process.arch`.
