# Exact fleet scoped qualification preparation

This directory records source and metadata preparation only. No build, test, Clippy run, or Cargo dependency cache download has occurred. Heavy execution awaits the coordinated CPU window after the Granite continuation.

## Exact source identity

- Remote commit: `dc984bb3b3cb21259f838a31f67a7c2983ea9510`.
- Git tree: `cd388fb79077d62f041c9b0c63b46be24c949d70`.
- Prepared source: `/dev/shm/hepta-fleet-qualification-20261028/source` in the actual host execution view.
- The existing NDU checkout remains clean at `4b6391e116949af0c7e59776baead67271856bdb`.
- The existing fixture worktree remains clean at `b3a5db1a43751ad1720e47fae838866e97f64b7d`, whose tree equals the published tree.

The new directory uses its own Git metadata, downloaded missing source blobs, Cargo home, target and temporary directories. It borrows already-present Git objects read-only from the original repository, leaving both original checkouts unchanged. Source preparation ran with niceness 19.

Exactly 1,113 selected real files (18,209,129 bytes) were restored, including repository Cargo manifests and original target entry points, complete fleet/contracts/paths/cargo-bin source, required compile-time fixtures, and unchanged Cargo/Clippy/nextest/just configuration. `EXACT_INPUTS.json` records every file's SHA-256, size, mode, and matching pinned Git blob. No synthetic stub file was created.

## Actual offline metadata validation

The installed Rust 1.95.0 Cargo successfully executed:

```sh
cargo metadata --locked --offline --no-deps --format-version=1
```

It completed with exit 0, no stderr, in 175,033,117 ns. This parses manifests and target metadata; it is not compilation or test execution. The command discovers **193 actual workspace members**: 187 explicitly declared members plus the automatically included `codex-windows-sandbox`, `core_test_support`, `codex-chatgpt`, `app_test_support`, `codex-message-history`, and `mcp_test_support` packages. The fleet library and `hepta-fleet-leased` binary target are both present.

Keeping the original workspace metadata matters because the original nextest configuration includes package-specific overrides for other workspace members. A reduced four-package workspace would fail those original filter matches. The preparation preserves the full actual member metadata and original filters instead of changing them.

Cargo.lock SHA-256, unchanged before and after metadata:

`8354b4cbdf14389db7aa5508e2ed5b524fc2d4c4ea0ecb475955c933f8bea389`

Fixed authority fixture SHA-256:

`78358f02576bd5442473d432db5bbf7273ff76c3b95d05591f2459c9e0f354db`

## Deferred execution

After the CPU window is released, use the actual host view, the installed Rust 1.95.0 toolchain, just 1.59.0, and cargo-nextest 0.9.103. The source working directory is the prepared `source/codex-rs` directory. `QUALIFICATION_PLAN.json` specifies the independent CARGO_HOME, CARGO_TARGET_DIR, TMPDIR, and PATH. Keep `CARGO_BUILD_JOBS=1`; `CARGO_INCREMENTAL=0` limits rebuildable cache use without altering source or lints. Do not change sandbox guards, nextest hooks, Cargo lock, or lints.

```sh
just test -p codex-hepta-fleet --locked
just clippy -p codex-hepta-fleet --locked
```

The host tmpfs was executable (`noexec=false`) and had 3,210,407,936 bytes available at the final preparation check. Recheck available space before execution. Cargo dependency caches have not been fetched; dependency resolution/download failures or lock drift must remain explicit failures, not be bypassed by substitutions or lock edits.

The local qualification will cover the real fleet library/binary targets and their real dependencies under the original Cargo/Clippy/nextest configuration. It does not replace the remote required Bazel workflow, cargo-deny, Windows jobs, or platform-specific coverage. Earlier terminal failure evidence remains in its original directory.

## Evidence inventory

- `QUALIFICATION_PLAN.json`: source identity, preserved inputs, actual workspace member counts, storage/mount observation, deferred commands.
- `EXACT_INPUTS.json`: full restored-file hashes and matching Git blobs.
- `SPARSE_INPUTS.json`: exact selected source paths.
- `METADATA_PREPARATION.json`, `metadata-001.json`, `metadata-001.stderr`: actual offline metadata command, original raw output, and unchanged lock hashes.
- `SOURCE_PREPARATION_COMMANDS.json`: complete source-preparation commands and their outputs; it includes real Git tree inventory, not generated source.
- `INDEX.json`: SHA-256 and sizes of these evidence files.
