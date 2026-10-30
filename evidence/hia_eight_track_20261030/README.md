# Eight-track HIA implementation evidence

Implementation under test: `ab6d34613d1e2e90bbfc5081e0cd17354f1b8711`.
Implementation tree: `a288101efd886ad55a1d1904f34b6d399164a793`.
Integration base: `865a4626910efbc882cad47a7816e9aa276a9600`.

Read the [Chinese implementation and result report](../../docs/HIA_EIGHT_TRACK_CONVERGENCE_20261030.md) and [RESULTS.json](RESULTS.json) for findings and remaining gates. These observations do not close all eight workstreams. The evidence commit adds this archive and documentation; the retained execution results continue to identify the implementation commit above.

## Contents and integrity

- `RESULTS.json`: derived, machine-readable counts and claim boundaries with hashes of the original reports.
- `RAW_MANIFEST.json`: every archived path, original path, byte count and SHA-256.
- `raw-evidence.tar.gz`: unmodified UTF-8 files from the final validation campaigns, their failed/incomplete first attempts, external harnesses, and separately identified historical independent review.
- `BINARY_EXCLUSIONS.json`: original paths, byte counts and SHA-256 for native executables, shared libraries, objects and other non-UTF-8 files deliberately excluded from the archive.
- `ARCHIVE.json`: archive byte count, hash, deterministic packing details and integrity-check result.
- `CI_STATUS.json`: timestamped observation of the exact implementation Actions run. A pending run is not a successful qualification.
- `audits/`: independent read-only claim, migration and NDU audits. They are reviews, not new executions or proof certificates.

The raw archive uses relative paths rooted at `final-validation/`, `validation-loop-review/` and `replay-support/`. It retains original bytes and absolute execution paths inside receipts. Those absolute paths identify the original run; downloading this archive does not restore the original executables, toolchain, or host. Excluded binary hashes are inventories, not remotely available executable artifacts. Rebuild and rerun to obtain fresh execution evidence.

The independently authored historical loop review remains bound to `4867ebac68d80fbd7580ef16e0ba0ac882789ce9`. It is not counted in the final implementation's 159-test cohort or its 96-case project qualification. Its native scalar references used shared-library compilation; the final project qualification preserves the original translation-unit configuration and source operand more strictly.

## Observations are not interchangeable

The regression cohort, Rust crate tests, v4 collector methods, positive observations, refusal controls and native calls have different denominators and overlap. Do not add them into a single success rate. The 19 agent reference controls are authored fixtures with zero model requests. Cross-target execution uses QEMU, not physical boards. The finite affine proof establishes a minimum only within the declared 146-recipe grammar, cost function and ABI/ISA model.

All three corrected first attempts remain in `final-validation/`:

| Directory | Recorded outcome | Why a complete follow-up was run |
| --- | --- | --- |
| `agent-references/` | 19 infrastructure failures, zero model calls | The default Python build lacked `fcntl.F_ADD_SEALS`; actual `/usr/bin/python3` 3.12.3 was used for the complete follow-up, without a shim or source edits. |
| `c-loop-rust-parity/` | Incomplete external harness | The external script read the Rust report's `result` field instead of `values`; only that script was corrected. |
| `ndu-four-arm/` | Four NDU episodes refused before any delivered observation | The sandbox PID and `/proc` namespaces did not correspond. The complete four-arm campaign and empty-target build were rerun in a permitted environment with actual executable identity access. |

The NDU initial early-exit times are invalid performance comparisons. The qualified campaign uses the same frozen workload/protocol and does not constitute an unseen-workload result. The complete qualified result fails both warm and build-inclusive net-value gates. Candidate opportunity controls are negative. No slow samples or unsuccessful attempts were discarded to improve the outcome.

## Replay prerequisites

Use a **clean checkout of the implementation commit**, not the later evidence commit. Supply real Rust 1.90.0, Clang/LLVM 20.1.8, Z3 4.15.4, Linux process-group ownership, usable sealed memfd execution and actual QEMU user 8.2.2. Retained receipts include exact binary hashes, resolved paths and tool versions. The real model study requires a separately capacity-qualified model and is not performed by these commands.

Native NDU ranking used the original source pin `d3c2d760eca5065fc966820379c35c6e8d56e855`. The streaming bridge uses original source pin `c4a1bbed3a39beba43a6abf1a18b6f75c5725c21`. Source/binary admission must be performed again; a copied receipt is not authority. Each output directory must be fresh and outside the frozen checkout. The NDU process identity route must refer to the actual native child process; a PID-namespace mismatch must refuse, not bypass the check.

Example commands, after setting local tool paths and a fresh `HEPTA_REPLAY_OUT`:

```sh
git checkout --detach ab6d34613d1e2e90bbfc5081e0cd17354f1b8711
git status --porcelain

cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
python tools/qualify_hia_rust_api_v4.py \
  --expected-head ab6d34613d1e2e90bbfc5081e0cd17354f1b8711 \
  --output-directory "$HEPTA_REPLAY_OUT/rust-api-v4"

python tools/qualify_hia_c_loop_migration.py \
  --source-sha ab6d34613d1e2e90bbfc5081e0cd17354f1b8711 \
  --clang /usr/bin/clang-20 --output "$HEPTA_REPLAY_OUT/c-loop-migration"

python tools/qualify_hia_x86_bounded_affine.py \
  --clang /usr/bin/clang-20 --artifacts "$HEPTA_REPLAY_OUT/bounded-affine"

/usr/bin/python3 tools/qualify_hia_agent_tool_references.py \
  --study-version v9 --clang /usr/bin/clang-20 --rustc "$RUSTC" \
  --output "$HEPTA_REPLAY_OUT/agent-references"

python tools/qualify_hia_returned_loans_cross.py \
  --output-directory "$HEPTA_REPLAY_OUT/cross-targets" \
  --clang /usr/bin/clang-20 --linker /usr/bin/ld.lld-20 \
  --readobj /usr/bin/llvm-readobj-20 \
  --qemu-aarch64 "$HEPTA_QEMU_AARCH64" --qemu-riscv64 "$HEPTA_QEMU_RISCV64"
```

The exact selected regression module list is in raw `regressions.json`; its original runner is retained under `replay-support/`. The original external four-path harness is retained under `final-validation/c-loop-rust-parity-v2/replay.py`. Local path settings in these external harnesses require relocation before replay; the workload, expected source, observation and denominator rules must stay fixed.

For the NDU comparison, first construct the original streaming bridge from an empty target directory and retain the outer build cost:

```sh
python tools/measure_hia_ndu_build.py \
  --output "$HEPTA_REPLAY_OUT/ndu-empty-build" \
  --ndu-source "$HEPTA_STREAM_SOURCE" --target-dir "$HEPTA_EMPTY_TARGET" \
  --cargo "$HEPTA_CARGO" --rustc "$RUSTC" --cargo-home "$CARGO_HOME" \
  --expected-source c4a1bbed3a39beba43a6abf1a18b6f75c5725c21 --offline

python tools/qualify_hia_ndu_narrowed_candidates.py \
  --output "$HEPTA_REPLAY_OUT/ndu-four-arm" \
  --identity "$HEPTA_REPLAY_OUT/ndu-empty-build/build/identity.json" \
  --build-envelope "$HEPTA_REPLAY_OUT/ndu-empty-build/BUILD_ENVELOPE.json" \
  --clang /usr/bin/clang-20 --objcopy /usr/bin/llvm-objcopy-20
```

An empty target with an existing Cargo dependency cache is not a fully cold machine. Preparation, proof, build, switching, delivery and cleanup scopes are retained in the protocol and ledgers. Shared-host timing is an observation, not a physical WCET guarantee or statistical superiority result.

## Full CI

The implementation's full integrated workflow is [Actions run 40996752200](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40996752200), targeting the exact implementation SHA. It runs the complete integrated regression and the canonical safety matrix with real prerequisite tools. The local selected cohort does not replace those gates. A later evidence-only commit can have a different workflow run and source SHA; keep their statuses separate.
