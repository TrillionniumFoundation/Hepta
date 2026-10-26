# Unified standalone HIA delivery — 2026-10-26

This is executable integration work, with source-bound native evidence. **The six-part production/research request is not complete.** The final frozen run completed all **9** scoped gates, passed **8**, and reports **`scoped_gates_not_all_qualified`**. Performance status is **`measurement_inconclusive`**. The [machine-readable delivery ledger](delivery-ledger.json) records each remaining acceptance gap without upgrading a scoped pass to whole-language completion.

## Source identity

| Identity | Exact value |
| --- | --- |
| Local qualification commit | `06266df5df19cb2b08ec3756ac750699cd987b81` |
| Published source commit | [`b5687ecd4a633489e86894457545c6367b6acf20`](https://github.com/TrillionniumFoundation/Hepta/commit/b5687ecd4a633489e86894457545c6367b6acf20) |
| Identical complete Git tree | `4d7b498e7b3cec6304ee0755e7c0ddf42c26842f` |
| Source snapshot SHA-256 | `3806e85f3f1841574475925af1ba588866da868b2d4e8bf4eb30e6719476a326` |
| Source unchanged during qualification | `True` |

Git HTTP credentials were unavailable in the shell. The authenticated repository connector published the exact source tree; a separate read verified the remote commit/tree/ref. Commit metadata therefore differs from the local qualification commit. [publication.json](publication.json) records that mapping. Later evidence-only commits do not expand qualification.

The integration commit has both pinned implementation parents, `ea4337d60332373341190682a346f26fbe8727e5` and `fe08c39ca2c75b80e5a0d7b7b597ff1ab3284a03`. This is a real merge with code adapters and common executable semantics, not a bundle of previously passing reports.

## Final same-source gates

| Gate | Result | Wall seconds |
| --- | --- | ---: |
| `unit_regression` | PASS | 507.181 |
| `standalone_native` | PASS | 3.492 |
| `standalone_resources` | PASS | 4.272 |
| `source_migration` | PASS | 4.749 |
| `standalone_aarch64_qemu` | PASS | 2.024 |
| `legacy_executable_core` | PASS | 5.324 |
| `legacy_hosted_composition` | PASS | 1.599 |
| `legacy_cortex_m4_qemu` | PASS | 1.697 |
| `standalone_performance` | NOT QUALIFIED | 106.578 |

Full regression: **1730 tests**, **0 skips**, **0 failures**, **0 errors**. [qualification.json](qualification.json) retains every command, exit code, log hash and the before/after source inventory. Passing historical backend gates does not enable those features in standalone HIA.

## What was implemented

1. **Common executable core.** Actual structured executable-Core operations are decoded and lowered; actual legacy HIA SSA instructions and predecessor-selected PHIs are converted using explicit liveness. Both enter the same `verify_core`, resource checker, interpreter and LLVM path. Old source authentication remains an import requirement; resulting HIA no longer needs that source.
2. **Independent HIA entry.** Bounded, strict JSON with typed closed SSA, explicit CFG edges, integer operations, effects and linear byte-resource instructions. `verify`, `inspect`, `run`, `emit`, `build`, `lower`, `patch`, `import-executable` and `import-scalar` are CLI operations. Patches bind the expected program hash and reverify the complete result before publishing a new file.
3. **Resource composition.** Concrete records and `Result`, finite generic function/record specialization, multiple owners, moves, mutable/shared reborrows, local loans across CFG edges, loops and ordinary error cleanup execute together. The 128-instance/32-type-depth specialization bounds and the exact runtime/external assumptions are normative in [HIA_PROGRAM.md](../../docs/HIA_PROGRAM.md).
4. **Actual C/C++ migration.** Active C compilation-database declarations and two-resource bodies are translated from native AST. Scalar C++ class and closed C++ resource-owner migration outputs are generated freshly and then consumed by standalone HIA. Unsupported constructs reject; the C++ owner converter is a complete normalized protocol match, not a general C++ body translator.
5. **Direct native execution and measured performance.** Linux x86-64 objects/shared libraries and Linux AArch64 objects come directly from verified HIA. No original high-level source or Rust safety gate is needed by this backend. Qualification and performance inputs retain explicit tool/artifact/source identities.
6. **Agent-facing tools and an honest pilot.** Version-bound semantic patches, typed inspection and structured diagnostics are implemented. A real locked model failed the frozen capability eligibility checks; comparative trials did not start. This is not evidence of an agent productivity gain.

## Actual native/resource/migration observations

- Standalone host corpus: **289 returned-value executions**, **6 real SIGABRT controls**, and actual allocator observation **7 allocations / 7 frees / 0 live / 1 NULL refusal**. The deliberately compiled missing-free mutant is detected.
- Resource corpus: **16 combined interpreter cases** and **11 static rejection controls**, plus concrete record/Result migration checks. Ordinary error returns clean up; process aborts do not promise cleanup.
- Migration: **56 C cases + 20 scalar C++ cases + 475 owned C++ cases**, giving **1102 native result observations** and **212 actual binary allocator-refusal observations** across originals and HIA targets. These are controlled real NULL injections, not an operating-system OOM qualification.
- The owned C++ path accounts for **2 top-level declarations / 15 members** and compares all 475 vectors independently. Each binary reports **359 allocations / 359 frees / 98 refusals / 0 live**. Another **112 small-extent cases** run through the independent core interpreter.
- Target link inputs contain the newly generated HIA object and a C observation driver, not the original C++ implementation. An explicit scalar ABI prototype and `-Werror=implicit-function-declaration` prevent accidental implicit-int calls. Coordinated receipt tampering that adds `original.o` is rejected against independently reconstructed allowed link inputs.

See [native-summary.json](native-summary.json) and [migration-summary.json](migration-summary.json). Full logs, Core/LLVM, declaration receipts, source captures and retained migration binaries are in the final archive.

## Performance: qualification result, not a superiority claim

The workload and thresholds are unchanged: 3 kernels, 3 implementations, 7 paired groups, **63 samples**, fixed order, no clipping/retries/best-run selection, relative MAD at most 5%, each kernel ratio at most 1.20 and geometric mean at most 1.10. Both generated Rust and independent handwritten safe Rust must pass separately. The Rust builds retain checked arithmetic and abort-on-panic settings. Untimed correctness uses **588 native calls** and a real allocator/leak negative control.

Final result: **`measurement_inconclusive`**, `ok=False`. The following are descriptive paired medians from the retained run, not a qualified claim whenever the quality gate fails. A ratio below 1 means HIA took less time in that comparison.

| Kernel | HIA / generated Rust | HIA / handwritten Rust | Relative MAD by implementation |
| --- | ---: | ---: | --- |
| `constructor_error` | 0.8017 | 0.8160 | handwritten_rust: 9.45%, llvm: 8.06%, rust: 11.66% |
| `full_lifecycle` | 1.3332 | 1.3094 | handwritten_rust: 9.74%, llvm: 6.19%, rust: 11.35% |
| `two_stage` | 0.9527 | 0.5848 | handwritten_rust: 2.91%, llvm: 10.08%, rust: 11.21% |

Full samples, checksums, timing order, tool identities, flags, environmental data and every failed threshold are retained in [performance.json](performance.json). CPU affinity selects the lowest allowed logical CPU but does not provide exclusive CPU ownership.

The earlier 9fe295e run completed all 63 samples and failed measurement quality (8 of 9 groups) as well as performance thresholds. Its constructor path retained a whole-buffer `calloc`; both Rust implementations had removed the unused zero writes. The new backend uses `malloc` only when a complete-function closed whitelist proves byte contents unobservable: scalar boundaries, no calls, no byte loads/stores, all blocks/terminators checked. Allocation attempts, NULL branches and explicit drops remain; byte-observing functions retain `calloc`. This does not promise equal physical OOM behavior between allocator implementations. [The diagnosis](performance_diagnosis/README.md) and [independent review](zero_elision_independent_audit/README.md) retain their source bindings and limits.

The remaining `full_lifecycle` failure has a separate [static follow-up](performance_diagnosis/full_lifecycle_static_v2/README.md): the HIA checksum loop has an additional per-byte bounds branch; both Rust loops retain checked-add overflow handling without that bounds branch. All three main fill loops are vectorized. Rust also has a four-byte vector cleanup before its scalar tail. Both Rust implementations still initialize the full buffer here, so the constructor's eliminated-zeroing explanation cannot be reused for this kernel. These are concrete code-generation differences, not an attribution of the measured percentage. The HIA and handwritten-Rust retained binaries match final-run hashes; the generated-Rust static rebuild matches source/toolchain/flags but has a different binary hash, explicitly disclosed in the supplement. No additional timing or kernel execution was performed, and performance remains unqualified.

## Target and safety boundaries

- x86-64: actual native Linux execution in this environment.
- AArch64: actual QEMU userspace execution of the new direct backend, **17 return cases**, two wrong-Core controls, a bounds abort, and 4 allocations / 4 frees / 0 outstanding / 1 allocator refusal. The finite target runtime has a 4096-byte, single-live-allocation scope.
- Cortex-M4: historical Rust/BSP path only, with **6 emulator cold boots**. It is not evidence for standalone 32-bit HIA, physical devices or device timing.
- Physical boards, DMA, GPU, device timing and production workloads remain unqualified. A runtime check, finite native corpus or small abstract Lean proof is not a whole-language safety/refinement theorem.
- General nominal ADTs, escaping/stored source lifetimes, asynchronous tasks/cancellation/channels and arbitrary FFI are outside the standalone core. Historical Rust composition evidence is labeled separately and does not close these gaps.
- C++ class ABI, arbitrary templates/STL/custom destructors/exception unwinding, exhaustive source equivalence and low total migration labor are not established.

## Agent experiment status

The frozen [pilot evidence](../../experiments/hia_agent_pilot_20261026/preflight/) contains native positive/negative controls, model/runtime locks, prompts, token IDs and original responses. Its compiler bindings are the historical pilot snapshot, not a claim that the final compiler was used by those earlier probes. Actual model: SmolLM2-135M-Instruct. Two capability probes ran; both failed. Status: **`model_capability_preflight_failed`**, **0 comparative task attempts**. The planned 4 tasks × 4 arms and scripted correct controls are not model task successes. Success rate, error rate, maintenance cost and total development-cost improvements remain unproved.

## Retained attempts and archive replay

All three attempts are retained. The first includes the actual linker ENOSPC failure and explicit interruption; the second includes the 1,723-test failure log and complete inconclusive timing. The final run has its own unchanged source snapshot. No failed run was overwritten or selectively dropped.

| Attempt | Source | Result | Complete raw archive | Per-file manifest |
| --- | --- | --- | --- | --- |
| Initial | `35422e8` | Interrupted; storage failure retained | [hia_unified_20261026.tar.gz](hia_unified_20261026.tar.gz) | [277 files](hia_unified_20261026.manifest.json) |
| First correction | `9fe295e` | 7/9 scoped gates; full 63-sample timing retained | [hia_unified_fixed_20261026.tar.gz](hia_unified_fixed_20261026.tar.gz) | [281 files](hia_unified_fixed_20261026.manifest.json) |
| Final frozen source | `06266df` / remote `b5687ec` | 8/9 scoped gates; 1,730 tests pass; performance unqualified | [hia_unified_final_20261026.tar.gz](hia_unified_final_20261026.tar.gz) | [303 files](hia_unified_final_20261026.manifest.json) |

[archive-verification.json](archive-verification.json) records an actual readback of all three archives, including every file hash and the internal manifests.

[Source-history patches](source-history/manifest.json) reconstruct both earlier source trees from the published final source. An actual reverse-apply check with an isolated Git index produced each exact recorded tree. These patches preserve reproducibility despite the local/remote commit-metadata differences.

Each `*.manifest.json` lists the archive SHA-256 and every contained file's size/SHA-256. Archives contain raw outputs under their original run directory names and an internal `archive-manifest.json`. Logs retain the original absolute execution paths; extracting them elsewhere does not make old process paths current. Reproduce by running the qualifier into a new output directory, not by rewriting receipts.

```sh
git checkout b5687ecd4a633489e86894457545c6367b6acf20
python tools/bootstrap_toolchain.py
python tools/bootstrap_verification.py
export LEAN="$PWD/../toolchains/lean-4.19.0/bin/lean"
python tools/qualify_hia_unified.py \
  --output-directory evidence/my-new-hia-run \
  --clang /usr/lib/llvm-20/bin/clang \
  --rustc "$PWD/../toolchains/rust-1.90.0/bin/rustc" \
  --linker "$PWD/../toolchains/rust-1.90.0/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld" \
  --qemu-aarch64 "$PWD/../toolchains/qemu-8.2.2/qemu-aarch64-static" \
  --qemu-system-arm /usr/bin/qemu-system-arm
```

This requires the documented Linux compiler, GDB, namespace runtime and emulator dependencies; the workflow installs them explicitly. Local qualification is reported here independently of GitHub Actions status. The branch remains a draft integration candidate, not an assertion that all six requested completion standards have passed.
