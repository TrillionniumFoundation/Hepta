# Frozen final evaluation results

The final compiler comparison is complete and **fails the fixed performance
noninferiority gate**. The final local-agent pilot is complete and has **zero
successful repairs in all 16 cells**. These are useful negative results; neither
experiment establishes an advantage over Rust or improved agent productivity.
The evidence includes every earlier failed or incomplete attempt.

## Exact scope and identities

The benchmark compares two allocation/byte-buffer kernels on one shared Linux
x86-64 host. It includes actual source-to-Core verification and direct native HIA
compilation, independent safe Rust with `-O3`/fat LTO, C/C++ with `-O3`/full LTO,
and actual C/C++ instrumentation PGO trained only on the registered training
sizes and seeds. These are synthetic buffer workloads with realistic allocation,
fill, transform, checksum and release paths; they are not a real-application
benchmark suite.

The complete 84-sample inventory, fixed group ordering, every input seed, source
hashes and native-tool identities were written to `plan.json` before compilation.
All 84 samples and all 864 finite native correctness observations completed.
Every source, tool and built-artifact identity remained unchanged during the
final run. Complete bound source bytes are retained in `source_snapshot` inside
the final archives. The source was a dirty integration tree based on commit
`f3c036427f7cbd4c01ee67c16ddf47986f492343`; the hashes, not the commit alone,
identify the measured implementation.

The fixed benchmark protocol SHA-256 is
`a27a4e401b7cd5dbae76f50b523f1de1b018c52e3e69baf7f4c0b6ca58027e1e`.
The host pinned the benchmark to logical CPU 0 but did not provide exclusive CPU
ownership. The coordinator reported brief overlap with separate NDU native
checking, at most about 20 seconds; per-sample overlap timestamps were not
captured. This is retained as an environmental limitation. No sample was
removed and no replacement run was selected to improve a result. The protocol's
computed quality gate passed, which does not establish an isolated-host result.

### Subsequent source and artifact rebinding

After those measurements, `hepta/hia_optimization.py` received two safety
changes: each symbolic verifier request now owns an independent Z3 context,
and the checker identity additionally binds `hia_program_runtime.py` and
`hia_bounded_memory.py`. Within the historical source inventories, this is the
only changed file: 117/118 benchmark bindings and 116/117 agent bindings remain
identical, with no added or removed files. Its hash changed from
`c881acf7ff8bea135d526f2022d4ea0ebd02c789749f1068f90f5432b1bd6999` to
`25407ba518ed0c54614fe54f6744d1e9f553a97ea23b0e62bc043b811f0fc6da`.
The separate NDU loop tool also changed, outside these two experiments' bound
execution paths; these inventories are not a claim that no other repository
file changed.

[`rebind.json`](rebind.json) records a separate source/artifact check after the
NDU measurements ended. It performed exactly one native rebuild of the original
two-kernel HIA library through the final source's lower/verify/emit/compile path,
with the original compiler identity and flags. The rebuilt Core, emitted LLVM
and 15,536-byte native library are all byte-for-byte identical to the measured
artifacts. The native SHA-256 remains
`9b02e9faf8fcd4dd37328659abec332b6c00054aa50bba7133d7a87db8957b42`.
The changed optimizer module was not imported by this rebuild or prompt
regeneration path.

The same check regenerated all 16 task request files and both preflight message
arrays. Every task request's complete bytes and every preflight message matched
the original archived input; fixtures, withheld oracle, request tools and
native-evaluation source remain unchanged. The new receipt, complete source
manifests, exact source diff and regenerated requests are retained in `rebind/`.
All original report, plan, retention-manifest and archive hashes were rechecked
and left unchanged.

This is **artifact and prompt rebinding, not a new benchmark or model run**.
It collected zero performance samples, executed no benchmark binary and made
zero inference requests. The timing, compile/verification costs, token counts
and failed repairs above and below remain historical observations from the
original measured source. The entire final repository was not remeasured.

## Native performance results

All ratios below are **HIA / the independent baseline**; values greater than one
mean HIA took more time or peak resident memory. The prespecified thresholds
are an upper one-sided paired-time bound of 1.05, empirical batch-p95 ratio of
1.10, and process-peak-RSS ratio of 1.25. All three must pass. There are seven
paired process groups and 217 timed batches per kernel/backend. The t bound
assumes approximately normal independent group log ratios; empirical tails are
not population-tail confidence bounds.

| Kernel | Baseline | Paired geometric time ratio | Upper 95% time bound | Batch p95 ratio | Peak RSS ratio | Gate |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `full_lifecycle` | `rust_o3_lto` | 1.7469 | 1.8789 | 1.8095 | 0.7848 | Failed |
| `full_lifecycle` | `c_o3_lto` | 1.7032 | 1.8395 | 1.9031 | 1.0000 | Failed |
| `full_lifecycle` | `cpp_o3_lto` | 1.5370 | 2.0102 | 1.7137 | 0.4189 | Failed |
| `full_lifecycle` | `c_pgo_lto` | 1.7177 | 2.1068 | 1.8572 | 1.0000 | Failed |
| `full_lifecycle` | `cpp_pgo_lto` | 1.6880 | 1.9011 | 1.8043 | 0.4189 | Failed |
| `packet_xor` | `rust_o3_lto` | 1.3670 | 1.4286 | 1.3734 | 0.7945 | Failed |
| `packet_xor` | `c_o3_lto` | 1.3532 | 1.4288 | 1.4360 | 0.9950 | Failed |
| `packet_xor` | `cpp_o3_lto` | 1.3247 | 1.4412 | 1.3352 | 0.4370 | Failed |
| `packet_xor` | `c_pgo_lto` | 1.3014 | 1.4261 | 1.3898 | 0.9950 | Failed |
| `packet_xor` | `cpp_pgo_lto` | 1.2813 | 1.3762 | 1.0363 | 0.4370 | Failed |

The two HIA/Rust time ratios are about 1.75 and 1.37. HIA's process peak RSS is
lower in these runs, but its slower execution fails the required joint gate.
HIA's measured peaks are 744 KiB and 804 KiB; Rust's are 948 KiB and 1,012 KiB.
These are post-exec Linux `VmHWM` values for the whole driver process, not a
portable language heap-size metric. Raw `ru_maxrss`, external process wall time,
CPU time, every batch latency and all empirical p99 observations remain in the
report. Some baseline p99 values contain large tails; those samples are kept.

The native build costs below include each baseline's actual configuration. PGO
rows include instrumentation builds, training, profile merging and profile-use
compilation. Rust's shared library includes its normal runtime/static-library
costs. These costs describe this toolchain and tiny compilation unit.

| Backend | Build wall time (seconds) |
| --- | ---: |
| `c_o3_lto` | 0.118842 |
| `c_pgo_lto` | 0.376619 |
| `cpp_o3_lto` | 0.345272 |
| `cpp_pgo_lto` | 0.965331 |
| `hia` | 0.181190 |
| `rust_o3_lto` | 2.676898 |

HIA source-to-Core lowering took 8.212206 ms; explicit Core verification took
6.656661 ms; verified LLVM emission took 8.840373 ms. The native-build receipt
also includes its required verification. Finite native correctness checks took
149.580136 ms across all backends. Optimizer search cost is explicitly **zero
calls and zero time**: this is the fixed baseline evaluator, not a claimed NDU
search improvement.

## Why the measured HIA loops are slower

The HIA source uses checked `u64` checksum addition. Its two native reductions
perform one byte load and one carry-to-abort branch per iteration. The independent
release Rust and C references have eight-way unrolled scalar reductions without
those per-add checks. The HIA fill/transform loops already vectorize and their
buffer bounds checks have already been removed. The retained disassemblies do
not support a general claim that ownership itself caused the gap.

The unsigned reference sums wrap on overflow, while HIA traps. On the registered
finite domain, sizes are at most 65,536 and byte sums are at most 16,711,680, so
that semantic difference cannot change a result. It matters for arbitrary
library callers, and the benchmark must not be used as permission to delete
checked arithmetic globally.

A separate earlier diagnostic changed only the two sums to explicit wrapping
addition. All 144 finite checks and 28 paired executions passed; measured median
wrapping/checked ratios were 0.623750 and 0.778331. The reduction became eight-way
unrolled. This is evidence for a concrete optimization opportunity, **not** an
admitted semantics-preserving transformation or an independent held-out speedup.
`diagnosis.md` specifies a possible guarded reduction with the proof invariant
`sum <= 255 * i`, a checked fallback, and unchanged allocation/trap/cleanup
semantics.

Between the earlier complete run and the frozen final run, the allocator
freshness contract was expressed as `noalias` returns on `calloc` and `malloc`;
`no-builtins`/`nobuiltin` and opaque side effects were retained. The final emitted
LLVM contains those return attributes. **The final HIA shared library is still
byte-for-byte identical to the earlier measured library**, SHA-256:
`9b02e9faf8fcd4dd37328659abec332b6c00054aa50bba7133d7a87db8957b42`.
The packet pointer-distance overlap check at `0x15cf`–`0x15d9` is still present,
as are both checked reductions. Therefore this small declaration change cannot
be credited with a performance gain in these kernels. Tracking how allocator
freshness passes through the allocation helper's aggregate returns and pointer
PHIs is a next diagnostic, not an established fix. Final disassembly and its
post-run provenance are retained in the final benchmark archive.

## Matched local-agent result

The final pilot used the already available Qwen2.5-Coder 0.5B Instruct Q8_0 GGUF
with exact SHA-256
`e1a77721fa97d412f121878223eec81fb4ae6f271e18f922d746711f67b344d1`.
The actual local llama.cpp b11669 runtime and model bytes were checked before
and after use. Every arm used the same model, greedy seed 0, four threads,
syntax-only JSON grammar, 512 output tokens, one attempt and native test tools.

The four task contracts are the existing `capacity_roundup`, `tagged_octet`,
`epoch_delta` and `weighted_minimum` two-helper maintenance tasks. Each has
HIA/Rust and full/query-context arms. There are 77 withheld-from-prompt input
pairs per task: 13 boundary pairs plus 64 pairs from a frozen deterministic LCG.
Tests establish that adding those test inputs does not change any model prompt.
They are disclosed reproducible inputs, not a secret dataset or new task family.

All 32 buggy/partial/fixed native controls passed. Both format probes passed.
All 18 actual model requests returned: two probes and all 16 planned task cells.
There were no infrastructure failures or unaccounted requests in the final run.

| Arm | Correct / completed | Accepted but wrong | Rejected | Input tokens | Output tokens | Inference s | Native evaluation s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `hia_edit_query` | 0/4 | 4 | 0 | 1446 | 116 | 7.659 | 1.053 |
| `hia_full_context` | 0/4 | 4 | 0 | 3004 | 116 | 14.152 | 1.009 |
| `rust_edit_query` | 0/4 | 2 | 2 | 1109 | 603 | 18.429 | 0.351 |
| `rust_full_context` | 0/4 | 2 | 2 | 1270 | 111 | 7.367 | 0.348 |

The two format probes separately used 126 input and 52 output tokens. All costs
include failed attempts; no successful repair exists, so tokens per successful
task is `null` in every arm. Native controls took 7.034223141 s. The complete
model phase, including startup, identity hashing, probes, task inference,
native evaluation and shutdown, took 54.288187056 s; the whole experiment took
61.922016295 s. Model training/download, human review, tool implementation and
upstream integration costs are outside the measured scope.

The HIA query prompts use fewer input tokens than full HIA prompts in these
fixtures, but **0/4 versus 0/4 successful repairs cannot establish lower cost
per useful result**. Accepted syntax also does not imply correct maintenance.
One small model, four tasks, one attempt per cell and no successful task cannot
support a productivity advantage or satisfy the historical two-model gate.

## Reproduce and audit

The output directory must be new. Freeze the bound compiler/tool files for the
whole attempt. Do not run benchmark and inference concurrently. A future
independent benchmark should additionally use a quiet dedicated host while
retaining these original shared-host samples.

```sh
python tools/qualify_hia_optimizer_bench.py \
  --output-dir /tmp/hepta-bench-new-attempt \
  --profile-runtime /tmp/hepta-clang-profile-runtime/extracted/usr/lib/llvm-20/lib/clang/20/lib/linux/libclang_rt.profile-x86_64.a

python tools/qualify_hia_agent_holdout.py \
  --output-dir /tmp/hepta-agent-new-attempt \
  --binary /tmp/hepta-llama-b11669/llama-b11669/llama-server \
  --model /tmp/hepta-seven-stage-models/qwen2.5-coder-0.5b-instruct-q8_0.gguf \
  --model-sha256 e1a77721fa97d412f121878223eec81fb4ae6f271e18f922d746711f67b344d1

python -m unittest tests.test_hia_optimizer_bench tests.test_hia_agent_holdout
```

The nine evaluator unit tests passed after implementation. The local agent
server needs permission to bind its private Unix socket; it does not use an
external network endpoint. The native benchmark requires the exact recorded
Clang/LLD/profdata/Rust tools or a new explicitly identified run.

`evidence/README.md` lists all seven actual attempts/diagnostics. Each evidence
directory retains the exact original report and plan, a lossless `tar.xz` of
all regular output files, and a manifest giving every file's byte count and
SHA-256. Every archive was opened again and every member rehashed. Old temporary
raw directories were removed only after this verification to recover space
from the full shared filesystem; the archived bytes and failure records remain.
The external compiler tools and GGUF model are identified by hash but are not
bundled into the evidence archive.
