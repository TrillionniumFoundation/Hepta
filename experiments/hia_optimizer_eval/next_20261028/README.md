# Registered follow-up: 2026-10-28

This directory contains the next experiment protocol, executable evaluation
code, and subsequently retained evidence. Earlier results remain unchanged.
No new measurement is claimed until its raw execution record exists.

## Retained outcomes

- [The performance readout](benchmark-results.md) retains all 98 observations
  and 1,260 finite correctness checks. Quality passed; the unchanged strong
  baseline noninferiority gate failed. Guarded HIA improved over original HIA
  without establishing superiority to optimized Rust/C/C++.
- [The Chinese Agent report](AGENT_FINAL_RESULTS.md) and
  [machine-readable results](AGENT_FINAL_RESULTS.json) cover all 32 primary
  cells and all eight separate upgrade cells. Primary successes were 5/32;
  upgrade successes were 0/8. There were 50 actual completion requests and
  47 responses. Three timed-out output usages remain unknown, not zero.
- Original qualification status and supplemental coverage are distinct.
  Original Qwen upgrade and Granite primary loops stopped after timeouts;
  independently reviewed continuation tools executed only their never-started
  suffixes. Already-attempted cells were never retried, and original gates
  remain failed. See the [upgrade continuation](../upgrade_continuation_20261028/README.md)
  and [primary continuation](../primary_continuation_20261028/README.md).
- [Response diagnosis](AGENT_RESPONSE_DIAGNOSIS.md) records that all 12 complete
  upgrade responses omitted the required top-level `files` wrapper. They were
  rejected before candidate compilation. No response was repaired or rescored
  to create a successful upgrade.

The first two model-server starts were killed during loading before any
completion request. `RUNTIME_AMENDMENT.json` records the pre-answer change to
`LLAMA_ARG_REPACK=0`, applied equally to both families; the actual owned PIDs
are bound in `RUNTIME_AMENDMENT_APPLIED.json`. The original failure, readiness,
downloads, archive costs and all unmeasured-cost limits remain visible.
Original large archives and verified member manifests remain unchanged when
publication requires byte-exact multipart transport.

## Performance comparison

The unchanged `kernels.hepta`, `kernels.rs`, `kernels.c`, and `kernels.cpp`
fixtures exercise allocation, buffer fill, transformation, checksum and
release. The new schedule contains original HIA, independently verified
guarded HIA, Rust O3 with fat LTO, C/C++ O3 with full LTO, and actual
instrumentation-PGO C/C++ rebuilds. PGO training and holdout sizes/seeds are
disjoint. The follow-up uses Clang 20.1.2 and Rust 1.95.0, recorded by exact
tool bytes; the earlier Rust 1.90.0 run is not directly re-labelled.

There are 98 fixed observations: seven paired groups, two kernels and seven
arms. Every process measures 31 batches of 128 calls after 32 warmups. The
existing quality and noninferiority thresholds are retained. Missing or
failed observations remain failures. No trimming, discretionary retries,
adaptive repetition counts, or holdout-based flag selection are allowed.
Both HIA arms must be visible even when the optimized arm fails.

The optimized artifact is eligible only after independent guarded-reduction
verification and a native receipt binding the actual bytes. Proposal,
verification, compilation, PGO training and validation costs are retained.
The proposal is deterministic; no learned-search cost is claimed.

Run with the restored tools (or equivalent exact toolchain paths):

```bash
env PYTHONPATH=/tmp/hepta-next-z3-20261028 \
 LD_LIBRARY_PATH=/tmp/hepta-next-llvm-20261028/usr/lib/x86_64-linux-gnu \
 /usr/bin/python3 tools/qualify_hia_optimizer_bench.py \
 --guarded-next --output-dir /tmp/hepta-next-20261028-bench-final \
 --clang /tmp/hepta-next-llvm-20261028/usr/lib/llvm-20/bin/clang \
 --clangxx /tmp/hepta-next-llvm-20261028/usr/lib/llvm-20/bin/clang++ \
 --profdata /tmp/hepta-next-llvm-20261028/usr/lib/llvm-20/bin/llvm-profdata \
 --linker /tmp/hepta-next-llvm-20261028/usr/lib/llvm-20/bin/ld.lld \
 --rustc /tmp/hepta-ci-rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustc
```

A passing result establishes the registered finite-host comparison only.
It does not prove universal language superiority, global optimality,
application coverage, or LLVM/backend correctness.

## Actual Agent experiments

The primary experiment retains the four previous paired maintenance tasks
and their exact prompts. Each task changes two helpers atomically. There
are four matched language/interface arms, one attempt per cell, 512 output
tokens, greedy decoding, seed zero, four CPU threads and the same syntax-only
JSON decoder. Thirteen boundary cases and 64 newly seeded cases per task are
withheld from prompts. Every wrong or rejected output contributes to usage
and failure totals.

The two independent official GGUF families are fixed before inference:

| Family | Quantization | Exact bytes |
| --- | --- | ---: |
| Qwen2.5-Coder 7B Instruct | Q4_K_M | 4,683,073,536 |
| IBM Granite 3.3 2B Instruct | Q4_K_M | 1,545,303,328 |

Pinned revisions, SHA-256 values and runtime identity are in
`PROTOCOL.json`. The same 32 actual native bad/partial/good controls run
before each family. Two format probes per family are also real requests and
their tokens are retained. Both families must pass the original strict
primary gate; a stronger model improving correctness alone does not establish
lower development cost.

The secondary upgrade pilot adds two real provider/consumer changes:

- `wire_length_v2`: widen the provider input/result and move packet tag bits
  while preserving every length bit in its caller.
- `bounded_window_v2`: add capacity to the provider API, return validity plus
  the end position, and update the caller's tuple/failure handling without
  u32 overflow.

Both languages receive the complete two-file workspace, the same semantic
contract, and three public smoke cases. Both may make at most two submissions
of 1,536 output tokens each. Compiler/Core diagnostics and public smoke
results may trigger the one repair round. Hidden tests run once after the
first public-pass candidate; no hidden failure or expected answer goes back
to the model. The hidden inventories contain 110 and 160 cases respectively.

HIA submits real function replacements through `patch.v2` with
`interface_policy=migrate` and whole-module verification. Rust submits actual
`api.rs` and `client.rs` contents compiled with a trusted caller. The finite
pure-scalar profile excludes external code and imports. Executables run from
sealed memfd images with CPU, address-space and wall-time limits. Controls
verify that changing only one side is rejected by the real checker/compiler.

Reference implementations exist only to create controls. No reference or
manually repaired model response is scored as an Agent answer.
Human time remains `null`; token, inference, compilation/validation and
automatic repair-round costs are measured separately.

Before inference, `run_agent.py register` writes exact fixture and prompt
hashes. Its `validate` command fails on design/evaluator drift. The first
`run` call additionally freezes all relevant compiler sources, runtime files
and compilers in a suite plan. The second family must use that same plan;
there is no family substitution or repeat invocation for the same model.

```bash
/usr/bin/python3 experiments/hia_optimizer_eval/next_20261028/run_agent.py register
/usr/bin/python3 experiments/hia_optimizer_eval/next_20261028/run_agent.py validate
```

Each actual model phase uses `run --output-dir PATH --model-id ID
--model-path GGUF --binary LLAMA_SERVER --clang CLANG --rustc RUSTC`.
Run Qwen first and Granite second. Use the same Z3/LLVM environment as above.
The executed follow-up additionally sets `LLAMA_ARG_REPACK=0` for both models;
this runtime condition is an explicit amendment, not an unchanged default.
A `summarize --output-dir PATH` call writes the cross-family report.
The environment must see the same task-owned model tmpfs for download and
execution. No evaluation tool downloads or substitutes models.

All raw model requests, rendered/tokenized prompts, responses, output token
IDs, native commands, diagnostics, failed submissions and compiled artifacts
must be retained, directly or in a lossless archive with verified member
hashes. Model weights remain reproducible dependencies rather than Git
artifacts. Upgrades are reported separately from the primary four-task gate.
