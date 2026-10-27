# Fixed strong-baseline optimizer evaluation

The completed frozen runs and their limitations are documented in
[`results.md`](results.md). The benchmark fails its fixed noninferiority gate;
the completed local-agent pilot has zero successful repairs in 16 cells.
All earlier failed or incomplete attempts remain in the evidence catalog.

`tools/qualify_hia_optimizer_bench.py` compares the same two allocation/byte-loop
algorithms as standalone verified HIA, independent safe Rust, C, and C++. The
fixtures include complete allocation, fill, transform, checksum and release paths.
This is a finite buffer-kernel experiment, not an application benchmark suite or
a universal language performance comparison.

The fixed backends are HIA's admitted direct LLVM `-O3` backend, Rust `-O3` with
fat LTO and one codegen unit, Clang C/C++ `-O3` with full LTO, and actual
instrumentation-PGO versions of both Clang baselines. PGO builds run **only** the
training sizes/seeds, merge their real `.profraw` files, and rebuild with
`-fprofile-instr-use`. Training and holdout size/seed sets are disjoint. The
benchmark never chooses flags or repetition counts from holdout results.

```sh
python tools/qualify_hia_optimizer_bench.py --output-dir /tmp/new-bench-attempt
python -m unittest tests.test_hia_optimizer_bench
```

The native toolchain needs Clang/Clang++ 20+, LLD, Rust, `llvm-profdata`, and
Clang's profiling runtime. On a minimal installation without compiler-rt, pass
`--profile-runtime /path/to/libclang_rt.profile-x86_64.a`; the evaluator records
that archive's exact identity and performs the normal instrumented-object build
followed by explicit runtime linking. The downloaded package used in development
is identified in `evidence/clang_profile_runtime.json`. A missing runtime is a
recorded build failure, not grounds for silently dropping the PGO arms.

The output directory must not exist. It retains input copies, verified Core,
emitted LLVM, all actual native binaries, training profiles, exact commands,
their stdout/stderr/exit status/timing, every scheduled sample, and the report.
Failed attempts are kept. There are no retry, trimming, or threshold override
options. An optional `--candidate-core` takes a separately verified HIA program;
the oracle and benchmark contract remain fixed and do not come from that candidate.

Each of 84 fresh-process observations performs 31 batches of 128 varied calls.
Reports include paired complete-loop timing, the external process wall time,
CPU time, empirical p50/p95/p99 batch durations, and that subprocess's Linux
`VmHWM` after exec. `ru_maxrss` is retained separately because it can include
the Python launcher's fork-to-exec high-water mark. Compile, explicit verification, finite-correctness and PGO training
costs are retained separately. This fixed-configuration baseline does no
optimizer search and reports zero search calls and zero search time.

Quality and performance are separate gates. Missing, failed, malformed, noisy,
too-short or changed-identity measurements fail quality. A slow correct HIA
sample remains data and can fail the fixed noninferiority thresholds: a 1.05
upper paired-time ratio, 1.10 empirical p95 batch ratio, and 1.25 peak-RSS ratio.
The paired bound uses a one-sided t calculation on seven group log ratios; its
independence/normality assumptions are explicit. Tail quantiles describe these
217 batches per kernel/backend, not production-service p99 or population bounds.

The experiment freezes exact file hashes even for a dirty development tree and
records whether it was committed. Changes during an attempt invalidate that
attempt. The complete scheduled sample inventory and input seeds are registered
before building native code; the bound source files are copied verbatim into
the final attempt's `source_snapshot`. Shared-host affinity does not establish exclusive CPU ownership.
Finite native outputs do not prove general semantic equivalence, C/C++ safety,
compiler refinement, global optimality, or superiority over Rust. Allocation
failure and arbitrarily large inputs are outside this performance domain.

## Matched local agent pilot

`tools/qualify_hia_agent_holdout.py` runs one exactly identified local GGUF model
on the existing four two-helper maintenance contracts. It adds 64 deterministic
input pairs per task to the existing 13 boundary pairs, and never sends the
test inputs or oracle outputs to the model. Each task has HIA/Rust and full/query
context arms, all with the same model, syntax-only JSON constraint, 512-token
output limit, one attempt, and native test tools. All 32 buggy/partial/fixed
native controls must pass before model execution. The four-task, one-model
result cannot satisfy the historical two-model gate or establish broad coding
productivity. Correctness, rejected responses, accepted wrong repairs, attempts,
token costs, inference time and native-evaluation time are retained separately.

```sh
python tools/qualify_hia_agent_holdout.py \
  --output-dir /tmp/new-agent-attempt \
  --binary /path/to/llama-server \
  --model /path/to/locked-model.gguf \
  --model-sha256 EXACT_SHA256
python -m unittest tests.test_hia_agent_holdout
```

The owned offline server uses a private Unix socket with peer-PID checks; its
socket must be permitted by the execution environment. The evaluator has no
network/model-download fallback. The evidence catalog retains infrastructure
failures as well as completed model outputs.
