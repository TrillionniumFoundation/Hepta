# Executable HIA / NDU candidate integration

This integration adds a real, finite compiler search loop. It uses the NDU
`evaluate_candidates_with_policy` implementation from
`TrillionniumFoundation/hepta-private-ci` at immutable commit
`f8c9419df6ddeb36ff8b522a50219981fb8d9345`. It does not implement a similarly
named Python scoring function and call that NDU.

The loop produces a bound, advisory result or an explicit `no_change`.
It never activates code. A successful no-change is useful evidence that the
admission path retained the baseline when improvement was not established.

## Entry points and scope

| Component | Responsibility | Boundary |
| --- | --- | --- |
| `hepta.hia_ndu.prepare_candidate` | Verify immutable baseline, bind a strict plan, reproduce one of the three registered rules below, reverify exact candidate | Primitive v1–v6; scalar public entry; arbitrary type-safe edits are refused |
| `observe_semantics` | Compare actual interpreter results, trap codes and complete resource ledgers, including injected allocation failure | Finite corpus; instruction budget equivalence and foreign effects are excluded |
| `tools.hia_ndu_measure.measure_pair` | Compile both Cores through the current LLVM consumer; check each native result; retain paired C-loop timings and optionally the actual measured binaries | Linux x86-64, `(usize, usize, usize, usize) -> u8`, 1–64 cases |
| `rust/hia-ndu-bridge` | Call the actual upstream V2 evaluator with required abstain, explicit utility/aggregation rules and resource ceilings | Host-supplied evidence; authority remains `DENY_ALL` |
| `tools/qualify_hia_ndu.py` | Produce the transformation, validation, artifact, measurement and decision record | No production admission or code installation |
| `hepta.hia_version_dispatch.LocalVersionDispatcher` | Explicit host-controlled staging, generation CAS and pinning of actual interpreter calls | Separate interpreter-only lifecycle experiment; no automatic NDU activation |
| `hepta.hia_native_version_dispatch.NativeVersionDispatcher` | Actual background Clang compilation, sealed native images, isolated child calls, generation CAS, drain and rollback | Separate Linux x86-64 scalar ABI lifecycle; baseline or exact selected registered rewrite; no automatic NDU activation or external-state migration |

The existing Core language and verifier remain the semantic authority. This
adapter accepts only the exact registered rewrite of the frozen baseline.
An imported candidate is reverified and compared byte-for-byte with the
locally reproduced result. A model's assertion, score, or `proved` flag is
not an admissibility certificate.

All three registered passes have finite structural contracts. They are not
general semantic equivalence provers.

| Registered pass | Exact admitted change |
| --- | --- |
| `byte-swap.v1` | Replace the checked two-load/two-store swap of one mutable view with `buffer.swap` |
| `full-view-fill-loop.v1` | Replace a closed zero-to-view-length, unit-stride byte-store loop with `buffer.fill` |
| `checked-unsigned-reduction.v1` | Replace an exact zero-initialized unsigned checked-add counting loop with checked multiplication |

Composite and primitive v7 inputs remain outside this NDU adapter's contract.
The separate public byte-swap and checked-reduction APIs preserve v7 and refuse
composite input instead of erasing its structured identity. Their wider public
API support does not expand NDU admission automatically.

The fill-loop rule recognizes an actual zero-to-length, unit-stride loop over
the same exclusive byte view, with an invariant byte and no other body effects.
It preserves the length computation and replaces only the admitted loop with
`buffer.fill`, then reverifies the complete result. It excludes instruction-step
budget, host interruption and host allocation-failure equivalence. See the
[registered rule contract](HIA_FULL_VIEW_FILL_LOOP.md) for the exact constraints.

The checked-reduction rule requires count, invariant addend, index and sum at
the same unsigned type. It verifies the complete loop body, every incoming
edge, zero initial index/sum, unit stride and unchanged carried values. The
body has no memory operation, call or resource event. Nondecreasing partial
sums overflow exactly when the mathematical product does; a taken index
increment stays within the count's type. Successful final index and sum values
are preserved even when they escape the loop. Surrounding ownership and loan
operations keep their original order.

`formal/HiaCheckedReduction.lean` gives an independent arithmetic model with
universal theorems for complete checked outcomes, overflow agreement and the
index bound. Its controls also reject a changed initial sum and a missing
overflow guard. Those theorems do not verify the Python matcher, Core CFG or
resource semantics, LLVM lowering, native ABI or backend refinement. Step
budgets and host interruption remain excluded from the transformation's
equivalence claim. See [the checked-reduction contract](HIA_CHECKED_UNSIGNED_REDUCTION.md).

The native dispatcher additionally offers an explicit diagnostic loan profile.
It binds observations to selected Core borrow/end locations in the actual
version images, allowing a finite activation/rollback/drain experiment while
an old native call is waiting within that loan interval. Diagnostic images
have additional observations and are excluded from ordinary execution and
performance comparison. This does not introduce callbacks, external borrowed
addresses, shared-state migration or persistent workers. See
[native version dispatch](HIA_NATIVE_VERSION_DISPATCH_20261027.md).

## Building the actual upstream evaluator

First obtain a checkout containing the pinned upstream Git commit. The builder
exports immutable Git objects rather than the checkout's possibly modified
files. The upstream crates are generated under an ignored directory; they are
not vendored into this repository.

```sh
python3 tools/build_hia_ndu_bridge.py \
  --source-checkout /absolute/path/to/hepta-private-ci \
  --cargo /absolute/path/to/cargo
```

`Cargo.lock` is committed. Ordinary builds use `--locked`; `--generate-lock`
is an explicit dependency-maintenance operation, not a qualification shortcut.
The isolated workspace retains unchanged production Rust sources for
`hepta-ndu`, `hepta-contracts`, and `hepta-types`. Only their workspace packaging
is narrowed to omit monorepo test-only dependencies. The builder checks the
production dependency declarations against the original workspace.

The build provenance records the exact upstream/source hashes, local bridge,
builder, manifests and lock, actual Cargo/rustc identities, the executable
reported by Cargo, and before/after input equality. Git replacement objects
cannot substitute different contents behind the pinned commit. Build-target
environment variables cannot cause an old default-path executable to be
mistaken for the new artifact. None of these content identities is a remote
attestation or proof of compiler correctness. Upstream monorepo qualification
has not been inherited by this isolated integration build.

## Running the entire finite loop

Use the executable path and SHA-256 from the new build provenance. The report
path must be new; completed reports are not overwritten.

```sh
python3 tools/qualify_hia_ndu.py \
  --program examples/hia_ndu/byte_swap.json \
  --cases examples/hia_ndu/byte_swap_cases.json \
  --entry swap_candidate \
  --bridge /absolute/path/to/hia-ndu-bridge \
  --bridge-sha256 ACTUAL_BUILD_SHA256 \
  --clang /absolute/path/to/clang-20 \
  --samples 31 --iterations 10000 \
  --horizon-calls 100000000 \
  --output /new/path/qualification.json
```

Optional `--negative-cases` adds a bounded JSON list of failure and boundary
controls to interpreter validation. It does not execute trap cases inside the
native timing process. Independent native trap/allocator qualifications remain
necessary and are not replaced by this performance instrument.

Optional `--artifact-directory /new/path/native-artifacts` retains the actual
baseline library, candidate library and C driver from that measurement. The
directory must be new. Successful measurements record each retained file's
byte count and SHA-256 after the normal before/after execution identity checks.
Core/LLVM text, compiler identities, driver source, raw observations and costs
remain in the report. Partial build or execution failures leave available
files and diagnostics in the retained directory without claiming a successful
artifact set. Without this option, the temporary binaries are cleaned after
execution; their measurement-time hashes cannot later substitute for reopening
those deleted files.

For the fill-loop candidate use `--pass-id full-view-fill-loop.v1`,
`--program examples/hia_ndu/fill_loop.json`,
`--cases examples/hia_ndu/fill_loop_cases.json`,
`--negative-cases examples/hia_ndu/fill_loop_negative_cases.json`, and
`--entry fill_probe`. The supplied experiment protocol fixes the run count,
corpus, budget and thresholds before measurement; see
`experiments/hia_ndu_native_20261027/README.md`.

For the checked-reduction candidate use `--pass-id checked-unsigned-reduction.v1`,
`--program examples/hia_ndu/checked_reduction.json`,
`--cases examples/hia_ndu/checked_reduction_cases.json`,
`--negative-cases examples/hia_ndu/checked_reduction_negative_cases.json`, and
`--entry reduction_probe`. The separately committed
[checked-reduction experiment](../experiments/hia_checked_reduction_20261027/README.md)
fixes exactly two attempts, the same 18-case corpus, 31 pairs and 50,000 complete
corpus repetitions per side. Each attempt schedules 55,800,000 timed native
calls and 36 untimed correctness calls, retains the measured binaries and
rehashes them in the coordinator. The 5% MAD ceiling, 2% relative margin,
three-MAD paired-saving condition, 60-second search admission ceiling,
two-second decision reserve and 100-million-call horizon stay fixed before
timing. All failed, noisy, regressive and no-change outcomes must be retained.
The older fill/swap protocol and its results remain unchanged.

This new corpus is an authored arithmetic mechanism, not an unchanged external
application's hot function. An accepted mechanism gain would still leave
industrial P4 acceptance open. Neither the protocol nor artifact inequality
is an observed performance result.

NDU evaluation generations start at 1 because that is the upstream type's
contract. Local dispatch generations start at 0 and belong to a different
host state machine. The evaluator generation is not a dispatcher CAS value.
There is no implicit conversion or activation between those two domains.

## Measurement and cost interpretation

Both programs receive the same fixed input corpus, number of repetitions,
compiler and compilation flags. A single C driver loads both libraries and
times repeated indirect calls entirely in C. Python, compilation and loading
are outside the timed loop. Each case is checked independently before timing;
a matching aggregate checksum cannot hide two incorrect individual results.

The fixed schedule alternates baseline-first and candidate-first pairs.
The report retains every wall-clock and process-CPU observation, execution
order, checksum, native result, tool/artifact identity, and diagnostic. A zero
CPU-clock increment is retained as a clock-resolution observation. Wall time
must be positive. There is no sample trimming, adaptive repeat-until-success,
or selection of a favorable run.

The policy requires all of the following before the candidate is marked
feasible for NDU:

1. Exact candidate reproduction, Core verification and finite semantic checks.
2. Actual native results matching the Python VM run for each corresponding
   Core on every timing input. This qualification CLI itself uses Python plus
   native observations. Separate `test_hia_rust_owned_bulk` checks execute both
   swap and fill-loop candidates in the independent Rust VM; those scoped tests
   are additional evidence, not a third backend inside this measurement CLI.
3. Actual native artifact hashes must differ. Policy v2 records
   `identical_native_artifacts` and refuses eligibility when the complete
   native bytes are equal, even if noisy timing appears favorable. Artifact
   inequality alone establishes no behavioral or performance improvement.
4. Baseline and candidate median absolute deviation (MAD) at most 5% of each
   median, or a tighter declared threshold.
5. A positive paired median saving exceeding three paired-saving MADs and
   the declared relative margin (2% by default).
6. Projected runtime savings over the declared call horizon exceeding the
   measured search cost and a reserved two seconds for the decision path.
7. NDU's actual hard-feasibility and resource checks admitting the candidate.

The measurement policy report is `hepta.hia.ndu-measurement-policy.v2`.
The qualification path supplies both actual artifact hashes. Direct arithmetic
unit tests may omit both; their report then explicitly says native identity was
not checked and does not constitute native candidate qualification. Historical
v1 reports remain unchanged.

These are conservative engineering filters, **not statistical confidence
intervals or a proof of expected future gain**. Workload distribution and the
call horizon are explicit assumptions. A microbenchmark result does not become
a production workload measurement.

The projected baseline is the counterfactual original workload without
starting this search. The projected candidate includes the measured elapsed
search work (candidate generation, validation, emission, compilation and
measurement) plus the decision reserve. NDU does not erase paid costs by
calling them sunk. If the actual remaining decision work exceeds the reserve,
the host keeps no-change even if NDU advised the candidate. Both projected and
actually paid costs remain in the report, including unsuccessful searches.

`costs.total_paid_wall_ns` measures the work inside `qualify()`. The CLI's
initial reads and prevalidation, Python startup, and final report serialization
are outside that interval. An enclosing runner must also record the complete
CLI process wall time when reporting the observed command cost. Neither
interval represents the entire project's development and maintenance cost.

`maximum_search_ns` is a cost **admission ceiling**, not a preemptive deadline
for the whole Python call. Already-exhausted searches stop before native
measurement; running native subprocesses have individual timeouts. A slow
phase may still pay more than the ceiling, after which the candidate is
ineligible. Initial toolchain installation, building the NDU evaluator,
engineering labor, model tokens, energy, and long-term maintenance costs are
outside this per-search wall-time figure and remain separate P4/P5/P7
obligations.

Memory ceilings here refer to the observed Core byte-owner ledger. Artifact
ceilings refer to the actual native library bytes. Neither metric measures
total compiler RSS, allocator metadata, host process state, or all future
inputs. The measurement driver's address-space limit is separate and recorded.

## Identity and authority

The plan binds the baseline Core, registered pass, export, objective and
generation. Each contribution binds candidate Core SHA-256, native artifact
SHA-256 and an evidence digest covering validation, raw measurement and policy
assessment. The bridge hashes those three identities into its support digest.
The host independently checks the echoed candidate identities, recomputes the
support digest, and checks objective, generation, candidate coverage and
`DENY_ALL`. For `evaluation_sha256`, `evaluation_policy_sha256` and
`utility_profile_sha256`, the host checks nonzero lowercase SHA-256 syntax;
it does not independently recompute those three digests or rerun the evaluator.
Their authenticity relies on the pinned Rust evaluator and the host trusted
computing base. The executable is hashed before and after invocation.

The NDU request is an immutable serialization snapshot; subsequent edits to
the caller's original Python object cannot relabel the saved receipt. These
controls assume integrity of the host process and selected tools. A hostile
Python process, compromised compiler, forged build provenance or arbitrary
malicious native executable remains outside this boundary.

There is always a real `abstain` contribution bound to the baseline artifact.
The actual upstream evaluator rejects missing or infeasible abstain. A tie
without a registered scalarizer stays a Pareto set requiring a slow path; this
host keeps no-change. NDU cannot make an invalid transformation valid, turn
tests into a proof, override a host rejection, or grant execution authority.

## Qualification status

This work establishes an executable, reproducible integration path for three
finite compiler passes. It does not close the entire P0–P7 roadmap. In particular:

- General typed-place/layout/concurrency semantics and arbitrary resource
  models still require their own language and proof obligations.
- Rust/LLVM/native correspondence remains scoped evidence, not a whole
  compiler refinement theorem or absolute native safety.
- The current corpus is a real native microbenchmark, not evidence of general
  superiority to Rust or an industrial hot function's repeatable net benefit.
- General C/C++ translation, automatic contract recovery, migration labor and
  bridge maintenance costs remain unqualified.
- Interpreter and isolated-child native version pinning, including the
  instrumented observation of selected native loan intervals, do not establish
  in-process patching, external-state migration, callback lifetime safety or
  distributed rollback.
- Physical targets, long-lived complex-resource workloads and independent
  Agent productivity experiments require additional executions.

See [the Core consumer contract](HIA_PROGRAM.md),
[local version dispatch](HIA_LOCAL_VERSION_DISPATCH_20261027.md), and
[native version dispatch](HIA_NATIVE_VERSION_DISPATCH_20261027.md), and
[the integration acceptance boundaries](HIA_SEVEN_STAGE.md).
