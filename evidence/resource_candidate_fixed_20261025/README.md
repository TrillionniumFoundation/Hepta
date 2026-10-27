# Unified resource candidate: complete second integration attempt

Code commit: **`2f8cd75d5ab5dba08f130561c1b9198c76e6ba6e`**.  
Code tree: `61a4b8bc0d32eb2fbcb187bbfee77be42ffdd736`.

The complete run finished all **46 planned gates**: **44 passed, 2 failed**.
The unit and native integration suite passed **1,369 tests, with zero skips**.
The source snapshot was unchanged throughout the run. The aggregate remains
**`failed`**, and **`whole_project_blockers_closed=false`**.

The two failures are the scalar and owned-resource LLVM performance gates.
Both completed their native correctness checks and all planned timing samples.
Both satisfied the frozen speed thresholds, but exceeded a frozen measurement
stability limit. They remain `measurement_inconclusive`; favorable observed
ratios are not a release pass. No sample was removed, replaced or rerun to
select a passing result.

## Identity and complete results

| Item | Recorded value |
| --- | --- |
| Run start | 2026-10-25 17:36:53.458043 UTC |
| Run completion | 2026-10-25 17:49:32.728652 UTC |
| Complete run wall time | 759.270609 seconds |
| Unit suite time / gate wall time | 391.163 / 391.615 seconds |
| Compiler source SHA-256 | `0bc527cfc5aec67c6bf9b41929dec267abe5eda0704aa12bc63256817374b6b9` |
| Complete source snapshot SHA-256 | `4d228091e1cd920938528f50a8dcb946c3ed7f20a581188edf4bdc2ef68fc67d` |
| Source changed during qualification | No |
| Live controlled AI-model trials | 0 |

[release-validation.json](release-validation.json) is the original aggregate.
[attempt-summary.json](attempt-summary.json) derives the counts, source identity,
original failed rows and complete performance evaluations from that run.
[stage-ledger.json](stage-ledger.json) maps the actual results to all seven
requested stages and preserves the remaining production blockers.

The previous run's C++ status-collection defect is closed in this candidate:
`cpp_owned_migration` accepts the producer's exact scoped success status and
still performs strict current-source replay and native-evidence validation.
Its actual gate now passes. The [first complete failed attempt](../resource_candidate_20261025/README.md)
is retained unchanged. This run does not replace it or retroactively change
its result.

## Performance: observed speed and failed measurement quality

The scalar protocol retains **42 samples**, with **186 correctness vectors /
372 native calls**. Its paired geometric LLVM/Rust time ratio is **0.911476**.
Only the Rust `branch_accumulate` series violates the 5% relative-MAD limit:
its recorded relative MAD is **10.3231%**.

The owned-resource protocol retains **63 samples**, with **196 correctness
vectors / 784 calls** across LLVM, same-source Rust, independently written safe
Rust and checked C. C is a correctness reference, not a timed baseline. The
native driver times allocation, initialization, borrowed access, cleanup and
dispatch; no Python or ctypes call is inside the timed loop.

| Owned workload | LLVM / same-source Rust | LLVM / handwritten Rust |
| --- | ---: | ---: |
| Complete allocation/use/drop lifecycle | 0.535022 | 0.939845 |
| Constructor error and cleanup | 0.767976 | 0.848654 |
| Two-stage resource use | 1.016452 | 0.560189 |
| Geometric mean of paired median ratios | **0.747484** | **0.764494** |

Both baselines satisfy the unchanged per-kernel ceiling of 1.20 and geometric
ceiling of 1.10. The constructor-error series violates the 5% relative-MAD
quality limit for **Rust (7.8514%)** and **LLVM (6.1607%)**. Therefore this
candidate has **no passing scalar or owned LLVM performance qualification**.
These figures describe one host and these inputs; they do not establish a
general performance advantage over Rust.

Original reports: [scalar LLVM](llvm_native.json), [owned LLVM](llvm_owned.json).
The [independent consistency review](performance-consistency-review.json)
compares protocols, source identities and native artifact digests with the
earlier attempts. The records do not establish a particular scheduling,
frequency or co-tenant explanation for the timing variation.

Earlier performance attempts remain available: the [initial and optimized
resource experiments](../llvm-owned-native-20261025/README.md), the [first
integration](../resource_candidate_20261025/README.md), and the [earlier
40-gate candidate](../unified_candidate_20261025/README.md). Historical success
does not substitute for this candidate's failed quality gates.

Other measured paths also retain regressions. The Ring-Buffer observation
records Hepta/C-ABI time ratios to original C of **1.212688** for byte operations,
**0.523213** for 64-byte batches and **0.979674** for state queries. Those are
short, non-affinity-controlled observations under different C/Rust compiler
profiles, not a universal parity claim; see [stateful_c.json](stateful_c.json).

## Actual implementation and native execution

### Source semantics and resource core

The shared source checker and canonical semantic encoder feed explicit backend
profiles. Source, semantic/resource projections and regenerated LLVM are bound
by fresh replay. Rehashing a forged graph or LLVM payload cannot replace source
correspondence. Unsupported backends reject without a silent fallback.

The Rust reference path implements the broader hosted profile. Independent C
covers the finite owned-resource profile. The direct owned-byte LLVM path
covers finite structs/enums/Result/generic instances, Buffer<u8>, checked
integer arithmetic, read/mut borrows, immediate returned slices, move and drop.
Its machine code is generated from LLVM, while a pinned Rust reference check
remains a validation dependency. General stored views, tasks and I/O are not
silently enabled in that LLVM profile.

Independent local stored-view rules now track shared copying, exclusive moves,
access and end-of-loan conditions. [resource_views.json](resource_views.json)
combines those rules with an owned generic wrapper and fallible construction:
**9 native calls, 2 actual allocator refusals, no remaining live allocation**.
It does not claim general interprocedural lifetime or type/lifetime composition.

The [separate Rust allocator qualification](llvm_owned_rust_allocator.json)
recompiles both unchanged performance application sources with observing
allocators. Each normal run observes **7 allocations, 7 frees, 1 refusal and
zero live allocations**, then successful recovery. First-allocation refusal
also returns the expected error and recovers. Both actually compiled
deallocation-omission controls retain 7 allocations and exit **86**. These are
untimed instrumented programs, not an allocation trace of the original timing
binaries.

### C migration

The build-configuration migration accounts for the complete active declaration
set of its accepted translation units. It executes the original and converted
implementations independently. [c_project.json](c_project.json) records
**7 converted functions, 11 declarations and 1,046 differential calls**.
[upstream_c.json](upstream_c.json) migrates complete `compare-int` and `hash-int`
modules: **3 implementation functions, 6 declarations and 25,302 calls**.
[stateful_c.json](stateful_c.json) covers the complete selected Ring-Buffer
module: **9 functions, 22 declarations, 65,544 calls, 16,384 state transitions
and 8 capacities**.

The Ring-Buffer configuration is explicit: C11, NDEBUG and unsigned char.
The external pointer/record-view contracts remain caller obligations. Its
additional Hepta Buffer owner is an authored client, not a conversion of an
upstream allocator. These results cover the recorded configurations, not
arbitrary C preprocessor configurations or unexamined source declarations.

### C++ bridging and actual implementation migration

The library bridge executes `std::vector`, `std::string`, Boost.Math and
explicit template instances with checked constructor, lifetime and error
contracts. Scoped RAII retains the original C++ implementation and destroys
the automatic object before publishing its copied result. These bridges do
not count as rewriting the external library.

The selected scalar value-class migration separately translates real method
and constructor bodies into Hepta, with **1,777 native cases per C++/Rust/C
implementation**. The exclusive byte-owner migration checks a complete
**321-node native AST protocol** and translates its resource implementation
into Hepta Buffer/Result/move/borrow/drop. It is a closed accepted protocol,
not arbitrary semantic inference for all C++ RAII classes.

The original C++, converted Hepta/Rust, converted Hepta/C and the independently
compiled LLVM migration output each execute **475 vectors**, observing
**359 allocations, 359 frees, 98 actual refusals and zero remaining live
allocations**. The LLVM end-to-end gate consumes the actual migration output;
the translated implementation links no original C++ and uses no object
generated by Hepta's Rust or C backends. A separately compiled C harness
observes execution.

See [cpp_class.json](cpp_class.json), [cpp_owned.json](cpp_owned.json) and
[cpp_owned_llvm.json](cpp_owned_llvm.json). A compiled generated-C control with
its actual free removed is rejected after observing a live allocation. No
claim is made about arbitrary destructors, multi-owner coupling, inheritance,
retained aliases or preserving a C++ class's mangled ABI.

### Upstream library upgrade and actual cost

[cpp_upgrade.json](cpp_upgrade.json) executes nlohmann/json **3.11.3 and 3.12.0**
with an unchanged adapter, contract and Hepta caller: **98 semantic cases per
version**, unchanged generated public boundary and matching C export symbols.
The observed upgrade needs **zero source/contract/caller changes**. The initial
authored integration still contains **33 adapter lines, 104 contract lines
and 8 Hepta caller lines**. Human hours and actual agent tokens are unknown,
not zero. Complete per-version qualification times are **11.5533 and 11.3523
seconds**; these are execution costs, not total development costs.

Every calibrated allocation site is injected: **17 sites per version**.
Sites **1–14 recover** with unchanged error-output sentinel, restored allocation
baseline and successful subsequent invocation. Sites **15–17 terminate with
SIGABRT** in foreign `noexcept` destruction. Both reports retain
`all_allocation_failure_paths_recovered=false`. The gate passes complete
upgrade observation; those six terminating processes across two versions do
not acquire recovery qualification.

## Platform, agent tooling and formal evidence

Linux x86-64 native ABI execution, AArch64 user-mode QEMU and the Cortex-M4
system-emulator profile passed. The current candidate's real Windows job
**121240985758** in run **40217258938** passed both optimization profiles,
**181 foreign calls per profile**, layout checks and a compiled wrong-control
rejection. The original [Windows artifact](platform/windows-x86_64.json) and
[strict source replay](platform/windows-receipt-replay.json) are retained.
Replay uses the exact commit with the Windows CRLF checkout representation;
it does not rewrite the receipt or pretend to repeat Windows execution.

[GitHub Actions observations](platform/github-actions-observation.json) retain
the other host jobs and full qualification as queued at observation time.
Queued work is not an executed result. Windows Rust/C ABI success does not
qualify the Linux-only owned LLVM backend for Windows.

The agent workspace supports pinned semantics, constrained edits and a
prepare/commit/recover protocol. Strict namespace qualification executes the
five selected task fixtures. All **10 real process-death checkpoint cases**
pass the crash/recovery fixtures, with **624 hidden native checks**. This tests
the selected process-death checkpoints, not power-failure durability or
arbitrary-instruction termination. The comparison framework and cost adapter
are implemented, but **controlled live-model trials remain zero**.

The current [execution prerequisites](execution-prerequisites.json) record no
configured provider API key, failed provider-domain resolution and no visible
GPU/serial board device paths in this process. No API request was sent.
These observations do not assert that other hosts or remote devices do not
exist. No private credential value is included.

Lean checked **30 abstract-core theorems** and rejected **7 selected negative
mutations**. The models are conditional abstract resource/provenance/type
cores; they do not prove the actual compiler, all source-to-backend refinement,
foreign implementations or the full concurrent memory model sound.

## Remaining completion conditions

The seven-stage ledger distinguishes implemented and exercised profiles from
the complete production-language objective. In addition to the two current
performance-quality gates, broader lifetime/type combinations, global resource
accounting, composed task/I/O cancellation, service APIs, general migration,
broader backend coverage and production package infrastructure still require
implementation and validation. These are not all external-environment issues.

Controlled model comparisons require actual model access, a frozen model and
budget, and fully metered complete trials. Additional host claims require real
reports on those hosts. Board/GPU claims require their semantics, implementation
and actual devices. A small proof core cannot be promoted to an unconditional
memory-safety guarantee for arbitrary C/C++ code.

Performance qualification should next use a controlled eligible host with the
same source, protocol, baselines and thresholds. The existing failures remain
in the evidence. Any new measurement attempt must be identified independently;
neither selecting the best prior run nor weakening quality thresholds closes
the current blocker.

## Reproduce and inspect

Use the pinned toolchain configuration and verification bootstrap documented
in [UNIFIED_CANDIDATE.md](../../docs/UNIFIED_CANDIDATE.md). Set `RUSTC` and `LEAN`,
and select the recorded C/C++ tools. Owned LLVM currently requires native
Clang 20+ on Linux x86-64.

```sh
python -m hepta migrate-cpp-owned \
  examples/cpp/owned_migration/owned_bytes.cpp \
  --output /tmp/hepta-owned-example.hepta --clang clang++
python -m hepta build-llvm-owned /tmp/hepta-owned-example.hepta \
  --output /tmp/hepta-owned-example.o --kind object --clang clang

python tools/release_check.py \
  --output-directory evidence/my-new-candidate \
  --continue-on-failure \
  --qemu-aarch64 /absolute/path/to/qemu-aarch64-static
```

Use a new output directory. The release command retains all planned results
and returns failure when a gate fails; continuation does not turn failure into
success. [archive-manifest.json](archive-manifest.json) hashes unmodified JSON,
logs and generated text. Generated work-directory text is copied under
`retained_workdirs/`. Native products are identified but not stored in Git;
another checkout must reproduce them before using retained-file validators.
Evidence-only publication does not modify the tested compiler/source snapshot.
