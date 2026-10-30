# HIA Core convergence and eight delivery tracks

This work integrates PR #399 at `e0ab595468d67bcf95485eacd22cea8ff332520c`
and PR #400 at `1bdb305fc5c6706c0e41ed66a4d43772c297d00e`, using their
actual common ancestor `0e1f5dd9bf0f54c492d96bd5dd1ae52e8c804997`.
Both parents and their historical evidence are retained. A historical passing
report is not an integrated-source qualification.

## One instruction contract

`hepta/hia_opcodes.py` defines all 50 primitive instructions, their exact
attributes, operand/result signatures, introduction versions, effects,
conditional effects, trap descriptions, resource guards and transitions.
The production Core verifier consumes these contracts. Terminator field
validation uses the same catalog. The public interface is:

```sh
python -m hepta hia catalog --schema hepta.hia.program.v8
python tools/generate_hia_catalog.py --check
```

The same source generates [the instruction reference](HIA_OPCODE_REFERENCE.md)
and [the JSON catalog](hia-opcode-catalog.v8.json), and is included by the
schema/route inventories. The textual assembly parser delegates instruction
admission to that verifier; it does not maintain another instruction whitelist.
It now accepts explicit primitive v6/v7/v8 and preserves v8 declarations such as
`return_loans(["input",null])`. Missing versus explicit nullable contracts remain
distinct canonical bytes. Older primitive and nominal spellings keep their
existing explicit adapters; no namespace is guessed or automatically upgraded.

The generated portion is local checking and named resource-guard dispatch.
The complete CFG/ownership algorithm, interpreter, LLVM lowering and machine
code remain separate implementations. They are not made proved by generating
a catalog. The production authority remains the full Python Core checker; the
Rust shadow is still a comparison implementation.

Every affected native/checker identity includes the new actual dependency.
Incremental admission now binds imported checker functions and the constants
read by both the Core module and the opcode module. Independent review found
that rebinding the latter's integer widths could otherwise leave a cached
literal admitted after fresh checking rejected it; a regression retains that
counterexample and requires rejection in both paths.

## Explicit resource and proof contracts

The [optimization resource contract](HIA_OPTIMIZATION_RESOURCE_CONTRACT.md)
rechecks actual leaf-call expansion and recomputes ticks, frames, allocator
interactions and live payload. `candidate_requalified` and
`both_fit_same_quotas` are distinct policies. Removing calls can change a VM
quota failure even when results and ordered resource actions agree; neither
policy promises an unchanged stop location, native RSS or asynchronous cleanup.

The [selected register proof](HIA_REGISTER_SAFETY.md) adds generic totality,
defined-register-read, exact register-growth and dead-literal transformation
theorems. The selected straight-line u32 machine is deliberately small.
Exporter correctness, source-to-Core correspondence, ownership, LLVM and
machine-code refinement remain outside these theorems. Native differential
execution and source hashes are separate evidence, not formal proofs.

## Registered evidence and source identity

New Agent tasks and NDU workload protocols live under
`benchmarks/hia_agent_public_tools/` and
`benchmarks/hia_ndu_converged_holdout/`. Implementations and no-generation
controls are committed before registration; registrations are committed before
actual model generation or future-workload measurement. Hidden results never
enter model feedback. Positive reference controls are not model successes.

The NDU comparison retains exact finite/stream source and Rust pins, sealed
image custody, independent sessions and equal zero result-cache capacity.
Exact Q32 DP and lightweight controls receive the same finite candidate bank.
Historical native build costs, new setup and two-episode amortization are
reported separately. The fixed-plan comparator is strong within that candidate
set; it is not a claim about all C/C++/Rust compilers or universal optimality.

The real Ring-Buffer maintenance cycle reconstructs both complete upstream Git
trees, preserves the original Makefile and interfaces, and replaces the nine
implementation bodies through the checked Hepta-to-Rust path. It retains the
old `0xff`/EOF failure and observes the upstream correction after upgrade.
This route is not relabeled as standalone HIA-to-LLVM refinement. Independent
byte oracles, allocation failures, process recovery and pthread profiles are
required, with source identities before and after execution.

## Acceptance discipline

Each final result must identify the exact source and selected host/toolchain.
Correctness, measured performance, NDU contribution and Agent productivity are
separate gates. No failed performance comparison is removed by averaging it
with another profile. Unknown dependency acquisition or human review costs
remain unknown, not zero. x86-64 host processes and pthreads do not qualify
physical AArch64/RISC-V devices, GPU, DMA, shared mutable heaps or general async
cancellation. Those profiles remain open until their own evidence exists.

The one-time maintenance, strong-static optimization, NDU and Agent studies
have now completed. Their negative observations are retained. Completion of an
experiment is not acceptance of its proposed advantage.

| Identity | Exact commit or scope |
| --- | --- |
| Published integrated implementation | `71aff3e9dbaa89601e0e0acacacac6c775e9f7f1` |
| Registration published before formal workload/model generation | `e223932a8bf25521db4204883af925dd64acc57a` |
| First integrated CI repair | `000acac3c357430ca062957ba288756a8d89e147` |
| Oracle normalization and Lean dependency repair | `3ecae1a92f6e77f14a0561fbd3a22595ebf1d09b` |
| Integration pull request | [Hepta #405](https://github.com/TrillionniumFoundation/Hepta/pull/405), based on #399 and retaining #400 as the other merge parent |

The formal studies ran on the registration commit, not on a retrospectively
edited source tree. Their complete bound source snapshots and before/after
identities are retained. Subsequent CI repairs update the reviewed safety
registry, resolve module/class/method test selectors, retain the actual pinned
Z3 version, and let regression tests find actual CI compilers. They do not
replace the study protocols, production study runners, held-out observations
or measured results. Two Agent regression test files do change after the
freeze; consequently the entire current test tree is not represented as the
original study snapshot.

Further real CI execution exposed a missing `zstandard` bootstrap dependency
and a CRC replay that exhausted its unchanged 120-second budget. The next
repair pins `zstandard==0.25.0` and removes redundant JSON encode/decode from
the exact-u32 oracle-observation path. It preserves type/range rejection,
fresh result containers, every oracle call and first-trap behavior. The
CRC protocol, candidate bank, 210 observations, 2,856 contexts and budget do
not change. This does change `hepta/hia_finite_context.py` after the original
study freeze, so the registered results continue to refer to `e223932a`.
The failed replay is retained and is not relabeled as successful or used to
replace the formal Ring/NDU/Agent results.

The [machine-readable acceptance ledger](../experiments/hia_core_catalog_convergence/RESULTS_20261030.json)
keeps the eight requested outcomes distinct. The PR remains a draft research
integration. There is no release or full-language safety qualification.

## Eight-track readout

| Track | Completed and observed | Acceptance boundary still open |
| --- | --- | --- |
| 1. Core, versions and instruction inventory | One 50-instruction source drives local checker contracts, assembly admission, versioned Agent discovery and generated documentation. Independent comparison against original #399 covers 12,513 distinct primitive programs with zero admission/canonical-byte differences. | Finite comparison is not a checker-equivalence theorem. CFG ownership, VM, LLVM and machine semantics remain separately implemented. |
| 2. Resource, failure, cancellation and optimization contracts | Explicit preservation/requalification policies; actual normal, allocation-refusal, cooperative-cancellation and trap observations; actual quota changes and rejecting controls. | Trap cleanup, arbitrary async cancellation and external host resources are not guaranteed. VM payload/tick/frame bounds are not native RSS/time/stack bounds. |
| 3. Selected trusted Core | Actual pinned Lean kernel checks selected register safety and a dead-literal rewrite, with 14 dependency reports, three rejected proof controls and 272 separate VM comparisons. Existing abstract models also rechecked. | Production checker soundness, exporter/source correspondence, LLVM lowering and emitted machine-code refinement remain unproved. |
| 4. Existing-project maintenance | Actual Ring-Buffer module migration, original build/API/clients, two real upstream revisions, upgrade behavior, native faults and recovery; all finite correctness gates pass. | Human contract/review/maintenance hours are unknown. Only one small C module is migrated; there is no equivalent full C++ maintenance cycle or general low-cost claim. |
| 5. Net-positive optimization | Preregistered new traces, real Clang/GCC LTO and LLVM IR-PGO controls, all actual campaign costs retained. | **Not met:** observed finite-horizon net-benefit upper bound is **−6.465594891 s**. |
| 6. Independent NDU contribution | Eight equal-bank/equal-budget arms, 16 completed native episodes; all outputs and budgets pass. Cold and prebuilt costs are separate. | **Not demonstrated:** even prebuilt NDU costs more than exact Q32 DP. Long-term amortization is unmeasured. |
| 7. Agent development advantage | Four new tasks per language, real model requests, complete selected-version catalog, public checks, terminal hidden execution, usage and repair records. Both languages succeed on 4/4. | **Not demonstrated:** HIA uses 2.2343× the registered token charge and 2.4914× the cell wall time. Human review time and population-level productivity are unmeasured. |
| 8. Hardware and concurrency | Native x86_64 and AArch64 scalar ABI profiles; separately, x86_64 Ring-Buffer ABI, child peak RSS, batch p99, pthreads, process fault recovery and allocation refusals. | No physical-device/MMIO/DMA/GPU/ISR qualification. ARM RSS/tail/concurrency were not measured. Shared mutation requires the tested external mutex. |

## Independent Core and resource evidence

The [Core evidence summary](../artifacts/hia-core-contracts-20261030/SUMMARY.json)
retains the original execution identity and individual report hashes. Its
[publication binding](../artifacts/hia-core-contracts-20261030/PUBLICATION_BINDING.json)
checks all 37 bound source files against published implementation `71aff3e9`;
this is a byte-identity check, not a claimed new execution of the old reports.

The compatibility comparison loads original #399's checker, schema and JSON
preflight directly from the pinned Git objects. It does not use the current
checker as its baseline. From 112 primitive seeds it checks 12,513 distinct
mutations: 454 accepted and 12,059 rejected, with zero acceptance or canonical
byte differences. Composite elaboration is excluded from this comparison.

The resource qualification executes 13 regressions with no skips, four exit
categories, two actual quota differences and three rejecting controls. In the
selected call-expansion example, VM ticks change from 14 to 11 and call depth
from two to one, while allocator interactions remain two and peak live payload
remains four bytes. At a tick quota of 11 or a depth quota of one, the source can
stop while the candidate returns. A requalified candidate therefore cannot
inherit a claim of identical quota-failure behavior from result equivalence.

The trap observation explicitly retains **one live owner, four live payload
bytes and zero drops**. Normal return, allocation refusal and cooperative
cancellation have their own actual cleanup observations. The report does not
invent unwinding or mark retained resources as cleaned because a process ends.

The selected register theorem covers all `2^64` pairs of u32 arguments in the
imported model. Its 272 VM cases are separate finite corroboration. Generic
defined-read, totality, register-growth and dead-literal transformation
properties do not prove the Python exporter or backend. The existing abstract
resource model contributes 11 theorem reports and two rejected controls; the
abstract provenance/typing model contributes 19 and five. These counts are
reported by model rather than pooled into a full-language soundness claim.

## Real C maintenance, strong baselines and measured cost

The [maintenance and host report](HIA_RING_MAINTENANCE_AND_HOST_QUALIFICATION.md)
documents the complete experiment and guarantee boundary. The two real
upstream revisions are `1468e24fc55986d7c432d1d26115e3b28f985fe0` and
`8de8fff55a0baee4fef2a1c6a82d258a27c3c0ba`. Both complete 12-file Git trees,
blob identities and executable modes are retained and reconstructed.

The original `make all tail`, public header and C clients are preserved. A
narrow compiler wrapper replaces the expected `ringbuffer.c` implementation
input with the newly migrated library. Nine bodies and the complete active
22-declaration inventory pass through Clang AST → checked Hepta → Rust
reference backend → C ABI. Unchanged clients may inline original header
helpers; the dynamic host calls all nine migrated APIs directly. This is a
module implementation migration with explicit foreign-pointer contracts.

The upstream upgrade only changes `examples/tail.c`. The old signed-char
`0xff`/EOF failure is preserved and the actual upstream correction is observed:
input `61 ff 62` produces `61` before the upgrade and `61 ff 62` afterward. The
generated module and bridge remain byte-identical across that caller upgrade.
This is a real maintenance cycle, but not a claim to have adapted a changed
library ABI or migrated a large C++ dependency graph.

The formal maintenance run retains 1,380 top-level process invocations and took
11.48528909 seconds of automatic qualification. Fresh migrations took about
1.858 and 1.766 seconds. It includes nine invalid-boundary child aborts, each
followed by a valid parent round trip, and six separate owned-storage calls
that finish with zero live allocations. Human authoring, review and
maintenance hours remain `null`; zero manual generated-body edits does not
establish zero human labor.

The process count describes retained top-level invocations, not every compiler
subprocess or forked descendant in the operating system.

The separate optimization protocol preserves its already observed development
seed and result under `DEVELOPMENT_` filenames. A published amendment changes
only the formal held-out seed to **3698156298**, selected once before generation.
The formal trace is executed once, with no candidate/flag tuning or replacement
seed after observation. Training seed **1708132849** remains separate.

Four actual arms compare Clang native LTO, Clang IR-PGO plus LTO, GCC native
LTO and Hepta-generated Rust native fat LTO. Positive IR counters are checked
for all nine APIs. Each arm executes 983,040 held-out transactions across three
new authored trace shapes. The frozen selection rule picks Clang native LTO as
the strongest single static C arm for this run.

| Registered finite-campaign accounting | Observed seconds |
| --- | ---: |
| Aggregate matched process-wall saving | +0.000103767 |
| Measured non-held-out preparation, translation, checking, builds, training, observation and cleanup charged | 6.465698658 |
| Net-benefit upper bound | **−6.465594891** |

The approximately 0.104 ms gross difference on a shared host is not evidence
of a repeatable speedup. Unknown human work, complete refinement proof and
final publication costs are additional costs, not zero. No unexecuted future
horizon is counted as an achieved saving. The negative upper bound is a
finite-accounting result, not a statistical confidence bound.

## NDU: correct finite execution without a measured planning advantage

The [registered NDU/Agent report](../artifacts/hia-ndu-agent-20261030/README.md)
retains the complete evidence and exclusions. Eight NDU/control arms share the
candidate bank, initial information, budgets and zero-capacity result caches.
Each has an independent native session and may use only its permitted completed
observations. All 16 episodes finish with correct outputs and valid actual
budgets. Four real transitions occur in the fixed-small/fixed-wide controls;
both NDU variants, exact DP and the best-plan/light controls retain base.

| Planner/control | Prebuilt marginal total (s) | Standalone total including original native build (s) |
| --- | ---: | ---: |
| Fixed best calibrated plan | 5.332587656 | 5.332587656 |
| Lightweight controller | 5.367453911 | 5.367453911 |
| Exact Q32 DP | **5.287006205** | **5.287006205** |
| Native NDU | 5.401191507 | 26.788522143 |
| Compact native NDU | 5.394100221 | 26.781430857 |

The original empty-target native build cost is 21.387330636 seconds, from its
retained actual build envelope. It is charged explicitly and was not rebuilt
in this round. Full NDU remains 0.114185302 seconds slower than DP even in the
prebuilt comparison. Two observed episodes establish only that short horizon;
long-term amortization has not been measured. Shared preparation is charged
once to each hypothetical standalone arm, so summing arm totals does not give
the wall time of the shared experiment.

This fixed candidate-bank comparison is distinct from the Ring-Buffer
cross-language LTO/PGO baseline. NDU is an untrusted finite evaluator with
`DENY_ALL` authority; independent verification still decides safety. These
observations establish neither unrestricted instruction-level global
optimality nor a safety guarantee supplied by NDU.

## Agent: successful new tasks with a negative efficiency comparison

Four newly authored tasks (`quota_clip`, `rotate_lane`, `weighted_prefix`,
`buffer_lane`) compare primitive HIA Core JSON v6 with Rust. This is not a
benchmark of the v8 textual assembly syntax. All four HIA cells actually fetch
the complete selected-version catalog. Every final candidate passes six
public and 72 terminal hidden native cases; HIA also checks the VM against an
independent oracle. Hidden cases never become repair feedback.

| Actual model-study outcome | HIA | Rust |
| --- | ---: | ---: |
| Successful fresh tasks | 4 / 4 | 4 / 4 |
| Actual model requests | 13 | 7 |
| Registered token charge | 244,188 | 109,290 |
| Total cell wall time | 95.565021552 s | 38.357774668 s |
| Failed public checks requiring a repair | 1 | 0 |
| Human answer modifications | 0 | 0 |

The HIA `weighted_prefix` candidate first fails the real checker for duplicate
SSA value `count`; the model repairs it from the public diagnostic. The failed
candidate and its request cost remain in the archive. All 20 real CLI requests
have complete retained usage and confirmed process cleanup. The full wrapper
takes 136.001399127 seconds, including shared work outside the cell totals.

The registered token metric is `input + output + reasoning`; it is not an
invoice and does not infer whether provider output/reasoning counters overlap.
Raw usage is preserved. Model alias `gpt-6.1-sol`, executable identity and task
protocol are fixed; service scheduling, model-route weights and service caches
are not controlled or attested. Four tasks, a restricted Rust API profile and
unknown human review time cannot establish a population productivity result.

Before generation, actual negative controls exposed incorrect Rust signature
acceptance, comment/dead-helper resource shortcuts, HIA uncalled-helper
shortcuts, malformed RPC crashes and a parameter-name restriction. Those were
fixed before the published registration. The retained positive/negative
controls are authored tests, not additional model successes. The separate
reviewer also contributed the Rust audit fixture; this was internal review,
not an independent external audit.

## Hardware profiles and guarantee ledger

The [native-host evidence](../evidence/hia_native_hosts_20261030/README.md)
comes from actual successful x86_64 and AArch64 jobs at registration `e223932`.
Each runs 48 functional cases through three implementations (144 native
entries), plus 16 resource cases through two implementations (32 entries).
Compiled ABI probes confirm LP64 and retained ELF files identify machines 62
and 183. Both are direct host processes, with no cross-execution/QEMU prefix.
The original ZIPs, 394 checked manifest members and ten checked ELF files are
retained. Physical bare-metal provenance is not attested.

That profile translates captured C to standalone Core and LLVM with a scalar
C ABI. It does not use the new maintenance experiment's Rust path, and it
does not measure RSS, tail latency, pthreads or hardware I/O.

The separate x86_64 maintenance profile measures single-thread, four disjoint
records, and four externally mutex-serialized threads. Its original GCC `-O2`
build is a maintenance control, not the strong optimization baseline. In all
three descriptive profiles, migrated runtime/batch p99 is lower while median
child peak RSS is higher: 2,084 versus 1,756 KiB for one thread, and 2,064 versus
1,880 KiB in both four-thread profiles. Batch p99 describes complete
128-transaction batches and includes mutex wait; it is not per-instruction
latency or a worst-case bound.

| Boundary | What is supported | What remains trusted or unproved |
| --- | --- | --- |
| C source capture | Pinned upstream trees, actual translation, finite byte/state oracles and original-client upgrade | General C/C++ equivalence; inferred foreign lifetime/extent; undefined input behavior |
| Primitive Core admission | Generated local contracts plus full existing CFG/ownership checks; negative regressions | Soundness of the production Python checker and composite elaborator |
| Selected formal Core | Pinned Lean kernel checks the selected register model and rewrite | Exporter correctness and extension to ownership/concurrency/full language |
| Optimization | Explicit observable/resource policy and new candidate budget checks | Native RSS/stack/CPU quotas and arbitrary failure-equivalence |
| Rust and LLVM backends | Actual compilation/execution with source and artifact identities | End-to-end refinement and compiler/linker/runtime correctness |
| Native ABI and host | Measured target-specific ABI, calls, failure containment and stated host metrics | Foreign caller contracts, OS/hardware behavior, untested devices/profiles |
| Planning | Equal-bank controls, actual transitions and complete declared cost categories | Unrestricted global optimality, NDU net advantage or lifetime amortization |

## Evidence index and integrated validation

- [Core, resource and selected formal evidence](../artifacts/hia-core-contracts-20261030/SUMMARY.json).
- [Ring maintenance result](../experiments/ring_maintenance/RESULT_20261030.json) and [raw receipts](../experiments/ring_maintenance/EVIDENCE_20261030.tar.gz).
- [Strong-static optimization result](../experiments/ring_optimization/RESULT_20261030.json) and [raw receipts](../experiments/ring_optimization/EVIDENCE_20261030.tar.gz).
- [NDU and Agent summary](../artifacts/hia-ndu-agent-20261030/SUMMARY.json), [raw archive](../artifacts/hia-ndu-agent-20261030/evidence.tar.gz) and [per-member export verification](../artifacts/hia-ndu-agent-20261030/EXPORT_VERIFICATION.json).
- [Native x86_64/AArch64 original CI artifacts](../evidence/hia_native_hosts_20261030/SUMMARY.json).
- [CI repair and final remote validation](../artifacts/hia-ci-convergence-20261030/README.md).

The 65-test local CI-repair suite passes with zero failures, errors or skips.
Its 18 native portability controls are also executed using compiler paths that
differ from the frozen development-machine configuration, without modifying
the production protocol. That rerun is a subset and is not added to the 65.
Actual Z3 4.15.4 matches the source pin and installed wheel 4.15.4.0. Full remote
workflow results, exact tested commits and any further minimal repairs are
recorded separately in the linked CI evidence; local focused tests are not
substituted for those remote gates.
