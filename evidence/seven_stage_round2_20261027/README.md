# HIA seven-stage round 2 — executed source and retained failures

The final frozen qualification completed **2,215 tests,
zero failures/errors/skips**, and **18/19 scoped gates**.
The remaining performance gate is `measurement_inconclusive`.
The two-family atomic maintenance study is `completed` and retained
**36 actual requests / 36 responses**.
**The complete seven-stage language, ecosystem, hardware, safety and productivity
goal remains open.**

## Exact source identity

- Qualification and model-study source:
  `5818c5814fb42dbd97a027e9b328f4ae3099c0fc`.
- Source tree: `94686c350b10e93f631ea164811ecbc5948b3775`.
- Compiler SHA-256: `50501bcda11e2d0b2be75cc05f75fc90d091abab30f3167656488e07774f3006`.
- Complete selected source snapshot: `de71f2ae7267f323a318ca7aee422f6ed881a8351028a5583f74d3446b3272c6`.
- Initial round-2 merge: `806110df3ef57a388d593ac454e3011724a802e3`, with parents
  `bdb8690317e96e1cd4a6f140e96376faa9dba522` and
  `b41db78816c39ab59dd42d35c28426c54d1fe45d`.
- [PR #210](https://github.com/TrillionniumFoundation/Hepta/pull/210) remains a
  draft integration. The previous evidence and failed model protocols in
  `evidence/seven_stage_20261026` are preserved unchanged.

The final source increment changes only two invalid test fixture strings and
prerequisite documentation. The compiler, isolation checks, benchmark protocol,
model tasks, response policy and acceptance criteria are byte-identical across
the completed round-2 runs. Independent Git-object and AST comparisons verify
that no assertion was removed and no skip was added. Qualification and model
evidence refer to their tested source commit, not a later evidence-only head.

## Functional increments and exact limits

| Area | Executed or implemented increment | Boundary |
| --- | --- | --- |
| Shared language rules | Explicit `hepta.hia.program.v7` and `hepta.hia.composite.v2`; the latter lowers to v7. Existing composite v1 still lowers to v6. Explicit legacy conversion and upgrade paths remain independently verified | Recognizing a version never grants an older budget analyzer or Rust shadow permission to analyze unsupported v7 resources |
| Recursive ownership | Actual runtime-sized `Nil` or `Node(buffer, chain)` nodes, fallible push, consuming pop, read/mutable head loans, iterative destruction and cooperative cancellation | Fixed buffer payload; not arbitrary recursive ADTs, shared cycles, escaping loans or preemptive destruction |
| Atomic agent edits | 1–16 nonoverlapping SSA sites, one immutable program snapshot, exact typed JSON matching and one final whole-module verification | Atomic acceptance does not prove behavioral equivalence or general agent usefulness |
| Real C modules | Unchanged upstream Ring-Buffer plus a separately authored caller, two configurations × two translation units, all project declarations classified, original and generated exports checked | Two safe Hepta/Rust variants; zero standalone HIA record-view variants. Foreign pointer validity and truthful contracts remain premises |
| C++ lifetime pipelines | Automatic objects and copied scalar/POD values compose across vector/deque and two real nlohmann/json releases; copied result publication follows reverse destruction | Two bridge upgrade variants, zero new native C++ implementation migrations in this pipeline; the foreign library remains C++ |
| Targets | Actual x86-64, AArch64/QEMU and new RV64GC LP64D/QEMU execution; historical Cortex-M4 Rust/BSP qualification stays separate | RV64 evidence is a finite integer ABI/runtime slice. No physical board, device protocol, DMA, interrupt or GPU qualification |
| Correspondence | Native/VM/spec checks and the existing selected actual four-instruction Lean property remain executable on the frozen source | Selected arithmetic proof is not Python-verifier soundness, LLVM refinement, recursive-resource soundness or whole-compiler proof |

### Recursive chain execution

The dedicated native collector executed **324/324** planned cases with separate
header/payload ledgers, independent arithmetic expectations and direct VM
comparisons. The maximum actually successful tested structure has **4,098
nodes**. Headers request **24 bytes** each; those are requested object bytes,
not allocator metadata or host-process RSS. Construction depth comes from
runtime control flow, and destruction uses an explicit loop.

`chain.try_push` consumes its incoming SSA handles on both outcomes. Successful
allocation returns the new chain and an empty fallback buffer. Refusal returns
the original chain and original payload under new handles, preserving both.
Head loans retain the chain's ownership root, preventing move/pop/drop/transfer
while the loan is live. Generic records/enums, locally stored reborrows,
failure recovery, polling and cancellation compose with the chain.

Two actual mutants remove header or payload frees and leave observed leaked
bytes; an empty-head operation executes a real bounds trap. VM budget stops
retain their stopped resource state, and process termination is not labeled
normal destructor completion. Existing v1–v6 cost analyses and the opt-in Rust
shadow reject v7 until extended, rather than assigning a dynamic drop one
constant-cost event.

### Real C resource matrix

Each configuration has **37 active project declarations** with explicit
dispositions: ten converted functions, sixteen resolved prototypes, two
complete records, two forward records, four aliases and three repeated inline
definitions. Compiler/system declarations are recorded separately. All ten
actual original object function exports match the generated target. The
generated implementations do not link the original C objects.

Per configuration, **2,048 upstream state transitions** yield **8,200 paired
original/translated operation observations = 16,400 actual external calls**.
The cross-translation-unit client adds **1,536 state transitions**, **3,072
transfer calls**, **3,072 subsequent query calls**, and **12 initialization
calls**. Returns, persistent fields, every backing byte, input immutability,
output sentinels and an independent deque oracle are compared. These units
must not be mixed into an invented single test denominator.

Five actual boundary-control child processes run per variant; three invalid
contract groups reject. Mutable ranges are checked for numerical disjointness
before Rust references are constructed. Live allocations, pointer provenance,
absence of concurrent foreign aliases and the declared input restrictions
remain external premises. This route has **no independent performance
qualification** and is not a theorem for arbitrary C.

### C++ execution and retained termination

Each of nlohmann/json **3.11.3** and **3.12.0** runs 56 vector/deque and 112 JSON
composition cases, each through direct C++ and the generated Hepta bridge:
**672 actual case-route executions**, with a separate Python oracle. Thirteen
actual bridge C exports and unchanged API/normalized generated bytes are
checked across the upgrade. Contract, authored adapter and Hepta caller stay
unchanged between releases.

All **156** calibrated allocation-refusal attempts execute: **132** recover,
clean up and preserve the output contract; **24** terminate with `SIGABRT` and
`std::bad_alloc`. The latter remain unrecovered foreign noexcept paths. The
observation gate's status is `complete_observation_with_foreign_termination`;
its `ok` means the fixed observation protocol completed, not that all failures
recover or the foreign library is memory-safe. Three actual negative controls
cover a native signature mismatch, wrong result and removed destructor.

### RISC-V64 execution

The new target executes **212** scalar/bulk C-to-HIA calls in two binaries plus
**21** recursive-resource calls in a third, totaling **233**. There are
**213** corresponding VM observations and **seven** actual target negative
executions. C ABI argument/return extension, twelve-argument register/stack
placement, finite allocator/memory imports and actual node/payload cleanup are
observed. The unsigned-u32 RV64 return sign-extension corner has an independent
native Clang probe. General foreign-call support remains false.

## Performance: both complete runs are retained

The unchanged v3 protocol fixes three workloads, three backends, seven rounds,
order and quality/ratio thresholds. Both completed runs retain all 63 samples:
**126 observations, zero exclusions**.
Both satisfy the numerical ratio limits and fail the fixed relative-MAD
measurement-quality limit. The values below are descriptive observations from
unqualified timing runs, not stable speedup claims.

| Run | Samples | HIA / same-source Rust geometric paired time ratio | HIA / independent safe handwritten Rust | Status |
| --- | ---: | ---: | ---: | --- |
| run1 | 63 | 0.935646 | 0.928050 | measurement_inconclusive |
| run3 | 63 | 0.935899 | 0.945237 | measurement_inconclusive |

The final quality failures are retained verbatim in `performance.json` and
`SUMMARY.json`. These workloads do not cover arbitrary recursive chains,
all C/C++ migrations, every processor or total-system resource usage.

## Two-family atomic maintenance experiment

The fixed study has four two-site tasks × four interfaces × two model families:
32 planned task requests plus four format probes. Every task requires two
helper repairs while preserving its caller. The four compositions reuse eight
previously disclosed arithmetic helper contracts; they are not independent
production task sources or representative repository maintenance. HIA has
three functions in one module; Rust has three source files. This is not HIA
multi-module linking evidence.

The models are Qwen2.5-Coder 7B Q4_K_M and IBM Granite 3.3 2B Q8_0, pinned by
publisher revision and exact file SHA-256. Comparisons are within model;
different sizes/quantizations are not equal-compute model samples. Every arm
uses one greedy attempt, seed zero, four threads, 8,192 context tokens and a
512-output-token cap. The decoder constrains only a generic JSON object. No
answer fields or correct replacements are inserted into its grammar.

All **32/32 native controls** passed:
neither helper repaired, only helper 0, only helper 1, and both repaired for
each language/task. Wrong candidates must actually execute and disagree with
the independent oracle or exhibit the explicitly recognized overflow failure;
unrecognized crashes and compiler/loader failures cannot count as detection.

| Model | Interface | Correct / planned | Completed task cells | Rejected responses | Accepted but wrong | Known task input + output tokens |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| qwen_coder_7b | hia_full_context | 0/4 | 4 | 1 | 3 | 3265 |
| qwen_coder_7b | hia_edit_query | 2/4 | 4 | 1 | 1 | 1673 |
| qwen_coder_7b | rust_full_context | 2/4 | 4 | 1 | 1 | 1386 |
| qwen_coder_7b | rust_edit_query | 1/4 | 4 | 0 | 3 | 1322 |
| granite_33_2b | hia_full_context | 0/4 | 4 | 4 | 0 | 5149 |
| granite_33_2b | hia_edit_query | 1/4 | 4 | 3 | 0 | 2009 |
| granite_33_2b | rust_full_context | 0/4 | 4 | 4 | 0 | 1768 |
| granite_33_2b | rust_edit_query | 0/4 | 4 | 4 | 0 | 1727 |

Primary criteria per model: **[False, False]**.
Secondary criteria per model: **[False, False]**.
Both require the entire study to finish and all four HIA-query tasks to be
correct. The primary also requires success at least as high as Rust query and
no more task tokens; the secondary compares success and token reduction with
full HIA. Unstarted cells remain explicit and do not become successful,
incorrectly executed or zero-cost completed attempts.

- `qwen_coder_7b`: 7646 task tokens + 178 preflight tokens = 7824 known tokens; 18 requests, 18 responses, 0 unstarted cells and 0 requests without usage.
- `granite_33_2b`: 10653 task tokens + 232 preflight tokens = 10885 known tokens; 18 requests, 18 responses, 0 unstarted cells and 0 requests without usage.

Total known generation cost, including probes, is
**18709 tokens**. All requests, raw transport
responses, parse failures, accepted wrong repairs, native artifacts, unfinished
cells and costs are retained. There are no retries, output repair, fence
extraction or later rescoring. General productivity and total development-cost
improvement remain unestablished; model load/setup, training, human labor,
integration and real upstream upgrade cost are not measured.

The supervisor records show the model study started after performance
qualification ended. Independent time checks bind those records; this is not
a claim that the shared host had no unrelated workload.

## Failures, interruption and audit history

1. The first complete run on `806110d` produced 2,215 tests with 43 failure and
   20 error observations, and passed 17/19 gates. Sixty-one failing subcases
   were blocked by missing memfd-seal constants in portable Python 3.12.14;
   two C fixtures ended with literal backslash+n. Its 63 timing observations
   also failed the fixed quality criterion. All reports and artifacts remain.
2. Native Python 3.12.3 exposes the required constants. An actual kernel probe
   seals a memfd and observes `EPERM` for writing, growing, shrinking and
   changing its seals. Security policy is unchanged. The two fixture constants
   are corrected; all 58 related native/ELF tests pass without skips.
3. The first restarted run lost its collector/tool session and never produced
   a terminal qualification or captured unit summary. Its plan and start log
   remain. It is **interrupted**, with `tests_run=null`; no terminal denominator
   is reconstructed. The observed orphan later disappeared, and no signal was
   sent to it or to unrelated work.
4. The final run uses a separately recorded supervisor on the same `5818c58`
   source. It completes all 19 gates with source identity unchanged. The sole
   remaining gate failure is the performance quality result reported above.
5. Development failures, including the recursive collector's concurrent-source
   drift rejection, earlier C/RV64 build failures and both snapshot bug
   reproductions, are retained separately from final acceptance.

The final main record audit passes **5,205 consistency checks**, and the
separate C/C++/RV64 record audit passes **2,212**. These are record checks,
not additional tests or program executions; earlier overlapping audit counts
are not added to them.

Independent audits re-read Git objects, source bindings, raw process outputs,
allocation ledgers, performance samples and model transport records. They do
not run new native programs or transform local evidence into third-party
execution attestation. An early audit omitted the explicit VM-bool to native
0/1 ABI mapping and reported 66 audit failures; its correction first verifies
the declared Core return type and VM bool kind, then applies that ABI mapping.
Both the failed audit and correction record remain. No qualification evidence
was modified and no program/model response was rerun for that correction.

## Review and reproduction

`SUMMARY.json` holds exact counters, outcomes and unclosed claims;
`SOURCE_HISTORY.json` binds every run to its commit. Top-level copies of the
qualification and study reports/plans provide quick review. Every archive has
a SHA-256 member inventory and original path mapping. The model weights and
installed tool caches are not rehosted; publisher identities and observed tool
bytes are retained. One reproducible Cargo installer is explicitly excluded
from the development archive while its hash and bootstrap records remain.

Run `python verify_bundle.py` in this directory to verify retained files and
archive members without extracting or executing them. This proves inventory
consistency, not the truth of a hostile producer or compiler soundness. Source
reproduction commands are in `docs/HIA_SEVEN_STAGE.md`,
`docs/HIA_RECURSIVE_CHAIN_V7.md`, `docs/C_RESOURCE_MATRIX.md`,
`docs/CPP_COMPOSED_RAII.md`, `docs/HIA_RISCV64_LP64D.md` and
`experiments/hia_atomic_maintenance_20261027/README.md` at the tested commit.

General recursive ADTs/escaping loans, whole-compiler refinement, arbitrary C
and C++ replacement, native record-view HIA lowering, foreign noexcept
recovery, other host ABI families, physical device evidence, stable broad
performance and representative total maintenance-cost improvement remain
open. `full_seven_deliverables_complete` is intentionally **false**.
