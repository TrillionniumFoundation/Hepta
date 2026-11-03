# RFC: Hepta Intelligent Assembly — AI-Native Verified Semantic Assembly

**Draft**: 2026-10-31  
**Status**: Architecture proposal / research; **not implemented as a complete language**, not production-qualified.  
**Target**: Preserve Hepta 0.2 main and converge on the standalone HIA v8/Core research in PR #418; do not rewrite from scratch.  
**Repositories**: [Hepta](https://github.com/TrillionniumFoundation/Hepta) and [hepta-private-ci](https://github.com/TrillionniumFoundation/hepta-private-ci).

## 0. Decision

Proceed with a **typed, capability- and ownership-aware semantic assembly**, not a mere syntax blend of Rust/TypeScript/Python/Go/C/C++/traditional assembly. Preserve the existing compact HIA assembly and deterministic canonical Core semantics. Introduce an independently versioned optimization objective and NDU advisory plane that can propose candidates but cannot grant safety authority or alter the executable meaning of an instruction. An independent validator determines admission; target backends produce verified-and-bound artifacts. The strongest intended safety guarantee applies to **admitted safe HIA profiles** under explicit trusted-computing-base and external assumptions, not arbitrary foreign C/C++ binaries.

Do **not** promise an unrestricted global optimum, universal Rust performance superiority, an automatic safe conversion of all C/C++ code, or physical resource bounds absent suitable evidence. Use finite-domain optimum claims only with a fully enumerated/solved registered candidate space, frozen cost model, checked completeness, and bounded optimization budgets.

## 1. Exact starting point and non-claims

1. Hepta `main` SHA `125d11c5454835a7df1dc51915fc49901fbede5b` (2026-10-30). Its [blocker ledger](https://github.com/TrillionniumFoundation/Hepta/blob/main/docs/BLOCKERS.md) marks the full target unfinished; it has a Python frontend, Rust-native path, independent C11/GCC subset, C ABI probes, scoped ownership and budget rules.
2. Hepta PR [#418](https://github.com/TrillionniumFoundation/Hepta/pull/418) head `3201298a9828927452d42bcac146e610e1348a7f` is a **draft** HIA convergence study: shared catalog (50 primitive opcodes in [reference](https://github.com/TrillionniumFoundation/Hepta/blob/3201298a9828927452d42bcac146e610e1348a7f/docs/HIA_OPCODE_REFERENCE.md)), text assembly, independent checks, LLVM native path and finite C++ migration. Tested 552 safety selectors but not whole-language soundness. The [semantic contract](https://github.com/TrillionniumFoundation/Hepta/blob/3201298a9828927452d42bcac146e610e1348a7f/docs/HIA_SEMANTICS_CONTRACT.md) limits primitive types and excludes general floats/raw pointers/foreign calls.
3. PR [#458](https://github.com/TrillionniumFoundation/Hepta/pull/458) documents a mutable caller-owned Core preflight/serialization race; it remains draft. Never treat a partially scanned mutable tree as an immutable program. Bound, capture, and verify the same source snapshot.
4. hepta-private-ci `main` SHA `732e934ba496d90fbe042b8d41d479ef901643e5` contains the original Rust NDU evaluator (`codex-rs/hepta-ndu/src/evaluator.rs`) and control-plane adapter (`codex-rs/hepta-control-plane/src/planner_ndu.rs`): feasibility/risk/resource constraints, Pareto frontier, optional scalarization, source/generation/policy digests, abstain, receipts, and advisory recommendation; not execution permission.
5. hepta-private-ci PR [#4118](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4118) has an executable bounded NDU/HIA bridge, explicitly `DENY_ALL`. Its preregistered complete cost comparison was negative: strong fixed 348.754475126 s; lightweight DP 352.591082376 s; NDU 398.457516886 s. As of that study NDU cost 49.703041760 s more than fixed (~14.25%). PR [#455](https://github.com/TrillionniumFoundation/Hepta/pull/455), [#456](https://github.com/TrillionniumFoundation/Hepta/pull/456), [#457](https://github.com/TrillionniumFoundation/Hepta/pull/457) add draft four-arm accounting, measured ELF process observation and paired task sign gating. These do not establish positive application-level benefit or authority.

## 2. Language architecture: one authority, three artifacts

### A. HIA Semantic Core (normative)

A versioned, canonical serialized IR with deterministic decoding, typed closed SSA blocks, explicit CFG edges and instruction effects. It is the single semantic authority for source adapters, interpreter, optimizers, Rust shadow verifier and LLVM/native compiler. Unknown schema, type, permission, budget, feature and foreign obligation **reject**. Verifier/codegen congruence must be qualified rather than assumed.

Required future types/values (only after separately specified and qualified):

- `i8..i128`, `u8..u128`, target-resolved `isize/usize`, `bool`, `unit` with precise overflow, shift, cast and trapping semantics;
- explicit `f16/bf16/f32/f64`, deterministic operation/rounding/NaN policies; fast-math is a distinct, explicitly authorized non-equivalent contract;
- `owner<T,region>`, `read<T,'a>`, `mut<T,'a>`, `slice<T,'a>`, `cap<Permission,Scope>`, `resource<Token>`, with a pointer provenance model;
- `repr(C)` aggregates, target data-model facts and `extern` contracts; native layout, vtable and exception interfaces must be handled in target-specific profiles;
- scoped task/channel/atomic operations with explicit memory orders, cancellation and scheduling effects; device address spaces with volatility, cache coherence and DMA/IRQ obligations.

**Do not add all these as opcodes prematurely.** First specify and verify the ownership/effect/type contract, then expose only implementation-supported feature profiles.

### B. HIA Goal Manifest (non-executable)

A separately versioned and signed/bound contract: user-visible task specification, target identity, allowed transformations, hard invariants, resource ceilings, preferred performance dimensions, Pareto tolerance, candidate-bank source, cost accounting and optimization horizon. Goals cannot alter opcode semantics. The same hash-bound manifest is consumed by optimization and independent requalification. Distinguish *semantic equivalence* from *agreement with user intention*: tests or natural-language explanations do not themselves prove an intent is correct.

Illustrative, **not currently accepted by HIA v8**:

```yaml
schema: hepta.hia.goal.vnext
source_core_digest: sha256:...
target: x86_64-unknown-linux-gnu
contract:
  observable_equivalence: exact-defined-behavior
  ownership: linear
  loan_aliasing: exclusive-writer-or-shared-readers
  trap_and_cleanup: preserve-registered-semantics
  foreign_assumptions: []
  max_peak_live_payload_bytes: 262144
  max_activation_work: 1000000
objective:
  mode: pareto_with_registered_scalarization
  minimize: [p99_latency, wall_time, energy_joules, peak_rss, binary_bytes]
  costs: [compile, proof, testing, controller, recovery, deployment, migration]
  no_change_baseline: required
optimization:
  horizon: 16
  candidate_limit: 128
  optimization_deadline_ms: 2000
  unknown_or_timeout: refuse_and_keep_baseline
```

The illustrative goal is not sufficient to *prove* CPU time, RSS, p99 or energy ceilings; such guarantees require qualified analysis/hardware-specific observation and stated probabilistic assumptions.

### C. Verified Deployment Bundle

Atomic, identity-bound receipt containing canonical Core digest, goal digest, candidate digest, verifier implementation identity, proof/counterexample/failure disposition, backend/compiler/target/ABI, final native bytes digest, resource evidence, dependency/foreign-code trust obligations, experiment and observer identities, supersession/generation, allowed activation envelope and rollback metadata. Runtime deployment must compare actual sealed bytes and active route/generation at final use. NDU scores cannot mint proof or execution authority.

## 3. Existing deterministic agent assembly remains the front door

Actual HIA v8-compatible text spelling (subject to the existing verifier and toolchain):

```text
hia-asm.v1 hepta.hia.program.v8 sums
exports(total)
fn total(a:u32,b:u32) -> (u64) effects() entry(entry)
block entry(a:u32,b:u32)
  a64:u64 = int.cast(a) {"mode":"wrap"}
  b64:u64 = int.cast(b) {"mode":"wrap"}
  answer:u64 = int.add.wrap(a64,b64)
  ret(answer)
end
```

The inputs are widened **before** addition; optimizing to wrapping `u32` addition would change observable results and must not be treated as a valid equivalent transformation. New language-level features must be elaborated to a fixed versioned primitive contract and independently reverified. AI-authored text is untrusted input.

## 4. Safety invariant model and proof obligations

The envisioned safe subset must enforce:

- **Ownership**: each linear owner has one live authority; move consumes the source; drop is checked; no double release, use-after-move or leaked owner on normal returns.
- **Borrow/provenance**: mutable access is exclusive; shared loans cannot overlap unauthorized writes; reborrows/outlives and returned loans have explicit origin; foreign pointers carry obligations rather than silently becoming safe references.
- **Effects/capabilities**: no operation may gain an undeclared effect or widen authority; I/O, host calls, filesystem, network, device and GPU permissions are attenuable capabilities. This provides a goal stronger than Rust's usual type-only API if implemented and independently verified.
- **Exit/exception/cancellation**: normal, error-value, trap, unwind, cooperative cancellation, external kill, process crash and restart are distinct. No promise of cleanup after a trap or power loss without an actual qualified runtime mechanism. Tests must cover every exit edge.
- **Concurrency**: race-free in admitted safe profiles, explicit atomic orders, task scopes, cancellation propagation and resource settlement. Unverified foreign callbacks and cross-thread retention reject.
- **Resource accounting**: distinguish payload bytes, allocator overhead, VM fuel, CPU cycles, stacks, mapped RSS, device memory, long-lived objects, external effects and process-descendant costs. Do not convert a VM budget into an unmeasured physical bound.

For a transformation `T`, prove or independently revalidate the registered relation:

\[
  \forall x\in D_{defined},\; Trace(T(P),x) \preceq_{contract} Trace(P,x),
  \quad Safe(T(P)) \land Bound(T(P),B).
\]

The trace relation must explicitly include observable values, ordered effects, first trap, cleanup and exit mode as required by the specific contract. A timeout/unknown/counterexample is **not** a proof. For whole-backend soundness, separate HIA→LLVM/target refinement from per-pass translation validation, which is necessarily incomplete for arbitrary software.

## 5. Intelligent global optimizer

**Architectural rule**: choose program-wide plans, **not** schedule a network inference for every executed machine instruction. Instruction-level alternatives can be planned at compile time; runtime adaptation occurs at explicit guarded safepoints or against a small set of preverified variants. Recoup optimization overhead over subsequent executions.

Recommended pipeline:

1. Freeze exact Core, target, workloads, semantic specification, no-change baseline, candidate grammar and total optimization budget.
2. Enumerate legal changes through deterministic analyses (SSA, interprocedural summaries, alias/escape, e-graphs/equality saturation for proven equalities, typed rewrite rules, polyhedral/vectorization/data-layout proposals, allocation/stack promotion, specialization and profile-guided variants).
3. Reject candidates violating type, ownership, effects, ABI, source limits and resource constraints **before** valuation. Do not use score to soften a hard constraint.
4. Cost the feasible Pareto set through a hierarchy: local heuristic/known compiler, bounded DP or exact finite solver, NDU advisory evaluation. Include prepare/build/proof/control/measurement/failures, not only hot-path time.
5. Independently verify semantic and resource obligations on each selected candidate, including cross-function call, failure and cleanup behavior. Use bounded SMT/translation validation where applicable; unknown means keep baseline.
6. Produce actual native bytes and bind them to the source, compiler, target, proofs and allowed interfaces; compare with credible strong Rust/C/C++/Clang LTO/PGO baselines.
7. Apply variant using the single deployment authority (generation fence, CAS, safe-point, artifact identity, ledger, rollback). Reject stale or mutable source/artifact inputs.
8. Observe the next execution window with independent measurements; promote only if preregistered positive benefit survives complete accounting, uncertainty and regression thresholds. Otherwise retain/revert baseline.

Objective restricted to independently admitted set `A_safe`:

\[
\pi^* = \arg\max_{\pi\in A_{safe}} \mathbb E[\text{long-horizon task utility}(\pi)] - C_{compile} - C_{proof} - C_{controller} - C_{deploy} - C_{failure} - C_{maint}.
\]

Choose separate hard bounds on safety and acceptable risk, latency/energy/RSS if qualified. The no-change program is an explicit candidate. Exact global optimality is claimable only for a complete **finite** candidate set and exact frozen objective/solver; otherwise label output `bounded_best_known` or `Pareto_advisory`.

Practical optimization economy: use deterministic local compiler first, and trigger NDU only when registered expected future savings exceed measured total overhead with a conservative confidence margin. For latency-sensitive systems, NDU should not run on the hot instruction path.

## 6. Roles and trust boundaries for hepta-private-ci NDU

The existing native Rust evaluator already has `evaluate_candidates_with_policy`, `NduEvaluationReceiptV2`, normalized policy digests, abstain, resource/risk ceilings, Pareto and optional scalarization. Reuse this original implementation rather than copy scoring logic into an unverified Python optimizer. `NDU_SYSTEM_EXECUTION.md` labels specification closure separately from implementation/activation and places objective, evaluation and owner authority in separate planes.

Suggested ports:

- `CoreSnapshotPort`: immutable Core, source/producer identity, schema, call graph, feature set;
- `CandidateGeneratorPort`: effects-/ownership-aware legal alternatives and immutable candidate identities;
- `CostObserverPort`: trusted workload and lifecycle measurements, including refused/failed attempts and human cost as unknown rather than zero;
- `NativeNduAdvicePort`: frozen candidate contributions, policy, generation, uncertainty, abstain and evaluation receipt;
- `ProofAndBackendPort`: independent semantic/resource/ABI checks and final machine byte binding;
- `PublicationAuthorityPort`: CAS, final-use check, generation fence, route cutover, ledger, rollback. **No direct model or NDU write access.**

The no-change baseline must remain frozen across learning and candidate promotion. Report all `missing`, `unknown`, `failed` and `inconclusive` cost cells, with no silent default to zero. For small candidate sets, DP/strong fixed baselines are essential because current NDU bridge failed a complete-cost win.

## 7. C and C++ migration with lowest defensible cost

A one-command product may be offered, but guarantees are per translation unit, target, library and selected contract, not universal.

### `c2hepta` stages

1. Read real `compile_commands.json`, complete target/macro/defines/includes and compiler/toolchain identities, and enumerate all active translation units and configurations. Unknown conditional builds are explicit.
2. Use Clang AST and compiler layout probes to recover type, control flow, source/ABI obligations, external symbols, macro expansion and pointer provenance requirements.
3. Lower defined behavior to a migration IR with explicit source-language semantics (C signed overflow/UB, sequence points, volatile/atomic, integer promotions, alignment, memory lifetime). Never pretend the HIA operator with the same spelling automatically means the same thing.
4. Analyze ownership/aliasing/escaping callbacks: classify as **SAFE_STATIC**, **SAFE_GUARDED_RUNTIME**, **FOREIGN_UNVERIFIED**, **UNSUPPORTED** per function and per configuration.
5. Emit HIA where checked; emit isolated `extern C` shims or retained original libraries for C++ where necessary. Preserve headers, layout, symbol export, linker script, name mangling, calling conventions, unwind and allocator identity.
6. Differential test original and rewritten programs on a frozen defined-behavior domain, including sanitizer, fuzz, negative owner tests and real upstream version upgrades. Where formal source refinement is unavailable, publish limited empirical evidence rather than proof.
7. Measure total rebuild/human review/maintenance cost and performance against the unchanged original. Refuse automatic safe promotion if any required obligations remain unproved.

### C++ L0–L3

- **L0**: retain existing C++ library; generated, type-checked **C ABI shim** and scoped safe HIA wrappers. Lowest migration cost; foreign binary stays outside safe-core guarantee.
- **L1**: selected concrete ABI-compatible calls and layouts, including RAII-owned types whose construction/destruction/exception behavior is verified for a pinned compiler/stdlib ABI.
- **L2**: translate finite instantiated templates, class hierarchies, virtual dispatch, ownership, callbacks, standard containers and exception contracts with differential and resource proofs.
- **L3**: whole-project migration with tooling, upstream source maintenance, multiple compiler/stdlib/OS/architecture compatibility and replacement of all unsafe foreign dependencies. This is an ambitious research target, not present capability.

For some projects, a `SAFE_GUARDED_RUNTIME` translation using bounds checks, reference counts, dynamic borrow guards or copying is a valid **safety-first** intermediate migration. Optimize such checks away only after independent proof. Absolute same-as-C performance is not assumed.

The broad C++ ecosystem is not a single portable ABI: Itanium C++ ABI and MSVC families differ, and RTTI, exceptions, STL layouts, templates and allocator contracts may not cross an FFI boundary safely. Start with C ABI stable shims and explicit targets. A header/ABI probe is not an implementation safety proof. General source translation with unknown UB may be declined rather than producing silently unsafe code.

## 8. AI Agent protocol and ergonomics

Expose a semantic catalog and safe-edit API: `catalog()`, `check()`, `explain_refusal()`, `propose_patch()`, `validate_patch()`, `benchmark_candidate()`, `publish_if_authorized()`. Each operation uses immutable Core/goal/target IDs and returns machine-readable precise refusals, proofs, counterexamples, resource plans and cost receipts. Agents can make scoped and atomic patches, query ownership/borrow obligations and compare variants without learning hidden compiler defaults.

For TypeScript/Python/Go ergonomics, provide typed frontends, gradual import adapters and developer tooling, not GC or dynamic semantics inside safety-critical HIA Core by default. Optional dynamic objects and runtimes must remain explicit regions/capabilities with accounted allocations and foreign obligations.

## 9. P0–P7 implementation and strict closing gates

| Phase | Delivery | Close only with |
|---|---|---|
| P0 semantics | Adopt one versioned HIA Core/opcode catalog; explicitly adapt Hepta 0.2 HSIR and draft lineages; bounded immutable input capture | Same semantics in checker, assembly, Rust verifier, interpreter and LLVM consumer; old profiles explicit; negative mutation/failure tests and exact source SHA |
| P1 safety | Extended owner/loan/provenance/effect/capability and exits; concurrency/deallocation/foreign-boundary model | Independent positive/negative proofs and tests; FFI obligations never silently promoted; allocation failure, trap, cancel, crash and concurrency suites |
| P2 native & ABI | x86-64 Linux first, then AArch64, Windows/MSVC, RV64; direct LLVM and sealed artifact publication | Actual ABI round-trip, target-specific layout/exception/atomic tests; source→Core→LLVM→machine refinement scope stated; independent hardware/native test matrix |
| P3 migration | C99/C11 whole-project differential pilot, C++ L0 first and scoped RAII L1 | Build-system retention, complete active translation-unit census, original/new binary differential, upstream upgrade, human hours and unverified foreign contracts accounted |
| P4 optimization | Certified rewrite/e-graph/DP, frozen no-change baseline, exact cost model, signed evidence | Real held-out tasks, full lifecycle cost; performance and safety vs Rust/C/C++ strong LTO/PGO controls, p50/p95/p99, RSS, allocations, compilation/proof costs and failure negatives |
| P5 NDU integration | Native Rust advisory port and generation-bound candidate/utility receipts | Fixed/DP/NDU four arms, same semantic/candidate/workload budgets, paired independent held-out results, net positive including build/proof/control costs and failures; otherwise continue advisory only |
| P6 Agent productivity | Stable instruction API, scoped edits, structured errors and transactional maintenance | Source-disjoint real tasks, 2+ model tiers and paired Hepta/Rust tasks, equal context/tools/budgets, real quality metrics, human effort/maintenance and full measured tokens and wall costs |
| P7 production & hardware | Generation-safe hot swap, persistent evidence, rollback and physical device profiles | Exact artifact/final-use generation bind, failure recovery, multicore race tests, MMIO/DMA/IRQ hardware evidence, long-run RSS/p99 regressions, independent release review |

Each gate has `pass`, `fail`, `blocked`, or `unknown` and exact source/evidence hashes. Never mark failed gates complete because new code was added; status and PR should remain draft until actual qualification. A separate product-release decision may authorize a narrow qualified profile without claiming the universal language vision is complete.

## 10. Critical supporting literature and limitations

- [MLIR language reference](https://mlir.llvm.org/docs/LangRef/) — multi-level, SSA and extensible dialect architecture; use as infrastructure/inspiration without mistaking MLIR itself for proof of HIA ownership or safety.
- [Alive2](https://github.com/AliveToolkit/alive2) — LLVM translation validation; explicitly says its current implementation does not support interprocedural transformations; not a complete whole-program proof.
- [C2Rust manual](https://c2rust.com/manual/) — C99 transpilation generally emits unsafe Rust, illustrating why functional translation does not by itself establish safe ownership.
- [Cpp2Rust research](https://doi.org/10.1145/3808266) — newer subset C++ safe-Rust translation may use runtime ownership and mutability checks; its safety/performance trade-offs should be compared, not assumed solved.
- [Rustonomicon FFI](https://doc.rust-lang.org/nomicon/ffi.html) — foreign calls and unwind boundaries require explicit contracts.
- [Itanium C++ ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html) — ABI layouts, mangling, exceptions and link interfaces are substantive and platform-specific.
- [CHERI bounds](https://cheri-alliance.github.io/build/technology/cheri-capabilities/bounds/) — hardware pointer capabilities can strengthen bounds but do not automatically prevent temporal use-after-free, logic errors or side channels.
- [Equality saturation / egg](https://doi.org/10.1145/3815481) — a useful basis for exploring equivalent rewrite alternatives and extracting under a cost function; resource/effect equivalence must still be included explicitly.

## 11. Immediate prioritized engineering recommendation

Freeze #418 semantic authority, review #458 mutable Core snapshot repair, unify versioning/legacy adapters, and build an immutable Goal Manifest atop the existing 50-opcode HIA v8. Then run one full **end-to-end third-party C migration** and one **identical HIA/native-Rust compiler optimization pilot** with all resources and lifecycle costs. Only then scale NDU into more expensive searches. Do not enable unconstrained per-instruction runtime neural decisions or unsafe automatic C++ migration.

**Success definition**: a small admitted safe language profile can be used by an Agent to author code, which is checked, compiled to real native instructions, executed and replayed; a new variant is promoted only after independent semantic/resource/native verification and a statistically credible full-cost win. Unproved cases refuse or retain the original implementation.