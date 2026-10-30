# Guarded runtime-context specialization: registered continuation

This pass selects the actual checked divide leaf from the automatically migrated,
unmodified `stb_divide` 0.94 component pinned at
`003501f6d7a8668ce8b6d875e34dd97ad0d5d5b5`. The complete six-function migration
runs again during preparation; the selected optimization is only its truncating
signed 32-bit divide leaf. It does not replace the other library functions or
claim a complete application speedup.

## Admission and proof boundary

`hepta/hia_context_specialization.py` proposes an exhaustive equality guard.
A matching divisor follows a constant-divisor body; every other input follows
the unchanged divide, including zero and INT_MIN/-1 traps. The independent
admission code checks public exports, semantic version, arguments, return,
effects, guard, both transfers, hot substitution and exact fallback. Pinned
Z3 4.15.4 checks the two compositional cases over all 2^64 argument pairs.
There is no workload precondition. A timeout or unknown result grants no
admission. Twelve positive/adversarial tests include erasing exports, silent
version changes, inverted guards, mismatched constants, wrong fallback,
corrupted transfers, exceptional exits, and a refuted actual LLVM arithmetic
mutation. The export/version regressions were found by independent review.

The selected internal emitted LLVM body and extracted hot body are checked
separately. The native batch bridge is C code with a checked context constant
and the same pointer/length obligations as each baseline. That bridge, the
external wrapper, a single `alwaysinline` hint, LTO, native object generation,
OS and hardware remain trusted and finitely tested. The LLVM checker proves
internal body semantics only. The intermediate hot scalar wrapper is hidden
in the final batch profile; its final public ABI is `batch` plus the guarded
`c_stb_div_trunc` entry. This is an explicit new experimental native profile,
not a claim that the generic `build_program_native` ABI certificate covers it.

There are no allocations or owners in the selected scalar Core. The host owns
both arrays, verifies their complete outputs, and releases arrays, DSOs and
sealed file descriptors on each successful invocation. Operation ticks,
native bytes, proof/compile time and switching/retirement budgets are newly
measured, never inherited from the source. A trap ends a child process; no
claim of an in-process continuation after abort is made.

## Development discoveries retained

The first whole-program guarded form was semantically valid but LLVM merged
its constant divide back into a generic divide. Subsequent attempts exposed
an inter-module inlining gap. Both the slower measurements and infrastructure
failures remain in separate development directories. A separately checked hot
body and explicit foreign batch guard, bitcode LTO object, final export map,
and one pure-wrapper inlining hint produced actual vector multiply code.
The development divisor is 1009. It is not a formal result or a formal holdout.
A deliberately corrupted batch guard compiles but fails the full native oracle.

## Frozen prospective comparison

`experiments/stb_context_opportunity/PROTOCOL.json` declares every arm, seed,
training task, selection rule, sequence, budget, cost and benefit criterion.
No formal context or workload may be generated before remote registration.
Eighteen static arms include Clang/GCC LTO, Rust release/fat LTO, libdivide
5.2.0 scalar and explicit AVX2/AVX512 full/branchfree implementations, and
actual Clang instrumentation-PGO plus LTO. All preserve the same batch ABI.
The fastest training arm and two challengers are selected before holdout
materialization. The comparison also uses the pointwise fastest of all three,
so the candidate cannot benefit by ignoring a measured stronger challenger.

PGO collection uses exactly one 256-round pass per training task; static-arm
selection separately uses two 4096-round passes. All are charged.

The three new full-int32 contexts run 24 measured repetitions each, 16,384
values by 1,048,576 actual passes per repetition: 1,236,950,581,248 actual
scalar divisions per arm. Each invocation checks all final outputs and an
observable per-pass checksum. The same single pinned logical CPU is used;
exclusive physical CPU access is not attested. The entire preparation cost,
including all static builds, PGO, training, migration, proof, compilation and
preflight checks, is charged conservatively to the candidate. Full Python
invocation time includes sealing, startup, switching, warmup, kernel time,
observation and cleanup. Remaining timed-phase orchestration/checkpoint
costs are also charged. Evidence archival is reported separately from live
runtime-resource retirement.

The gate requires positive net observed time against the pointwise static
envelope and positive aggregate savings in every context. It is neither a
statistical confidence bound nor evidence of general global optimality.
Only the executed fixed horizon counts; no future lifetime is extrapolated.
A negative result remains a negative result. Previous frozen Ring/CRC and
NDU/Agent studies are unchanged.

Human engineering/review, this session's AI token cost and prior cached toolchain
acquisition are unmeasured and remain null. The economic gate concerns the
declared controller machine-time horizon, not total project return on cost.
