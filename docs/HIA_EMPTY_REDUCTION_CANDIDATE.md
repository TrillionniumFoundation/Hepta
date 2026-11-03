# Empty-entry reduction candidate

Status: isolated candidate based on `17cf02914f523d7674752ebfa336e9ed6ff9bdc8`.
It does not change registered v1/v2 protocols, acceptance thresholds, qualified
reduction entrypoints, or the public native compiler gate. It has no performance
qualification or deployment authority.

## Observed problem

The original source-17cf CI artifact records these empty-input medians, in
nanoseconds per batch. These are observations of the original reduction, not
measurements of this candidate.

| Workload | Calls per batch | HIA reduction | Rust wide | Rust byte | HIA/Rust |
| --- | ---: | ---: | ---: | ---: | ---: |
| linear | 16 | 70 | 50 | 50 | 1.400 |
| linear | 64 | 250 | 190 | 190 | 1.316 |
| affine | 16 | 80 | 50 | 50 | 1.600 |
| affine | 64 | 271 | 181 | 181 | 1.497 |

These four cohorts account for eight failed Rust comparisons. The original
report remains unchanged: 164/180 comparisons passed, while the complete Rust
and holdout gates failed. Original `reduction/RESULT.json` file SHA256:
`22236e6bafdbdb0e8075841f9df707a4307868b666c29d1cf9c879afdf6fc4cf`.

In the original `linear/hia_reduction.calculate.asm`, `calculate` at `0x11b0`
saves `rbp`, `r14`, and `rbx`, copies both arguments, loads the 64-bit reduction
bound, checks that bound, and only then tests zero. Its zero block at `0x12f8`
clears `r14d` and jumps to the shared return at `0x14cd`, which moves the result
to `rax` and restores the three registers. Affine has the same entry structure.
Both Rust arms start with `test rdi,rdi; jne nonempty; xor eax,eax; ret`, with the
prologue after the empty return.

This explains additional structural work on the observed path. Assembly alone
does not establish how much of the timing difference it causes. The existing
HIA empty path already performs zero native allocation/free calls.

## Resource semantics and transformation

[The Core runtime](../hepta/hia_program_runtime.py) creates a real linear owner
for a size-zero allocation. It succeeds without consuming an allocator attempt
or deterministic failure-injection index. Its drop increments the owner ledger
without calling native free. Both workloads at `n=0` therefore create and drop
one owner; allocation, loan, live-byte, and live-owner counters finish at zero.
A naked empty-input return would erase those Core events.

[hia_empty_reduction.py](../hepta/hia_empty_reduction.py) instead constructs an
effect-free entry guard, `length == 0`, followed by two complete alpha-renamed
copies of the admitted reduction. The false edge passes all arguments unchanged.
The true edge passes the literal zero in the length position and all other
arguments unchanged. Both clones retain the reduction's fast and checked bodies
and every owner, loan, call, trap, arithmetic, and control-flow instruction.

This gives the existing LLVM optimizer a constant for folding the old bound
guard, zero-sized allocation helper, zero-trip loops, and native pointer-drop
guard. There is no custom LLVM replacement, backend attribute, compiler flag,
or exception to the native publication gate. Machine-code layout remains to be
checked; Core equivalence does not guarantee a prologue-free empty return.

## Checked argument and scope

The checker consumes actual source-bound Core, not producer receipts. It:

- Re-verifies the candidate with the existing Core verifier.
- Independently recovers both clones' definition-name bijections and compares
  their normalized blocks exactly. Operations, operands, attributes, results,
  edges, effects, interfaces, and unselected functions must match.
- Checks the actual equality guard and both edge argument lists. A pinned Z3
  query must find no input for which the true edge executes but substituting
  zero changes the length value. Every other input is passed identically.
- Freshly runs existing narrowing and guarded-induction proofs and requires
  their admitted Core to be exactly the program that was cloned.
- Binds the report to source, candidate, checker, pinned solver, and policy.

For linear and affine, the original stages retain 20 scalar obligations and 14
induction obligations. Each gets one checked clone pair and one additional
UNSAT guard-substitution obligation.

On either branch, the clone starts with the same runtime values as the admitted
reduction. The next operation and edge are identical under the checked renaming.
This simulation preserves scalar results, the first specified trap, allocator
failure sequence, and ordered Core resource/call events. It does not assume a
particular seed, loop count, or empty return value. A valid reduction that traps
after dropping its empty owner must still trap.

Coverage is the accepted transformation/profile: existing verified reductions
with scalar interfaces and a `usize` guarded length. This is not whole-language
soundness or a proof of the Python verifier, LLVM, or native machine code.

The entry adds exactly **three VM steps per dynamic entry into a transformed
function, relative to the already composed reduction**: two scalar operations
and a branch. A call tree can enter transformed functions several times; the
delta from the original checked program also includes prior reduction rewrites.
The empty specialization adds no call frame or resource operation. The same
tight step limit can therefore produce different evaluator outcomes. The report
sets `vm_steps_preserved=false` and excludes evaluator-budget outcomes from its
trace claim. A regression exhibits the reduction returning while the candidate
exhausts the same finite step budget.

## Non-timed validation

With pinned Z3 available, run:

```bash
python3 -B -m unittest tests.test_hia_empty_reduction -v
```

Independent VM regressions compare checked, admitted-reduction, and candidate
programs with direct arithmetic oracles. They exercise lengths
`0, 1, 15, 16, 17, 73`, seeds `0, 255, 4294967295`, and failure indices
`None, 1, 2`, with reduction guard 16 to execute both guard sides. Extra cases
cover zero heap budget at `n=0`, oversized object rejection, a post-drop
divide-by-zero trap, and the finite-step limitation.

Negative cases include well-typed nonzero constants, inverted equality,
changed generic arguments, changed nonempty and empty arithmetic, a bare zero
return that removes owner events, and changes to an unselected function. All
must be refused. A positive case independently renames both complete clones
and must still verify, checking independence from the proposer's chosen names.

The VM observations compare results and resource counters. The structural
clone correspondence supplies the stronger argument for event ordering;
sampled counter equality alone is not presented as such a proof.

The optional native test uses the existing `build_program_native` gate and a
C observer wrapping `malloc`, `calloc`, and `free`. It checks 48 inputs per
workload, including allocation refusal and object-size rejection, and checks
that empty/failed owners do not call `free(NULL)`. It performs no timing. Run
only in a coordinated idle host window:

```bash
HEPTA_TEST_CLANG=/path/to/clang-20 python3 -B -m unittest \
  tests.test_hia_empty_reduction.EmptyReductionNativeTests -v
```

The cloud environment has no Clang. Native execution, candidate assembly, and
candidate timing remain pending; a skipped native test is not a native pass.
The final cloud run of this module together with
`tests.test_hia_reduction_induction` completed 16 test methods: 14 passed and the
two native methods were skipped. An independent source review found no blocking
soundness issue within the stated Core scope.

## Next evidence and limits

Before measuring, preserve a fresh proposal, full proof, actual Core, emitted
LLVM, object, compiler identity, and `calculate` disassembly. Use
`empty_reduction_program` for fresh proof admission, followed by the unchanged
`emit_program_llvm` / `build_program_native` interfaces. Inspect whether zero
returns before register saves, the old bound guard, allocator calls, and stack
adjustments. If not, preserve that negative result; do not infer code-generation
success from Core proofs.

Nonempty dispatch can add cost, and duplicate CFGs can increase compile time or
code size before LLVM optimization. Later evaluation must include these costs,
the strong Rust wide/byte arms, and original checked/reduction arms.

This candidate follows inspection of CI results, including the old holdout.
A later performance claim therefore requires a newly registered campaign with
fresh independent lengths and seeds, frozen source/toolchain/protocol, all load
shapes, unchanged strong Rust treatment, and full median/tail/correctness/failure
evidence. Old v1/v2 failures and simultaneous main-host observations stay intact.
This work registers or runs no new performance campaign.
