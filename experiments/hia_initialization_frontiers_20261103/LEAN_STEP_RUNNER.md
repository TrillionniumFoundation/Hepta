# Projected scalar kernel runner and validation history

> Historical finite Core/native observations; removed harnesses are not
> delivered product entry points or current-source qualification.

Proof status is tied to an exact input and repository-pinned Lean run. The
successful narrow result is recorded below; local mocked tests alone are never
proof evidence.
This directory holds the experimental extension rather than modifying existing
formal models or production proof gates.

## Exact intended result

`GuardedUsizeSlice.lean` is appended to the exact existing
`formal/HiaInitializationPrefix.lean`, using its existing Omega import and
increment_within_limit theorem. Nine new named theorems specify partial tagged
usize reads, immutable phi lookup, actual projected guard evaluation, checked and
modulo addition, successful successors, and rejection of false guards/invalid
descriptors. No extra import, custom axiom, sorry or native_decide is used.

The universal conclusion is about the explicitly defined projected scalar
semantics. It is NOT Python/Core exporter refinement, a body-prefix frame proof,
complete runtime edge transfer, allocator behavior, actual Python mask semantics,
LLVM, whole-loop induction, initialization elision or a performance result.
The descriptor's direct literal operand does not execute its defining body prefix.
All twelve ledger obligations remain unproved and all reports remain DENY_ALL,
including after a successful narrow kernel result.

## Actual-Core binding and nonvacuity

`retired harness check-guarded-slice-lean` reconstructs each descriptor from reverified
Core using a hint only as a locator. The actual comparison, branch condition,
ordered true-edge operands, target parameter slots, selected add, actual literal
and ordinals are read from Core again. Unsupported enums are encoded explicitly
for kernel rejection; missing/ambiguous structures refuse before execution.
The manifest retains the full relevant function, locator and source-slot mapping.
The exporter remains trusted/unproved even though its output is hash-bound.

Eight actual deferred slices (four for each workload) plus one Core-valid crossed
parameter/ingress permutation are exported. For each of nine descriptors, the
kernel must accept a concrete Valid theorem and inhabited 0/1 and maximum-1/maximum
witnesses, each checking both checked and wrapping results. The crossed case
permutes target parameter positions and ALL incoming argument lists together.
Four more positive examples check that missing, opaque, oversized and false-guard
environments yield no selected step. Together with the existing 16 prefix and
nine new generic theorems, the exact axiom inventory has 56 names.

Ten negatives are deliberately distinguished:

- Four actual reverified Core mutations: non-strict guard, wrong index phi,
  literal two, and a branch condition different from the comparison output.
- Three descriptor-policy mutations: false arm, non-usize type and missing phi.
  These are NOT presented as re-exported actual Core programs.
- Three local evaluator mutations: shifted phi lookup, wrong addition and skipped
  guard. The unchanged theorems must fail at their intended proof locations.

Positive kernel failure, missing checker/support, timeout, absent or unexpected
axiom inventories, unsupported declarations, unexpected negative diagnostics or
source/tool changes cannot count as success. A negative only counts if Lean exits
with a proof error in the intended generated theorem's line range. Syntax/import
failures before that range do not qualify. The positive source must pass first.

## Isolation and bounds

The runner verifies the locked Lean binary and support identities before preparing
output, uses a fresh output directory, and binds inputs, sources, binary and
support before/after checking. The existing helper bounds each Lean invocation
to 60 seconds and checks retained output length. There are eleven planned kernel
invocations (one positive plus ten negatives); the runner enforces a 540-second
new-invocation deadline, with a 600-second external CI command limit. These are
trusted-runner bounds, not adversarial sandbox/atomic filesystem guarantees.

The separate exact-HEAD CI job reuses existing SHA-locked --lean-only bootstrap
in RUNNER_TEMP, with no local tool installation, QEMU, target compiler/native
execution, artifact upload or production gate edits. It installs only existing
bootstrap/solver dependencies on its fresh GitHub runner, logs package versions,
and uses the repository-pinned archive/executable digests and import support list.
The bootstrap package itself is not pinned by that Lean lock; host/acquisition
trust remains explicit. The dedicated Python-only lane now has exactly 120 tests,
including 18 mock/exporter/protocol controls; those controls cannot establish the
Lean theorem. Generated proof/checker diagnostics are printed in the kernel job
log for reproducibility and contain only repository fixture/proof data.

The available dot host lacks Lean and zstandard, so no local kernel result is
reported. If CI rejects this unexecuted proof text, preserve the failure and fix
only within the narrow research scope before claiming the intended kernel result.

Only the successful positive input prints and validates axiom dependencies.
Negative inputs remove all axiom-print directives so expected failed declarations
are not inspected as if they were completed theorems. Positive checks still
unconditionally reject sorryAx and incomplete/unexpected axiom inventories.

## First actual kernel attempt (retained failure)

PR #600 head 2876c936b095dd33a7ca6d58ac1c9e9f190d90ed, run 41637574322,
completed the locked toolchain acquisition but rejected the positive Lean input.
The new generic proof text had an unescaped `opaque` case label and used original
read equalities after case analysis had already reduced those goal components
to reflexivity. The runner correctly left the projected theorem flag false and
did not execute or count negative controls. Concrete descriptor/witness checks
alone were insufficient to establish the intended generic result.

The follow-up changes only the case-label syntax and uses reflexivity for the
already reduced equalities; it does not weaken theorem statements, add assumptions,
change semantics or relax the runner. It remains UNCHECKED until a new exact-head
kernel run accepts the complete positive input and all required negatives.


## Accepted narrow kernel result

On head fa96fcbce8718a065094b686701a5072b6367c72, tree
338b9f4dd1dd17aa4c5f45b9d08f720ecd164159, the actual locked Lean run
[41638129107](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41638129107)
(job 125924418398) accepted the complete positive input with exit 0, exactly
56 named axiom checks and no error or sorryAx. All ten required negatives exited
1 at the intended proof locations, not import or syntax failures. The elapsed
checker administration time was 12.438 seconds, not a performance measurement
of Hepta programs. An independent review reconstructed and matched every source,
manifest and negative-input digest from the original job log.

Positive input SHA-256:
8c615ecd34ae3e67c6ecc78d57cacca3437cc53ec3efcbd18c6b505f54127f31.
Manifest SHA-256:
0e8a0d95373a2d52e3c7e4571f7245a1348e16d39c3fd0be6b9432084133b839.

This establishes only the stated conditional universal theorem for the defined
partial projected scalar evaluator and its concrete validity/nonvacuity witnesses.
The Core/exporter/runtime/body-prefix/all-edge/whole-loop connections are NOT
proved. All twelve global obligations and DENY_ALL remain unchanged. The first
failed attempt above is retained rather than replaced by the successful result.
