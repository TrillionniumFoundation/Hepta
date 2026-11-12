# Kernel-checkable local slice interface: plan and current blocker

Historical pre-implementation design. At the time this plan was written, no new
proof had been kernel-checked. See LEAN_STEP_RUNNER.md for later exact-run results. All twelve obligations remain
unproved, actual_core_bridge_proved=false and DENY_ALL. Production zero
initialization and gates stay unchanged. This work must not become another
finite-sample exercise or a second initialization-memory model.

## Toolchain audit

On this dot host, lean/lake/elan are absent from PATH. No bin/lean was found in
/workspace/shared or /tmp through the expected installation depth, or in the
repository's default sibling toolchains location. The available Python venv
also lacks zstandard. Nothing was downloaded or installed. Consequently a local
kernel check is currently blocked; unexecuted proof text cannot be called proven.

The repository already has a reproducible CI path:

- formal/toolchain-lock.json selects official Lean 4.19.0 Linux release, archive
  SHA-256 6fe3ce97a58f44e2b3567d455b994eacec5bfe9ae7774f2a573444480ba813fe
  and executable SHA-256 92c3d35b5bfaa5e0fea413a775d504cf46cd95e1345df61c2274f76779e7e023.
- tools/bootstrap_verification.py --lean-only uses that existing lock, extracts
  only the selected checker/shared-runtime/transitive .olean files and validates
  the full archive and executable before committing the install directory.
- tools/qualify_hia_selected_formal.py already supplies _run_lean (60-second
  subprocess bound, cleared LEAN_PATH/LEAN_SRC_PATH, explicit LEAN_SYSROOT) and
  _support_identity for exact imported .olean/shared-runtime hashes.
- hepta-intelligent-assembly-closure.yml already uses --lean-only in RUNNER_TEMP;
  hepta-qualification.yml supplies the optional zstandard dependency. These are
  existing acquisition mechanisms, not evidence the new proposed theorem passed.

The lock expressly says publisher_digest_available=false. These are reviewed
repository-pinned digests, not a claimed publisher signature. Hashes/proof kernel
are a trust boundary, not hostile-runner attestation. The bootstrap Python package
and host are also in the acquisition trust boundary.

## Reuse rather than recast the arithmetic

Reuse HiaInitializationPrefix.increment_within_limit, and the existing Lean
standard List/Nat library. The arithmetic +1 bound and the standalone handwritten
Z3 unsigned condition are already present. HiaSelectedCore/HiaRegisterSafety
model a different u32 append-register profile; HeptaCore's u64 expression/stack
translation and HeptaMemory's expression/memory models likewise do not encode
this actual CFG edge. Do not silently call those an existing usize-phi theorem.

The missing small component is an explicit *projected local slice evaluator*
whose input contains the real operand-position relationships. It is intentionally
not the complete Core interpreter, allocator or prefix-memory semantics.

## Concrete descriptor and kernel validation

The producer exports the exact actual slice, not its desired result. Retain exact
Core bytes/hash, function/header/target/op ordinals and the full relevant source
operations in a paired manifest. A positional descriptor contains:

- source operand identifiers/positions for index and extent, with actual usize
  type tags and compare opcode;
- branch condition identity and the actual labelled then edge (not an arbitrary
  supplied Bool); condition must identify that compare's output;
- the complete ordered incoming operand list, target index/extent slots and
  source-to-target positional relationships;
- selected add opcode (checked or wrapping), its operand positions and usize
  result type, actual literal-one definition/type and source ordinal.

A Lean structural predicate/decider must check opcode/type/condition/arm/literal
constraints and incoming[indexSlot]=sourceIndex plus the analogous extent
identity. Generated concrete positives prove this predicate by kernel reduction;
Python must not inject an axiom, a pre-proved True field, a source i<N fact or
an assumed phi equality as a replacement. Invalid or missing slots reject.
Hash binding alone is not a proof that the exporter represented Core faithfully.
That exporter and the actual JSON parser/verifier correspondence remain unproved.

## Universal evaluator theorem, not finite replay

A source environment maps positions to optional tagged values. A usize read
accepts only the usize tag and a Nat value at most M=2^64-1. Non-usize values may
be abstract opaque values because this theorem gives no resource semantics.
Simultaneous target phi reads are defined from the immutable source environment
through the descriptor's ordered incoming list, not by in-place assignments.
This is a selected partial scalar projection: defined selected reads do not prove
that EVERY actual runtime edge operand is defined. Full edge-transfer validity
remains a separate obligation. The actual literal is used directly as a local
operand, not written into the target environment; thus this first model must not
silently model an RHS slot that overwrites the index or extent.

The projected guard evaluates the descriptor's source reads and actual strict
comparison. The projected selected-true-edge evaluator returns no step unless
that guard evaluates true and the validated branch/arm applies. Its add reads
index through that actual phi map and uses the validated actual one literal.
Checked addition tests the M bound; wrapping addition uses modulo M+1.

The conclusion must establish existence of a successful projected result, not
only constrain a result if one happens to exist: an always-failing evaluator
must not satisfy the claimed positive obligation.

The proposed theorem universally quantifies over source environments and valid
descriptors: when the projected guard evaluates true, projected local checked
AND wrapping addition return a successor whose Nat value is source i+1, at most
the same N and at most M. The proof must *derive* i<N from guard evaluation and
operand identity from phi lookup, then instantiate increment_within_limit. It
must not merely restate these conclusions as caller hypotheses. Wrapping's
modulo reduction and checked acceptance are additional kernel-checked steps.

This evaluator projects directly to the add. It does NOT execute intervening
body stores, loads, arithmetic or their traps. Thus it proves neither arrival
at the add nor preservation of its input slots by the actual body. A separate
normal-prefix/SSA-frame connection is still required before applying the result
to full actual-body execution. The #598 observer is finite evidence for that
connection, not a premise which discharges it. Likewise modulo semantics here
does not machine-prove Python's bitwise mask implementation or LLVM semantics.
Do not hide this limitation in a generic claim such as Core step proved.

## Nonvacuity and failure controls

For EVERY exported positive slice, require a concrete valid descriptor and
inhabited guard witness, not only an implication with an impossible
validation predicate. A small i=0,N=1 example must kernel-check a true guard and
successor 1; an upper-bound example i=M-1,N=M must check successor M. Empty
false guard must produce no selected step. Include both checked and wrapping
modes, alpha-renamed/reordered source identities and same-target branch arms.

Generate mutations from real Core and reverify them before export. A changed
true-edge index operand, condition identity, signed type, <= guard, literal 2,
wrong extent slot or false arm must fail descriptor validation or a fixed
concrete theorem. Never regenerate the expected specification from the mutant. Consistent slot
renaming remains valid. Consistently changing BOTH the guard extent and its phi
binding may also remain scalar-valid: this property has no allocation-extent
identity theorem. Do not claim all changed operands must invalidate this slice.
A crossed source/target-slot witness must retain simultaneous old-environment
reads rather than accidentally validate sequential rebinding.
Separately mutate local evaluator logic (wrong phi lookup / skipped guard /
wrong add literal) while holding the theorem fixed so the kernel must reject
its proof. Negative controls must be syntactically well-formed changes at exact
counted sites and fail the intended obligation, not a missing import or typo.

Inventory named theorems and #print axioms output. Reject sorry/sorryAx, custom
axioms, unsafe/native_decide/elaboration escape hatches, unexpected declarations,
missing checks, timeouts and tool/source changes. Preserve the distinction
between a rejected descriptor (expected), a rejected theorem mutation (expected)
and unavailable/broken toolchain (unknown/failed, never success).

## Proposed bounded CI execution

After implementation and independent review, use a separate read-only exact-HEAD
Ubuntu job and the existing --lean-only bootstrap in a fresh RUNNER_TEMP path.
No local install, QEMU, target compilation/execution or production gate edits.
Use existing package acquisition only for the bootstrap dependency; log versions
and bind archive, binary, support manifest and all source/export identities.
Run positive input, theorem/axiom inventory, nonvacuity and required negatives
with per-process and total job time limits. No artifacts are uploaded by this
new lane; generated proof input identities and results can be printed in its CI
log. The checked-in source and exporter allow reproduction.

Any kernel result will be named precisely: universal correctness of the
validated *projected local slice evaluator*. Python/Core exporter refinement,
actual normal-prefix framing, whole-loop induction, resource/allocator/backend
semantics and all twelve ledger statuses remain unproved. DENY_ALL remains even
if the new narrow theorem passes. Only actual CI kernel acceptance, not reviewed
proof-looking text or mock tests, can establish that narrow result.
