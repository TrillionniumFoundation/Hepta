# HIA program v3: overlap-safe byte move (P1/P2)

## Scope and instruction contract

This increment extends the **existing** standalone typed HIA Core/verifier,
interpreter and LLVM emitter. It does not introduce another checker/compiler.
The new explicit schema \`hepta.hia.program.v3\` has one additional opcode:

\`\`\`text
buffer.move_within(mutbuf, destination: usize, source: usize, count: usize)
  -> ()
  effects {read, write, trap}
\`\`\`

The caller retains exactly **one live unique mutable loan** to the same
byte-buffer owner for the duration of this operation. That loan must not have
suspended child views. Passing an owner or shared read loan directly rejects.
The source and destination are offsets within that **one** buffer, not two
pointer or view objects. This avoids manufacturing conflicting aliasing loans.

The operation is \`memmove\`, not \`memcpy\`: overlapping ranges are supported in
both directions. The verifier requires all three scalar offsets/counts to be
exactly \`usize\` and an empty attributes map. Normal linear cleanup is still
required on every normal return. As with earlier HIA versions, a trap aborts;
no eventual Drop after an abort is claimed.

Bounds are checked in this exact order:

\`\`\`text
destination <= extent
source <= extent
count <= extent - destination
count <= extent - source
\`\`\`

Thus no unchecked \`destination+count\` or \`source+count\` addition can wrap a
64-bit \`usize\`. Offset \`== extent\` with count \`0\` is defined and valid;
an offset greater than the extent traps even when the count is zero.

## Execution paths

- **Independent interpreter:** performs verified directional copies using O(1)
  auxiliary memory, including overlapping forward/backward ranges.
- **Existing LLVM emitter:** lowers **exactly the reverified Core** to the
  \`llvm.memmove.p0.p0.i64\` intrinsic with all four unsigned guards. For count
  zero, it branches around pointer derivation and the intrinsic altogether,
  so an empty owner never supplies a possibly null pointer.
- **Native target identities:** the LLVM x86-64 and AArch64 object profiles
  have explicit \`.v3\` identifiers. Existing v1/v2 reports and emit paths
  remain unchanged. V1/v2 refuse \`buffer.move_within\` with
  \`E_HIA_OPCODE\`, even if someone rehashes a v1/v2 program.
- **Safety:** unique-loan lifetime, parent suspension, SSA and effect
  enforcement remain in \`verify_program\`, not in a second model.
  The existing zero-init elision whitelist does **not** admit move_within.

## Focused tests and evidence boundary

Committed \`tests/test_hia_overlap_v3.py\` verifies both overlap directions,
unchanged bytes, zero-length empty buffers, out-of-range offsets, \`usize\`
overflow extremes, rejected v1/v2 opcodes, wrong loan/type/effect/attrs,
allocation/loan cleanup on successful return, and exact emitted LLVM
\`memmove\` native host differential/child-process SIGABRT rejection.

Standalone **actual Clang 17 x86-64** LLVM intrinsic smoke in this session
passed **2,090** valid tuples over byte extents 0, 1, 2, 8 and 16, including
both overlapping directions and \`null\`+zero-length. One compiled native
negative control with \`destination=UINT64_MAX\` exited 134/SIGABRT.
The corresponding independent Python directional copy matched 2,090
reference slice moves. **This smoke is a handwritten intrinsic/guard control,
not full source-built HIA emitter qualification.**

Required exact-commit tests on a full Hepta checkout:

\`\`\`sh
python -m unittest tests.test_hia_overlap_v3 tests.test_hia_bulk_memory \
    tests.test_hia_program tests.test_hia_program_llvm -v
python -m unittest tests.test_hia_v2_agent_policy_integration \
    tests.test_hia_interface_policy -v
\`\`\`

Use a real pinned Clang 20+ for production \`build_program_native\`, and
require true QEMU/physical target execution separately before making target
execution claims. An unexecuted exact-head test, an unproven LLVM translation,
or historical CI results never imply qualification.


## Existing Agent patch policy on HIA v3

No new Agent patch verifier is introduced. \`hia_program_tools.apply_program_patch\`
binds the expected original program SHA, performs edits only inside its
existing approved actions, and sends the complete candidate to the same
\`verify_program\` checker. HIA v3 may be edited through legacy interface-
preserving \`hepta.hia.patch.v1\` or explicit-policy \`hepta.hia.patch.v2\`,
without changing the program schema.

The separate \`tests/test_hia_v3_agent_policy.py\` regression now checks
valid body edits, stale identity, forbidden loan/type changes even under
an explicit migration policy, missing effect rejection, return-interface
migration only with \`migrate\`, and explicit denial of schema confusion.
A valid migration still has
\`external_callers_revalidated=false\` and
\`behavior_equivalence_proved=false\`.

## P0–P7 remaining blockers

This closes only a finite **language/LLVM capability gap** relevant to
in-place C/C++ byte-buffer algorithms. It does **not** certify arbitrary C
pointer provenance, unmodeled overlapping C++ aliasing, GPU codegen,
multithreaded atomics, general lifetimes/nominal ADTs, original-source-to-Core
soundness, whole-backend refinement, full multi-compiler C/C++ ABI compatibility,
actual Agent-model A/B, production p99 or physical MMIO/DMA/IRQ.

\`whole_project_blockers_closed=false\`. This branch is stacked on the exact
head of PR #184, not the older scalar-only HIA candidate.
