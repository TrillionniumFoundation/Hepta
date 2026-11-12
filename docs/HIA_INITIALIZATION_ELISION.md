# Local buffer initialization coverage

The canonical Core still creates initialized byte buffers. The native backend
may reuse its existing malloc path when zero initialization cannot change a
specified return value, first trap, resource transition or later byte read.
The original unread-allocation whitelist remains available.

The added checker in `hepta/hia_initialization.py` first restricts its input to
local allocations, scalar arguments/results and a closed operation inventory.
Actual emission receives detached, canonically reverified Core. A saved
coverage report is not imported as native admission authority. Calls, resource
escapes, unknown memory operations and ambiguous origins retain calloc.

For functions containing reads, every read must have a unique local allocation
root, transported through actual owner/loan operations and CFG argument edges.
Allocation sites that can execute repeatedly are refused. This prevents one
static SSA allocation name from standing for multiple live dynamic instances.

A complete fill witness requires all of the following:

- A header comparing its `usize` index with the exact allocation request length.
- Every non-backedge entry supplies index zero and that same length.
- The true edge enters one body with no other predecessors or byte reads.
- That body stores through the same allocation at the current index, then
  increments it by exactly one, and jumps back with unchanged length.
- The false edge reaches an exclusive completion block. That completed-fill
  block dominates every subsequent read of the corresponding allocation.

The origin fixed point, CFG size and operation count have explicit admission
bounds. Exhaustion keeps zero initialization. A different index, smaller fill
extent, stride two, skipped fill, earlier read, foreign call or another owner
does not inherit the witness. Native allocation length normalization, zero-size
handling, object-size limits, NULL/refusal, byte bounds and owner drops remain
unchanged. Allocator family selection and physical initialization work can
change; abstract allocation outcomes are compared under the existing coupled
allocation/refusal model, not a promise that libc malloc and calloc always
make identical decisions on an unconstrained host.

`formal/HiaInitializationPrefix.lean` proves a separate mathematical model:
for arbitrary initial memory and arbitrary length, a contiguous zero-based
unit-step write schedule initializes every byte below the length and yields
the same bytes as executing that schedule from zeroed memory. It also proves
the prefix step, exact completed exit and preservation of the finite upper
bound on the next index. Partial fill, starting at one and stride two retain
holes. The qualifier checks all named theorems with the pinned Lean kernel,
support identities and targeted rejected mutations; no `sorryAx` is accepted.

This theorem does not machine-prove the Python CFG checker, its finite-integer
bridge, the allocator or LLVM. The actual Core-to-witness bridge is checked
structurally and exercised independently with legal Core counterexamples. A
real malloc wrapper fills new memory with `0xa5`: admitted complete fills still
return their written values, while rejected partial/wrong-owner paths retain
calloc and their specified zero bytes. Bypassing the witness for a starts-at-one
candidate produces a real byte 165 where the Core interpreter returns zero.

The checker is included in the native implementation digest, selected scalar
lowering checker digest and sequential proof-chain source identity. Native
experiment source inventories include all `hepta/*.py` files. This binds the
actual dependency without upgrading the mathematical model into a general
compiler refinement theorem.

The previous LTO and PGO timing observations remain source-specific negative
results. This optimization does not change a registered threshold or establish
a performance advantage; any new performance claim requires a separately
frozen implementation, prospective protocol and new held-out workload lengths.

The separate `verified-initialized-reduction-rust-pgo-release-v1` profile reads
its sole protocol-v3 registration from
`benchmarks/hia_native_ndu/INITIALIZED_RELEASE_TIMING_PROTOCOL.json`. It retains
the original training axes, strong Rust opt-level 3/fat-LTO/single-CGU/PGO,
C/C++ build budgets and median/p95/p99 gates. New timing lengths are
3, 17, 65, 259, 1031, 4099, 16387 and 65519; new timing seeds are
1597, 2633 and 4261. A census of available structured timing receipts found no
overlap, excluding one-call/one-sample correctness probes; this is not a claim
about inaccessible global history. The source-bound census digest is retained
in the registration. Earlier correctness exposure does not make these unseen
program inputs; they are a new timing cohort.

One future campaign on the final clean implementation is registered: 132 timing
requests, 2,772 batches, 177,408 timed calls and 192 correctness/refusal requests.
Before timing, the runner freshly reverifies the optimized Core's two complete
allocation-fill witnesses, binds them to the actual compilation Core and checks
the compiled object's malloc import and absence of calloc. PGO training still
receives only its original training axes. Preparation, loading, measurements,
all source/tool/profile/artifact identities and negative gates remain retained.
Protocol v1/v2 registrations retain their original canonical digests; none of
their earlier negative results are replaced by the prospective registration.
