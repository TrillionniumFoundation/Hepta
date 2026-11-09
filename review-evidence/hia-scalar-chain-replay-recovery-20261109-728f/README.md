# Scalar-chain v2 source recovery snapshot

## Status

**This is a source recovery draft, not a completed qualification.** Its parent is
PR #830 head `39dedf9f7933b9743fb8a6c720e5deb4615296eb`. The final local working
tree became unavailable before a complete validation run or local commit.
The files in this follow-up were reconstructed from retained source text and the
recorded applied edits. Exact equivalence to the unavailable final working tree
has not been independently established.

The source implements a v2 packet with original profile, context, proof,
adoption and rollback dependencies, and a reader that reconstructs the complete
selected artifact chain before regenerating the original 13 obligations per
type. Historical v1 packets have a separate explicit saved-query-only mode.
The draft contains nine focused regression methods and a stronger existing CI
step requiring both focused modules, a fresh full-width v2 native qualification
and strict original-byte replay. These are requirements; the recovery snapshot
has not yet passed them.

## Validation observed before the environment became unavailable

- An earlier development u32 v2 packet completed 125 workload vectors on each
  of two distinct images (250 native workload calls) and ten actual owner calls,
  including retained/new leases across rollback. It retained 45 artifact
  exports, before the additional seven profile definitions were included.
- That development packet's artifact-chain reconstruction and fresh model
  checks completed all 13 per-type obligations with byte-identical regenerated
  queries. The reader did not emit, link or load native code.
- Nine new regression methods passed in 13.429 seconds on an earlier source
  revision. This result does not qualify the recovery snapshot.
- After seven original profile exports and additional consistency checks were
  added, the combined twelve-test suite started. It printed passing results
  for the existing three tests and the historical-v1 mode test, then terminated
  with **exit 137, Killed**. The suite is incomplete.
- The executor then became unavailable. The connected HeptaRuntime tools also
  returned internal errors. This draft was preserved through the explicitly
  authorized GitHub connector fallback.

The original development logs and generated packet were in the unavailable
execution environment. They are not copied into this snapshot, so the bullets
above are contemporaneous execution notes, not substitute raw receipts.

## Required before qualification or normal publication

1. Review the reconstructed source and run both focused test modules without
   skips or expected failures (at least twelve tests).
2. Run a new clean-source v2 qualification for `u8 u32 u64 usize`.
3. Use the newly selected manifest to run the strict default reader. Require
   four complete reconstructed chains, 52 freshly regenerated obligations and
   52 original saved-query replays. They are two checks of the same 52
   obligations, not 104 distinct obligations.
4. Retain the exact-source CI results, source identities, full original packets
   and failure artifacts. A result must identify this follow-up's actual head;
   #830's earlier CI does not qualify these changes.
5. Exercise the optional adoption identity projection after separately reviewed
   `fbcc97ec` / `cf862a42` work is integrated. Those commits are deliberately
   absent from this recovery branch.

## Scope

No production adoption, runtime selection, public release lock or online
activation is performed by this source recovery. The v2 reader validates
consistency of pinned evidence and reruns the identified executable SMT models.
It does not independently authenticate the original operator's execution and
does not turn digests into a machine-semantics theorem. Kernel-checked Core
soundness, complete hardware/loader refinement, foreign-resource liveness,
compiler-buffer refinement and full economic benefit remain unproved.
