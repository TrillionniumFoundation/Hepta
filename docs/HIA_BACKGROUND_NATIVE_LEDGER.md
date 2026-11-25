# Native detached background accounting ledger

This component owns eight unbounded decimal counters and the most recent 64
immutable receipt references. It implements atomic ledger storage and once-only
settlement against the accounted marker in the actual native Job. It does not
format receipts, collect clocks, validate rankings, or qualify the entire
BackgroundOptimizer.

The composing optimizer invokes the ledger under its original logical condition
lock. The ledger also has its own native futex mutex. Receipt production and job
completion remain separate: a later cancellation or caller result mutation cannot
rewrite previously captured accounting bytes. Reported prior search costs are
not implicitly added here; the business owner supplies the actual independently
derived submit-plus-worker cost value.

## Fixed providers and lifetime

Initialization captures the actual native decimal-value, immutable-payload and
Job providers and their contexts. Normal operations accept no replacement
provider pointer. Each call retains a Job reference before inspecting its private
metadata. The call guard is released after the ledger mutex, including any Future
closure destruction triggered by that release. The public enclosing owner keeps
all contexts and images alive across the call.

Counters are immutable decimal objects with independent strong-reference nodes.
There is no u64 counter or refcount substituted for an original public integer.
The counters are settled jobs, observed submit-plus-worker time, and outcomes
published/abstained/stale/rejected/cancelled/interrupted. A mask records which
outcomes have actually occurred, preserving the original initially empty mapping.

Settlement first checks the actual Job marker. An already-accounted job returns
without consuming the proposed receipt or cost. A new settlement validates the
receipt capability, calculates all three new decimal values, installs the new
counters and receipt, and finally sets the Job marker. Allocation failure before
commit drops unpublished references and leaves the marker, counters and receipt
ownership unchanged. The return carries an explicit transfer flag.

Snapshots retain all eight counters and recent receipts while locked. Returned
nodes are independent. If a retain fails, all unpublished clones are released.
The chronological ring keeps at most 64 receipts; eviction releases only its own
reference. Retained snapshots survive subsequent eviction and ledger destruction.

## Private six-word ABI

hia_mv_background_ledger(input, input_bytes, output, output_bytes, context, context_bytes)
uses disjoint views, exactly 128 input bytes, output >= 8192, context >= 4096.
Malformed frames return 0xfffffffd without changing the owner context.

Input HIABLG01:

| Word | Meaning |
|---|---|
| @8 | operation: 0 initialize, 1 settle, 2 snapshot, 3 destroy, 4 marker query |
| @24/32/40 | settle/query Job capability; initialization value function/context/extent |
| @48/56/64 | settle owned receipt capability; initialization payload function/context/extent |
| @72/80/88 | settle borrowed observed-cost value capability; initialization Job function/context/extent |
| @96 | settle outcome index 0..5 in the order above |
| all other words | zero |

Initialize, snapshot and destroy have no Job/value capabilities beyond the
initialization provider fields. The observed-cost reference is borrowed.
An accepted receipt reference transfers to the ledger; a duplicate exact node
already owned by its ring is refused. A retained receipt must use a distinct node.

Normal completion returns zero and HIABLGR1. Status @8: 0 success, 1 invalid
capability, 3 duplicate owned receipt, 4 allocation failure, 5 lifecycle/PID
refusal, 6 syscall failure, 9 invariant/provider failure. Recent count @16,
outcome mask @24, returned-reference count @32, receipt-transferred flag @40,
already-accounted flag @48 and PID @56 are followed by zeros.

Snapshot records start @4096, each 48 bytes: kind @0 (1 decimal, 2 payload),
index @8, owned capability @16/24/32, byte length @40. The first eight records are
counters in the order above; remaining records are receipts oldest first.
All records returned successfully are owned by the caller. No caller may replay
an effect after a transfer flag reports commitment.

## Actual qualification

The actual HIA value, payload and Job owners were used. Seven behavior groups
passed with 1286 ledger calls. They include 300 fresh arbitrary-width sums,
all six outcomes, the complete 64-receipt window, duplicate settlement,
400 concurrent once-only settlements plus 400 duplicate attempts, concurrent
consistent snapshots, later actual Future cancellation, retained old snapshots
across eviction, foreign/stale references, PID rejection and final empty
reference registries.

Thirty-seven controls inject failures at actual native decimal/payload allocation
sites: each initialization site, each settlement site, all eight counter clones
and each receipt clone. Failed initialization can retry the same empty context;
failed settlement preserves its receipt and marker; failed snapshots release
both classes of unpublished references. Twenty-four packer and full readable
mechanical-prefix checks passed.

The first external observer used an incorrect hardcoded expected byte length for
one literal receipt. It failed after the product's correct result. The observer
was corrected to use the actual literal length, with the original failure
preserved. No ledger policy or product bytes changed for that correction.

This evidence closes storage, ownership and exact cumulative arithmetic only.
The original receipt rendering, live elapsed measurements, rank validation,
runtime publication and whole background business qualification remain separate.
