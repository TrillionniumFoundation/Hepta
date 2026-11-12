# HIA P7 — bounded source-owned queue item snapshot

## Why this is an input/safety increment

In the exact HIA source baseline `12d8ca6e4c30ae1781de899c563b1543c9aaf315`, `OwnedAdaptiveRuntime.submit_queue`
froze the outer Python list, but its individual plain mutable dictionaries
remained producer-owned. The prior code tested `set(item)` and then separately
read `item["slot"]`, `item["iterations"]`, `item["delta"]`. A concurrent
producer could delete/retype or replace fields after the structural check,
causing inconsistent admission or an unhandled host exception.

## Scoped repair

`_snapshot_queue_work_item` captures at most three ordinary built-in dictionary
entries into an independent local object before any semantic field validation.
It refuses nonstandard keys, additional/missing fields, subclasses and
iteration mutations. The actual queue now validates these captured immutable
integer references and constructs frozen `_Work` values. Hashing, budgets and
native execution never reread original input dictionaries.

The outer producer list remains bounded (128 entries); total committed native
iterations retain the original upper limit. Producer mutation *after* a
complete capture cannot alter accepted work or its bound SHA256.

This is not an atomic multi-key transaction over arbitrary concurrent
mutations, a full crash journal, or exactly-once recovery. Python, native C,
LLVM, loader, OS and hardware remain in the trusted computing base.

## Exact qualification gates

1. Pure adversarial intake (no native shortcuts), frozen after original input
   is cleared, missing/extra key, invalid scalars, cumulative quota and outer
   list budget controls.
2. Real Clang20 + Z3 native owner: mutate producer dictionary between snapshot
   and work acceptance; execute the unchanged `OwnedAdaptiveRuntime` native
   driver and confirm original digest, committed steps and detached state.
3. Retain existing native producer-mutation regression, basic Core/resource
   correctness and clean-worktree invariant; zero skip on nominated tests.

No P0–P7 production gate closes from this targeted queue-intake repair.
P7 still requires durable journal, real crash/restart, post-publish Final-use
and Generation Fence, rollback evidence, load/energy/latency on actual hosts.
No production activation or merge without separate exact-head qualification.
