# Native BackgroundOptimizer business worker checkpoint

This is an actual native pthread integration checkpoint. It does not qualify the full BackgroundOptimizer or the retained-cleanup failure domain.

## Actual covered behavior

The native worker invokes fixed HIA execution, accounting, publication, and Future completion policies. The first case processes three real submitted Jobs: cancellation before execution, rank abstention, and an actual ranking exception. Original accounting receipts are compared byte for byte. Repeated Future result access and mutation observe the same shared value object.

A second case performs rank proof, independent candidate verification, and runtime publication on the native worker; a previously accepted queued Job then becomes stale. The same actual cancellation token protects the publication.

The fatal case raises an actual user callback BaseException after the active Future becomes terminal. While that callback is blocked, eight additional Jobs are submitted. The HIA failure policy closes admission, drains all eight pending Jobs, accounts all nine Jobs exactly once, and continues after a second callback raises. Original failure truncation, field order, receipt bytes, and final mutable result values match the original _stop_failed_worker implementation. User callbacks in this test are external callback fixtures; business policy and the pthread loop execute natively.

Every case checks owned references and exact FD recovery after runtime teardown. The complete source, two independent native policy compiles, native packer, native shared linker, and image pins appear in the JSON.

## Captured interface and ownership

The handler accepts the existing HIABGWQ2 request and returns HIABGWR1. Its HIABWBC1 context owns a 16384-byte captured prefix followed by a 1048576-byte private output workspace. The mechanical adapter checks disjoint views and dispatches only the two fixed policies. It copies the 128-byte public reply back to the worker stack; it does not allocate a large stack frame or implement job policy.

The queue condition protects record lookup, work-start observation, active/pending settlement, failure publication, and accounting. Future completion and arbitrary user callbacks occur after that condition is released. Context bytes 512..535 hold the actual strong worker-failure value reference, for independent snapshot capture under the same queue condition.

The active Job remains separately owned during fatal processing, even if its ordinary pending record was already removed. Drained pending order is retained; an already settled active Job is appended and skipped when both its accounting marker and Future state show completion. Mutable result, immutable accounting receipt, Job slot, and external Future lifetimes remain separate.

## Open boundary

Retained cleanup retry, allocation and dependency failure recovery, physical thread-exit observation, public shutdown, and constructor ownership still require implementation or final qualification. The current reports use their recorded intermediate Future and ledger images; the final coherent inherited-Future and insertion-order ledger combination must receive its own actual integration check. No whole-background or whole-release claim is made.
