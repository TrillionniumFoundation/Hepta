# Complete historical nominal importer — development design

This new overlay preserves the frozen ordinary 33-image executable and its
20-file source manifest. No ordinary source, selector, cold gate, or retained
owner is changed. The public contract being moved is the complete
`import_legacy_composite_v2` function in the restored e2f392e baseline.

## Required semantic order

1. Admit the original raw integer JSON using the existing complete raw native
   pipeline, including the original byte, full UTF-8, source-order parse,
   integer-profile, node/depth, and canonical detached-snapshot boundaries.
2. Check exactly the four historical root keys, then the explicit nominal-v2
   schema. Schema spelling is caller selection, never producer authentication.
3. Change only that schema to composite-v1 in a full issued typed packet. Do
   not impose a new 8 MiB limit on this derived transport: the rename adds two
   bytes and the original old-core verification must still happen first.
4. Use a fresh native context for the complete legacy lowering. Change the
   resulting Core schema to primitive-v1, then perform complete primitive
   admission and native canonical hashing. No v6 instruction is admitted by
   changing the historical label alone.
5. Only after step 4 succeeds, enforce the original caller-owned renamed-input
   byte boundary and run a second, independent ordinary composite-v1 public
   admission and lowering to primitive-v6, with fresh types/counters/caches.
6. Compare all canonical Core bytes after the single schema substitution.
   Accepted JSON has no floating-point values, and canonical key order removes
   dictionary insertion order from this comparison. The generated operational
   payload is unchanged by the label-only adapter; a mismatch refuses.
7. Emit the complete canonical Core, complete renamed structured input, and
   exact import report with four native SHA-256 digests and original claims.

## Native execution mechanism

The new fixed executor introduces a mechanical RUN_CHILD operation. HIA chooses
its mode, private source mapping, target mapping and lease. It creates a fresh
buffer table, 1 MiB controller state, command/frame mappings and spool handles,
then calls the same immutable HIA image table directly. There is no process
creation, exec, interpreter, dynamic loader, value materialization or descriptor
translation. At most the importer and one child context are live. The child
receives a borrowed read-only private mapping; cleanup may not unmap or make it
writable. A successful canonical Core mapping is transferred to the parent;
all other child mappings and actual file descriptors are released before ACK.

RUN_CHILD is opcode 15 and is legal only for the fixed root importer role 46.
Arguments are `[mode, sourceSlot, 0, extent, targetSlot, childLease, 0,...]`.
Mode 0 starts the unchanged raw public pipeline, then ordinary lowering and
publication role 45. Mode 1 starts the unchanged complete constructor from the
already issued renamed SourceIndexLease, legacy=1, and publication role 47.
The ACK has actualReturn=128 and 160 observed bytes: actual terminal frame,
actual transferred capacity, target slot, terminal role, zero. Any ABI/IO
failure aborts and discards the whole process lease. No failure is retried as a
fresh admission, and semantic errors remain ordered by the HIA root FSM.

Role 28 is the strict historical root/schema projection. Role 29 compares the
two complete admitted canonical Core values. Role 46 owns the full importer
continuation/report. Role 47 is an independent, source-bound old publication
variant: it verifies the exact final canonical root schema suffix before the
one-byte v6→v1 substitution and uses the same whole primitive admission image.
No changed old publication image is presented as the frozen ordinary image.

## Limits and evidence status

The original 128-function/1536-block/8192-instruction compiler limits, 10 CPU /
20 wall seconds /256 MiB development compiler process, 8 MiB language input and
Core bounds, node/depth/fresh/slot/inventory gates remain unchanged. A response
containing both independently admitted input and Core is derived transport,
not an additional source-language input. Runtime allocations are bounds-checked
against their actual private mapping extents and disjoint roles.

This file is a design checkpoint, not a generated/compiled or tested claim.
All future attempts retain separate identities and original failures. The
existing local ptrace denial is retained; no syscall-trace claim is made.
