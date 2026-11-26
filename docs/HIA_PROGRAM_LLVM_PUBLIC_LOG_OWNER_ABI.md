# Native public LLVM command-log ownership ABI

This component is an actual HIA state machine, a fixed mechanical bridge, a native HIA object packer and the existing native shared linker. It owns the real Value list and the row currently being updated. It does not yet certify the enclosing `compile_program_llvm` hooks.

## Construction and trusted binding

The product exports two six-word entries:

- `hia_program_llvm_public_log_bind_owner(source, source_bytes, logger_workspace, logger_bytes, sole_owner, owner_bytes)`
- `hia_program_llvm_public_log(source, source_bytes, reply, reply_bytes, logger_workspace, logger_bytes)`

Binding requires a zeroed 65,536-byte logger workspace, a live actual 2,048-byte sole owner and a 64-byte `HIALLBO1` request. Word 8 and bytes 40–63 are zero; bytes 16–39 are the borrowed actual command-log Value capability. The native binder holds the sole owner's actual mutex while it verifies PID, workspace identity and live state, captures the sole Value entry/context/nonce, and executes the native token/list-retain sequence. The caller cannot supply a Value entry, context pointer, nonce or code address in this request.

The HIA policy checks exact list kind 5, creates an actual arena token with private Q06/21, and retains the list through Q05/91. The binding reply is at logger offset 1,024. The sole-owner mutex is released after this sequence. A kernel notification gate stops actual Value `getrandom` inside binding, observes the actual owner mutex held, and proves concurrent destruction is refused.

The raw `HIALLVB1` seam is internal bridge code and is not an ELF export. The component has no embedded copy of Value. The captured entry and arena are the enclosing owner's actual entry and arena.

## Main requests

Requests use the 128-byte `HIALLVQ1` header. All words are zero except the magic, operation at 8, tail size at 96, and the capability explicitly allowed below.

| Operation | Inputs | Native effect |
|---|---|---|
| 0 | Nonempty JSON tail | Import a real dictionary using Q10/1, append it to the held actual list using Q07/16, and retain the row until its update completes. |
| 1 | Nonempty JSON dictionary tail | Import an actual update dictionary and update the held row through real Q09/23 atomic entry snapshots and Q06/10 dictionary writes. |
| 2 | Borrowed actual update-dictionary capability at 24–47; no tail | Retain that dictionary, then perform the same native update. Arbitrary values, including non-text error codes, remain actual Value references. |
| 3 | No capability or tail | Release all local row, patch, key, value and log references; release the independent arena token; retry actual local mapping retirement. |

Operation 0 requires the ready state. Operations 1 and 2 require an in-progress row. Operations 1 and 2 release the component's row reference after the update succeeds; the caller's list retains its own real graph edge. Removing the row from the list while capture is running does not invalidate the component's independent row reference.

Updates preserve the same dictionary identity and insertion order. Previously completed field writes survive a later update failure. There is no replacement shadow dictionary and no conversion of arbitrary error-code objects to strings.

The HIA owner maps an actual temporary input frame for JSON import, copies only the actual request bytes, and unmaps that frame during cleanup. A failed `munmap` leaves the real mapping address and extent in native custody for operation 3.

## Replies and custody

Replies are 128-byte `HIALLVR1` records.

| Offset | Meaning |
|---|---|
| 8 | Primary error, or cleanup error when there is no primary error |
| 16 | Actual detail or errno |
| 24 | Operation; 4 identifies binding |
| 32 | State: 1 ready, 2 row active, 3 binding, 4 body error, 5 pending/quarantine, 6 locally retired |
| 40 | Primary append/update/bind action completed |
| 48 | Actual held log reference |
| 56 | Actual held current-row reference |
| 64 | Held temporary patch/key/value references |
| 72 | Unknown disposition/quarantine |
| 80 | Any local mapping or shared resource-queue pending fact |
| 88 | Known local custody |
| 96 | All component-local references, token and mappings retired |
| 104 | Local frame or arena mapping pending |
| 112 | Shared native resource queue pending |
| 120 | 1: this entry defers resource-finalizer execution |

A successful primary action is independent of later cleanup failure. For example, an actual append followed by denied `munmap` returns primary-completed 1 and mapping-pending 1 while preserving the row and mapped frame. It does not hide the append or falsely report retirement.

All reference releases use actual Q05/78 or Q05/92 consumption facts. Unknown receipts quarantine custody. The final Q05/93 retry accepts the genuine active-arena status 6 with mapping-pending 0. A queue-only pending condition is reported separately and does not become a false local mapping failure.

The component never invokes Q05/56 or runs resource finalizers. Final resource drain belongs to the enclosing native owner after its outer locks are released. Local-retired 1 with queue-pending 1 means only this logger's custody is closed; the enclosing Value owner still owns the queue. Repeated operation 3 on a locally retired logger does not call a possibly retired Value arena.

## Actual qualification

The receipt binds all source and product bytes. Qualification uses CPython 3.14.4 only for independent expected values and test orchestration; all list/dictionary mutation, retention, token creation, cleanup and pending facts come from the real native product.

Ten groups cover:

1. Native capture of the unique Value entry/arena and updates to the identical log row.
2. A row removed by the caller remaining live for failure updates.
3. Arbitrary non-text error-code Value alias preservation.
4. Actual logger `mmap` ENOMEM.
5. Actual logger `munmap` EIO after primary append, followed by native retry.
6. Actual Value token `getrandom` EIO.
7. Actual Value arena `mremap` ENOMEM without a partial appended row.
8. An actual code-retirement queue remaining deferred across bind, append and logger close.
9. Exact-list and malformed/state request rejection.
10. Actual owner-mutex protection of token binding, independent logger token lifetime and successful final destruction.

The producer and packer retain the original HIA function/block/operation budgets. Both compile twice with the pinned native compiler; the native object is byte-for-byte equal to the independent structural object encoding. The shared object is produced by the existing native linker.

## Remaining enclosing work

The public LLVM wrapper must call append before the actual capture starts, update the same row after each actual capture, and preserve the original ordering of typed failure construction and cleanup. The wrapper's fresh IR-origin validation, real output path conversion, budget checks and complete public API are separate unfinished work. This component's qualification does not mark those domains complete.
