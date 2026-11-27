# Inspect physical-entry lease: class-default successor R2

## Authored scope and source relationship

This is an unexecuted Python connection-layer correction for the explicit
`function_signature` and `inspect_program` HIA presentation owners. Generation,
compile, Source tests, actual-machine entry and VM execution in this scope are
all zero. Current-cold and whole-native qualification remain false.

The base is the actual 3,187-file source at
`v119-inspect-generation-only-r1/attempt-r1/source`, tree
`7df49dd24bbba4ba3210168e639d6ea35a76a475`. Runtime preimage:
14,926 B, Git `4b12ae8a634492ed56d54073812a584c7905960f`, SHA-256
`ca78ddc3f8dbd568f8b542b3f01bbd26dbeb196e6aa55fc1d5db346f73245645`.
R2 runtime: 16,497 B, Git `a2990590788b909505070241c63079b605afdea2`,
SHA-256 `8db7befea61305e52d08abe874ddc252d5cec0072b92e44e55be50a9c439f89d`.

The two-path packet carries that complete preimage/after-image and one new
Source-test file. `BASE-R2-RUNTIME.diff` is the application delta. The two
`R1-R2` diffs retain the separate relationship to the unexecuted private R1.
R1 source, authoring failures and observations are unchanged. No shared source,
hardlink, generator, HIA body, generated output or original test was written.

## Exact physical boundary

The unchanged original Native method
`InspectNativeProtocolTests.test_machine_entry_reentry_has_no_second_initial_call`
wraps `owner._entry` and calls the same frame's `step()` before the actual entry.
It requires a RuntimeError and zero additional entry-count delta. At this point
the outer inherited `_invoke` has written its command header and incremented
`image.entries`; the HIA body has not begun and `_started` is still false.
An HIA-only flag set inside that body cannot guard this earlier callback.
This is a static diagnosis: the original method has not run in this candidate.

R2 declares `_machine_busy = False` on the class and has no `__init__` override.
The inherited constructor callable is preserved exactly, including argument
binding and exception paths. There is no new forwarding constructor frame or
extra constructor-local reference to image, arguments, captures or witness.
Before any instance field exists, partial-constructor cleanup can read the
class's false default.

`_invoke` requires exactly false, assigns true on its own instance, delegates
once to the original physical implementation, and assigns false in `finally`.
It never writes the class or another frame. The idle check is outside the try,
so a rejected nested call cannot clear the outer call's lease. Header writes,
six transport arguments and the entry increment remain in the inherited body.

`step`, `service`, `take`, `close` and `_retire` check before their inherited
bodies; unchanged `drive` first calls `step`. This rejects reentry before an
inherited catch can mistakenly close the frame already inside the physical
call. `FrontUnknown` remains a RuntimeError subclass. The diagnostic identifies
the new physical refusal; no equivalence to erroneous old reentry is claimed.

## Internal flow and cleanup

| Original transition | R2 timing |
| --- | --- |
| Partial constructor calls `close(release=False)` | The class default is false; original cleanup and exception remain reachable. |
| `step` sends initial/resume/ACK | `finally` clears before original `_started` and `_accept_result` processing. |
| `service` claims and calls a provider | The physical claim returns and clears before the foreign effect. Original pending/executed/completed rules still govern provider reentry. |
| Ordinary `service` returns | Lease is false; original reply and completion ownership remain authoritative. |
| `take` or `close` outside entry | Original keyword shape and behavior are delegated unchanged. |
| `close` calls `_retire` | Both guards see idle; original `_retiring` and release order remain. |
| Retirement command 4, service loop and ACK | Each physical call clears before the next service/step transition, so ordinary cleanup is not falsely refused. |
| Initial/claim/effect-ACK/terminal-ACK loss | Physical `finally` clears before the original catch marks uncertainty and calls `close(release=False)`. |
| Retirement return is lost | Original uncertainty/quarantine is retained; no retry or synthetic release. |
| An already uncertain frame is later retired | Original `_UNCONFIRMED_RETIREMENTS` branch remains reachable without a new machine call. |

Clearing the lease only ends a physical-call interval. It grants no ACK, replay,
effect permission or buffer authority. The HIA nonce/sequence/claim/retirement
protocol is untouched. Shared FrontFrame and ContinuationFrame bodies and all
existing inspect methods remain exact after inverse projection.

Non-constructor forwarding methods still add observable Python frames. R2
removes the specific constructor-retention difference; it does not claim
arbitrary traceback/reference-count/private-frame equivalence. Original held
error, finalizer and provider controls still require actual execution. This
is a synchronous frame-local guard, not an atomic thread lock, raw-pointer
guard or permission to mutate private class/instance fields.

## Source8 and original controls

Eight new Source methods remain separately declared. The revised first method
checks absence of a local constructor, exact inherited-callable identity,
direct argument observations and the real inherited partial-constructor error
path. The other seven method ASTs equal R1. Synthetic `_frame` no longer sets
an instance default, so these controls exercise the class lookup itself.
They cover seven reentry routes, original header/arguments/count, raw
BaseException, initial/claim ACK loss, normal/lost retirement and independent
same-image frames. They use synthetic Python callbacks, not HIA evidence.

The complete original `inspect_exec_cases.py` and `inspect_exec_vm.py` are
retained byte-for-byte: 17 actual-machine methods and 12 VM selectors. Their
IDs, assertions, order, fault injections, frame-selection predicates and limits
are not altered. Source10 and the four original test files for original3/CLI43
also remain exact. The original direct-entry negative is not replaced by the
new synthetic Source8 checks.

Existing original3 PASS belongs to retained R2 under `-I -B`; CLI43 PASS belongs
to retained R3 under `-B`; R2's two color subtest failures stay FAIL. None is
attributed to this new runtime, and none is scheduled again by the minimal
design. Their source/manifest lineage stays separate.

## Real generation and storage

`EXECUTION-DESIGN.json` is a design, not a runnable authorization. Exact staged
runners/argv and actual predecessor pins still require review before execution.
No full base copy or new source view exists in this scope.

Adding hardlinks to the already guarded source would change inode ctime/nlink.
The authorized future design therefore uses independent new inodes, via
reflink or per-file byte copy, with complete byte/mode checks and unchanged old
source stats. No old source gets a new link. The actual source map totals
98,101,193 bytes; the two-path overlay would give 3,188 files/98,115,293 bytes
before real generated differences. These are disk estimates, not image or
workspace limits. The original 1-GiB free-storage floor remains unchanged.

Future generation runs the exact existing generator twice, then `--check`,
with three external output files and an independent 180+3 owner per call.
Both assemblies and ports must equal each other and the old actual generated
bytes. Identity output must match both passes and bind the actual new runtime
through unchanged HOST_SOURCE_FILES/compatibility_data. These equalities are
required future gates, not claimed results. Only successful actual outputs
are installed on three independent new inodes. The final source map/tree is
computed from actual bytes, never predicted or patched metadata.

## Minimal downstream execution design

After generation, original Source10 and new Source8 run in separate owners.
The new Source8 request needs its own explicit group validation; the old kit's
fixed ID table is not silently extended.

Build-inspect then calls unchanged frozen `_build_inspect` once with the fixed
ordinary B3: 673,413 B, SHA-256
`bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.
Keep 20-second compile, 1-MiB source/output/workspace/image, author128/1536/8192
and outer180+3. The actual manifest binds actual generated source, image,
compiler, host hashes and full receipt. The old compiler child retains full
output and a workspace header, not its entire post-compile workspace; this
gap remains explicit. No new observer or reconstructed workspace is proposed.

Run Native17 in its seven original groups and order, with one fresh child per
lost-return method. Unchanged FrameJournal captures complete actual S/O/W
before/after each call. Lost ACK is injected only after a real recorded return.
Any test, incomplete journal, source drift or incomplete cleanup stops all
later stages without retry. Unknown ownership cannot be carried to another
group as success.

Only the resulting complete actual catalog can feed VM12's two original
groups. All twelve witnesses must exist and bind the exact admitted image and
raw frame files. Preserve 10,000,000 steps per frame, 8-MiB heap, depth128 and
180+3 owners. VM finally saves complete real buffers on success or failure.
Only these twelve selected transitions can receive Native/VM equivalence;
unselected recorded frames are not silently included.

There is no new resource asset, optional registry entry, setup change, manifest
permission, default activation or CLI op10 connection. Eventual Source
registration would add the one new test path/class; Root owns shared registry
edits. This connection-layer correction does not remove Python or authorize
legacy deletion or whole-CLI/native claims.
