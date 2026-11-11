# Complete batch edit-context renderer — development handoff r2

## Outcome and exact scope

The two HIA kernels implement the complete retained `render_batch_context` algorithm: caller-policy normalization, exact prepared query/site validation, original first-error order, complete single-query presentation admission, signature/CFG/operation conflict detection, ordered inventory merging, and the entire final display. The executing harness disables the hosted batch/single renderer, bounded JSON wire, public decode, old preflight/materializers and `json.loads`. Its work is fixed image dispatch, exact byte-view copying, allocation/GROW and recording actual calls.

This is a source-bound development component. The ordinary Python public renderer has not been switched to it. Incremental capture of arbitrary foreign Python objects, subclass lookup/equality behavior, Python exception-object reconstruction, installed selection and whole-stack cold qualification are not claimed by this handoff.

The semantic split is control/collection and final display. The emit image is exactly unchanged between r1 and r2. No old/reference owner has been removed.

## Frozen r2 identity

- Source manifest: `checkpoints/edit-render-batch-source-r2/source.json`.
- Source manifest SHA-256: `6917537be8c961810b5347c07e835bc2516a231a44a9d2ca08f01d04a3316f43`.
- Bundle: `development/edit-render-batch-compile-r2/bundle.json`.
- Control image SHA-256: `f108d941ee85719c8d696cc8f7b1b7a799a90fdf58c4ac20188578e9654869d9`.
- Emit image SHA-256: `5f7bfd3a5160662aafedee843d43243de48159a3e55cbb19a1cd4ab708b0025a`.
- Retained development compiler SHA-256: `0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8`. Its historical identity does not qualify the current source tree.

Both were actually compiled by that B3 image under the original 10 CPU second / 20 wall second / 256 MiB compilation limits. No language/compiler limits changed.

| Kernel | Functions | Blocks | Instructions | Largest function blocks | Largest block parameters |
| --- | ---: | ---: | ---: | ---: | ---: |
| Control r2 | 55 | 1,039 | 4,898 | 119 | 10 |
| Emit, unchanged r1/r2 | 48 | 831 | 2,590 | 119 | 10 |
| Original compiler limit | 128 | 1,536 | 8,192 | 256 | 16 |

## Evidence, separated by revision

| Evidence | Result and actual scope |
| --- | --- |
| r1 first integration smoke | 12 complete pipelines passed |
| r1 complete differential | 468 complete pipelines passed: 177 accepted, 291 rejected; includes all 99 actual prepared queries |
| r1 original monolithic attempt | Exit 137 after 95 complete matching outcomes; no Python exception or final wait4 receipt. It remains incomplete and is retained |
| r1 interrupted case 95 isolated | Passed under the same 90 CPU second / 1 GiB test limits; wait4: 7.0378 s wall, 5.2671 s user + 1.7562 s system, 56,972 KiB max RSS |
| r1 grouped complete panel | All 468 original cases, original assertions and limits; eight fresh groups, each with wait4 and exact before/after source custody |
| r2 exact transition replay | 4,892 actual calls (3,767 control + 1,125 emit) from the entire r1 panel: complete return code and every workspace/output byte equal |
| r2 actual peer terminal frame coverage in that replay | 2,549 wire-success, 414 prefix-success, 108 prefix-error, 251 single-success and 97 single-error frames |
| r2 private protocol/GROW | 145 recorded controls passed, including exact-capacity same-site collection replay, cross-site overlap, malformed/replayed/cross-kernel frames and all fixed policy-2 error enum boundaries |
| r2 fresh integration smoke | 12 complete pipelines passed, with the old semantic owners disabled |
| r2 exact input/output boundary | A 1,048,576-byte canonical input produces the complete 1,049,845-byte display; no new display-size cap |

The 4,892-call replay is not labeled as 468 newly executed r2 pipelines. It re-executes each recorded exact transition with the real r2 image and compares every buffer byte. Its immutable input pages and complete buffer maps are independently reread after replay. Four complete source pipelines used to establish private protocol states are also present in the protocol run; they are not confused with 145 independent public cases.

The complete r1 panel made these real entries: control 3,767, emit 1,125, prefix 2,685, single 2,147, wire scan 7,129, wire emit 11,493, public decode controller 2,221, native JSON decoder 414 and arena-to-Graph 828. Its 176.4543 s is total elapsed time across the eight independently limited test processes, not a changed per-process quota and not a cold qualification measurement.

## r1 findings and exact r2 change

A direct r1 batch entry accepted an invalid Graph default root of zero far enough to request the actual bounded-input peer. That peer immediately returned BAD. The complete pipeline did not accept this invalid graph. The r2 entry now checks the Graph default root range before the first request, consistent with the GraphLease grammar.

A separate r1 private frame probe started from an actual prefix rejection. Replacing the prefix's numeric error in both correlated fields with 2^63 led first to GROW, then to an ordinary semantic error terminal carrying that unknown code. The full original diagnostic bytes remained unchanged. This was a forged private peer frame, not public input or an admitted Core. The complete two-call counterexample is retained.

R2 checks the exact policy-2 code/cause/detail set before diagnostic allocation. Invalid codes now return BAD and remain rejected by either kernel. These are the only production algorithm-function changes: `render_batch` and `bounded_reply`. An AST check removes only the two explicitly enumerated new guards and proves the entire old control AST identical. Collection, equality, ordering, all presentation functions and the emit source/image are unchanged.

The independently recorded same-site growth control reaches collection phase 20 three times at exact required capacities. It produces the identical full display and issues exactly eleven control services for two sites: one prefix, four snapshot wires and one single renderer per site. Replaying current-site partial inventory commits does not repeat an external peer or hide a later overlap.

Other real controls preserve bool versus integer distinction, arbitrary-width integer low-byte differences, unordered map equality, ordered list inequality, operation metadata outside displayed fields, v3 origins, function/callee conflicts, selected/downstream block conflicts in both orders, affected-name union/sort, branch-flag OR, and earlier conflict priority over a malformed later site.

## Large boundary

The actual large test uses 256 distinct callees and one large ASCII attribute. The canonical query is exactly the original 1 MiB maximum. Its complete resulting display is 1,269 bytes larger than that input limit.

- Input bytes: 1,048,576.
- Input SHA-256: `defdaf59ce8611190a2fb53824c6b6306c9aa17e03d9813552fdb5e6cc9d7a34`.
- Output bytes: 1,049,845.
- Output SHA-256: `5aa6c857e7a864f9dbfe759fe93c999fc051e999cc6ca82b4de65af5a7d463d8`.
- Actual entries: control 10, emit 261, prefix 6, single 264, wire scan 1,038, wire emit 1,560, public decode controller 5, JSON decoder 1 and arena-to-Graph 2: 3,147 total.
- wait4: exit 0; 46.2366 s wall; 37.5747 s user + 8.5305 s system; 146,232 KiB max RSS.
- Original test limits remain 90 CPU seconds and 1 GiB address space.
- Source/image pins were unchanged. The complete lossless evidence added approximately 172 MiB; full buffers were not truncated.

These timing numbers describe this development test only.

## Minimum mechanical integration

Read `docs/HIA_EDIT_RENDER_BATCH_ABI.md` for the complete word layout and lifetime contract. The HIA control image receives original GraphLease bytes, a 64-byte BEGIN and a zeroed workspace of at least 32,768 bytes.

The 256-byte event is `HIABRE01`. Actions are DONE=0, GROW=1, CALL=2, ERROR=3, REBIND=4 and NEXT_KERNEL=5. GROW preserves the exact second lease only when event word 22 is one; otherwise the next second buffer is empty. REBIND copies the exact native-selected normalized Graph view into an immutable first lease. NEXT_KERNEL selects the independently source-bound emit image without resetting workspace.

Peer 1 is the native Graph wire (scan then emit); peer 2 is the parent's frozen bounded-input r3, policy 2; peer 3 is the complete native single renderer. Each peer completes fully before its actual entire workspace is wrapped in the 64-byte `HIABRR01` correlation frame. Only native-selected views are copied. The executor must not inspect query fields, construct inventory plans, reinterpret source indexes or precompute error ordering.

The final display/error view belongs to the batch workspace. BAD=0xfffffffd permanently disposes the session, regardless of stale event bytes. Nonces and header equality are only private correlation; the fixed issuer retains the same immutable input/reply bytes over GROW.

The current reproducible test interface is:

```python
from edit_render_batch_harness_r1 import Actual
actual = Actual(output_directory, r2_bundle_path)
outcome = actual.render_graph(issued_graph_bytes, "case", digits=4300)
actual.close()
```

`Actual.check(value, ...)` additionally runs the old reference and mechanical foreign Graph capture solely for differential testing. It is not a production public-capture implementation.

## Complete artifact representation and history

All new native run buffers use lossless content addressing: each buffer's original byte length and SHA-256 identifies an ordered list of original 4 KiB pages, each itself identified by SHA-256. Every recorded source, request, configuration, before-workspace, after-workspace and decoder output can be reconstructed byte for byte. Canaries and both read-input bytes are checked on each actual call. The final artifact validation reconstructs every complete map and checks all ledger references.

Original authoring failures, the first fixture-construction mistake, monolithic exit 137, direct-interface r1 counterexamples and the successful revisions are separate artifacts. The fixture-construction issue was a shared mutable reference in the independent case list; it was fixed before the full native panel by copying each case, and the original five reference-expectation mismatches are preserved.

The already-durable single-renderer raw duplicates were retired only after rereading each file's complete SHA/size/mode against its sealed r8 manifest. Its original archive remains exact and reachable; all source/images/manifests/summaries/ledgers remain present. The retirement receipt is included for provenance. No active batch original or unfrozen owner was deleted.

