# R5 witness10: two required verifier observations conflict with one expected refusal

Status: source-level review only, after environment reset. No project module was imported, no product or test was run, and no original test, source tree or budget was changed. The original R5 gate remains **FAIL**.

## Conclusion

There is no wrapper/adapter-only repair that preserves all of the requested original semantics and the existing witness10 assertions. In its second section, `test_entry_error_busy_unknown_no_retry` directly constructs and finishes an actual Inspect component frame. It does not call the CLI op10 adapter. The original inspection policy performs two verifier observations inside the same temporary provider replacement: the initial `verify_program(document)`, then the `VerifiedProgram.normalization_report` property's global `verify_program(self)`.

For this unchanged primitive fixture, when both effects complete normally, the callback runs twice. Each callback appends a refusal marker **after** checking that `frame.drive()` raises `RuntimeError`, that no machine entry is added, and that the frame remains executed but uncompleted. Preserving both callbacks and their successful local assertions necessarily produces two markers. The later assertion requires exactly one. That is a test-contract conflict, not evidence that the second real revalidation should be removed.

This is a conditional conclusion for the specified successful fixture and current providers. It is not a claim that every inspection input always causes exactly two callbacks. The first section intentionally raises from its first verifier call and correctly expects one call. Composite inputs or replaced providers can have other behavior. Those possibilities do not reconcile the fixed second section's successful result with its singleton expectation.

## Exact recovered authorities

The review recovered all eight parts of the complete R5 author archive referenced by recipe `8d24df97c067381c8bca3937184bc5793a1fadb9`, checked compressed and decoded payload identities, and checked all 33 member payloads. Its projected source map is the exact 779234-byte `f400270fe733603befffde0006fb11f306cde2ea` target map bound by the R5 plan. Twelve selected source files were recovered and compared in full against that map.

The full original witness file is `98582224513d486f706459183e3b5cd7a089bf0c` (29331 bytes); its support is `b65cdbd5be3890e7d4bb424504a2a7ff4e70a371` (12740 bytes). Both match the R5 plan's control pins. The complete `hia_program_tools.py` after-image was recovered from the initial Inspect source capsule `8e91c8be30734df36217b5d37f7f226b5abbb154`: 24542 bytes, `2d6f00150fa3545a8abfb5cceeace42f3cae55c4`. Its first 23798 bytes are exactly the stable R20 source; the remaining 744 bytes add definition anchors. The two original functions and HIA policy author inputs are equal in complete function text and AST.

The actual R3 drive source was recovered from capsule `651102e1d05f5854271d7f2f0a4404ca159dd057`: 16685 bytes, `714247cd3d821339575983a70a804c9a69471b1e`. This matches the R5 map. `hia_program.py`, the continuation and front runtime, the fixture helpers, the generated ports and the CLI adapter were also matched to that map. No source was reconstructed by guessing the appended bytes or by inventing old stat fields.

`SOURCE-REVIEW.json` contains full pins, complete relevant function excerpts, the exact original limits and witness group, and the source-only checker result. It distinguishes author target identities from actual historical execution observations.

## Causal sequence

1. Witness10 line450 calls `c.owner.prepare('inspect_program', (c.fixture(),))`. `ActualComponents` requires a real admitted `NativeInspectProgram`; the constructor binds slots and allocates its buffers without executing policy instructions.
2. The test captures the current real verifier, defines `reenter`, and installs it in `c.program.verify_program` for the whole synchronous `c.owner.finish(frame)` call (lines451–461). The unchanged context manager restores the provider only after that call exits.
3. The retained policy imports the current verifier and calls it on the document (`hia_program_tools.py` lines285–288). This calls `reenter` once. Its three assertions pass before its marker is appended; it delegates to the captured real verifier.
4. The fixture is primitive schema v1 with a simple constant-returning function. The original verifier returns a `VerifiedProgram` with `structured_bytes=None`. Later in the ordered result construction, `getattr(verified, 'normalization_report', None)` observes the actual property (line294).
5. That getter begins with `checked = verify_program(self)` (`hia_program.py` lines411–426). This is a fresh module-global lookup, not a call to a saved private verifier. The installed global is still `reenter`, so its three assertions and append run again. Its argument is now the `VerifiedProgram`, not the original dictionary; the original verifier fully rechecks those immutable bytes.
6. Each callback is inside a claimed foreign effect. `ContinuationFrame.service` sets `executed=True` before calling the provider and sets `completed=True` only after it returns. A nested `drive()` therefore skips the R3 pending-service branch, then the original `step()` rejects the missing acknowledgement before entering its mutation/cleanup `try`. It adds no machine entry and leaves the three tested state conditions intact.
7. The outer call returns normally. The test's `error is None` assertion passes. Its next line compares the two-marker list to a singleton and fails.

The refusal guard does not append the markers; the test callback does. Making the guard idempotent, returning the same exception object, or declining to enter HIA a second time cannot coalesce those external appends.

## Why apparent implementation fixes are not compliant

| Candidate | Conflict with the fixed contract |
| --- | --- |
| Change only the CLI op10/report session wrapper | The failed section directly calls the Inspect owner and bypasses the wrapper. A change would have to alter shared component/provider state outside the declared adapter route. |
| Close, complete or clear the frame after the first refused reentry | Breaks the original executed/uncompleted state assertions, subsequent continuation, or the required successful outer return. |
| Use the captured old verifier/private verifier for normalization | Some validation might still occur, but the current public provider call, its side effects and exceptions are removed. That is not preservation of the real original reverify. |
| Proxy the verified result, cache normalization, skip the property | Changes the returned object/descriptor observations, revalidation or late-provider semantics. |
| Move a verifier call into `prepare`, or defer it until after the replacement scope | Changes original effect and exception timing; the original constructor does not run policy and `finish` is synchronous. |
| Swallow a second callback assertion or exception | Violates original exception propagation. It also cannot undo an append already performed by the observer. |
| Filter/deduplicate the list, change the fixture, or redefine assertion behavior | Changes the test's observation rather than repairing the implementation. |

The call count is not a duplicate-execution bug in the wrapper. The second call has a different input and a distinct validation purpose. Caching or coalescing it would also invalidate the requested fresh provider observations.

## Proposed contract decision — not applied

Keep the original R5 test body, frozen inputs and failure as immutable historical evidence. Under its current contract, do not claim that R5 passed. No implementation patch is proposed as a way to make that exact old gate green.

If the contract owner explicitly authorizes a **separate versioned baseline**, the minimal correction is to count refusal observations per real verifier invocation. This fixed primitive fixture requires two markers. `PROPOSED-CONTRACT-SUCCESSOR.diff` shows only that hypothetical count change. It is a proposal against a new versioned copy, not an edit to the recovered file, not an applied source patch, and not execution authorization.

All three original state assertions stay inside `reenter` and therefore run on both invocations. The initial verification and the real normalization revalidation, their provider lookups, argument identities, effect/exception order, and no-machine-entry behavior remain unchanged. The new baseline must separately demonstrate these facts with actual complete observations. It must also reach the later lost-claim/unknown-frame assertions, which the old failed method never reached. Existing tests/IDs/qualification results are not silently relabeled or transferred.

A different decision to coalesce observable verifier calls would define new product semantics and require its own provider/alias/descriptor/exception contract and qualification. It is prohibited by the current instructions and is not recommended as a means of satisfying this test.

## Evidence boundary after reset

The earlier Root/peer terminal observation reported session63905 exit1, 69.814360769 seconds, first13 groups passing, and the sole witness10 failure at the singleton assertion with errors0/failures1. The prior diagnosis associated `OBSERVATION-0002` with 522 machine calls (indices19 through540), 3132 frame references and 10298016 raw bytes. Those are historical observations, not a new full frame readback in this review.

The old large R5 execution frames and original diagnosis payloads were not completely remotely sealed before reset. Their known diagnosis IDs remain hash-only; this report does not fabricate frames, old stat identities, or replacement execution evidence. The current conclusion is independently supported by exact recovered source. New local reader mistakes (a capsule member-schema assumption and an out-of-range text display) are recorded in the JSON; neither imported or ran project code.

All original budgets remain unchanged: 180+3-second owner, 20-second compiler, 1MiB image, 10M VM steps and the frozen storage threshold. This review uses none of those product gates.
