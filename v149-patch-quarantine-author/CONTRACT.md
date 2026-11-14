# Patch terminal custody candidate R1

Status: unapplied source authoring with static byte and AST checks only. No project module, generator, binder, compiler, Native image, VM, or test has run for this candidate. The actual R3 product remains `FAIL native-11`; its original assertions and complete evidence remain unchanged.

## Actual defect

R3 `test_real_error_pending_reentry_and_lost_claim_never_retry` observed two real Patch machine calls for the lost-claim case and zero old-policy calls. The real claim returned before the transport wrapper raised the original `LostPatchReturn`. The frame became uncertain and closed. Its exception traceback still retained it, so `__del__` had not run and `_UNCONFIRMED_RETIREMENTS` was empty at the assertion.

The original shared `ContinuationFrame.close(release=False)` clears pending/reply/error state but does not call `_retire`. The shared `_retire` starts with a retired return, followed by an uncertain branch that registers the frame and returns before any machine invocation. This candidate uses that existing primitive at the Patch component's own terminal boundaries.

## Exact source scope

The sole changed production file is `hepta/hia_patch_result_native.py`, based on the actual R3 source. It gains `NativePatchResult.finish` and one branch in the existing lazy generator's `finally` clause. No base class, MRO, constructor, import, shared engine, Inspect implementation, old test, or old fixture changes.

The seven `PatchResultFrame` proxies (`_invoke`, `step`, `service`, `drive`, `take`, `close`, `_retire`) retain their complete source text and their AST equality to the Inspect proxies. The original Source test explicitly enumerates these seven methods; it does not require `_function` to equal Inspect. All 23 files in the original retained-files fixture have been read in full and match their original length, SHA256, Git blob, and mode. Their final seven-field stat checks also match.

The root method delegates to the complete existing `super().finish(frame)` inside a `try`. Its `finally` acts only when the existing captured `_TYPE` identifies the exact `PatchResultFrame`, that frame's image is this owner, and `_uncertain is True`. Foreign/duck-typed frames receive no new attribute probe after the exact-type comparison fails. Frames from another image are not adopted.

The lazy generator already owns a locally created Patch frame. It preserves the original `value = None` in its `finally`, then calls `_retire` only if that frame is uncertain. This covers the actual `sorted(name for ...)` generator in `_check_patch_interface`, whose `drive` does not pass through the owner's root `finish`. It does not turn ordinary generator cancellation into eager retirement.

## Retirement and reentry

Both new paths call the original dynamic `frame._retire()`. The existing Patch override first checks the per-frame physical idle lease. The inherited shared implementation then returns immediately if `_retired`, or registers an uncertain frame and returns. On these new uncertain paths it does not send command 4, issue a claim or ACK, replay an effect, clear values, release buffers, or enter a foreign provider.

Physical `_invoke` already clears the lease in its original `finally` before the existing step/service exception cleanup is entered. Existing busy/pending/closed guards remain in their original locations. There is no image-wide lock; an unrelated frame can still enter the same owner. Repeated registration uses the same nonce key and retains the same frame. A failed actual retirement was already registered by the shared retirement catch; the new terminal call only reaches its registry-only branch again.

Normal successful `finish` completes original take/close/retirement before the new `finally`, and the new condition is false. A known foreign exception with `_uncertain=False` keeps the original traceback-owned lifetime and does not enter the global unknown registry. Partial construction remains inherited and never enters the new root/lazy terminal boundary.

## Exception and lifetime boundaries

Neither new branch catches, replaces, clears, or assigns the original exception, traceback, cause, or context. The original exception propagates with its original traceback frames; the new owner method adds one Python stack frame. Source locations after its insertion also change. Earlier strong retention of uncertain frames is the intended custody change. Arbitrary Python stack/refcount identity is not claimed.

The no-extra-Native conclusion depends on the exact retained class methods and internal boolean/nonce invariants. It is not a promise about arbitrary private-field/class monkeypatching or resource exhaustion. The existing registry assignment can allocate; universal exception-identity equivalence in a new allocation failure is not claimed.

An explicitly prepared frame whose caller never invokes owner `finish` remains under that caller's original completion/retirement responsibility. This is not a shared `close` repair for all Continuation/Front/Inspect frames. The independently admitted Inspect signature provider remains a separate owner with unchanged custody semantics.

## Compatibility and qualification

The old `hia_patch_result_data.py` is preserved as input evidence. It still pins the old Patch runtime and must reject this runtime if used unchanged. Only the original `tools/generate_hia_patch_result.py` may produce the new compatibility data after a separate reviewed generation authorization. No generated data or host SHA has been edited here, and no future output pin is invented.

The policy bodies, HIA input, ports, compiler, ABI, source lists, and all original limits remain unchanged by this author package. Their actual generated or built equality is a future observation. Original Source/Native/VM qualifications do not transfer to this candidate.

`proposed-tests/test_hia_patch_result_quarantine_native.py` adds three unexecuted real-Native controls: root command 0/2/1/4 lost returns, a lazy-child lost claim, and ordinary foreign-error/independent-success lifetime. They use the original actual admission and FrameJournal setup, preserve each full physical frame, and never call `_retire` to manufacture the expected registry result. They are separate future IDs; no old method or assertion is substituted.

## Rejected alternatives

Changing the Patch `close` proxy would violate the retained seven-method AST gate. Adding a private MRO layer was rejected and was never materialized. Changing shared `ContinuationFrame.close` would conflict with the frozen retained engine row and the independently pinned report-host authority. Those alternatives are static findings only. This candidate leaves their sources, authority values, tests, and fixtures intact.

## Next reviewable stages

After review, a new independent source view would receive this runtime and separately declared new controls. The original Patch generator must run twice and check its outputs under the original 180+3 owner limit, with protected sources and complete actual output identity guards. Only those real results can bind a successor Source/compile/Native plan. The original Source8, old Patch Source11, original Native12/CLI12, and any new boundary controls must be reported separately; no past PASS or old failure may be renamed.

No execution plan, source-tree copy, binder, or product launch is authorized by this package. All original 1 GiB storage floor, 20 s/10 CPU/1 MiB compile bounds, 180+3 owner bounds, and later 10M VM bounds remain applicable to any separately approved stage.
