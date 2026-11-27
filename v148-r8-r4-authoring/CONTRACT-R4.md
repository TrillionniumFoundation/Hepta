# R8 R4: run the existing native-frame validator for zero-call phases

This is an isolated author-only successor to the actual R3 qualification failure. No binder, preparation stage, oracle restoration, project import, test, compiler, VM, executable, CI run or ref mutation is performed by this author package.

## Exact repair

The original R3 wrapper skipped `validate_native_frames` when a phase expected zero standalone Native calls, then compared the resulting `None` to zero. R3 therefore stopped after the genuine `EXPECTED_PUBLIC_R5_REFUSAL`. That original observation reached neither the provider nor the VM. Its owner, supervisor and outer process returned 1; all seven later groups were not started.

R4 changes the native-frame action to invoke the **unchanged original** `S.validate_native_frames(out, name)` in every phase. The original `value == phase['standalone_native_calls']` assertion stays byte-for-byte unchanged. There is no synthetic zero, deleted comparison or accepted missing readback.

The original validator scans `request.json` paths whose parent is named `native` and whose parsed schema is `hia.linux-stdio.native-request.v1`. With no selected requests, it writes a real zero-row `SIX-BUFFER-READBACK.json` and returns integer zero. A selected request in a stage other than `native162` or `semantic-edge-vm` reaches the original unexpected-stage rejection. Its existing filters still skip other parent names and schemas; this package does not describe those other protocols as verified by this scanner.

## Isolated paths and complete projections

The author root is `/tmp/hia-u32-r8-post-reset-r4-dda7`. The future product root is `/dev/shm/hia-u32-r8-controls-r4-dda7`, and its future outer root is `/tmp/hia-r8-original-controls-r4-outer-dda7`. Both future roots are absent at author completion.

There are 64 original executable-authority files: 58 remain byte-for-byte identical. Six change: the wrapper, the three support modules' single output-root constants, the fixture report's single ELF pathname, and the execution plan's derived bindings. All seven original phase scripts are entirely byte-identical. Every function body in the three support modules is entirely byte-identical. `r8_common.py`, `r8_private_reference.py` and `restore_oracles.py` are entirely byte-identical.

The fixture path update is necessary: the original kernel caller consumes `build.executable`. It must refer to the independent R4 input copy rather than the retained R3 copy. No image, component pin, original input, controller or assertion changes. Complete inverse projections for all changed original bytes are provided in `EXACT-INVERSE.json`, the original before files and readable diffs. The new `PRODUCT-LAUNCH.json` changes only the author/output paths, derived plan authority and the actual new runner/plan identities and inode metadata.

## Completed data stages are explicitly reused

`ORACLE-RESTORE-PLAN.json` is copied **entirely unchanged** from R3. It still binds the real completed owner at `/dev/shm/hia-u32-r8-oracles-r3-dda7.owner` and destination `/dev/shm/hia-u32-r8-oracles-r3-dda7`. Its original 496 required-file mapping and 136 restoration order remain exact. It is not rebound to a nonexistent R4 owner, and the successful data stage is not automatically replayed.

All 948 execution input roles, identities, paths, phase memberships and order remain unchanged, representing the same 944 distinct payload paths. The 808 existing input-view files and 136 restored oracles require a **new complete fresh-byte admission** before any R4 product execution. The complete 3180-file source, runtime executable/library, existing preparation/result/owner/final records and all R4 controls also require fresh admission. Historical Root readbacks are retained evidence, not substitutes for this new check. The original `guards('_prepare')` reads its 13 assigned input roles; it is not misrepresented as a full 944-path reuse scan. Original per-phase full-byte guards and the entire `prepare_context` function remain unchanged.

The old `POST-RESET-PROVENANCE.json` and other copied author records keep their original historical status, including statements that the oracle owner was pending when R3 was authored. Current completed stage records and the explicit R4 reuse requirements establish the later state without rewriting those historical files.

## Original execution contract

There are still eight stages in their original order: public R5 refusal, Native162, semantic edge VM, remaining semantic VM, kernel130, observer build, pipeline7 and tail2. The seven retained child bodies and all assertions are unchanged. Each owner remains 180 seconds plus 3 seconds cleanup. Each native compile/call remains 20 seconds, 10 CPU seconds and its original 1 MiB spans. VM fuel remains 10,000,000; original standalone and pipeline heap limits remain 1 MiB and 16 MiB. The 8 MiB + 1 file extent, native canaries, complete six-buffer observation, fail-stop behavior and no-retry rule remain unchanged. The product free-space floor remains exactly 3 GiB.

R4 has no preparation or restoration command. Only the reviewable future product launch is supplied. Its author-only launch record is not execution authorization. Root must complete the new reuse readback and explicitly schedule a single attempt in the unique product slot.

## Qualification boundaries and retained failures

The public R5 entry and its pins remain unchanged and must reject R8. Private R8 execution retains the original controller, component, loan, order and exception checks with the existing explicit private source-pin projection. The retained private execution report still carries the original public profile field because that body is unchanged; this field does not confer public-profile qualification on R8.

R3's complete failure remains preserved by recipe `234c072875fa88e49ef7db376675f733f4de7a5d`, including all 38 actual raw files and Root's separately preserved reader and launcher mistakes. The 808-stage recipe is `1d6b2979f1d3b1aea44886d3629986b48fbcd713`; the original 136-owner recipe is `2ca46d0cd9aac2fe6d444f4491aac9d7ace2b157`. No R3 qualification result is changed to PASS. Original R5 semantic six-case history, including its fuel failure, remains unchanged.

This package establishes no ordinary-compiler admission, matching current-cold qualification, installed/portable qualification, default R5 acceptance, whole Native qualification or whole-language qualification. Restored Python 3.14.4 is still a separately verified stdlib runtime; this package does not claim to restore the old venv or missing site-packages.
