# Explicit HIA div/rem VM slice

This is an opt-in mathematical component, not a replacement interpreter. The ordinary `hepta.hia_program_runtime.execute_program`, `_Machine`, Prepared and Arithmetic files remain byte-for-byte unchanged. No CLI, route, worker helper registration or default selection changes.

## Public entry and actual execution

`NativeDivRemExecutor(manifest_path, expected_manifest_sha256)` is a new callable with the original public keyword defaults. It admits the actual current component files and compiler-produced image before mapping. Every selected div/rem call uses a fresh process-counter nonce and private request/reply buffers. Source, manifest and image bytes are reread before and after the call. A real DeliveryRecord is armed immediately before the captured image entry; complete receipt fields, input echoes, extents, canaries and result construction are checked before terminal confirmation. A lost call retains the actual VM and buffers, rejects retry on the same binding, and does not poison an independent binding that shares immutable image bytes.

The selected operation code is mechanically derived from the complete retained runtime. Only the div/rem body changes. The original invoke body keeps its ticks, depth check, loops, edges and resource semantics, with exact live-code guards at entry and immediately before its original operation lookup. Public execution retains its entire body except the machine constructor name. All other instructions remain hosted. No Python division/remainder computes the selected result; Python converts declared integer representations and raises the original trap class after the complete HIA receipt is confirmed.

The HIA source implements both operators for i8/u8/i16/u16/i32/u32/i64/u64/isize/usize. Divisor zero precedes the signed-minimum/-1 check, including rem. Signed quotient truncates toward zero; remainder has the dividend's sign. The 64-bit mask has a separate branch. The unsigned division and product operate on proven bounded magnitudes.

## ABI and profile

Request 64 bytes, reply 96 bytes, logical workspace 0. The Python caller adds its fixed 17-byte canary outside each declared extent; the ABI never includes canary storage. The separate raw-framing controls use their own fixed 16-byte canary. f0 has 13 blocks with at most 12 parameters, f3 has 9 formal parameters. The current compiler's parameter ceiling is 16, functions 128, blocks 1536 total / 256 per function, SSA slots 2048, instructions 8192, and source/output/workspace ceiling 1 MiB. Existing exact name discovery handles b20/b99; no graph/label rewrite or limit increase is proposed. Actual compilation may still refuse and must be retained as such.

## Qualification boundaries

New Source3 contains complete Core verification, all 2500 transport encodings, six actual HIA VM witnesses and code-derivation inverse checks. New Native8 contains original-original-freeze-native full 2500 observations; the complete old generic21 first ordinarily and then through the explicit factory; 24 actual-return receipt-loss controls; 20 actual malformed-ABI refusals; 7 admission controls; 10 code/authority controls; 4 process/thread/scope/reentry controls; 24 original-first tick/trap/resource boundaries; and a real wheel install/probe.

Every finite expected row is produced by the complete retained interpreter. Two independent original child processes must finish and their entire observations and raw traceback streams must match before the candidate child starts. The independent reader consumes all rows, both original streams, the selected stream, owned-process receipts and logs; it rechecks the same consumed bytes at the end. A separately supplied producer-report digest binds the reader. Raw traceback differences remain visible and OPEN. Success is named PASS_VALUE_TRAP_REPORT_DOMAIN_ONLY, never whole-VM equivalence.

The original generic21, Prepared3 and Arithmetic7 methods, input fixtures and budgets are untouched and must run independently. Their old PASS does not qualify this new factory. The full old 7822/15830 domains and their original 1800-second gates remain necessary in their own scopes. New finite lanes have an explicit 600-second bound each; the new finite qualifier is bounded by a separate 1800-second parent. These new values do not change an old gate. Existing compile_stage retains its original 20-second compiler child budget.

## Installation and registration

Three new hepta/*.py modules are automatically in the full source/installed Python inventory. Ten non-production support paths are appended to SOURCE_FILES and MANIFEST. setup copies the one independently selected HIA resource into hepta/_data; the existing exact installed resource inventory is extended only by those concrete paths. Agent NATIVE_SOURCE_FILES, the 50 HELPERS and native bundle schemas remain unchanged. The standalone component refuses execution inside an unselected or unrelated worker scope; there is no implicit worker-bundle upgrade. The original selfhost-contract test file remains unchanged because its automatic-Python exclusion and release equality already cover the correct ten-path append.

## Open hosted boundaries

First-use AST parsing, code compilation, FunctionType/type creation and extra Python frames are deliberate hosted operations of this experimental factory. Weak machine bookkeeping and delivery records can change allocation/GC topology. Float and complex code constants are compared through their IEEE byte representations, including signed zero. Live globals are an actual snapshot identity control domain: this does not prove source semantics for arbitrary imported-function globals replaced before admission. Raw traceback, arbitrary private reflection/global mutation histories, tracing, host MemoryError at all allocation points, and complete cross-version frame equivalence are not claimed. No traceback is cleared, no GC is forced and no allocation count is compensated. The existing interpreter still owns verification, its main loop, the remaining opcodes, resources, budgets, reports and ordinary public entry. Nothing here authorizes deleting it.

This package was prepared by text/byte work only. No AST, product, test, compiler, VM, Native, SQL or GC execution was performed by its author.
