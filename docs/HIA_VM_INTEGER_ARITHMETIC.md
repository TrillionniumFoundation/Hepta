# Explicit HIA integer arithmetic slice

Status: **STATIC CANDIDATE — NOT QUALIFIED**. This source was authored without running Python AST, imports, assembly, compilation, a VM, a native image, tests, or GC. A successful component build is not a qualification result.

## Entry and scope

The new explicit entry is `hepta.hia_vm_integer_divrem_runtime.NativeIntegerArithmeticExecutor(manifest_path, expected_manifest_sha256)`. It uses a separately bound `vm-integer-arithmetic.image.bin` built from `examples/hia_bootstrap/vm_integer_arithmetic.hepta`. Its manifest schema is `hepta.hia.vm-integer-arithmetic-native.v1`. The existing `NativeDivRemExecutor`, old div/rem HIA source, default `execute_program`, `_Machine`, opcode registry, Prepared and Arithmetic modules are retained. No worker helper or environment selector is registered; HELPERS stays at 50 on the R23 baseline.

The HIA image owns eight complete integer operations on i8/u8/i16/u16/i32/u32/i64/u64/isize/usize: original div.checked/rem.checked plus add.checked/add.wrap/sub.checked/sub.wrap/mul.checked/mul.wrap. Host code performs representation conversion, exact source/image admission, invocation and receipt validation. It does not calculate an expected or fallback arithmetic answer.

| HIA operation | Computation and failure |
| --- | --- |
| add.wrap / sub.wrap | Native u64 arithmetic, masked to the declared width |
| add.checked | Unsigned carry from the masked result; signed equal input signs and changed result sign |
| sub.checked | Unsigned borrow; signed differing input signs and changed result sign |
| mul.wrap | Low width bits of the native product |
| mul.checked | Signed or unsigned magnitudes, a sign-dependent representable limit, and a guarded nonzero-divisor limit comparison |
| div.checked / rem.checked | Original zero-before-signed-minimum/-1 decision order and truncation/remainder behavior |

For multiplication, a negative signed result may have magnitude 2^(width-1); a nonnegative result may have at most 2^(width-1)-1. The zero-magnitude divisor branch never executes the limit division. Width 64 has an explicit all-bits mask, so mask construction never shifts by 64. Every operand is checked for canonical width before computation. Invalid requests return zero without writing output.

The wire is unchanged in extent: 64 request bytes, 96 reply bytes, and zero workspace bytes. Operation codes 1/2 retain statuses 0/1/2. New checked operations 3/5/7 permit status 3 for range overflow; wraps 4/6/8 permit only status 0. Request identity, nonce, operation, width, sign, both operands, version, checksum and completion all bind the receipt before terminal confirmation. Trap receipts contain a zero result word. The runtime converts status 3 to the original `HIAProgramTrap("overflow", f"result is outside {typ}")`.

## Mechanical interpreter integration

The explicit factory derives operation, invoke and the public-shaped executor from the admitted complete current runtime. Its retained baseline is SHA256 ce39be78627f253447f1d4e4b3272ba6689c594c31b22e3be204b1fcfea2ca56; the exact v9 extension below has a separate source pin and full byte inverse. In the arithmetic profile it replaces exactly two operation bodies: the existing div/rem body and the single six-operation add/sub/mul body. Inverting both bodies must reconstruct the complete original operation AST. The old per-invoke and per-operation live function/code/globals/defaults/closure/builtin checks remain. The original tick placement, result validation, resource transitions, allocation limits, call-depth rules, trap reports and unrelated opcode branches remain the source of truth.

A fresh machine is still constructed for each explicit invocation. Each arithmetic effect uses the existing NativeCall record and a fresh request nonce. Buffers, exact call target and arguments are captured before enter_native. Complete response and canary validation, fresh source checks and final current-custody checks precede confirmed(terminal=True). Missing/stale/altered/partial responses preserve sticky actual pending custody and prohibit retry of the same binding. Independent bindings do not share that loss. PID, thread, reentry and unselected worker-scope rejection remain explicit.

This is not a complete native VM. It still uses the hosted verifier/interpreter, Python frames, allocation and source-admission I/O. Arbitrary reflection, tracing, asynchronous allocation failure and complete GC/traceback identity have not been proved equivalent. The finite reader preserves all raw tracebacks, reports their differences separately and never normalizes them into a whole-domain PASS.

## Independent input authority

The old 2,500-case div/rem fixture is byte-preserved at its original path and SHA256 325dbc6db74918277d4b1eb842e43de2cf83fcc5307d797e3e0d77f2f467086a. The new fixture contains only 8,700 add/sub/mul inputs and its exact reference to that old file. Each signed type has 13 declared boundary values; each unsigned type has 11. These include endpoints, nearby small values, the highest bit and both sides of the square-root overflow boundary. Every ordered pair is included for each of the six new operations. Values are decimal strings. The fixture contains no expected results.

The combined 11,200 IDs preserve the entire old 2,500 ordered prefix, then the new 8,700. The finite qualifier runs two complete fresh original processes under the original interpreter first. Both complete semantic streams and raw traceback streams must agree and be pinned to the child reports. EXPECTATIONS-FROZEN is written before the candidate process starts. The candidate is a third fresh process using the actual image. Its full value/trap/report stream is compared against the original; its complete raw tracebacks remain separately visible.

Each lane retains a 600-second supervision limit, while the whole finite child retains 1,800 seconds. These are new component gates with fixed limits, not changes to the old div/rem or other repository gates. Success is only PASS_VALUE_TRAP_REPORT_DOMAIN_ONLY when the complete ordered domain, steps/reports/resources and exact original observations match. A missing, partial, timed-out or differing lane is HOLD. No count, raw traceback, GC result or expected value is normalized.

## Complete qualification sources

The new module `tests.test_hia_vm_integer_arithmetic_native` has three Source methods and eight Native methods in actual unittest name order.

Source3 covers the complete source/graph profile and exact two-body inverse; all 11,200 transport inputs and per-operation allowed status sets; and 320 original-first typed HIA VM witnesses (eight operations, ten types, four input pairs). Each HIA witness uses a fresh original Machine with 4,000,000 steps, 16 MiB heap and depth 128, verifies the input buffer and zero allocation attempts.

Native8 covers:
- complete original-original-freeze-native 11,200 and independent full data readback;
- unchanged original generic21, followed by the same 21 methods through the explicit arithmetic executor;
- 20 malformed raw ABI controls and all 24 real-return/canary/receipt/error controls;
- all seven manifest/image/source-admission controls and ten live-original/derived/factory controls;
- PID/thread/fork/reentry/unselected-scope controls;
- 144 complete original-first step, allocation-failure, stopped-resource and depth observations across all eight operations;
- an actual wheel install outside the checkout with 12 original-first installed observations, source-drift rejection and refusal to silently join an unregistered worker scope.

The old div/rem Source3, Native8, original 2,500 finite, generic21, original prepared/arithmetic tests and all retained repository gates remain required. The new gate does not replace Slot7822, Bootstrap15830 or any existing public/handled/GC/TB domain.

## Construction and evidence

`tools/build_hia_vm_integer_arithmetic.py` requires exactly one explicit development choice or a complete matching-source cold report. CI uses only the matching-source cold path, with no development fallback. Builder INPUTS include the exact three host modules, all transitive component sources, the complete new qualification sources and both old/new input fixtures. Compilation receipts and full output are checked before a manifest is written; compiler, source and cold bytes are reread.

The independent data reader `tools/read_hia_vm_integer_arithmetic.py` consumes all three complete child receipts, logs, reports, planned IDs, semantic streams and raw tracebacks, plus the pre-candidate authority, manifest and image. Hashing and parsing use the same captured bytes, followed by exact terminal rereads. The entire CI evidence directory is uploaded even on failure.

No result from the original div/rem component or an earlier tree transfers to this new source closure. The source suffix remains .hepta; the host bridge remains Python. Existing 50 worker helper registrations and default-entry behavior are unchanged.

## Reviewed v9 runtime composition

The v9 runtime from commit `d99855451c8140899c85cf264b330a81a1c00362` has SHA256 `db118314608168799a0d2c1210cec04ba38981a329e8da6cf4debcd07b267aa0`. Admission removes exactly its single word-memory branch and the two added byte-order imports, then requires the complete resulting bytes to match the retained `ce39` original. The original fixture and its SHA256 remain unchanged. An unrelated edit, extra newline, altered word bound or changed byte-order mapping is rejected.

This inverse is an admission proof. Execution derives from the complete actual current v9 source, preserving the four unselected word operations and every original loop, tick, resource and report statement; the selected integer-body inverses are still checked over that whole actual operation AST. The live byte-order dictionaries are checked at construction and at the existing per-invoke/per-operation guard. The native integer operation set, selector, wire extents, original case inventories and execution budgets do not change. All three component manifests and their complete original qualifications must be rebuilt against the final composed cold source; earlier results do not qualify this source change.
