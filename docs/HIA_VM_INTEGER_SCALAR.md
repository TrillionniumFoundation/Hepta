# Explicit HIA integer scalar profile

Status: **STATIC CANDIDATE — NOT QUALIFIED**. This layer depends on the exact three shared host sources and five registration sources in the separately frozen arithmetic package. It has no R24 tree identity. No AST, import, assembly, compiler, interpreter, native image, test, reader or GC was executed while authoring this layer.

## Entry and ownership

The sole new explicit entry is `hepta.hia_vm_integer_divrem_runtime.NativeIntegerScalarExecutor(manifest_path, expected_manifest_sha256)`. It requires its own manifest schema `hepta.hia.vm-integer-scalar-native.v1`, source `examples/hia_bootstrap/vm_integer_scalar.hepta` and image `vm-integer-scalar.image.bin`. There are still exactly the same three production host modules: protocol, native binding and runtime factory. No production Python module, worker helper, default selector or default interpreter entry is added.

The old `NativeDivRemExecutor` and `NativeIntegerArithmeticExecutor` complete classes remain byte-identical to the arithmetic baseline. Their old HIA sources and fixtures are not edited. Their distinct protocol classes retain their closed operation sets. All three profiles must be freshly built from the final composed source closure and run through their entire original gates; an older image manifest cannot authorize changed shared source bytes.

This profile owns fifteen integer computations across i8/u8/i16/u16/i32/u32/i64/u64/isize/usize. The first eight operations retain the div/rem and checked/wrapping add/sub/mul graph. Seven operations are added:

| Opcode | HIA computation and exact original boundary |
| --- | --- |
| int.shl.checked | Validate count before shifting, then keep the low declared-width bits. Data overflow wraps, exactly as the retained original body does. |
| int.shr.checked | Validate count, shift the canonical bits, then fill high bits only for a signed negative operand. |
| int.neg.checked | Signed minimum and unsigned nonzero values trap; representable negation is computed in HIA and masked. |
| bit.and / bit.or / bit.xor | Native bit operation on canonical operands, masked by their already admitted width. |
| bit.not | Width-bounded complement. |

Both shift operands have the original declared integer type. The count is not silently converted to usize. A signed negative count and a count at least the word width produce the original overflow message `shift count is outside the word width`. The count-zero path does not shift by 64. Negation overflow preserves `result is outside {typ}`. Existing div/rem still checks zero before signed minimum divided by minus one.

Comparisons, casts, select, bool, unit, const, buffer ownership, validation, control flow and all other interpreter branches remain hosted. This does not establish a complete native VM or a whole-stack HIA rewrite.

## Wire and live admission

The request remains 64 bytes and the reply 96 bytes, with zero workspace bytes. Codes 1–8 are unchanged; codes 9/10 are shifts, 11 is negation, 12/13/14 are and/or/xor, and 15 is not. Unary codes require the unused rhs word to be exactly zero. Invalid framing, type, canonical-width data, reserved fields or unary rhs return zero without writing output.

Status 0 is success. Original div/rem statuses 1/2 retain their original meanings. Checked add/sub/mul/negation permit status 3 for result overflow. Shifts permit status 4 for invalid count. Wrapping arithmetic and bit operations permit only status 0. Every nonzero status has a zero result word. Native return size, complete request identity, nonce, operation, width, sign, operands, checksum, completion and canaries are checked before terminal confirmation.

The binding's full `evaluate` body remains byte-identical to the arithmetic baseline. Each call freshly checks admitted sources/image and current delivery custody, captures the actual target and argument objects, enters native once, and confirms only after the complete reply and final guards. An actual missing/altered receipt remains a sticky loss with the real VM owner retained; the same binding cannot retry. Independent bindings remain independent. PID/thread/reentry/unselected worker-scope checks remain.

The selected runtime derives from the admitted complete current `hia_program_runtime.py`. Its fixed original baseline remains SHA256 `ce39be78627f253447f1d4e4b3272ba6689c594c31b22e3be204b1fcfea2ca56`; the exact v9 extension below has a separate source pin and full byte inverse. The scalar profile replaces six exact operation bodies: div/rem, six-op arithmetic, shifts, negation, binary bit operations and complement. Inverting these six bodies must reproduce the entire original operation AST. Original invoke/public bodies are mechanically retained apart from the existing explicit factory plumbing. Original step/resource/report rules and fresh machine construction remain.

## Independent input authority

The fixture `tests/fixtures/vm_integer_scalar_inputs_v1.json` contains only 7,918 additional typed inputs. It contains no expected results, trap decisions or generated oracle answers. It pins the complete unchanged div/rem 2,500 fixture and arithmetic 8,700 fixture. The combined order is the original 2,500 rows, then all original 8,700 arithmetic rows, then all 7,918 new scalar rows: **19,118 ordered inputs**.

New scalar inputs cover every declared integer type. Nine value boundaries per type are combined with all declared negative/zero/in-range/width/oversized shift counts. Every bit position is used by both shifts, both unary operations on one-hot and complemented one-hot inputs, and every binary bit operation on adjacent one-hot inputs. Binary bit operations also include all ordered pairs of the nine boundary values. Unary interpreter programs have exactly one parameter and one operand; the wire's zero rhs is not introduced as a second interpreter argument.

Each finite lane is a fresh process. Both complete original processes run before the native process and must agree on all semantic observations and raw tracebacks. The pre-candidate authority pins their complete reports and streams. Only then may the native lane start. The full independent finite reader compares every original result/trap/report/resource/step field, retains all raw traceback differences, and performs terminal byte rereads. Static fixture construction never computes expected answers.

The unchanged finite supervision values are 600 seconds per lane and 1,800 seconds for the complete finite child. The new finite reader permits files up to 64 MiB to retain the larger complete raw streams; the old readers' limits are unchanged. No execution budget is increased. Partial, missing, timed-out, reordered or differing evidence is HOLD.

## Complete new qualification source

`tests.test_hia_vm_integer_scalar_native` declares Source3 and Native8 in unittest method-name order.

Source3:

1. Complete HIA source/profile verification; old HIA identity; all three explicit derivations and exact six-body inverse; no host arithmetic in the selected replacement bodies.
2. All 19,118 exact transport inputs, operation-specific status acceptance, rejected status 5, scalar/unary input refusal and malformed extents.
3. Complete original-first 600 typed HIA VM witnesses. The old 320 witnesses are an unchanged ordered prefix; 280 cover the seven new operations. Every original observation is captured twice before any candidate HIA witness. Every witness uses a fresh original Machine with 4,000,000 steps, 16 MiB heap and depth 128.

Native8:

- Complete original-original-freeze-native 19,118 with independent full finite data readback.
- Entire unchanged generic21 under the original interpreter, followed by the same 21 IDs through the explicit scalar factory.
- Twenty-two malformed raw ABI controls, including both unary nonzero-rhs packets, and all 24 original actual-return/receipt/canary/error controls.
- One additional fresh-process actual missing-receipt control for each of the seven new operations: healthy original-first result, real HIA return, lost ACK, exact pending VM resource, no same-binding retry, and a healthy independent binding.
- All seven manifest/image/source-admission controls and all ten live original/derived/factory controls.
- Thread, fork, caught-reentry and unselected worker-scope controls; complete original-first 270 step/heap/allocation-failure/depth observations. The old 144 are unchanged in order before the new 126.
- A real installed wheel outside the checkout, with the original twelve installed cases preserved before thirteen new cases, for 25 total; fresh source drift refusal and no implicit worker-scope upgrade.

This list groups the eight method bodies by subject; exact eleven method IDs are listed in the package qualification plan. No original Source/Native method, input, observer or budget is replaced.

The independent reader covers all three finite lane receipts, logs, reports, streams, authority, manifest/image and source identity. It is not a substitute for independent suite-level supervision of the remaining Native8 control/installed commands. Root must preserve and review their actual owned receipts and the complete gate result as well.

## Required composition and regression

The layer adds nine exact source/resource paths after the complete arithmetic source inventory. Production `hepta/*.py` discovery is unchanged. The strict installed-resource test adds only the exact new source inventory and HIA data file; its original method IDs, other assertions and budgets remain. HELPERS remains 50. Existing CI steps remain byte-identical and in order. New scalar Source3, cold-bound build, Native8, finite reader and unconditional evidence uploads are appended as separate steps. CI has no development fallback.

Required before qualification:

- Verify all exact source/splice inverses and execute the existing original Core/source contracts.
- Assemble/compile the new HIA from the final frozen tree; do not raise profile limits.
- Rebuild all three profile manifests/images against the same shared host bytes.
- Run original div/rem Source3/Native8 and 2,500, arithmetic Source3/Native8 and 11,200, scalar Source3/Native8 and 19,118, with their complete original generic21, boundaries, installation and custody controls.
- Retain every full raw observation and traceback, all natural-exit/timeout/cleanup evidence, and final source rereads. A build, a small witness set or an earlier-tree PASS transfers no qualification.

The package does not alter Slot7,822, Bootstrap15,830, public/handled suites, original GC/TB fields, old static provenance fixtures or any default public entry. No original fixture removal is authorized.

## Remaining semantic boundary

This remains an explicit hosted factory around HIA integer computation. Python verification, byte/bit representation conversion, source I/O, delivery machinery, frames and allocation remain present. Raw traceback identity, arbitrary reflective history, concurrent private-class mutation, tracing, asynchronous allocation failure and whole GC/lifetime equivalence remain unproved. The finite success label is only `PASS_VALUE_TRAP_REPORT_DOMAIN_ONLY`; raw traceback differences remain visible as OPEN, never normalized. The new protocol class has the same pre-existing scope of class-attribute reflection checks as the two old classes; no expanded proof of arbitrary live private namespace tampering is asserted.

## Reviewed v9 runtime composition

The v9 runtime from commit `d99855451c8140899c85cf264b330a81a1c00362` has SHA256 `db118314608168799a0d2c1210cec04ba38981a329e8da6cf4debcd07b267aa0`. Admission removes exactly its single word-memory branch and the two added byte-order imports, then requires the complete resulting bytes to match the retained `ce39` original. The original fixture and its SHA256 remain unchanged. An unrelated edit, extra newline, altered word bound or changed byte-order mapping is rejected.

This inverse is an admission proof. Execution derives from the complete actual current v9 source, preserving the four unselected word operations and every original loop, tick, resource and report statement; the selected integer-body inverses are still checked over that whole actual operation AST. The live byte-order dictionaries are checked at construction and at the existing per-invoke/per-operation guard. The native integer operation set, selector, wire extents, original case inventories and execution budgets do not change. All three component manifests and their complete original qualifications must be rebuilt against the final composed cold source; earlier results do not qualify this source change.
