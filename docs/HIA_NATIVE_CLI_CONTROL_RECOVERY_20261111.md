# Ordinary CLI control owner — recovery revision 4

This is an explicit native control and presentation owner, not a complete native
CLI release. Its ordinary entry is the existing `hia_main` through
`HEPTA_HIA_CLI_MANIFEST`. With that selector, the retained CLI function and
`argparse.ArgumentParser` are not used. With no selector, the original entry
remains available. A selected but missing, malformed or source-mismatched bundle
fails closed; it does not retry through the retained parser.

The frozen local development candidate is
`fd4d6724ecb630b4727731db13fdfedbc05ee1f2`, from exact base
`e09c6faf5507fc4e38d8b7c36ba2650a1c0a10d6`.
The old executor's earlier r1/r2/r3 source and 30-case observations remain
historical and were not reused as passes for this revision.

## What HIA owns

Two separately compiled HIA images share one source-bound bundle. The control
image parses argv and owns the 15-action continuation, argument abbreviation,
clusters, repeated options, option/value boundaries, sentinel handling,
required/choice/excess diagnostics, publication branches, imported-module order,
input-limit selection, result mutations, output-before-exit decisions and
one-use effect acknowledgements. The formatter owns complete help/version/error
and E_DRIVER JSON text, line wrapping, repr/Unicode escaping, terminal color and
column decisions. The bridge observes Python objects and carries out requested
effects; it does not select the next action or re-enter the retained CLI parser.

An effect permission is consumed before calling foreign code. A malformed ACK,
protocol rejection or a BaseException at the native/foreign boundary closes the
session. The tested original exception object, active exception context, output
order and file results are preserved.

## All 15 ordinary actions

Every row uses the native argv, formatting, phase and exit owners above.
Successful JSON pretty-printing remains the existing Python `output_json`
effect. This table names the remaining action semantics explicitly.

| Action | HIA stage decisions | Remaining Python semantic/effect owners |
|---|---|---|
| capabilities | Choose capability operation, then output and success exit | `agent_capabilities`, returned object and successful pretty JSON |
| catalog | Admit schema choice, request catalog, then output | `opcode_catalog`, catalog object and successful pretty JSON |
| import-assembly | Read limit, assembly admission order, optional publication branch, receipt/output order | `read_bounded`, `assemble_program`, VerifiedProgram object, `publish_program`, object report and JSON |
| render-assembly | Verify before render, text or file branch, ordered publication/output | `verify_program`, `render_assembly`, verified artifact publication and filesystem effects |
| check-assembly | Read then diagnose; output before reading accepted truth and choosing exit | `diagnose_assembly`, report object, raw Python truth observation and JSON |
| verify | Bounded read, verify, report, output, exit | `verify_program`, VerifiedProgram.report and JSON |
| inspect | Bounded read, verify, inspect, output | `verify_program`, `inspect_program`, returned object and JSON |
| normalize | Verify and obtain normalized object, optional publication, output | VerifiedProgram.as_dict, `publish_program`, artifact IO and JSON |
| build | Admit target/backend/kind/output options, verify, build, output-before-ok and exit | `build_program_machine` and its remaining compiler/backend owners, object publication and JSON |
| patch | Input/request limits, decode/apply order, optional publication and receipt fields | `decode_json`, `apply_program_patch`, program objects, `publish_program`, JSON |
| impact | Read/decode/analyze sequence and receipt/output composition | `decode_json`, `analyze_patch_impact`, returned program/receipt/impact objects and JSON |
| edit-query | Function/block/value/field selection, split positions, query/publication flow | Raw Python string slices, `prepare_edit`, `publish_json_view`, filesystem and JSON |
| edit-apply | Preserve single-query decode and response-read error order, select 16 KiB response bound, apply/publish/output | `decode_json`, `apply_edit`, program objects, `publish_program`, filesystem and JSON |
| edit-batch-query | Select read/decode order and query/publication branch | `decode_json`, `prepare_batch`, `publish_json_view`, filesystem and JSON |
| edit-batch-apply | Preserve batch query/response read order, 1 MiB query and 64 KiB response bounds, apply/publish/output | `decode_json`, `apply_batch`, program objects, `publish_program`, filesystem and JSON |

The Python bridge still owns object handles, Namespace construction, mechanical
dict/list operations, actual module imports, file/console calls, resource
allocation, exception capture and immutable machine-image mappings. The HIA
controller chooses when to request those observations/effects. The assembly
publication helper retains its original filesystem and verification policy.
The successful pretty JSON effect and the business functions in the last column
are not claimed to have been ported by this change. Independently selected
owners inside those functions retain their own source and qualification scope.

## Current actual observations

On Python 3.12.14, the exact candidate ran once under the unchanged process owner:
15 loaded test IDs equal 15 executed IDs, all passed with zero failures, errors,
skips, expected failures or unexpected successes. The source/Core VM controls,
200 parser/presentation comparisons, all 15 actual actions and 23 file-result
branches are included. File comparisons use exact bytes and modes at the same
input pathname, without JSON or pathname normalization.

The unchanged original agent-entry module executed all six methods and made
23 selected CLI child calls. Its original assertions remain intact; those
children reject entry into the old CLI function and argparse parser. The
development observer recorded 1,058 actual native image returns. The complete
run used 13,823,239,296 ns, exited normally, observed ECHILD and reaped its
leader without killing a remaining child. All 542 locally materialized source
records and the explicit compiler remained equal before and after.

The compiler is an exact 668,608-byte development copy with SHA-256
`0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8`.
Its original 416 desktop cold run remained HOLD. Neither this build nor its
passing tests relabel that run or provide a matching-source cold qualification.

The native compiler's original limits are unchanged: 128 functions,
1,536 blocks, 8,192 operations, 256 blocks per function, 2,048 SSA definitions
per function and a 1 MiB source limit. Current control has 45 functions,
1,030 blocks and 4,139 operations; formatter has 64 functions, 919 blocks and
5,555 operations. Maximum per-function counts are 141 blocks and respectively
600/617 SSA definitions. Both images were actually compiled and executed.

## Presentation profiles and pending scope

Profiles are pinned to CPython 3.12.14, 3.14.4 and 3.14.10, English messages and
the default color theme. Arbitrary custom argparse subclasses, theme overrides,
non-string argv objects and concurrent mutation of the parser environment are
outside this selected profile. This does not remove the original entry.

The official 3.14.10 argparse change quotes each choice in an invalid-choice
diagnostic; HIA profile 31410 implements that difference separately. Its
`_colorize.py` and complete Unicode classification database are byte-identical
to 3.14.4. The other argparse source difference concerns implicit program-name
inference and cannot affect the ordinary entry's explicit `prog="hia"`.
These are source observations, not proof of actual 3.14.10 execution.

Actual desktop Python 3.14.4 validation is pending. Matching full-source cold,
installed wheel resources, joint CI, all retained action-body replacement and
final native-only release/cleanup remain pending. Existing code is not removed
on the basis of this development result.
