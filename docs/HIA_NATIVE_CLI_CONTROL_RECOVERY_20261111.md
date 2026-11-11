# Ordinary CLI control owner — versioned argv and installed-resource revision

This is an explicit native control and presentation owner, not a complete native
CLI release. Its ordinary entry is the existing `hia_main` through
`HEPTA_HIA_CLI_MANIFEST`. With that selector, the retained CLI function and
`argparse.ArgumentParser` are not used. With no selector, the original entry
remains available. A selected but missing, malformed or source-mismatched bundle
fails closed; it does not retry through the retained parser.

The executed 17-method source candidate is
`30a513ce68e97a21e96b2d80b1a3f079f3bb843a`
(tree `42b403c14436106712fb73eed9a737ac4fc21005`), from exact base
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

## Earlier 15-method observations, retained unchanged

On Python 3.12.14, the earlier candidate
`fd4d6724ecb630b4727731db13fdfedbc05ee1f2` ran once under the unchanged process owner:
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
per function and a 1 MiB source limit. The 30a513ce control has 45 functions,
1,034 blocks and 4,163 operations; formatter has 64 functions, 919 blocks and
5,555 operations. Maximum per-function counts are 141 blocks and respectively
600/617 SSA definitions. Both images were actually compiled and executed.

## Version-specific negative-argument repair

The original complete desktop run of
`2963cfbffffd9c2d1e87dafbb82466c0daf21615` used real CPython 3.14.4.
All 16 methods executed; two subcases in the original argv method failed:
`verify -1.` and `verify -1e2`. The original argparse accepted each token as
the input pathname, while the HIA implementation incorrectly reported a
missing input. This original run remains HOLD. Its other methods, including
all 15 actions, the original six caller methods and the additional color
controls, passed. Both the inner owner and outer guardian exited naturally
with exit 1, complete reaping, ECHILD and no remaining direct children.

The repair preserves the exact runtime distinction. The official
[CPython 3.12.14 argparse](https://github.com/python/cpython/blob/v3.12.14/Lib/argparse.py)
uses `^-\d+$|^-\d*\.\d+$`; the HIA 312 branch retains its whole-token
scanner and final-LF behavior. The official
[3.14.4](https://github.com/python/cpython/blob/v3.14.4/Lib/argparse.py) and
[3.14.10](https://github.com/python/cpython/blob/v3.14.10/Lib/argparse.py)
use `-\.?\d` with `match`: after the minus and optional dot, one Unicode
decimal digit is sufficient. The HIA 314/31410 branch implements that prefix
rule using the existing pinned Unicode tables. The bridge does not classify
these tokens. Twenty added subcases exercise arbitrary suffixes, incomplete
prefixes, non-decimal characters, new Unicode 16 decimal digits, NUL,
surrogates and option values. No original assertion or subcase was removed.

The repaired 16-method candidate
`4c674bc3bfbdb461291beb8118caa63fb242e2d1` passed once on CPython
3.12.14: 16 loaded/executed IDs, zero anomalies, 1,189 main-process native
returns and 12,085,081,694 ns under the original owner. Its distinct desktop
request was issued under one fixed key. At this documentation checkpoint,
the transport returned an MCP timeout without a job ID; its effect and
terminal state remain UNKNOWN. It is not counted as a desktop pass or failure.
The original request is not replayed under a new key.

## Actual installed-wheel gate and complete 17-method run

Candidate `30a513ce68e97a21e96b2d80b1a3f079f3bb843a` added one actual
installed-wheel method and the two explicit package resources. The complete
module then ran once on CPython 3.12.14: 17 loaded IDs exactly matched 17
executed IDs; failures, errors, skips, expected failures and unexpected
successes were all zero. The owned elapsed time was 13,991,315,411 ns.
The original 180-second process owner and native profile were unchanged.
Source and compiler observations were equal before/after; the leader exited
normally, ECHILD was observed, and `remaining_direct_children` was empty.

The method built a real wheel using the declared `setup.py` resource lists
and installed it with pip using no index, no dependencies and no build
isolation. It did not manually inject resources into the wheel. The actual
wheel was 2,267,029 bytes with SHA-256
`21122532b6123705364317b2c171295a6e345e6aab671f38a08aecbdeacaf413`.
Both installed HIA sources were independently compared with their declared
source bytes. The installed `console_scripts` entry `hia = hepta.cli:hia_main`
ran under `-I -S -B` with an empty PATH, with imports of authoring tools and
entry into the retained CLI and argparse forbidden.

The isolated process made eight entry calls and observed 26 control-image
returns plus 14 formatter-image returns. Its nine refusal cases separately
cover changed/missing control and formatter sources, an invalid bundle
schema, child-path traversal, incorrect child hash, missing selected bundle
and empty selected bundle. Refusals occurred before native invocation or
console output; the two resources and bundle were restored byte for byte.
All three forbidden-entry lists remained empty. The main suite separately
recorded 1,189 native returns; that count does not include the isolated
installed child or pretend to count every original caller subprocess.

The fixed receipt path is
`<HEPTA_HIA_CLI_FIXTURE_EVIDENCE>/installed-control/report.json`, schema
`hepta.hia.cli-installed-control.v1`, with successful status
`PASS_INSTALLED_NATIVE_CLI_CONTROL`. It contains the original manifest path
under the field `original_manifest`, the wheel identity, all three process
records, source hashes before/after and the nested
`hepta.hia.cli-installed-execution.v1` observation. The name
`original_development_manifest` was changed before the first installed
execution; no earlier execution report was rewritten.

The local 17-method receipt SHA-256 is
`7d660c18adb84d132e3f86e3a5e8094ae28ebca82d3222194ee1fc1a5be47748`.
Complete raw trees are retained with typed regular/directory/symlink records;
every regular archive member is independently read and hashed, with mode,
UID, GID and mtime checked. The 16-method tree contains 567 members and
17,095,798 regular bytes; the 17-method tree contains 1,456 members and
54,889,994 regular bytes. Symlink targets are preserved as text and not
followed or extracted. These retention operations do not rerun product tests.

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

The complete repaired desktop runtime result is not established by the local
17-method evidence. Matching full-source cold, joint CI, actual 3.14.10
execution, all retained action-body replacement and final native-only
release/cleanup remain separate required work. Installed CLI resources have
the actual local wheel evidence above; that does not qualify the whole runtime.
Existing code is not removed on the basis of these development results.
