# Explicit HIA CLI control and presentation

This v75 candidate is authored on the exact v74 CLI from the 38-file overlay
`05b1c5c8c25c5a00455289480a863f1c789a842b`, whose base is
`ac3fb576419d9ec36841822b4be0fca420268f1b`. The native control/format authoring
origin is the separately inspected PR888 revision
`acffa9262f31d073f8f0a6f0201eae201039f619`. No test, cold-build or whole-product
claim from that revision is inherited by this candidate.

The original v74 function body is retained byte for byte under
`_reference_hia_main`. With no `HEPTA_HIA_CLI_MANIFEST`, `hia_main(argv)` calls
that original function with the original argument object. Explicit selection
loads both native images before any argument/action operation and refuses an
invalid selection without calling the original parser. The selected profile is
ordinary strings, English argparse presentation, and the enumerated CPython
3.12.14 / 3.14.4 / 3.14.10 profiles. Arbitrary Python argument objects and other
parser/environment profiles remain outside the equivalence claim; they are not
removed from the default public API.

## Native responsibilities

The HIA control image owns argument recognition, abbreviation and cluster
rules, repeated options, sentinel boundaries, required/choice/excess errors,
all fifteen actions, semantic-call/import order, the existing read limits,
publication branching, report updates, exit selection and foreign permission
state. The companion formatter owns help/version/parser-error/E_DRIVER bytes,
Unicode escaping, wrapping and the declared color/terminal decision profiles.

The selfhost extension is part of HIA parsing and sequencing. Both
`--selfhost-manifest` and `--selfhost-manifest-sha256` are required and must be
nonempty for `--backend selfhost`. Supplying either option to the native backend
has the original early parser error, including an explicitly empty value.
Required/choice/excess/help parsing keeps its original order before this paired
check. HIA selects operation 42 for `build_program_selfhost`; the bridge has no
backend-policy branch. The original output, target, kind and two operator pin
objects are passed to that foreign owner. HIA does not reinterpret or prevalidate
the compiler pin beyond the original CLI pairing rule.

| Action | Native control responsibility | Named foreign semantic owners |
|---|---|---|
| capabilities | Operation, output, exit | Capability object and successful pretty JSON |
| catalog | Schema choice, catalog operation, output | Opcode catalog and JSON |
| import-assembly | Read, assemble, optional publish, output | Bounded file policy, assembler, program/publication objects |
| render-assembly | Read/verify/render, text or publish branch | Program verifier, renderer, original assembly publication body |
| check-assembly | Diagnose, output before accepted observation, exit | Assembly diagnosis and Python truth observation |
| verify | Verify/report/copy, report fields, output | Verifier/program object, mapping mechanics, JSON |
| inspect | Verify then inspect/output | Inspection semantic body |
| normalize | Verify, object or publication, output | Program object and publication |
| build | Native/selfhost selection, output before ok observation | Existing native and selfhost compiler/publication owners |
| patch | Request read limit, apply, receipt/publication flow | Patch semantic body and publication |
| impact | Request read/analyze, report composition | Impact analysis and returned objects |
| edit-query | Native split boundaries, prepare/publish/output | String slice mechanics, edit preparation and publication |
| edit-apply | Query read/decode, response limit, apply/publish | Decoder and edit-apply semantic bodies |
| edit-batch-query | Read/decode/prepare, output/publication | Decoder and batch preparation |
| edit-batch-apply | Query/response limits, apply/publication | Batch apply and program publication |

Successful `output_json`, `read_bounded` policy, verification/edit/compiler
bodies and the assembly/JSON publication bodies are still explicit foreign
owners. Invoking them from HIA does not turn their remaining Python decisions
into HIA code. Existing independently selected native owners inside those
functions keep their own source/custody and qualification boundaries.

## Permission, object and exception lifetime

Each original foreign command 1–41, the selfhost call 42, handler cleanup 43
and pending-argument read 44 require a native preclaim. A claim binds the live session nonce, command and
monotone sequence. HIA marks it consumed before the adapter launches the first
callback. A repeated claim, cross-session claim, malformed outcome, lost native
ACK or interrupted effect fences the session. No handler, retry or fallback
obtains a second permission for an uncertain effect.

HIA supplies a per-argument ownership-consumption mask. The fixed bridge moves
only those handles onto the actual Python call stack; it does not retain a second
temporary alias in an append-only result pool. This preserves the important
distinction between a temporary read/decode/report result and a named local.
For nested query/response calls, HIA selects a fixed pending-argument read
primitive: the prior argument is moved onto the real Python evaluation stack
before the second read. If that read fails, Python releases the pending argument
during stack unwind before the CLI except handler becomes active. A successful
read returns both still-live arguments to HIA for the subsequent call.
HIA retains the named raw/result/program/text/receipt/query/revised/impact locals
and supplies the terminal release order. Terminal releases occur after the real
exception handler has unwound. The native handler separately orders message and
exception-handle releases while the original exception is active.

These are cooperative same-process transport invariants. The nonce is a private
monotonically allocated instance identity, not a hostile-code authentication
secret. A lost allocation consumes its number; close and garbage collection
cannot reuse it. Exhausting the u64 transport namespace refuses without wrapping. The fixed bridge
still owns actual Python reference transfers, function calls, exception frames
and object storage. Unknown continuations remain strongly held with their actual
objects and native bytes; there is no production quarantine-forget or automatic
retry operation. Independent reentrant CLI calls use different private native
states; reentry into the same pending session refuses.

Full-span argv fields borrow the exact observed ordinary-string object.
Partial spans use the requested substring, with no normalization. This covers
the original input/output/manifest/pin object identities in the authored
differential controls. No general identity or physical-stack equivalence claim
is made for arbitrary Python argument objects or unsupported interpreter profiles.

## Source, image and installation custody

The pair is bound by the unchanged explicit bundle wire and separate child
manifests. On every selection, including a warm mapping-cache hit, the bridge
freshly reads both source resources, both child manifests, both image files and
the bundle. It verifies the source/image/compiler identities, bounded relative
paths and final readback before returning the owner. Cached executable mappings
remain immutable; a changed or missing selected file refuses.

Production `tools/build_hia_cli_native.py --cold-report ...` accepts only a
complete matching current-source cold report. Every input participates in source
readback; each native compile receipt is strictly typed and its recorded copy
must agree. Images, manifests and build receipts are published exclusively and
read back. A failed build may retain diagnostics but cannot return a selection.
The separate `--development` entry uses an explicitly named retained compiler
and labels that result DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD.

Installed resources are the two .hiaasm assets; authoring Unicode tables and
generators are checkout/source-build inputs. The original installed-wheel
control copies all five current resource groups and poisons the original CLI,
argparse and authoring-tool imports. Source, child manifest and image refusals
are separately exercised. The public worker helper/checker/publication interfaces
are not replaced by this CLI change.

## Verification status and commands

The initial immutable source packet was **AUTHORED_NOT_EXECUTED**. Subsequent
observations are independent development records. The original r1 generator
invocation failed to import the source package without an explicit PYTHONPATH;
r2 preserved that failure and supplied the actual checkout path. Its 6 source/VM
controls and 14 new native controls passed, while the retained 14 native methods
reported 9 failure events across 4 methods: impact named-owner consumption, two
query-error cleanup cases, and six narrow-width hyphen-wrapping cases. The actual
installed wheel and nested original agent-entry suite passed in that same run.
The r3 source addresses those observed failures and adds a real read-unwind
exception-context differential and complete-buffer native/VM protocol comparison.
The exact r3 group completed 36/36 controls successfully, with zero skips. A
separate later bounded witness found that using Python object addresses for
instance nonces allowed an old claim to match a new state after address reuse:
the third prepared session reused an identifier from two completed calls, and
the original claim was accepted by the actual HIA image. No new foreign effect
was launched by that witness. The earlier fixed-address 2048-attempt observation
did not reproduce reuse and is retained separately. R4 replaces the address nonce
with the private monotone counter and adds closed-instance/late-claim and exact
u64 exhaustion controls; its result belongs only to its own completed evidence.
The HIA assets are byte-identical to r3. Peer images and passes remain historical
inputs, not current qualification.

```sh
python -B tools/generate_hia_cli_control.py
python -B tools/generate_hia_cli_format.py
python -B -m unittest tests.test_hia_cli_native.CliSourceTests \
  tests.test_hia_cli_continuation_native.CliContinuationSourceTests
```

Current-cold tests use `HEPTA_HIA_CLI_COLD_REPORT`; explicitly separate development
tests use `HEPTA_HIA_CLI_DEVELOPMENT_MANIFEST`. Both together refuse. Neither
means the native class is explicitly skipped, never passed. Evidence uses
`HEPTA_HIA_CLI_FIXTURE_EVIDENCE` with a unique child per class. The native groups
are `CliNativeTests` and `CliContinuationNativeTests`.

The retained 17-method source/native fixture and independent original
agent-entry/seven-stage modules remain. New controls compare actual retained and
selected behavior for selfhost parse/error order, input/pin identity, temporary
destructors, named local destruction, nested calls, native claim loss, foreign
result loss, cross-session/repeated claims, warm image drift/missing and immediate
terminal release. Actual observations must be retained even when they fail;
no limit, original assertion or prior failure is changed to manufacture a pass.

This candidate does not change the default, broaden the bootstrap profile,
activate a service, delete the retained implementation, qualify the whole
compiler/CLI or establish a whole native delivery.
