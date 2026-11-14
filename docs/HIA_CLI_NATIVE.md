# Ordinary HIA CLI: current native ownership

This is an explicit native control and presentation owner, not a complete native
CLI release. Its ordinary entry is the existing `hia_main` through
`HEPTA_HIA_CLI_MANIFEST`. With that selector, the retained CLI function and
`argparse.ArgumentParser` are not used. With no selector, the original entry
remains available. A selected but missing, malformed or source-mismatched bundle
fails closed; it does not retry through the retained parser.

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
The separate `HEPTA_HIA_CLI_DISCOVERY_JSON_MANIFEST` selector enables complete
HIA-generated capabilities/catalog JSON through both CLI routes. Other
successful JSON remains at the existing output boundary. This table names the remaining action semantics explicitly.

| Action | HIA stage decisions | Remaining Python semantic/effect owners |
|---|---|---|
| capabilities | Control/output/exit; complete JSON when discovery is selected | Process entry and text stream; original dynamic provider when discovery is absent |
| catalog | Control/schema option/output; complete JSON and catalog SHA when discovery is selected | Process entry and text stream; original dynamic provider when discovery is absent |
| import-assembly | Read limit, assembly admission order, optional publication branch, receipt/output order | `read_bounded`, `assemble_program`, VerifiedProgram object, `publish_program`, object report and JSON |
| render-assembly | Verify before render, text or file branch, ordered publication/output | `verify_program`, `render_assembly`, verified artifact publication and filesystem effects |
| check-assembly | Read then diagnose; output before reading accepted truth and choosing exit | `diagnose_assembly`, report object, raw Python truth observation and JSON |
| verify | Bounded read, verify, report, output, exit | `verify_program`, VerifiedProgram.report and JSON |
| inspect | Bounded read, verify, inspect, output | `verify_program`, `inspect_program`, returned object and JSON |
| normalize | Verify and obtain normalized object, optional publication, output | VerifiedProgram.as_dict, `publish_program`, artifact IO and JSON |
| build | Admit target/backend/kind/output options, verify, build, output-before-ok and exit | `build_program_machine` and its remaining compiler/backend owners, object publication and JSON |
| patch | Input/request limits, decode/apply order, optional publication and receipt fields | `decode_json`, `apply_program_patch`, program objects, `publish_program`, JSON |
| impact | Read/decode/analyze sequence; selected HIA change comparison and both-version transitive graph | Core/patch/receipt verification, fact transport, final report/digest and JSON |
| edit-query | Function/block/value/field selection, split positions, query/publication flow | Raw Python string slices, `prepare_edit`, `publish_json_view`, filesystem and JSON |
| edit-apply | Preserve single-query decode and response-read error order, select 16 KiB response bound, apply/publish/output | `decode_json`, `apply_edit`, program objects, `publish_program`, filesystem and JSON |
| edit-batch-query | Select read/decode order and query/publication branch | `decode_json`, `prepare_batch`, `publish_json_view`, filesystem and JSON |
| edit-batch-apply | Preserve batch query/response read order, 1 MiB query and 64 KiB response bounds, apply/publish/output | `decode_json`, `apply_batch`, program objects, `publish_program`, filesystem and JSON |

The Python bridge still owns object handles, Namespace construction, mechanical
dict/list operations, actual module imports, file/console calls, resource
allocation, exception capture and immutable machine-image mappings. The HIA
controller chooses when to request those observations/effects. The assembly
publication helper retains its original filesystem and verification policy.
Only the explicitly selected discovery owner replaces capabilities/catalog
JSON construction. Other action semantics and successful JSON remain as listed. Independently selected
owners inside those functions retain their own source and qualification scope.

## Current selection and qualification

Canonical HIA sources use `.hepta`. The selected `--backend selfhost` route
preserves both operator pins, root-level parser constraints and refusal to
enter the direct Python emitter. Its build effect still forwards the existing
public compilation boundary. No semantic owner is activated by default.

See [discovery JSON](HIA_CLI_DISCOVERY_JSON.md) and
[patch impact](HIA_PATCH_IMPACT_NATIVE.md) for the new selected semantic owners,
original caller controls and installation custody. Source/image/manifest drift
refuses; no selected failure silently falls back to the original body.

The original compiler bounds remain 128 functions, 1,536 blocks, 8,192
operations, 256 blocks and 2,048 SSA definitions per function, and a 1 MiB
source input. Installation includes every declared source/build resource role.
Original parser controls retain supported CPython-version differences,
negative tokens, Unicode decimal rules, all fifteen actions and exact output
file bytes/modes. No original assertion or deadline has been removed.

The [current state index](CURRENT.md#source-bound-qualification) records actual
source identities and terminal results. Matching-source cold, original CLI
methods, real installed callers and full retained regression are distinct
gates. A prior source or development image does not qualify the current tree.

The superseded recovery narrative, including original failed argv comparisons
and lost-executor observations, remains at its
[exact published revision](https://github.com/TrillionniumFoundation/Hepta/blob/ad352eeb77d804c14d7407713e23d37e7f037cf1/docs/HIA_NATIVE_CLI_CONTROL_RECOVERY_20261111.md).
Its original size, Git blob and SHA-256 are in the
[process-document ledger](../review-evidence/hia-native-cleanup-20261111/retired-process-documents.json).
Historical failures and unknown outcomes retain their original meaning.
