# Native ordinary worker request admission

The explicit `HEPTA_HIA_WORKER_REQUEST_MANIFEST` selection moves the complete
request-payload admission in `hia_agent_worker` into the checked-in
`examples/hia_bootstrap/worker_request.hepta`. A selected missing, changed or
invalid source/image is refused; there is no hosted admission retry.

HIA owns UTF-8/JSON parsing, duplicate-key and structural limits, decoded string
and key handling, finite decimal-to-binary64 conversion, shortest binary64 JSON
printing, canonical byte ordering, the root worker field/schema checks, SHA-256
request identity, catalog matching and the 128-codepoint tool-name ceiling.
The numeric algorithms use integer HIA instructions. They do not call a foreign
floating parser, printer, JSON codec or hash implementation.

The existing `hia-agent-worker-request-v1` contract and eleven-tool catalog do
not change. Only the root `request_sha256` member is omitted from its digest;
an argument with the same name remains part of the request. Integer `-0`
normalizes to `0`, floating `-0.0` remains negative zero, object keys sort by
decoded Unicode, and strings are UTF-8 with the existing JSON escape spelling.
NaN, infinity, lone surrogates and duplicate decoded keys remain invalid.

## Memory and compatibility boundaries

The public input remains at most 8 MiB, 262,144 value nodes and depth 128.
The trusted foreign-integer conversion limit is supplied from the actual
`sys.get_int_max_str_digits()` setting; zero retains its unlimited meaning
within the independent wire/node limits. It is not hard-coded to the usual
4,300-digit default. Output writes check both the real output capacity and the
8 MiB canonical budget. Numeric canonicalization can grow the source spelling:
`1e15` becomes `1000000000000000.0`.

Request admission bounds the same **five-field digest payload** as the original
worker. It does not impose a new canonical-size gate on the full six-field
request. An exact 8 MiB raw request whose five-field canonical payload fits but
whose six-field canonical spelling does not fit is a retained positive control.
The separate canonicalization mode intentionally applies its own complete-output
8 MiB limit.

Native key sorting uses the value arena temporarily. Before every parsed
success or semantic refusal returns, HIA restores the original source-preorder
child/sibling links in two bounded linear traversals. The existing strict
foreign-arena validation and Python insertion order remain intact. A semantic
refusal can therefore preserve the existing worker correlation report; a
syntax/Unicode/numeric decoding refusal cannot invent such a report.

The three borrowed buffers are private to each call. The decoded arena, trusted
request profile, decimal/printing limbs and hash state occupy disjoint bounded
regions. No pointer supplied by the request selects code or memory authority.

## What still owns the surrounding operation

The Python adapter validates installed code/source custody, allocates buffers,
and materializes the already-decoded arena into objects consumed by the existing
service. The service still owns its catalog validator, SQLite namespace,
request intent, completion journal, costs, artifacts, leases and adoption.
The worker still owns administrator argument parsing, service entry, installation
readback, unknown-result handling and final report serialization. The Runtime
still owns process creation, cancellation and report identity checks.

This request kernel is not a complete native worker or a new native journal.
The default hosted path and the Runtime executable profile are not changed by
this explicit selector. The current Runtime profile does not expose this selector
as a model argument or silently import ambient environment configuration.

## Reproduction and evidence

`tools/generate_hia_worker_request.py` reproducibly authors the checked-in HIA.
Development authoring is still hosted. The general native builder supports
`candidate='worker-request'` and requires a complete successful cold receipt for
the exact current source contract before creating its output directory. Its
manifest is an executable/source identity, not an equivalence proof.

`tests.test_hia_worker_request_native` executes independent Core VM controls,
actual HIA compilation, ordinary worker/service calls, completed same-request
replay, changed-request conflicts, retained running-intent unknown results,
source/image refusal and a real isolated wheel without authoring imports.
`tests.test_hia_worker_request_review` supplies an independent standard-library
reference, finite binary64 bit patterns, Unicode/codepoint and budget boundaries,
rejection ordering, concurrent scratch and native ABI canaries.

The original development arena-order and six-field-budget failures are retained
as failed observations and regression controls. A development image is not
accepted in place of a requested matching-source cold qualification.
