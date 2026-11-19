# Native ordinary worker request and terminal envelope

The explicit `HEPTA_HIA_WORKER_REQUEST_MANIFEST` selection moves the complete
request-payload admission in `hia_agent_worker` into the checked-in
`examples/hia_bootstrap/worker_request.hepta`. A selected missing, changed or
invalid source/image is refused; there is no hosted admission retry.

For admitted requests in the ordinary worker route, the same HIA image
emits the terminal envelope. It uses the retained, authenticated request
fields rather than re-encoding the host's materialized request object.
The adapter supplies the installed source pins and an already serialized
terminal service object. HIA binds them to the request, preserves the
existing byte budget and canonical key order, and consumes the arena
once. The standalone admission-only command below does not expose this
internal continuation.

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
The worker still owns administrator argument parsing, service entry,
installation readback, service-body serialization and unknown-result
handling. Refusals before admission keep the original correlation behavior;
they do not have an authenticated terminal continuation. The separate
selected report-control route and the Runtime's process ownership,
cancellation and report identity checks are unchanged.

This request kernel is not a complete native worker or a new native journal.
The default hosted path and the Runtime executable profile are not changed by
this explicit selector. The current Runtime profile does not expose this selector
as a model argument or silently import ambient environment configuration.

## Installed native admission

The sealed release also supplies `hia-worker-admit`, a standalone
Linux x86-64 executable. It takes no arguments. An operator's process owner
writes one input on stdin:

| Bytes | Contents |
| --- | --- |
| 0–7 | ASCII `HIAWRA01` |
| 8–15 | Configured integer digit limit, unsigned 64-bit little-endian; 0 or 640 through 2,147,483,647 |
| 16–79 | The 64 ASCII bytes of the trusted catalog SHA-256 |
| 80 onward | The unmodified request JSON, at most 8 MiB |

The first 80 bytes must come from the process owner's configuration, not
from the request. On success stdout contains the exact admitted five-field
canonical digest input (no trailing newline); it does not contain a terminal
report. The kernel verifies the submitted request digest and catalog before
any stdout. Status 2 means admission refusal, 3 denotes a byte or structural
limit, 4 denotes transport/profile failure and 64 denotes unexpected arguments.
Error output does not carry a fabricated request or correlated report.
This command does not open a Store, run a tool, enter MCP or change the
current worker's administrator options or service selection.

The v14 worker release also has a private admission route in
`hia-worker-terminal`. The owner supplies `HIAWRA02`, the little-endian u64
request length and integer digit limit, the same 64-byte catalog SHA-256,
and the unmodified request. The `HIAWRO02` reply contains the u64 HIA status
and arena length followed by the HIA arena. Only a success or a parsed
refusal can carry an arena. The existing foreign graph bridge materializes
the arena for the service and retains the prior request correlation rules.
It does not run an in-process request parser if standalone transport fails.

## Installed terminal renderer

The same release includes `hia-worker-terminal`, an independent Linux x86-64
executable accepting one framed record on stdin and no arguments. Its process
owner supplies the first 296 bytes; user-supplied request JSON starts after
that header. All integers in the header are unsigned 64-bit little-endian.

| Bytes | Contents |
| --- | --- |
| 0–7 | ASCII `HIATRP01` |
| 8–31 | Raw request length, raw terminal response length, integer digit limit |
| 32–39 | 0 for no helpers digest; 1 to include it |
| 40–231 | Catalog, backend and worker SHA-256, 64 lowercase ASCII hex bytes each |
| 232–295 | Helpers SHA-256 or 64 zero bytes, according to the flag |
| 296 onward | Exact request JSON, exact terminal service JSON, then EOF |

The two input documents and the full canonical report each have independent
8 MiB limits. The service JSON must contain the existing contract version, a
nonempty request ID, and either `completed` with an object-valued `result` or
`rejected` with an object-valued `error`. HIA verifies the request and canonicalizes
the body before emitting the authenticated report and a newline. Failed framing,
admission or canonicalization emits no report. Statuses 2, 3, 4 and 64 indicate
content refusal, a size/structural limit, I/O failure and invalid framing or
arguments, respectively.

Only the process owner can attest the supplied source pins and service result.
The renderer supplies no tool execution, service entry, journal access, or
process authority. The v13 and v14 worker releases bind the installed executable to
the exact admitted request image and uses it for admitted terminal reports.
The adapter hands the executable and its one-use input to the child as sealed
file descriptors. A terminal refusal does not fall back to in-process
rendering. v12 and prior bundles retain the original report path; the default
public Runtime profile is unchanged.

## Agent schema selection

Build the `agent-schema` candidate with `tools.build_hia_json_preflight` and
select its manifest as `HEPTA_HIA_AGENT_SCHEMA_MANIFEST` or as that slot in
an operator-pinned helper bundle. It applies all eleven input schemas from
the existing catalog to both ordinary and selected-journal tools. The HIA
image binds the exact catalog SHA-256 and evaluates its type, field, range,
string, array, union and conditional rules. A selected missing or mismatched
image is not retried on the reference path.

Build and select `agent-response-schema` and `agent-verify-response-schema`
with `HEPTA_HIA_AGENT_RESPONSE_SCHEMA_MANIFEST` and
`HEPTA_HIA_AGENT_VERIFY_RESPONSE_SCHEMA_MANIFEST` for the complete set of
output schemas. The latter is separate to retain the current compiler's
module limits while covering the full verification proof response. These
replace the shape check on completed responses (before any atomic effect
commits) and on cached verification before replay. Authentication of
proofs, journal policy and tool decisions do not become schema decisions.

An admitted value does not run the hosted schema validator. Only a HIA
refusal may invoke that validator to recover the existing field diagnostic;
an unexpected hosted acceptance cannot authorize the value. Argument
materialization, tool logic and public activation are unchanged.

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
