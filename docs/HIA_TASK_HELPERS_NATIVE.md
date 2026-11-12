# Native task-helper Core generation

This component moves the complete `_Elaborator.helper` construction algorithm
into an explicitly selected HIA image. The image returns a complete primitive
Core function and the final generated-name counter. Python transports resolved
type descriptors and copies the returned function; it does not interpret a
lowering plan or choose task instructions, branches, effects or cleanup.

This is one semantic owner within nominal elaboration. The default path still
uses the retained reference helper. Type resolution, task-protocol validation,
the surrounding operation elaborator, primitive verification, installation and
program code generation remain separately owned. Selecting this image alone
does not make those other owners native or qualify whole-native delivery.

## Complete owner boundary

HIA owns the Core expansion for `start`, `poll`, `cancel`, `join` and `close`:

- Exact helper, block, parameter and instruction-name generation order.
- State-tag guards and all failure blocks.
- Poll calls, the independent poll-discriminant guard, variant payload offsets,
  ready-state selection and the returned task layout.
- Cancellation of live state, idempotence for completed/cancelled tasks,
  inactive owner cleanup and complete zero-padding construction.
- Join and close cleanup, primitive result layouts, effect union and sorting.

The existing protocol check happens before any generated helper name. The
type-session owner can independently supply that check when selected. The
helper kernel receives the task/state/result/step flat descriptors, the step's
original ordered variants and field descriptors, poll/cancel names and their
complete original effect lists. It determines how to use them.

The private transport uses the existing lossless typed-node representation.
The HIA kernel admits that representation, builds its complete function in
private memory, and emits JSON. Its `HIATHP01` frame contains the semantic
status, first helper-name number, final counter and exact payload extent.
The adapter rejects inconsistent headers, malformed or duplicate JSON fields,
changed input bytes and malformed complete-function envelopes. The ordinary
primitive verifier still checks the generated program before execution.

## Budget and refusal compatibility

The generated-name limit remains **8,192**. A helper still shares the enclosing
elaborator's counter; the kernel does not receive an independent quota. The
existing final function/block inventory checks and public Core byte/node/depth
limits remain in their existing owners.

The native result preserves partially updated state on semantic refusal. The
old implementation stores the first helper name immediately after generating
it. A later name-limit or loan-padding refusal leaves that cache entry and the
already advanced counter, but appends no complete helper. The native frame
returns exactly that state; the bridge copies it before raising the original
error category and message. A repeated direct helper call consequently has the
same cache-hit behavior. This internal partial state grants no verified-program
or execution authority.

The first refusal is retained even when the remaining construction would also
hit another refusal. Fresh-name allocation stops advancing once a refusal is
set. The three semantic statuses preserve the existing expansion-limit,
inactive-loan invention and inactive-loan-padding errors.

### Transport capacities

The private capacities are **128 KiB input, 2 MiB workspace and 4 MiB output**.
They do not reduce the admitted public language. A valid task has at most 512
flat slots, including its tag and token, so state plus result has at most 510
slots and the poll step at most 511.

There are at most 2,043 transported primitive-name occurrences. `buffer` is the
longest valid task primitive spelling; tasks cannot retain loan primitives.
Accounting for the fixed `u8` task tag and `u32` step tag gives at most 44,939
bytes for those typed strings. Fourteen array headers use 336 bytes. A four-digit
counter, the longest operation name, both original variant names, two 128-byte
source names and all eight effect strings use at most 538 bytes. The complete
reachable packet is therefore at most **45,813 bytes**.

The largest construction uses five blocks and at most 1,536 instructions. An
upper bound of 64 bytes for each parameter row, 256 bytes for each non-call
instruction, a separate complete 512-slot call row, all edge-name arrays and
fixed function fields stays below one MiB of JSON. The private 64-byte
instruction records, generated-name and type vectors, and temporary
concatenations also stay below one MiB. The larger fixed buffers leave the
independent typed-input validator and transport framing outside these bounds.

The development boundary measurement uses an ordinary verified source document
with a zero-width state, 510-buffer result, maximum-length poll/cancel names and
all effects. Every generated name has four decimal digits and ends exactly at
8,192. Its complete old/new helper objects compare equal:

| Operation | Generated names | Input bytes | Framed output bytes | Private heap bytes |
| --- | ---: | ---: | ---: | ---: |
| start | 1,543 | 45,812 | 121,134 | 16,648 |
| poll | 3,086 | 45,811 | 240,858 | 74,464 |
| cancel | 4,101 | 45,813 | 354,641 | 159,728 |
| join | 1,542 | 45,811 | 121,059 | 12,528 |
| close | 1,542 | 45,812 | 141,461 | 45,168 |

The tests also move one name beyond the last successful starting counter and
require the exact old refusal, counter and cache state. Both poll-variant orders,
zero-width layouts, all scalar padding kinds, chains, owners and direct-helper
loan-padding refusals are compared independently.

## Selection, source custody and installation

`HEPTA_HIA_TASK_HELPERS_MANIFEST` explicitly selects the image. The manifest
schema is `hepta.hia.task-helpers-native.v1`; it binds the HIA source, image and
compiler digests. Source selection uses the checkout-owned source or the
installed wheel's `hepta/_data` source. A missing or mismatched selected source
or manifest is a final refusal. There is no reference fallback after selection.

`tools/build_hia_json_preflight.py` exposes the `task-helpers` candidate through
its existing `build(..., candidate='task-helpers')` API. It uses the unchanged
complete matching-source cold gate and before/after readback of source,
compiler, cold report and the complete source map. Merely compiling an image
with an older development compiler does not satisfy that gate.

The HIA source is an explicit installed-package resource. The installation test
builds a real wheel, runs an isolated interpreter with no checkout imports and
an empty `PATH`, and disables `_Elaborator._reference_helper`. Ordinary task,
partial-state task and returned-loan task inputs must still produce the exact
reference Core bytes. Missing/changed installed source, a malformed manifest
and a changed image must refuse.

## Development evidence and remaining qualification

The initial kernel has **53 functions, 450 blocks and 2,079 instructions**. It
fits the unchanged self-hosted compiler profile. The actual development image
was produced by a retained B3 HIA compiler, with source readback preserved and
no forbidden compiler modules loaded. It is development evidence, not a fresh
matching-source cold qualification.

`tests/test_hia_task_helpers_native.py` covers exact generated objects and both
public normalized byte forms, error order and partial state, input custody,
workspace canaries, capacity boundaries, randomized layouts and the installed
wheel. The execution comparison includes task transitions, allocation refusal,
partial records, returned loans, range operations and complete resource cleanup.

An additional actual-ELF test uses **HIA-generated helpers and the retained
direct x86 program backend**. An independent C caller observes four successful
allocations, four frees, four real allocator refusals and no live allocations
over eight task executions; four invalid task transitions terminate with the
expected abort. That verifies this helper's executable behavior. It does not
claim that the program backend, all nominal lowering, or the whole installed
stack has become HIA-native, and it is not a native-compiler qualification.

The test fixture distinguishes `HEPTA_HIA_TASK_HELPERS_COLD_REPORT` from
`HEPTA_HIA_TASK_HELPERS_DEVELOPMENT_MANIFEST` and refuses their simultaneous use.
The v62 source contract, source regeneration, installed-resource manifest,
workflow and retained runner include this owner. A fresh matching-source cold
qualification is still required; the development overlay is not that receipt.

An independent review of the frozen first image compares 2,774 complete
outcomes, including 1,874 actual image entries: 1,430 acceptances, 1,280
expansion-limit refusals and 64 loan refusals. It compares the full generated
Core, error text, counter and cache, with source/input readback. Its 448 direct
loan controls are explicitly marked unreachable through admitted task source.
No difference was observed; the review makes no cold or whole-native claim.

A separate development overlay combines this helper with the native
parameter/protocol candidate. Six ordinary task documents retain exact
canonical and structured bytes, with 755 type-image and 26 helper-image entries
observed during the in-process normalization comparison. Thirty-four VM
execution/resource comparisons also agree. A real installed wheel then passes
all six documents with the hosted type resolver, parameter validator, task
protocol validator, loan-origin helper and task-helper generator disabled
together. Both installed HIA resources refuse after removal or modification.
The two frozen candidates remain unchanged by this overlay test.
