# Native ordinary task instruction lowering

`HEPTA_HIA_TASK_OPERATIONS_MANIFEST` explicitly selects the complete HIA owner
of the ordinary `task.create`, `task.state`, `task.start`, `task.poll`,
`task.cancel`, `task.join` and `task.close` branches. HIA owns their semantic
guards, type comparisons, linear transfer, fresh names, complete value
bindings and emitted primitive Core instructions. It also owns rejection of
an unknown ordinary task operation, after the original attribute/argument
guards. An operator-owned manifest binds the checked
`examples/hia_bootstrap/task_operations.hiaasm`, image and compiler digests.
Source programs cannot choose this manifest. A selected image/source,
transport, continuation or semantic failure never executes the retained task
reference branch.

The surrounding function/SSA traversal, ordinary call/primitive branches,
terminators and final primitive verification retain their existing owners.
Type and protocol resolution and task-helper generation are separate existing
owners, each with its own explicit native selection. This implementation does
not claim completion of the whole elaborator or the whole system. Accepted
source versions and normalized targets remain composite v1 to Core v6,
composite v2/v3 to Core v7, and composite v4 to Core v8.

## Complete responsibilities

| Operation | Native responsibility |
| --- | --- |
| `task.create` | Empty attributes, declared task/input arity, protocol-check request at its original point, state-type equality, state consumption, zero tag/token/result padding, every fresh name and the complete task binding. |
| `task.state` | Task input guard, both primitive-resolution requests around output reparse/comparison, exact last-resolved primitive identity, and alias to the original tag. |
| `task.start`, `task.poll`, `task.cancel` | Task input and output checks, consumption, complete fresh output binding, helper request after that prefix, and the complete primitive call after helper success. |
| `task.join` | Result type/arity, consumption, fresh result names including a zero-width nominal result, helper continuation and complete call. |
| `task.close` | Empty output inventory, consumption, helper continuation and complete call with no results. |

The bridge copies complete native instructions and bindings; it does not
generate names, select the expected result type, decide consumption, compute
task layout offsets, invent padding or interpret a lowering plan. New bindings
retain the exact descriptor selected by HIA and begin with `external=false`
and `consumed=false`. The source branch body is retained unchanged as an
independent reference.

## Continuations and observable ordering

The enclosing function resolves each argument and the initially declared
outputs before entering an instruction branch. Later owner calls happen only
in response to a native query, preserving their original position.

| Branch | Native phases and requests |
| --- | --- |
| Create | Phase 0 requests `check_task(task_type)`; phase 1 compares the state and performs the complete construction. |
| State | Phase 0 requests `resolve("u8")`; phase 1 requests output reparse; phase 2 compares outputs and requests the final `resolve("u8")`; phase 3 binds that exact final descriptor. |
| Start/poll/cancel/join/close | Phase 0 requests output reparse; phase 1 compares outputs, consumes input, allocates names and binds the complete result before requesting the helper; phase 2 emits the complete call using the returned helper name and updated counter. |

Requests 1, 2 and 3 carry no instructions, new bindings, changed flags or fresh
counter. Request 4 is intentionally different: it carries the already
completed consumption/output-binding prefix. The bridge applies that prefix
before invoking the existing `helper(task_type, operation)` owner. Only HIA
selects the type and operation in this request.

The original expression evaluates helper generation before appending its
primitive call. Consequently a helper failure must preserve the consumed
input, completed output binding and fresh counter, but must not append a call.
The helper may also have allocated and cached its own name before failing to
complete its function. Those changes remain in the helper owner exactly as
before. A subsequent lookup can reuse that cached name; the native ordinary
branch preserves this direct-owner partial-state behavior. Final program
verification continues to check that every emitted call has a valid callee.

After helper success, the bridge transports its returned name, current serial
and the exact native-issued prefix bindings back to HIA. The final native
entry verifies that prefix's descriptor, output name, ordered generated names,
consumption and counter bounds before constructing the call. It emits no
duplicate binding and allocates no additional name. The bridge neither
reconstructs a call nor replays the consumed operation in Python.

Create has similarly exact failure prefixes: its state is consumed before the
tag, token and result padding are built. A fresh-name failure between the
constant, buffer owner and success flag preserves the operations and counter
already produced. The task binding is installed only after every padding slot
succeeds. State projection never consumes its task, and a refusal during any
of its three primitive resolutions leaves the output unbound.

## Private packet and admission

```text
[phase, serial, operation, attributes, descriptors, values, arguments,
 initial_declared_outputs, owner_receipts, reparsed_outputs_or_null,
 helper_name_or_null, prefix_or_null]
descriptor = [kind, primitive_flat_types, linear, state_type_id_or_null, result_type_id_or_null]
value = [type_id, primitive_names, external, consumed]
argument = [source_name, value_id]
declared_output = [source_name, type_id]
prefix = [serial_after_output_allocation, native_bindings]
binding = [source_name, type_id, primitive_names, false, false]
```

Every held value is transported once, with each argument occurrence retaining
its value ID. Existing type sessions intern repeated nominal descriptors;
their identities are preserved without hashing/comparing semantic keys or
expanding a type graph. HIA compares nominal IDs and primitive names. Only task
state/result references are needed for these branches; record field graphs and
enum payload graphs remain the responsibility of their existing type owners.

Admission checks exact inventories, index bounds, booleans, source/generated
names, primitive layouts, task tag/token/state/result concatenation, cumulative
value slots and phase-specific receipts. It verifies the saved prefix before
using any of its names. This is a representation of held, admitted types, not
a new source declaration interface or user-controlled compilation manifest.

The image has private 256-MiB input, 8-MiB output and 16-MiB scratch regions.
The typed arena validator independently checks bytes, 8,388,608 nodes and depth
128. Public limits remain 8-MiB source, 262,144 JSON value nodes, depth 64,
128 nominal instantiations, 512 primitive layout slots, 32,768 elaborated value
slots and 8,192 generated names.

Let `N = 262144`, `V = 32768` and
`D <= 2*V + 2*128 + 128 + 2 = 65922`. Held values and initially declared outputs
share the first value-slot quota; output reparse can add another `V` primitive
descriptor objects. Each cached task contributes at most two additional
primitive state/result descriptors. There are at most 128 cached nominal
descriptors and two state-projection resolution receipts. Zero-width values
and repeated arguments do not create distinct nominal descriptors.

| Packet component | Conservative typed-node bound |
| --- | ---: |
| Attributes including object keys | `2*N` |
| Held values and physical names | `5*N + V` |
| Argument occurrences | `3*N` |
| Initial and reparsed output rows | `6*N` |
| Descriptors and flat layouts | `7*D + 128*512` |
| Saved output names, receipts and inventory containers | `544` |
| Total | `4,754,606` |

Charging 24 bytes to every typed node, four further public 8-MiB payload
allowances, all held physical names and all descriptor/primitive strings keeps
the packet below 192 MiB. Task links are indices, so nested task declarations
cannot expand transport depth. Attributes lose their original source
ancestors, and the private envelopes are shallow. These bounds therefore
preserve accepted source profiles and original semantic errors for rejected
wide instructions, rather than narrowing source arity to fit a private packet.

Fixed scratch tables/state occupy 6,303,744 bytes. The largest create has an
empty state and 510 buffer result slots: tag plus token plus result padding use
at most 1,534 fresh names, 1,023 primitive operations and 98,248 dynamic scratch
bytes, below a further 128 KiB. A helper-prefix entry needs at most 512 fresh
output names; its final call entry uses no fresh names and less than 16 KiB of
dynamic scratch. Consumption flags for `N` values plus all operations,
bindings and queries fit below 3 MiB of output. Every entry uses private
buffers, resets its used tables and verifies that input bytes were unchanged.

The header is eight little-endian u64 words: magic `HIATOP01`, semantic error,
final serial, request, payload length and three reserved zeros. The normal
return extent is 64 plus the payload length; ABI refusal returns `0xfffffff1`.
Payload keys are exactly `ops`, `consumed`, `values` and `query`. The adapter
checks strict JSON, complete inventories, counters, continuation order and
query framing before applying any returned state. Image custody is not a
sandbox for arbitrary machine code or an all-input equivalence proof.

## Evidence and qualification scope

The native tests compare exact normalized Core for all four source versions,
runtime results/resource cleanup, original errors and counter boundaries.
Direct differential runs use the unchanged original branch and its actual
enclosing closures, restoring env/ops/type caches/helper caches separately.
They compare complete operation prefixes, bindings, flags, counters, helper
functions, cached names and method-call ordering, including failures and a
cached-name retry. The last resolved `u8` descriptor is checked by object
identity, and each of its three possible callback failures is exercised.

Independent HIA VM/native bytes cover every continuation kind and partial
construction failure. Separate controls cover a 512-slot task, zero-width
state/result, inactive loan refusal, repeated zero-width arguments, the exact
global value-slot boundary, malformed continuation prefixes, short regions,
depth and concurrent entries. Seven selected native nominal owners compose
with all seven corresponding hosted references disabled. Actual machine
allocation/free failure controls and retained task trap/rejection cases check
execution meaning. Installed-wheel tests run without authoring tools or either
task reference owner, and reject missing/changed packaged source and malformed
manifests.

`HEPTA_HIA_TASK_OPERATIONS_COLD_REPORT` requests the matching-source cold build
fixture. `HEPTA_HIA_TASK_OPERATIONS_DEVELOPMENT_MANIFEST` is explicitly
development-only; setting both is rejected. Default bootstrapped fixtures are
labelled `BOOTSTRAP_DEVELOPMENT_ONLY`. A pinned predecessor compiler remains
development evidence for this new source, even if its bytes were previously
cold-qualified. Whole-profile registration, fresh cold qualification and any
retirement decision are separate gates.
