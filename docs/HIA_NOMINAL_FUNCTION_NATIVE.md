# Native nominal function controller

`examples/hia_bootstrap/nominal_function.hiaasm` owns the complete nominal
function traversal: block and instruction prepass, ordered parameter requests,
global value-slot charging, fresh parameter names, duplicate SSA checks,
entry/signature comparison, actual argument lookup, instruction-owner dispatch,
block assembly and final returned-loan bindings. Its output is the complete
Core function. Type resolution, individual instruction and terminator policies,
task-helper generation, module admission and module aggregation remain separate
owners. This document does not claim that the entire compiler, tool suite or
nominal helper-cache policy has been retired.

## Maintained source and recovery custody

The HIA assembly is the maintained source. Its complete 225,259 bytes were
recovered from the retained native compilation input, with SHA-256
`1f6f1fbc1e6604fc700f3713c5488d65481cab5ad540139ef0527527cc413f83`.
The retained development image has SHA-256
`db26fae9377f3a4188edd8b993ee5be851511681a7c399804055534f50a3c417`.
The corresponding interrupted-context bridge was reconstructed from complete
previously observed source and its patch; its 19,598 bytes match the separately
retained test report's SHA-256
`1cfcd31d068a04674e21ee953ffa0aa18ef8713826630b08160ffbb778c1f421`.

The original Python authoring generator was not recovered. There is no
replacement generator which merely reads this HIA source and claims independent
generation. Tests assemble and validate the actual maintained source, inspect
its complete IR and bounds, and compare its execution in the independent HIA
VM with the actual native image. The reconstructed tests and this document are
new source with new hashes. Recovery does not restore a missing Git commit's
identity, turn partial test runs into passing ones, or qualify the recovered
image against a new profile.

## Selection and downstream boundaries

`HEPTA_HIA_NOMINAL_FUNCTION_MANIFEST` explicitly selects the native controller.
A selected missing, changed or invalid image/source/manifest refuses. With no
selection, the retained `_reference_function` remains available. That original
function body has the independently recorded AST SHA-256
`c4725d8619bcb0ad80b34878ed64d327c58a054f90a088e9cfa9357ebb006075`.

At their original ordered points, selected function execution requires native
parameters/types, record transitions, record operations, enum operations,
ordinary task operations, call/primitive lowering, terminators and enum match.
No instruction-family decision, type equality, value lookup, SSA decision,
fresh allocation, operation construction or CFG construction is repeated in
the Python function controller. The bridge stores opaque descriptors, values,
environments and completed Core objects, and services native-selected requests.

Task-helper cache policy is a separately selected HIA owner. At the original
helper continuation, the function bridge admits that native cache image and
passes the exact object through the private `_native_cache` argument with
`require_native=True`. Missing cache selection refuses even if a hosted cache
already contains a name. The admitted HIA cache performs the lookup; a hit
still precedes generator selection and protocol checking. A miss requires the
native generator at its original point. The function path contains no hosted
cache decision or hosted generator fallback.

The original recovered bridge selected several downstream owners twice through
existing wrappers. A later actual-image observation confirmed that clearing the
call selector between those reads invoked the hosted primitive branch and still
produced a complete constant function. That completed observation is distinct
from an earlier witness attempt which was terminated without a result.

The corrected native function path passes the exact image admitted at each
continuation into the record, enum, call and match bridge. These private image
arguments are not public source fields. Task and terminator continuations
already invoke their admitted object directly. Ordinary wrapper calls preserve
their existing selection behavior. The original seven owner-kind controls clear the selector
after actual image admission, forbid every hosted reference, execute the held
image, and compare complete output and state with the reference function. This
pinning change is separately committed from the byte-exact bridge recovery.
The later cache integration adds an eighth owner-kind control with the same
actual-image admission, selector-clearing and complete-state comparison. The
hosted cache wrapper is disabled alongside the other retained references in
the complete selected-function controls and installed-wheel execution. Those
controls also disable the upstream inline oracle retained as
`_reference_main_function`, so integration cannot hide a different hosted
function implementation behind the original reference name.

## Issued result and graph integrity

An actual-image recovery control found that the original bridge accepted an
in-place change to a native parameter-path list. The altered path reached the
real native type owner even though HIA had requested a different source
location. The original failure is retained separately from the correction.

The bridge now captures the decoder-owned list/dictionary edges as the graph
is produced. Before a callback it checks the exact pending object, the issued
header and those immutable shallow edges. Public `lower` additionally consumes
an exact issued-result permission before materializing counters, propagating
semantic admission or returning a terminal function. Counter writes still
precede an original semantic refusal, but altered transport cannot introduce
new counter writes. Interrupted calls release the binding and both arenas.

Private step/VM drivers retain their existing responsibility to apply the
returned counters and semantic admission themselves. `service` checks the
native graph independently; it does not require the public materialization
method to have been used. Public `lower` always uses that method.

Binding metadata follows newly decoded wire edges and concatenation pieces.
It does not recreate a second expanded flat argument/origin array or impose a
new public width, node or wire quota. Source references have bound owned
structure. External tag-10/tag-11 objects retain exact identity and the
existing stable-pool contract: opaque interiors are not recursively frozen,
and changing an external list together with its concatenated output is outside
this guarantee. Tuple references bind their newly created outer list while
keeping child identities. This is private protocol integrity, not a security
boundary against arbitrary same-process code.

## Original semantic order

HIA checks the complete block inventory, exact block fields, names and duplicate
block names before parameter parsing. For each block, it requests all parameter
types, charges their complete flat width and allocates flattened parameter names
before validating the operation list. Value-slot charges are applied before a
limit refusal, as in the original implementation.

Each instruction is checked for exact fields, string operation, object
attributes, selected-profile membership and the argument-name list before its
output declarations are parsed. HIA charges those declarations immediately.
Duplicate SSA checking occurs only after the complete instruction prepass for
that block. Later output-parser errors and type-cache effects can therefore
precede the duplicate-SSA error. Definitions remain global within one function;
generated-name and value-slot counters remain global to the elaborator.

After every block's prepass, HIA checks entry name and existence, requests the
held function-name inventory, selects a signature by private ordinal and
compares both parameter names and exact opaque type identities. The bridge does
not select a callee or compare signatures by name.

During instruction execution, HIA checks actual argument names in order,
rejecting reserved, undefined/nonlocal or consumed values before requesting the
second output reparse. It selects a complete native operation owner, which
mutates the same held environment and operation list. Partial consumption,
fresh counters, bindings, helper-cache changes and operation prefixes retain
their original behavior on refusal.

The terminator owner supplies complete edge/exit policy and requests enum match
where appropriate. HIA constructs each Core block with its held parameter and
operation arrays. Match appends to that same operation-list identity and emits
its complete additional decision blocks. At the end, HIA constructs the entire
function, flattening return inventories and binding returned-loan origins to the
actual generated entry parameters. Composite v1 maps to Core v6, v2/v3 to v7,
and v4 to v8 through the separate module owner.

## Private continuation protocol

Each native step receives this typed transport packet:

```text
[function, sequence, serial, value_slots, parameter_loan_returns,
 nominal_operation_inventory, new_type_descriptors, reply, environment_delta]
type_descriptor = [id, kind, primitive_flat_types, linear, flat_pool_id]
environment_delta = [source_name, held_value_id, consumed]
removed_binding = [source_name, null, null]
```

Native type sessions intern repeated descriptors. The bridge preserves object
identity with append-only private IDs and never expands or compares semantic
type keys. Aliases of the same `_Value` share one value ID and observe the same
consumption state. Previewing `data()` does not acknowledge a packet; transmitted
type and environment snapshots advance only after a valid frame is decoded.

The HIA workspace retains phase, sequence, counters, prepass tables, generated
parameter layouts and native-selected ordinals. It copies the complete typed
function bytes on first entry and compares the exact bytes on continuations.
A digest is not substituted for that comparison. Persistent source offsets
refer only to the fixed original function; type layouts are copied into native
tables, and transient replies need not retain their offsets.

| Request | Fixed continuation |
| --- | --- |
| 1 | Parse parameters at the native-selected original source path |
| 2 | Store complete native block parameters, flattened parameters and bindings |
| 3 | Project the held function-name inventory |
| 4 | Project the signature at the native-selected ordinal |
| 5 | Use the requested block environment and a fresh operation array |
| 6 | Invoke the native-selected complete instruction owner |
| 7 | Invoke the complete native terminator owner |
| 8 | Store the complete HIA-created Core block |
| 9 | Invoke the complete native enum-match owner |
| 10 | Hold completed blocks and the original effects value |
| 11 | Project the existing return-origin inventory |
| 12 | Hold complete HIA-created origin arrays |
| 0 | Return the complete HIA-created function |

The eight-u64 header contains `HIANFN01`, semantic error, final serial, final
value slots, request, payload size, next sequence and reserved zero. The normal
extent is 64 bytes plus the complete graph. ABI refusal is `0xfffffff1`. The
bridge validates extent, sequence, counters, error correlation and exact query
fields. Source locations are checked generic paths into the held function.
Native counter changes are applied before raising a semantic refusal.

Each decoded request authorizes exactly one service of that same held query.
The bridge consumes the permission before invoking any callback. A following
native step requires the completed reply. Completion, rejected frames and
callback `BaseException`s close the context; public `lower` also closes in
`finally` and releases the two native buffers. Partial owner state is preserved.
An interruption after a callback returns but before its reply assignment cannot
make that callback eligible again. The original replay observation against the
earlier bridge is retained separately from corrected controls.

Complete Core uses generic native graph tags 0–11. External references preserve
already completed operation, argument and block arrays. HIA selects every
container, concatenation and reference placement. The host decodes generic
object structure; it does not reconstruct a semantic lowering plan. Large
existing call arrays are held directly, while the final new return and origin
arrays are expanded with the same logical contents as before.

## Capacity argument

Public source limits remain 8 MiB, 262,144 JSON value nodes, depth 64, 1,024
functions, 4,096 blocks per function, flat nominal width 512, 128 nominal
instantiations, 32,768 elaborated value slots and 8,192 generated names. The
transport does not use the nonzero-slot quota to bound zero-width declarations.
Each parameter/output declaration uses at least three public value nodes, so
there are at most `floor(N/3)` such definitions for `N = 262144`.

The private input, output and workspace bounds are 256 MiB, 64 MiB and 64 MiB.
The private typed arena also checks 8,388,608 nodes and depth 128. A conservative
input allowance is `2*N` nodes for source and object keys, `6*144 + 128*512 + 16`
for descriptors, `4*N` each for reply and environment projection, plus `2*N +
1024` metadata/container nodes. This is below 3.3 million nodes. Charging 24
bytes per node, four complete source-payload allowances, and bounded index/type
text stays below 128 MiB. Delta packets cannot exceed these complete inventories.
The fixed shallow envelopes remain below private depth 128.

| Workspace component | Conservative bytes |
| --- | ---: |
| Fixed state, tables and vectors | 32,325,632 |
| Exact typed function copy, `24*2*N + 8 MiB` | 20,971,520 |
| Parameter records, `40*floor(N/3)` | 3,495,240 |
| Physical names, `8*32768` | 262,144 |
| Interned flat types, `8*(128*512 + 16)` | 524,416 |
| Origin records, `24*(N/2 + 513)` | 3,158,040 |
| Total | 60,736,992 |

That total is below the 67,108,864-byte workspace. Explicit origin annotations
and return declarations each consume a source node, giving the `N/2` allowance.
Instruction cursors and the entry-parameter index avoid repeated whole-array
scans. Block generations give fresh native environment lookup without clearing
the full table on each instruction. The first 4 KiB is parser scratch; a private
ABI refusal may change that scratch while preserving semantic controller state.

An install-block output frame fits below 17 MiB; actual dispatch IDs below
6 MiB; origin chunks and final reference vectors below 8 MiB. Already completed
large Core arrays are held external values. The final decoder creates `W`
return elements, or `2*W` elements with explicit origins, plus six or seven
fields. Return declarations alone use fewer than `N` nodes; with origins,
twice the return count is less than `N`. Since each width is at most 512, the
new logical elements fit strictly below `N*512`. Existing held Core is not
recharged. There is no new whole-program aggregate quota or early rejection of
repeated wide aliases.

## Tests and qualification

Controls compare complete Core, exact errors, counters, type observations,
helpers, cached names and parameter-callback order against the retained
reference function. They cover all four schemas, prepass error ordering,
actual lookup before output reparse, callback failures, record/task/enum/loan
composition, and original resource cleanup behavior.

Independent VM/native controls compare complete result frames and full
workspaces through all 12 continuations. Boundaries include 15,000 zero-width
parameters, exact value-slot limits, and 8,193 repeated 512-slot arguments,
returns and explicit null-origin arrays. Source custody, capacity refusal,
concurrent private contexts, callback interruption and once-only permissions
are separate controls. Installed-wheel execution excludes authoring tools and
hosted function/operation bodies; changed or missing source and invalid
manifests refuse. Machine allocation/refusal/free controls and the original
75-case regression remain required checks.

`HEPTA_HIA_NOMINAL_FUNCTION_COLD_REPORT` selects a matching-source cold fixture.
`HEPTA_HIA_NOMINAL_FUNCTION_DEVELOPMENT_MANIFEST` selects an explicitly
development-only fixture; setting both refuses. Default bootstrap fixtures are
also development-only. A previously qualified compiler does not qualify a new
source tree. The interrupted full runs and reconstructed test/doc source must
be followed by new complete qualification; partial passes are not a substitute.

### Recovered-source development checkpoint

At commit `9a2a7f90f393042e4da3e0f8a26710e193b6e067`, the complete reconstructed
function and generic graph gate passed **36/36** tests in 636.468840607 seconds:
21 function controls and 15 graph controls, including all 75 original nominal,
resource and returned-loan tests inside the regression control. There were no
failures, errors, skips, expected failures or unexpected successes. All 2,801
Git-visible input files had identical before/after SHA-256 values; the retained
reference-function AST also remained exact. Ordinary Python collection was
used, without per-test or per-subtest collection overrides.

This is a development checkpoint using the separately identified retained
compiler and images. It does not qualify the current whole source tree or
replace the original cold gate. The earlier interrupted runs, the original
callback-replay observation, the completed selector-reselection observation,
and the test-runner failure remain separate evidence. A subsequent independent
allocation-fault injection found that refusing the second 64 MiB context arena
could leave the first arena retained by the constructor traceback. That
observation has no native entry and is not an explanation for earlier exit 137.
It requires its own correction and new verification after this checkpoint.

The complete evidence is retained in `function-recovery-development-r1` next
to the checkout. The following hashes identify its immutable files:

| Evidence | SHA-256 |
| --- | --- |
| `full-function-r1.json` | `356b42677f727fc52a81580101c96f07bbc21940c646dedff75793dc6f323e8c` |
| `full-function-r1-frozen.json` | `da25d3a61bd6d2c6052be5e41a3f9a5e98c5304eb8a4025a6213b9a5dc726465` |
| `full-function-r1.log` | `0fe2159b49dc1ad9c8bb26254826029c3097677606cfa356dd70980d3eda0376` |
| `full-function-r1-events.jsonl` | `20780cfb8731163a3ac3eaed7db0a1ea635cfcc7610668c24974659a109cf9a3` |
| `run-full-function-r1.py` | `3591e41a7e1d31ee17ed50687a9eac2b0707354cd3f0a7928bf3fb75a93cfcb5` |

### Partial-constructor allocation cleanup

The subsequent correction initializes both context arena references to null
and releases them inside the constructor if either allocation raises any
`BaseException`. `NativeNominalFunction.lower` cannot perform that cleanup
because construction has not yet returned its context. The original exception
is re-raised unchanged, and a traceback-retained context is already closed.
No HIA entry, semantic callback, counter or ownership mutation is involved.

The allocation control uses the real first 64 MiB ctypes allocation and
injects refusal at the first or second allocation, separately with `MemoryError`
and `KeyboardInterrupt`. It retains the original exception and constructor
traceback while asserting that both arena references are null and any actually
allocated arena has already died, without explicit garbage collection or
traceback removal. The original 9a observation remains independently retained
in `function-independent-review-r1/context-second-allocation-9a2a-r1.{py,json}`.
This bridge correction requires its own evidence; the preceding 36/36 result
continues to identify the earlier, exact 9a source.

No retention cycle follows merely from `_NativeTypeIdentity.session`: that
field holds a nonce object, not the type-session object. Exit status 137 alone
does not establish its cause. No public type-session lifecycle change is
justified by the earlier unproven cycle hypothesis.
