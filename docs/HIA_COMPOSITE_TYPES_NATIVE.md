# Native nominal type sessions

`HEPTA_HIA_COMPOSITE_TYPES_MANIFEST` explicitly selects the HIA implementation
of the ordinary nominal type resolver. `verify_core` and its existing callers
then use that implementation while elaborating composite v1, v2, v3 and v4.
A selected refusal, missing source, invalid manifest or failed native transport
does not invoke the hosted resolver.

The image owns the complete `_Types` responsibility: declaration inventories,
including unused declarations; names and generic arities; declaration cycles;
concrete layouts and exact instantiation identities; stored-loan restrictions;
partial-record states; symbolic lexical bindings and loan memoization; and the
stateful work and instantiation budgets. It produces a bounded graph of type
descriptors. Python transports that graph into the existing immutable `_Type`
data objects. It does not resolve a submitted type again or recompute its layout,
linearity, identity, cache membership or symbolic proof result.

The same explicitly selected session also owns the complete v4
`_Elaborator.loan_origins` decision: annotation inventory and order, original
formal lookup, record-field traversal, flattened offsets and loan permission.
It also owns complete nominal parameter-list admission and task-protocol
signature relations, through the existing `parameters` and `check_task` call
sites. These are described below; neither adapter repeats their algorithms.
The remaining nominal elaborator still lowers operations, constructs helpers,
and binds the HIA-computed original formal/offset pairs to generated entry
slots. The primitive verifier still admits the resulting Core program.
Request/JSON custody, the worker, storage, build/install control and default
delivery remain separate responsibilities. This selection replaces the type
owner, parameter admission, task-protocol relations and the returned-loan
origin decision; it does not declare the entire composite elaborator or
product native.

## Selection and source binding

Build the image with the qualified compiler and the current matching cold
report, using the shared builder's `composite-types` candidate:

```python
from pathlib import Path
from tools.build_hia_json_preflight import build

manifest = build(
    Path('/new/private/composite-types'),
    Path('/qualified/B3.image.bin'),
    Path('/completed-cold.json'),
    candidate='composite-types',
)
```

The builder requires the current profile and complete source manifest, every
cold gate, and three matching compiler generations. It checks the report,
compiler and source identities again before publishing a manifest. A compiler
image from a previous source tree does not make that tree's cold report qualify
the current sources.

The manifest schema is `hepta.hia.composite-types-native.v1`. It binds
`examples/hia_bootstrap/composite_types.hiaasm`, the executable image and the
compiler digest. Set the selector to the absolute manifest path for the desired
process. Submitted program data cannot select an image.

The loader reads the source owned by the checkout or installed package. An
installed package uses `hepta/_data`; missing installed resources never fall
back to a checkout, current directory or home directory. Code is hash-checked,
mapped writable only for the copy, and changed to read/execute before use.
Source custody is rechecked on every new selection, including when an immutable
image is already cached. The image is trusted executable code, not a sandbox
for untrusted machine code or a proof of all-input equivalence.

## Stateful ABI

The HIA entry has the usual three-buffer signature:

```text
(source: readbuf, output: mutbuf, workspace: mutbuf) -> u32
```

`source` contains one private JSON command, bounded to 8 MiB plus 128 framing
bytes. Public Core input remains bounded to exactly 8 MiB. `output` is a private
64 MiB transient decode/output region. `workspace` is a private 128 MiB
persistent session. Its decoder scratch, current-command arena, immutable
definition arena and session/type graph have disjoint regions. The caller
preserves the workspace between commands; it does not clear it before each
resolution or reconstruct state from descriptors. Different elaborations have
different workspaces, and calls on one adapter session are serialized.

The implementation uses these logical regions; MiB means 1,048,576 bytes:

| Workspace region | Purpose and bound |
| --- | --- |
| `[0, 32 MiB)` | JSON decoder workspace |
| `[32, 64 MiB)` | Current command's decoded arena |
| `[64, 96 MiB)` | Immutable initialization/definition arena |
| `96 MiB + [0, 4096)` | Session state |
| `96 MiB + [4096, 7168)` | At most 128 definition entries |
| `96 MiB + [8192, 24576)` | Declaration dependency graph |
| `96 MiB + [65536, 5963776)` | 144 type records, each 40,960 bytes: 16 primitives plus at most 128 cached/active nominal identities |
| `[102, 106 MiB)` | Partial-declaration queue, at most 262,144 entries of 16 bytes |
| `[106, 106.5 MiB)` | 65,536 symbolic hash-table slots of 8 bytes |
| `[106.5, 108 MiB)` | 65,536 memo entries of 24 bytes |
| `[108, 126 MiB)` | Exact symbolic DAG grows upward; known-loan frames grow downward from `126 MiB - 32` |
| `[126, 128 MiB)` | Separate bounded reference, resolution and symbolic traversal stacks, plus graph/selection scratch |

Each decoded arena requires at most
`64 + 262144 * 56 + (8 MiB + 128) = 23,068,864` bytes. Object keys do not
consume separate JSON value nodes: each 56-byte value record also stores its
object key's offset and length. The appended arena stores decoded UTF-8 keys
and string values once each; their combined bytes never exceed command bytes.
Literal UTF-8 occupies the same bytes in the source, and JSON escapes consume
at least as many source bytes as their decoded UTF-8. The 18 MiB shared symbolic
region is bounded by the existing work counter, including lexical alias calls
that do not increase layout depth. Each known-loan call consumes a step and a
192-byte frame. Each symbolic visit consumes a step and at most a conservative
560 bytes for its exact DAG payload and application edge. The combined upper
bound, including one pending frame and the root environment, is
`560 * 32768 + 192 + 32 = 18,350,304` bytes, below 18 MiB (18,874,368 bytes).
No additional accepted-input quota is introduced to make that region fit.

### Private framing preserves the public input limits

The ordinary verifier has already detached and checked the complete document
against 8 MiB, 262,144 JSON value nodes and root depth 64 before selecting the
type owner. Object keys contribute bytes but are not additional value nodes.
The command serializer uses the same compact, `ensure_ascii=False` encoding;
changing object key order does not change byte length.

For an initialization definition array of encoded length `B` and value-node
count `N`, the command has `B + 76` bytes in composite v1, `B + 75` in v2,
and `B + 74` in v3/v4. Its node count is `N + 4`. A valid complete program
requires at least `B + 209` bytes and `N + 18` nodes, so its initialization
command is strictly smaller. Even when the functions value is malformed, a
document reaching this point requires at least `B + 71` bytes and `N + 4`
nodes. Thus initialization needs at most five extra private framing bytes,
with no extra node allowance. The explicit 128-byte allowance covers this
case without replacing an earlier type diagnostic with a transport refusal.
Both the kernel entry and its embedded decoder/preflight use that same private
byte bound; their value-node bound remains 262,144.

A `resolve` command adds exactly 23 bytes and two value nodes to its reference.
Ordinary references come from a descendant of the original types/functions
arrays, or are fixed primitive names synthesized by the elaborator. Removing
the surrounding program more than pays for this wrapper; its depth is also
smaller. An ordinary `partial` command contains at most 64 already admitted
field names of at most 128 ASCII bytes and a type ID at most 144: its maximum
is 8,427 bytes, 68 value nodes and depth two. Initialization retains the original
definition depth, while the command decoder's depth allowance of 128 exceeds
the original public depth 64. No ordinary accepted input loses admission to
these private boundaries.

The native regression exercises exact 8 MiB ordinary inputs for all four
composite versions, with an invalid extra type field and an invalid functions
value. It requires the image to actually run and retain the original
`E_HIA_FORMAT` diagnostic. The maximum-overhead scalar functions case is also
covered. One extra public Core byte must still produce `E_HIA_LIMIT` before
any type-image entry. Private direct calls without a bounded Core document do
not acquire an unbounded input contract from this ordinary-language argument.

The other explicit stacks are separately bounded: 34 reference frames of
32 bytes, 34 concrete-resolution frames of 256 bytes, and 66 symbolic frames
of 640 bytes. Graph traversal uses 128 frames of 16 bytes and 128 flags;
partial selection uses 64 entries of 8 bytes. These areas do not overlap.
The worst descriptor batch has at most 128 nominal layouts, with up to
32 variants and 64 fields per enum. Even the conservative 137 bytes per field
name/ID pair, plus all variants, flat slots and metadata, stays below 37 MiB;
the 64 MiB output region covers it without reducing language limits.

The exact command shapes are:

```json
{"op":"init","definitions":[],"recursive_chain":true,"partial_records":true}
{"op":"resolve","ref":{"name":"Box","args":["buffer"]}}
{"op":"partial","base":17,"initialized":["value"]}
{"op":"origins","params":[["views",17]],"returns":[14],"return_loans":[{"param":"views","fields":["reader"]}]}
{"op":"parameters","params":[{"name":"state","type":"State"}]}
{"op":"task_protocol","task":19,"functions":[["poller",[17],[18]],["cancel",[17],[]]]}
```

`base` is an exact completed type ID previously produced by that session. The
adapter rejects a `_Type` from another session instead of reinterpreting its
numeric ID. Ordinary elaboration calls `resolve(ref)` and
`partial_record(base, initialized)` in their existing order.

### Returned-loan origin command

After resolving a composite v4 function's formals and results in their existing
order, ordinary elaboration sends their exact completed session IDs and the
original `return_loans` value to `origins`. An absent annotation property stays
absent in the command; it is not replaced by an allocated default list. An
explicit JSON null stays null. The HIA implementation makes all decisions
previously made by `_Elaborator.loan_origins`, including the distinction between
those cases. The hosted helper remains the unselected reference and is never a
fallback after a selected failure.

The private parameter representation is an array of `[name, type_id]` pairs.
Those formal names have already passed ordinary parameter admission, including
uniqueness. The HIA command still rejects duplicate names, invalid formal names,
nonintegral IDs, zero/out-of-range IDs and IDs of incomplete types as fatal
transport errors. The adapter refuses types from other sessions and copied or
forged `_Type` objects before entering the image. Neither raw IDs nor session
tokens enter public normalized Core or structured bytes.

For each result, HIA first checks whether an annotation is allowed or required.
For a borrowed result it checks the exact `param`/`fields` object inventory,
validates the original formal's name, looks it up, rejects owned or unsupported
source kinds, and then checks the field-path list and its existing depth limit
of 32. Fields are visited in source-path order; preceding declaration fields
contribute their flattened widths, including zero-width fields. The terminal
value must be a primitive incoming read or mutable loan, with sufficient
permission for the result. The earlier ordinary restriction on stored borrowed
return values remains in the elaborator, and the primitive verifier still
independently checks actual returned ancestry and call/CFG permissions.

The result uses the same 64-byte header layout with magic `HIALOR01`. Word 2
is the number of returned entries, or zero on semantic refusal. Its payload is
exactly `{"origins":[null,["original_formal",offset],...]}`. Offsets are integers
from 0 through 511. A semantic refusal returns an empty `origins` array and the
existing diagnostic category. The adapter checks the exact envelope, count,
formal-name correlation, integer offsets, magic, reserved word and error table.
It converts pairs to tuples without walking a type layout, interpreting a path
or checking permission again. Missing/corrupt frames poison the adapter session.

An origins command changes no type, cache, active set or partial-analysis work
counter. Its frame must report the same counters as the previous type command;
the adapter rejects any discrepancy. Semantic refusals leave the session usable
and preserve prior unsuccessful active instantiations. The input is serialized
into private bytes before native entry, preserving ordinary detached JSON
custody even if the caller later changes its annotation objects.

No new public quota is introduced. Replacing each original type reference with
an ID of at most three digits cannot increase its byte size, and replacing each
formal object with a pair saves bytes without adding value nodes. Removing the
rest of the already admitted program more than pays for the command envelope.
The annotation value is copied unchanged and optional defaults are not expanded.
More precisely, let `P` and `R` include the encoded parameter/result arrays, and
let `A` be the encoded annotation value when present. Compact framing has these
sizes, excluding those arrays/value:

| Container | No `return_loans` | With `return_loans` |
| --- | ---: | ---: |
| Private origins command | 37 bytes | 53 bytes |
| Smallest reachable function object | 66 bytes | 82 bytes |
| Smallest reachable complete v4 program | 140 bytes | 156 bytes |

The function lower bound even permits `effects`, `entry` and `blocks` to be
the one-byte invalid value `0`: those values have not yet been checked when
origins runs. Function/module names require at least three encoded bytes;
types and functions have already passed their earlier inventory checks. Each
parameter object becomes a pair with at least 14 fewer bytes. Every already
resolved type reference occupies at least three encoded bytes, and its ID at
most three. Thus the private command is at least 103 bytes smaller than the
public document, including when the eventual origin diagnostic is a refusal.
It cannot exceed the existing 8 MiB plus 128-byte private bound.

If `NP`, `NR` and optional `NA` include the respective value-node counts, the
command has at most `2 + NP + NR (+ NA)` nodes and the complete original program
at least `10 + NP + NR (+ NA)`. Parameter object/pair containers each contribute
one node, with their names and types/IDs contributing at least two more;
replacing reference subtrees with IDs cannot add nodes. The command therefore
stays below the public 262,144-node bound. Its parameter, result and annotation
paths remove two container levels, so their nesting depth also decreases.
The actual native regression exercises an exact 8 MiB public document whose
malformed annotation reaches the origins command and retains `E_HIA_FORMAT`,
plus a valid function with 2,049 mostly zero-width formals. Even a conservative
137 output bytes per admitted JSON value node stays below 37 MiB, within the
existing 64 MiB output buffer.

Original formal lookup uses exact strings and a private 131,072-slot hash
table. Each formal pair consumes three JSON value nodes, so the 262,144-node
command limit permits fewer than 87,381 formals: the table cannot fill for an
admitted command. Hash collisions are resolved by exact name comparison. The
table occupies workspace bytes `[132710400, 133758976)`, within the existing
128 MiB session and separate from all traversal stacks and persistent type or
memo records. It is cleared for each origins command. Session words at offsets
176 and 184 hold only the current result's temporary name node and offset.

### Parameter-list admission

The selected `parameters` command replaces the complete
`_Elaborator.parameters` decision at every existing call site: function
formals, block formals and instruction outputs. HIA checks that the submitted
value is a list, then visits each item in source order. It checks exact
`name`/`type` fields, validates the name, rejects duplicates, records the name,
and resolves that item's original type reference before advancing to the next
item. A type error in an earlier item therefore still precedes a duplicate or
name error in a later item. Type resolution uses the same session, exact IDs,
cache, active set and work counter as ordinary `resolve` calls.

The adapter transmits the original parameter inventory. It does not check its
names, decide duplicate membership or resolve references. A successful native
result materializes `(name, _Type)` tuples using the HIA-issued IDs. A semantic
refusal returns no partial parameter inventory, while retaining and emitting
types that completed before that refusal. Subsequent commands see the same
cache, unsuccessful active entries and partial-declaration work as the hosted
reference. The hosted body remains `_reference_parameters`, used only when the
native type session was not selected.

The result header uses the distinct magic `HIAPRM01`; word 2 is the number of parameter
pairs, or zero on refusal. The payload has exactly `types` and `params` arrays:

```json
{"types":[],"params":[["state",17]]}
```

`types` has the existing descriptor ABI and may contain newly completed types
even on semantic refusal. The adapter validates and materializes that graph,
checks the pair count and requires every returned ID to exist in the session.
It rejects malformed frames and unknown IDs without fallback. Name and shape
refusals retain their existing diagnostic categories and ordering; compact
native errors 1, 5 and 6 can omit the hosted diagnostic's contextual label.

No separate parameter quota is added. A parameter command adds 29 bytes and
two value nodes to its input value. Even an otherwise minimally shaped public
function with unchecked `returns`, `effects`, `entry` and `blocks` equal to
`0` requires at least 141 bytes and 11 value nodes outside that parameter
value. Thus every reachable parameter command is at least 112 bytes and nine
nodes smaller than the complete public input. Its nesting depth is at least
two levels smaller. An actual 8 MiB public-input test requires the HIA command
to run and retain the original parameter-shape refusal.

The per-command duplicate-name table reuses the scratch region described
above; it is cleared before each inventory. Each admitted parameter object
requires at least three value nodes, so the existing 131,072 slots cannot fill
within the 262,144-node command bound. On successful resolution HIA stores the
type ID in that parameter object's decoded-node parent word. The decoder has
finished and this owner never reads parent words afterwards; child/sibling
links, keys, references, original source bytes and the immutable definitions
remain unchanged. No persistent type or memo region is reused for this scratch.
The output pair array is smaller than the source parameter array, while the
existing descriptor batch remains below 37 MiB. Together they fit the existing
64 MiB output capacity without reducing public limits.

### Task-protocol relations

The selected `task_protocol` command replaces the complete
`_Elaborator.check_task` decision. It runs for every concrete task declaration,
including unused tasks, and at the existing task-helper check points. The
adapter projects the already resolved function registry into
`[function_name, parameter_type_ids, return_type_ids]` rows. It sends all rows;
it does not look up the task's poll/cancel function or compare any signature.
During ordinary construction, the `functions` and `signatures` dictionaries
are populated together after each function's checks and retain the same keys.
Subsequent lowering does not modify those registries.

HIA finds both original function names, then applies the original decision
order: both must exist; poll consumes exactly one matching state and returns
exactly one result; that result must be an enum with exactly `pending(state)`
and `ready(result)`, one field each; cancellation consumes exactly one matching
state and returns nothing. Variant order and field names do not alter those
relations. Exact native type IDs preserve distinctions between nominal types
and generic applications even when their flattened layouts are equal or empty.
The original task-policy messages and categories are retained for these four
refusals, including when multiple conditions are invalid.

Before this semantic decision, the private command validates its exact shape,
the completed task ID, the already admitted registry's names, distinct rows,
array shapes and completed type IDs. Forged, foreign-session or incomplete IDs
never gain authority. Success uses the existing `HIATYP01` frame and returns
the existing step enum ID. There are no new descriptors, cache entries or work
steps; the adapter checks that the descriptor batch is empty and all counters
are unchanged. A semantic refusal leaves that same state usable.

The existing public limit of 1,024 functions also bounds this private registry.
Replacing a parameter object with an ID drops its name and object framing;
replacing any resolved type reference with its ID cannot increase its byte or
node count. Each projected function row saves at least 60 bytes and three
nodes, before accounting for removed parameter names and function bodies. With
an ID at most 144, command framing outside the function array is 46 bytes;
even the smallest complete program needs at least 72 bytes outside its original
function array. Thus this command is smaller than its admitted public document
by at least 86 bytes and four nodes. Its projected JSON has depth at most four:
function names and primitive return IDs retain their original depth, and
parameter objects/type references are replaced by scalar IDs. It introduces no
depth beyond the public allowance of 64. Source snapshot tests and a full
1,024-row registry exercise native lookup and unchanged-state behavior.

| Source schema | `recursive_chain` | `partial_records` |
| --- | --- | --- |
| `hepta.hia.composite.v1` | false | false |
| `hepta.hia.composite.v2` | true | false |
| `hepta.hia.composite.v3` | true | true |
| `hepta.hia.composite.v4` | true | true |

A framed return is `64 + payload_length`. Its first eight little-endian u64
words are:

| Word | Meaning |
| --- | --- |
| 0 | ASCII `HIATYP01` interpreted little-endian |
| 1 | Semantic error ID, or zero for success |
| 2 | Result type ID, or zero for initialization/refusal |
| 3 | Payload byte length |
| 4 | Native completed instantiation cache count |
| 5 | Native active instantiation count |
| 6 | Native partial-declaration work counter |
| 7 | Reserved; must be zero |

The payload is a JSON object with exactly one `types` array. It contains only
newly completed descriptors. A descriptor has exactly these fields:

```text
id, kind, name, args, flat, fields, variants,
state, result, poll, cancel, linear, record
```

`args`, `flat` and the type references in fields/variants use native IDs.
`fields` is a list of `[name, type_id]`; `variants` is a list of
`[name, fields]`. `state`, `result` and `record` are nullable type IDs. `poll`
and `cancel` are nullable function names. `linear` is a JSON boolean. Primitive
IDs 1 through 16 name, in order:

```text
bool unit i8 i16 i32 i64 u8 u16 u32 u64
isize usize buffer readbuf mutbuf chain
```

Definitions can reserve a nominal ID before resolving their children, so a
descriptor batch can contain forward references. The adapter materializes the
acyclic graph while retaining shared children. It checks framing and descriptor
structure, but does not validate the source definitions a second time. It does
not derive the counters from the number of descriptors: primitives are not
nominal instantiations, and an unsuccessful active layout is not a completed
cache entry.

Semantic refusals retain a complete frame and the native session's completed
cache, active set and counters. They preserve the existing rejection category
and checking order. The work-budget diagnostics retain the existing messages
`partial declaration analysis budget exceeded` and
`symbolic type argument nesting exceeds budget`; some structural diagnostics
use the ABI's compact category text instead of a source-field label. The host
materializes any newly completed descriptors and reports the native error. It
does not clear an active entry merely because resolution failed: the hosted
reference has the same stateful behavior.

Fatal results at or above `0xfffffff0` are unframed ABI/command/decoder failures.
The adapter refuses them and marks that transport unusable. It also rejects an
unknown status, malformed extent/header, repeated descriptor ID, missing or
cyclic descriptor reference, or a result ID absent from the materialized graph.
No such failure grants fallback authority.

## Finite profile and exact identities

The existing language limits remain unchanged: 128 definitions, 128 completed
plus active instantiations, 32 reference/layout depth, 64 fields, 32 enum
variants, 512 flattened slots, and 32,768 partial-declaration analysis steps.
Symbolic argument traversal retains its separate depth bound of twice the type
depth. Partial types consume the same shared instantiation budget as ordinary
nominal types. Repeated cached resolutions do not consume a fresh entry.

The HIA implementation interns exact type/key DAGs. A hash may locate candidate
entries but does not establish identity without full exact comparison. Generic
arguments remain part of identity even when the declared type erases to zero
primitive slots.

Private nominal `_Type.key` values on the selected path are opaque objects
containing a held session nonce and the HIA-issued ID. Primitive keys remain the
original primitive strings. This avoids expanding an exponentially large
display string for a bounded shared generic graph. Nominal keys are consumed
only by internal type equality and task-helper memoization; primitive-emission
paths require primitive kinds before writing a key. Public normalized Core and
structured bytes contain no session token or native type ID.

## Validation boundaries

The dedicated tests compare the generated source and ABI table, execute real
HIA source in the independent Core VM, and compare actual native sessions with
the retained hosted `_Types` reference. They cover unused malformed declarations,
declaration cycles, lazy enum/task loan checks, lexical generic bindings,
symbolic memoization and its budgets, state after refusal, cache limits,
partial transitions, shared zero-width graphs and concurrent private sessions.

Ordinary `verify_core` tests compare both canonical Core and structured bytes
for all four composite versions with the hosted type owner disabled on the
selected run. Existing partial-record rejection and frozen-fingerprint cases
also exercise that ordinary route. A real wheel is installed outside the
checkout, imports of `tools` are forbidden, and selected missing/changed source,
invalid manifests and fresh corrupted images must refuse.

The focused origins suite compares the actual HIA image against the retained
hosted helper for absent/null annotations, exact object inventories, error
ordering, generic record paths, permissions, source kinds, zero-width DAGs,
32-deep paths, the 511-offset boundary and deterministic randomized paths.
Transport controls cover forged and unfinished IDs, cross-session objects,
duplicate formals, name-hash collisions, malformed frames, input immutability,
post-snapshot source alias mutation and unchanged counters after both acceptance
and refusal. Ordinary returned-loan programs and the installed-wheel control
run with both hosted `_Types` and hosted `loan_origins` disabled. Canonical and
structured bytes remain equal to the independent unselected results.
Equivalence of refusals means the diagnostic category and checking order.
Native errors 1, 5 and 6 use the ABI's compact shape/name messages, so their
English text can differ from the hosted helper's contextual labels such as
`nominal returned-loan origin` or `returned-loan field`. The suite does not
claim byte-for-byte equality of all exception messages.

The parameter/protocol suite separately compares actual native execution with
the retained hosted methods. It covers inventory/name/error order, the exact
128-instantiation boundary, partial-declaration and unsuccessful-active state,
source alias mutation, deterministic mixed histories, protocol lookup and
variant permutations, nominal identity with equal layouts, malformed IDs and
frames, the exact public byte boundary, and the full function-registry bound.
Ordinary composite v1–v4 programs run with all four hosted semantic owners
disabled. The installed-wheel control exercises task protocols, partial state
and returned loans with checkout tools and those hosted owners unavailable.

`HEPTA_HIA_COMPOSITE_TYPES_DEVELOPMENT_MANIFEST` is a test-only mechanism to
reuse a current-source development image. It cannot be combined with
`HEPTA_HIA_COMPOSITE_TYPES_COLD_REPORT`. The latter uses the complete current
source-bound builder. Development execution is not relabeled as cold
qualification, release promotion or default-runtime activation.
