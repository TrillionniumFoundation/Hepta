# Native raw JSON to nominal typed packets

This component implements the complete conversion of bounded raw HIA JSON bytes
to the existing nominal typed packet in HIA. It is developed from source freeze
`20838a0a3e35493f4d96c74c3fca7ef86e4c529a`. It introduces a separate explicit codec
API. It does not replace the existing public JSON/object routes, their diagnostic
messages, the constructor service adapters, or function/outer state bridges.

The implementation is authored in `tools/generate_hia_nominal_json.py`, rendered
as `examples/hia_bootstrap/nominal_json.hepta`, and loaded through the opaque-byte
bridge `hepta/hia_nominal_json_native.py`. Its image embeds the current complete
HIA JSON value-arena decoder. Python does not parse, classify, traverse, or
materialize payload nodes on this execution path.

## Exact input domain

The existing raw-input boundary is defined by
`hepta/hia_program_tools.py::decode_json` and
`hepta/hia_json_preflight.py::_preflight_hia_json_reference`:

- At most 8 MiB of raw bytes, decoded as strict UTF-8 before syntax checking.
- At most 262,144 structural values. Object keys are not structural nodes.
- Root depth is zero; the Agent JSON depth limit is 128. The separate Core
  semantic limit is not substituted for this input-envelope limit.
- Integers, strings, booleans, null, arrays, and objects. Fractions, exponents,
  nonfinite numbers, duplicate decoded object keys, isolated Unicode surrogates,
  and malformed JSON are already rejected by this raw HIA JSON boundary.
- Unicode escapes and valid escaped surrogate pairs retain their exact decoded
  strings. Keys compare decoded spellings, so `"a"` and `"\u0061"` conflict.
- Decimal integer conversion follows the selected digit-limit policy. The thin
  bridge snapshots `sys.get_int_max_str_digits()` by default, or accepts an
  explicit scalar policy of zero (disabled) or at least 640. HIA performs all
  payload digit counting and integer normalization. `-0` becomes `0`.

The generic foreign-object function
`hepta/hia_instruction_policy_native.py::transport` has a wider representation
domain: Python floats, tuples, unsupported-object tag 7, and surrogatepass
strings can be represented there. Those values are not additional legal raw HIA
JSON inputs. In particular `detached_packet_index` rejects float tag 3 and tag 7;
this component does not silently redefine that foreign-object route. No custom
Python `parse_int` or `object_pairs_hook` callback is part of the new byte API.

## Packet and wrapper

The output is byte-for-byte the existing little-endian `<QQ kind,payload_size>`
transport: null 0, bool 1, canonical decimal integer 2, UTF-8 string 4, list 5,
and dict 6. A container payload starts with its u64 element/pair count, followed
by the complete children; dict keys are ordinary string nodes. Object insertion
order is preserved. No source field is interpreted as a language schema here.

`packet(raw)` returns the plain document packet. `constructor_packet(raw,
legacy=False)` returns the complete existing transport of `[document, legacy]`.
The wrapper adds exactly 41 bytes and two typed nodes, and shifts document node
depths by one. It is added after JSON admission and never consumes the original
JSON node or depth budget. The old detached-packet index has no smaller depth
budget; downstream HIA owner semantic/transport admission remains a separate
operation. The wrapper is not used to narrow the admitted raw-input domain.

For N JSON values and B input bytes, the plain transport is bounded above by
`40*N + B`: there are at most N-1 object-key headers, at most N container count
words, and decoded scalar/key payload bytes do not exceed the raw input bytes.
The optional wrapper adds 41. The largest derived packet is below the existing
constructor's 64 MiB packet-input capacity. Allocation bounds use the existing
decoder's conservative `min(max_nodes, (B + 1)//2 + 1)` value bound; the HIA
parser charges actual values. Buffers are private anonymous mappings.

The HIA image first validates complete UTF-8, then runs the existing full JSON
decoder, then checks integer digit limits in source order. It computes complete
subtree packet lengths in a backward pass and writes every key/value node in
preorder. It emits the wrapper itself. No Python payload walk or encoder remains
between its raw input and final bytes.

Validation, subtree lengths, and emission are separate HIA functions. Their
control-flow joins stay within the actual native compiler's 16-argument limit.
The source tests independently check that profile constraint in addition to
general Core validity; Core/VM acceptance alone would not establish this native
compilability requirement.

## New result and refusal contract

`encode` returns opaque packet bytes plus fixed custody metadata: image, input,
and packet hashes; the selected integer policy and wrapper flags; actual source
node count; and domain-separated policy/result hashes. These hashes are identity
bindings, not signatures or proofs. The HIA response independently echoes its
consumed policy, source byte length, and node count. A mismatching fixed response
is refused before packet publication. Changing the digit policy changes the
identity even when both policies accept the same packet.

The new codec exposes these fixed refusal statuses:

| Status | Meaning |
|---|---|
| `0xfffffffb` | Input exceeds 8 MiB |
| `0xffffffff` | Invalid JSON syntax or raw UTF-8 |
| `0xfffffffe` | Structural-node or depth budget exceeded |
| `0xfffffffc` | Duplicate decoded object key |
| `0xfffffffa` | Integer exceeds the selected decimal digit policy |
| `0xfffffffd` | Invalid request/control or insufficient ABI buffers |
| `0xfffffff9` | Internal arena/packet invariant failed |

The first five become `NominalJSONRejected` with the actual status. ABI and
internal failures become `NominalJSONProtocolError`; they are not relabelled as
invalid user JSON. A rejected output buffer is private scratch, including the
decoder's work area, and the Python API never exposes it as a packet.

## Standalone native transport

Build with `tools.build_hia_nominal_json --standalone` to include
`hia-nominal-packet`. The Linux x86-64 executable takes no arguments; send
the 64-byte `HIANJQ01` request header, one little-endian unsigned 64-bit
JSON byte length, the raw JSON, and EOF. The header contains the eight-byte
tag, decimal digit limit, wrapper flag, legacy flag, and four zero words.

On success it returns the exact 64-byte `HIANJP01` header followed by the
packet, with no interpreter, runtime FFI, or subprocess. On codec refusal
it exits 65 and returns only `HIANJE01` and the original zero-extended status.
Truncated or overlong transport framing exits 64 without output; an
oversized declared JSON length instead returns the codec byte-limit refusal
without reading its body. This transport does not elaborate composite
types, run the verified Core program, or replace ordinary `hia verify`.

For a valid configuration, input-byte limits precede complete UTF-8 validation;
UTF-8 validation precedes the existing ordered syntax/budget/duplicate checks;
the full preflight precedes integer conversion limits. Thus a late invalid UTF-8
byte wins over an earlier duplicate key, and a duplicate or later syntax error
wins over an earlier over-limit integer. No host retry parser supplies a reason.

**This is a new fixed-status API, not full equivalence of the existing public
diagnostic strings or spans.** Syntax and UTF-8 are grouped in one status; the
embedded decoder does not export every reference parser reason/span. Neither
`E_HIA_EDIT` nor a new `E_HIA_JSON` prefix is used to pretend otherwise. The
existing public/object routes remain unchanged. Any later integration into a
public normalizer must implement and validate its complete required diagnostics
and earliest-refusal behavior before replacing that route. Accepted packet-byte
equality alone is insufficient for that integration.

### Fixed native ABI

The entry has the existing six-word native ABI: source pointer/byte length,
output pointer/capacity, and workspace pointer/capacity; the return is a
zero-extended u32. Buffers supplied by the bridge are private and disjoint.
`packet_buffer_sizes` computes capacities from byte length and the fixed input
profile without reading a payload node. The first 64 workspace bytes contain
eight little-endian u64 request words:

| Word | Request |
|---|---|
| 0 | `HIANJQ01` magic |
| 1 | Decimal integer digit limit; zero disables the limit |
| 2 | Wrapper mode: zero for the plain packet, one for constructor transport |
| 3 | Legacy flag, zero or one; only mode one allows one |
| 4–7 | Reserved zero words |

After success these words become `HIANJP01`, result size, consumed digit limit,
wrapper mode, legacy flag, source byte length, actual source value count, and
version one. No payload address or Python object identity appears in a control
field. A direct ABI caller must obey the buffer/alias contract and use a valid
request; malformed control data is an ABI refusal, not a raw-JSON diagnostic.

## Qualification boundary

The component's development checks must compare complete packet bytes against
the retained independent Python preflight/JSON decoder/transport reference,
exercise the real HIA VM before native bootstrap, compile with a fresh native
self-host fixed point, and execute the actual candidate image. They must include
the full byte/node/depth limits, wrapper accounting, Unicode and duplicate-key
controls, default and disabled integer limits, negative-zero normalization,
multi-defect error precedence, fixed-response policy mutation, private ABI
canaries, and a production-call guard against Python payload parsers/walkers.

Development evidence is not matching-source cold qualification. A qualified
builder must bind the actual compiler, complete current source map, consumed
source bytes, native compile receipt, and produced executable bytes with strict
integer/boolean field checks and input readback. Integration, installed-resource
checks, public diagnostics, and the still-hosted constructor/type/token/function
routes remain explicit release gates. This component makes no whole-stack-native
delivery claim and does not reuse the lost session's prior test results.

## Recorded development run

The revised component passed two generated-source/independent-VM tests and
twelve actual native tests. The native fixture built a fresh B0 seed, compiled
B1 and B2, verified their complete byte equality, and compiled this component
with B2. The exact tested source and image identities are:

| Input or output | SHA-256 |
|---|---|
| `nominal_json.hepta` | `c198752a724c9d393479df942ad033c0dffc18f18bf59bc77878a2159930f354` |
| B1/B2 compiler | `0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8` |
| Native codec image | `e58adf67cd845302bb352d3bb514243dd8a28af4ca97d62429df0f4a08ada7f8` |

The emitted HIA source is 139,057 bytes and the native image is 210,059 bytes.
The differential observation file contains 2,226 cases: 2,180 complete packet
matches and 46 matching fixed refusal statuses, in addition to the ABI, custody,
parallel-execution, and host-parser exclusion controls.

The run covers complete packet equality for 2,000 generated trees and the full
8 MiB byte, 262,144-value, depth-128 boundaries; maximum-node objects with keys
excluded from the structural count; a typed packet larger than 8 MiB; unchanged
raw budgets under the constructor wrapper; Unicode pairs, decoded duplicate
keys and malformed UTF-8; negative zero and 640/4,300/disabled integer policies;
multi-defect refusal precedence; private-buffer parallel calls; raw ABI canaries;
response-policy mutation; source readback and strict compile-receipt mutations.
Patching the retained Python payload parsers, materializer, transport walker and
detached-packet decoder to raise still permits the actual native byte conversion.

This run is explicitly `BOOTSTRAP_DEVELOPMENT_ONLY`. An earlier candidate was
valid Core and executable in the VM but failed real native compilation because
one join carried 19 arguments. Its original failure receipt/log is retained;
the revised HIA function decomposition fixes that profile violation without
changing the compiler, its limits, or the accepted raw-input domain.

The reproducible test entry is
`python -B -m unittest tests.test_hia_nominal_json_native -v`. Setting
`HEPTA_HIA_NOMINAL_JSON_EVIDENCE` to a fresh external directory retains the
compiler stages, source-bound candidate, manifest, native receipt, and per-input
observations. `observations.json` records observations rather than manufacturing
a test-suite PASS flag; the actual unittest result remains the success authority.

For integrated cold qualification, set
`HEPTA_HIA_NOMINAL_JSON_COLD_REPORT` to the matching complete-source cold report.
The fixture reads its real nested compiler and calls
`tools.build_hia_nominal_json.build` into a separate fresh directory. It does not
reuse a development manifest. The builder checks both the native child's actual
compiler/source hashes and produced bytes, rejects boolean-as-integer receipt
fields, rereads all consumed files, and publishes a `MATCHING_SOURCE_COLD` build
record. Complete source-contract registration and installed-package inclusion
of `examples/hia_bootstrap/nominal_json.hepta` are required before that integrated
qualification; this isolated component commit does not claim those gates passed.

## Existing constructor ingress is a separate gate

The raw codec's depth-128 Agent envelope is wider than the existing public
program envelope. hepta.hia_program._decode applies MAX_DEPTH = 64 before
elaborate_program, whose contract requires a detached and structurally bounded
document. A public input can therefore use at most 66 container frames after
the constructor wrapper, including a last empty container at depth 64.

The constructor imports tools.generate_hia_instruction_policy.py::validate:
its typed-packet limit is 1,048,576 nodes and 128 container frames. Raw values,
object keys and the wrapper require at most 524,289 typed nodes. The extra two
wrapper nodes do not exhaust that allowance. Some valid depth-128 raw trees
exceed the 128-container transport allowance after wrapping; the owner returns
an ABI refusal, which the existing bridge exposes as an E_HIA_TYPE transport
failure. The public program route already rejects those trees at its earlier
Core64 gate with E_HIA_LIMIT. No constructor limit is increased by this codec.

The dedicated constructor-ingress probe executes the real owner/render images,
compares new packets with the retained transport, checks all composite v1-v4
first type requests and v1 legacy mode, and checks the byte/node/depth boundaries.
Its scope ends at ingress and the first type request. It does not complete type
service or constructor initialization, and does not remove the Python callbacks.
Packet equality and first-continuation equality do not establish full public
normalizer or diagnostic equivalence.

A future raw normalizer must preserve ordering: full input-byte/UTF-8 checks,
then the Core64 preflight, then integer materialization policy and construction.
Running the current scanning preflight directly before UTF-8 validation can let
a depth error beat a later malformed UTF-8 byte. Running the entire raw128 codec
first can let an integer digit error beat a later Core64 depth error. Neither
ordering is a valid replacement for the existing public raw program boundary.

### Recorded ingress observations

The dedicated bootstrap-development run passed all four tests in 7.512 seconds.
It recorded fourteen old/new packet comparisons through the actual owner; the
five composite-profile/legacy cases also consumed the actual render stream.
The full 8 MiB input and both maximum-node representations reached the existing
semantic shape refusal, not a transport-budget failure. The two over-deep
wrapped raw inputs returned the existing ABI status 0xfffffff1, while the
public Core64 gate rejected them earlier with E_HIA_LIMIT. This is development
evidence only; matching-source cold and full initializer results are separate.

### Remaining continuation owners

The existing eleven images comprise one type kernel, one task-helper kernel,
two constructor kernels, five function kernels, and two outer kernels. Their
nominal decisions are already implemented in HIA, but these current Python
interfaces still own payload objects and retained state:

| Boundary | Remaining current host work |
|---|---|
| Constructor commands/results | ObjectTokenDecoder, detached source offsets, original-object custody, request dispatch, type IDs/origins, and the final six-item owner-state mirror |
| NativeCompositeTypeSession | json.dumps of commands; JSON descriptor DAG validation; construction of _Type objects; session _types/_ids/_descriptors; origin and parameter payload materialization |
| NativeTaskHelpers | Traversal of type flat/state/result/variant fields to construct its typed packet; JSON helper-result materialization |
| NativeFunctionSession | Registry/source snapshots; parameters, resolve, partial, task-protocol and helper callbacks; helper-cache updates; issued Python function identities; delegated exception retention |
| NativeOuterInvocation | Type/function/helper arena leases; _LeasedHelpers; binding native object handles to Python dictionaries; streamed full-Core object materialization |

The first complete replacement slice is constructor initialization across all
composite versions and legacy v1. It requires a native token/source-reference
renderer, all five constructor type-service commands, strict native response
correlation, a retained descriptor-ID registry, and the original 128 MiB type
arena. It must retain exact final and failure-prefix state, delegated diagnostic
identity, and the stage-dependent lifetime of the type arena. A successful first
type request alone is insufficient. Function partial/task/helper callbacks and
outer retained-object handles are later users of those same native facilities,
not grounds for omitting any constructor command or composite version.

The initial raw bytes API can be qualified separately while the existing public
routes remain. Any later public replacement must retain the byte/UTF-8/Core64/
integer-policy error order and original diagnostics, plus downstream primitive
Core verification. Fixed native image dispatch does not by itself replace the
host payload adapters listed above.

## Compact JSON rendering for type-command transport

The same executable also accepts `HIAJTQ01` followed by seven zero
little-endian u64 words, a u64 packet byte length, one nominal typed
packet, and EOF. The packet can be the result of the forward codec or a
derived type command. Rendering preserves object-member order, decimal
integer spelling and Unicode; quotes, backslashes and ASCII controls
are escaped as by the existing compact UTF-8 type-command writer.
It does not sort keys or normalize values.

A successful response is `HIAJTP01` followed by output length, input
length, the number of traversed packet nodes (including object keys),
three reserved zero words, version one, and the compact JSON bytes.
HIA validates container lengths and arities, key type, leaf framing,
canonical decimal and strict UTF-8, with no output on refusal. Like a
streaming JSON writer, it does not enforce unique object keys on an
externally constructed packet; forward admission and the type reader
remain responsible for semantic member validation.

Packets are limited to 32 MiB, 1,048,576 nodes and 130 nested container
frames; the JSON output is bounded by the existing type command limit,
8 MiB + 128 bytes. The extra frames allow a raw depth-128 document with
the existing constructor wrapper to round trip. These are codec
limits, not permissions to send more deeply nested commands to the
actual type resolver. Invalid packet representation uses
`0xffffffff`, traversal or output limits `0xfffffffe`, input byte
limit `0xfffffffb`, and invalid request/work buffers `0xfffffffd`,
in the existing `HIANJE01` envelope. Refusal returns no partial JSON.
The codec does not yet translate the constructor continuation tokens
or dispatch the five resolver commands.

The type resolver can return the existing `HIACTP01` constructor frame
directly, without constructing resolver descriptors or having a host
marshal the reply. The caller writes the last 64 bytes of a 128 MiB
type workspace: `HIACTQ01`, a nonzero request sequence, command kind
(1 initializer, 2 parameters, 3 resolve, 4 returned origins, 5 task
protocol), and five zero words. The unchanged compact JSON request
must agree with the requested kind.

A completed reply replaces the control words with `HIACTY01`, the
issued sequence and kind, the native semantic code, byte extent, and
the three resolver counters. Binary reply payloads are zero or more
u64 issued identities, or the original constructor origin rows. On
semantic refusal the constructor frame contains the existing generic
error bit, no rows, and the native code is retained in the separate
custody words. The caller, not the type resolver, owns continuation
sequencing. Invalid frames still fail before dispatch. Without the
explicit private request magic, the existing JSON-descriptor ABI is
unchanged.

## Standalone nominal constructor

`hia-nominal-constructor` binds the type owner, constructor owner and stream
renderer, and bidirectional codec from the same cold-built source tree. It
does not spawn a child process. The constructor can now issue each of its
five existing dependent type commands as a typed packet without host object
materialization. `HIACCQ01` plus the pending sequence and kind requests that
packet; `HIACCP01` returns the same sequence, kind and packet length followed
by four zero words and the packet. Emission is one-shot along with the
existing token stream path. Wrong sequence, replay and insufficient output
capacity cannot change the pending constructor stage.

The standalone command takes no arguments. Stdin is a 64-byte header
(`HIACSX01`, decimal digit limit, legacy bit, raw JSON byte length, four
zero words), the exact bytes and EOF. Stdout starts with `HIACSF01`, the
constructor and type error codes, final stage, interface profile, number of
completed dependent requests, input length and version one. The remainder is
the complete original `HIACTK01` token stream; source references denote offsets
in the exact immutable constructor packet for the original JSON. The
regular callback API still materializes its original objects and diagnostics.

Exit 0 completes initialization and emits the final state. Exit 65 reports a
semantic refusal and its completed state prefix, or the existing fixed codec
refusal with no constructor state. Exit 64 means bad outer framing; 74 means
an OS or internal transport failure. This plain constructor mode uses the raw
codec envelope and stops before function lowering. The later modes explicitly
enter the rest of the pipeline.

A client can request the exact constructor-to-next-stage packet instead of
the terminal token stream. With the same raw framing, use `HIACBX01` and
the first reserved word set to role 1 (function entry) or role 2 (outer
module entry). On success the response is `HIACIP01`, role, packet length,
profile, completed request count, three zero words, and the seed packet.
The HIA constructor assembles it from the committed document, signatures,
and (where appropriate) returned-loan origins. It does not round-trip
through host dictionaries or materialize the terminal token stream. On
construction failure, the original failure-prefix response is unchanged.
This exposes the handoff artifact, not completion of those later stages.

Role 3 in the `HIACBX01` envelope carries the first function through its
admission pass. The executable hands role 1's raw packet to the native
function owner with the same live resolver retained from construction.
For every block or instruction parameter request, HIA emits the type
command packet and reads the existing binary resolver reply directly.
Construction failure still returns the original constructor prefix.
Otherwise role 3 returns a single `HIAFAF01` frame: the original action,
admission error, phase, generated-name counter, slot count, request
count, and optional delegated type-error code. Action 10 / phase 100
means admission can hand off to records/lowering; it does not claim any
function body has been lowered. Action 1 is a semantic refusal.

The private stage admits existing parameter requests through either
`HIAFRS01` or the correlated two-party `HIACTP01` byte protocol. The
existing host-facing API and its original output remain unchanged.


Role 4 carries the first function through its complete lowering pass. It uses
the same live type session to admit parameters, resolve types, specialize
partial records, and resolve task protocols. For a task helper, the HIA
renderer projects the admitted descriptors into the original helper packet.
The HIA helper returns the complete generated function, correlated to the
request; the lowering image admits its result directly.

A successful role 4 response is `HIAFBL01` (with the same fields as
`HIAFAF01`), then `HIAFPP01` (action zero, request, payload length, final fresh
and slot counters, and two reserved words), the typed Core function packet,
and zero or more `HIAFHR01` helper frames. Each helper frame has error, final
fresh counter, generated name ID, compact JSON length, request number, and
two reserved words; its JSON is the original `{"helper":…}` envelope. The
adapter retains successful helper frames on a private anonymous descriptor
until the function completes. A refusal emits the status frame alone;
delegated helper diagnostics use codes 65–67, separate from type diagnostics.
An earlier constructor refusal retains its original framing.

The typed function packet is a private artifact bounded by the supplied
output buffer; it does not change the more general public streaming route.
Role 4 does not advance to later functions or replace outer-module assembly.


Role 5 carries the entire nominal module through native elaboration. It
starts both native handoffs against the same admitted constructor and
resolver. The outer owner selects each function and binds its completed
workspace, including the helper lease, completed handle count, names,
inventory caps and ordering. A native typed encoder then resolves the
issued object handles to the retained Core function packets. This
produces the complete Core document, not a dictionary assembled by a
host process. The private frame/output capacity does not change the
public structural quotas.

After successful elaboration role 5 emits `HIAOMF01` (action, outer
error, phase, request count, handle, ordinary function count, helper
function count) followed by `HIAOTP01` (request, payload length, ordinary
count, helper count, fresh-name counter, and two reserved words) and the
complete Core typed packet. On an outer refusal only the status frame
is written; a delegated function refusal also returns its `HIAFBL01`
status. Earlier constructor refusals retain their framing. No partial
module or helper stream is published. Primitive Core verification
remains a separate required stage.


Role 6 runs the complete native nominal path and then independently verifies
the emitted primitive Core. The original source also passes the
262,144-node / depth-64 ordinary canonicalizer, rather than relying on the
general packet codec's depth-128 envelope. Both canonical snapshots must
fit the existing 8 MiB budget. No canonical bytes are published before the
primitive loan, effect, SSA and other checks accept the lowered document.

On success `HIAVCF01` contains zero stage and status, original composite
profile, canonical input length, canonical Core length and two reserved zero
words. Original canonical UTF-8 bytes precede canonical Core bytes. On a
post-ingress refusal no payload is present: nonzero stage identifies original
canonical admission, Core encoding, primitive Core admission, or Core
canonicalization (1–4) and retains that stage's status. Existing codec,
constructor and outer error frames are unchanged.

Roles 7, 8 and 9 apply the same independent admission, then produce the
ordinary verification report, inspection report and normalized Core
respectively. Successful output is pretty JSON followed by a newline and
has no frame prefix. Refusals retain the existing role 6 framing, without
any report or partial Core. The reports distinguish the original structured
snapshot from the verified Core and do not claim native execution or
whole-language soundness.

The cold-built, sealed native `hia` routes `verify`, `inspect` and
`normalize` through this component. It checks the component's
size, digest and custody before handing over a source descriptor. The
component decodes the original schema and selects native nominal lowering
or the existing independent primitive verifier.

With `normalize -o PATH`, the verified canonical Core goes directly to
the existing native filesystem publisher in the same process. No public
frame can supply allegedly verified bytes. The result distinguishes the
original source SHA-256 from the verified Core SHA-256, and uses the same
nofollow and no-overwrite publication policy.

For `hia build -o PATH`, the installed object builder reuses the constructor
and outer lowering in the same process. The builder captures the input once,
independently admits the lowered Core in fresh scratch, and uses the same
native object emitter, inventory checks and no-overwrite publication as for
primitive Core. Its report binds the canonical nominal input separately from
the verified Core and the emitted object. Edit commands and the host CLI/API
are not changed by this route.

Ordinary `render-assembly` uses the same verified classification. Valid
nominal documents and primitive v1–v5 produce the exact public unsupported
profile diagnostic before any output-path effects. Nominal lowering alone
cannot trigger that diagnostic: the resulting Core must pass independent
admission. Primitive v6–v8 use the existing HIA renderer and round-trip
check before writing assembly bytes or publishing a new file. The direct
Core helpers remain available; the installed dispatcher does not invoke
the former unstructured renderer for this command.

For the packaged `hia build` object path, the bounded launcher expands the native
builder into a private executable file descriptor and seals it before execution.
The release pins the launcher bytes; the build receipt's implementation digest
identifies the exact expanded ELF that produced the object.

The installed `hia edit-query` paths (stdout and atomic file publication)
retain the original canonical input digest while selecting instructions from
independently reverified lowered Core. HIA finds the end of the base in the
strictly decoded command envelope; the Linux bridge preserves the selector
bytes.

The installed `hia patch` (stdout and atomic file publication) and
`hia impact` routes also admit nominal inputs. Both patch schemas retain
the original canonical input digest in the receipt without changing the
patch precondition: the request must bind the independently verified Core
digest. The impact graph validates these two identities separately.

`hia edit-batch-query` uses the same captured base for all ordered selections.
The outer manifest and every nested query retain its original input digest;
the Core digest still identifies the snapshot on which selections were made.
Overlapping selections are rejected before any publication. Edit application
does not yet use this route.
