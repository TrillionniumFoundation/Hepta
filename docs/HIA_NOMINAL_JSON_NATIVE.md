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

## Fixed-head integration note

The reviewed main/a733 runtime bodies are identical after the single active-source
path extension is normalized to the main canonical resource. The generator and
the original native test module have the same property. This integration therefore
retains the exact main runtime, generator and test bytes, including the independent
constructor-ingress test module present on main.

The codec status API still does not replace the public JSON diagnostic or object
entry contracts. Main byte limits, integer-digit policy, packet identity fields,
fixed response checks and installed source custody remain in force. A merged
builder or new support inventory requires its own actual regeneration and
qualification; the fixed-head textual comparison supplies no new execution claim.
