# Native nominal jumps, branches, returns and traps

The explicitly selected ordinary HIA owner implements all `jump`, `branch`,
`ret` and `trap` branches of nominal function lowering. It also owns the
original missing-terminator and unknown-opcode guards. A `match` term produces
an effect-free request to the existing complete enum-match owner at the
original point. The adapter applies the complete HIA-produced term and ordered
consumption prefix; it does not choose a control-flow target, compare nominal
types, decide a live-resource transfer or build an instruction-specific term.

This is one component of the nominal elaborator. Block and instruction
prepasses, function aggregation, final returned-loan origin binding, default
installation, ordinary Agent service and whole-product delivery remain outside
this owner. An explicitly selected image never falls back to the hosted
reference. With no selection, the original branches remain an independent
reference; they have not been removed or rewritten to match the new producer.

## Selection and complete results

The source is `examples/hia_bootstrap/nominal_terminators.hiaasm`; its authoring
aid is `tools/generate_hia_nominal_terminators.py`. Selection uses
`HEPTA_HIA_NOMINAL_TERMINATORS_MANIFEST`, schema
`hepta.hia.nominal-terminators-native.v1`, and the existing immutable image
loader. Source and executable hashes are rebound on selection. The compiler
hash is well-formed build provenance; current-source compiler/cold admission
is enforced by the candidate builder, not invented by the runtime loader.

The input packet transports the existing fresh counter, original raw term,
held interned descriptors, full block environment, block signatures and return
type inventory. Type IDs preserve held object identity. Environment rows also
preserve repeated aliases of the same `_Value` object; consumption is indexed
by that identity. Transport neither expands nominal display keys nor invokes
semantic equality. Primitive equivalence and nominal identity are compared in
HIA, using the already admitted descriptor contract.

The `HIANTM01` result contains semantic status, unchanged fresh counter,
structured/delegation flags, one consumption bit per held value, and the
complete logical term. A semantic refusal may contain the consumed prefix
left by earlier return values. Missing-terminator refusal occurs before the
current Core block is appended. Other term refusals occur after appending that
block with its original `term: null`. The bridge preserves both observable
orders. Delegation to enum-match carries no term or consumption changes.

| Original branch | HIA responsibility |
| --- | --- |
| Jump | Exact keys, target/name/argument admission, target lookup, linear transfer, exact nominal signature and complete edge |
| Branch | Exact keys, original condition lookup and bool check, then-edge before else-edge, complete two-edge term |
| Return | Exact keys/names, all initial value lookups, exact return types, ordered consumption including duplicate-alias failure, live-resource check and complete flattened values |
| Trap | Exact keys and complete raw term; arbitrary code data remains for the later primitive checker |
| Match | Effect-free delegation to the existing match owner; malformed match details are not checked early |

All existing error categories and messages are retained. A missing block wins
over the later argument lookup; duplicate edge ownership is checked before
live-resource loss, which precedes target signature comparison. Return type
mismatch is checked before any consumption. A duplicate linear return can
consume its first occurrence and then refuse its second occurrence. External
loans retain the original live-resource exemption. Branch edges have separate
seen-name sets and do not mutate consumption.

## Large logical arrays without a narrower language

The existing 32,768-slot elaboration budget bounds defined value inventories.
It does not bound repeated arguments or returns of the same non-linear value.
In particular, a return may repeat one 512-slot record thousands of times
before the independent Core normalizer reaches its original limit. Refusing
that case at a smaller wire buffer would change both behavior and error order.

`hepta/hia_native_value_graph.py` provides instruction-independent transport.
Ordinary typed nodes remain lossless. Tag 8 references a complete original
input node. Tag 9 concatenates original arrays selected by HIA. Source arenas
cannot themselves contain references, so cycles are impossible. The decoder
checks all extents, node boundaries, counts, exact scalar representations,
depth, keys and expanded-element bounds. It has no opcode/type/resource policy.
Repeated references may share decoder-owned containers, but no caller-owned
object is reused. Concatenation always creates a fresh outer list.

HIA emits the complete logical return or edge using these representation
primitives. Host decoding can therefore construct the same large Python Core
array as the original elaborator without repeating all string bytes on the
native ABI wire. This generic Python boundary remains part of the current
hosted object bridge; it is not claimed as a Python-free whole product.

## Capacity and unchanged public limits

The private limits are 256 MiB input, 16 MiB output, 32 MiB workspace,
8,388,608 typed nodes and depth 128. None changes the original public 8 MiB
document, 262,144-node, 4,096-block, 512-field-width, 32,768-value-slot or
8,192-fresh-name limits.

Workspace contains 524,288 descriptor offsets, 262,144 environment offsets,
a 524,288-entry environment hash, per-name seen marks, per-value consumption
and original-value pointers, and 4,096 block signature pointers. These fixed
tables end below byte 16,818,176. Dynamic vectors start at 16,826,368; two
maximum edge vectors use at most 4,194,304 more bytes. Input packet references
and aliases do not allocate expanded flattened vectors in this workspace.

Descriptor capacity includes separately parsed primitive return inventories;
it is not inferred only from reserved value slots. Environment and block
signature primitive descriptors are slot-bounded, return descriptors are
source-node-bounded, and interned nominal descriptors are bounded by the
existing type session. Their conservative sum is below 524,288. Native output
contains at most 262,144 flags and two source-array reference vectors, plus a
small object envelope, below the 16 MiB allowance.

The decoder permits 134,217,728 expanded elements. A successful large return
needs an actual value occurrence and a matching expected return occurrence,
each consuming a public source node. Its worst repeated flattened count is
therefore below 67,108,864, with ample allowance for the bounded cached source
arrays and object envelopes. Edge parameter inventories are further limited
by the existing reserved-slot budget. The later Core admission is unchanged:
native lowering does not turn an oversized logical Core program into an
accepted public program.

The final HIA source has 60 functions, 541 blocks, 1,987 instructions and at
most 11 block parameters. It fits the unchanged native compiler profile. The
development source digest is
`c17477282124024567724ace0d896d04813819debc391b9fab04ceefedc7c3b2`;
the development image digest is
`ce1792e031862614315eaeddb0dbf9ca1ae89c68bef3713262490a38e6f38975`.
The pinned predecessor development compiler is
`0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8`.
Those development identities are not a current whole-source cold receipt.

## Verification and original observations

Tests retain full original Core equality across all four nominal schemas,
resource and task fixtures, exact errors and result prefixes, consumed value
aliases, external loans, nominal identity, independent HIA VM/native frame
bytes, malformed ABI packets, canaries, nonzero workspace initialization,
concurrent calls, installed-wheel source/image custody without authoring tools,
and actual compiled allocator refusal/cleanup. Capacity controls include
15,000 zero-width environment values, all 32,768 defined slots, 8,193 repeated
512-slot returns, and the unchanged later Core limit on an ordinary public
source. A nested original 75-test nominal/resource/loan suite runs with the
hosted terminator reference disabled.

The first expanded development run exposed a real absent-field defect:
`{}` returned the missing `op` sentinel, which was then read as a node and
trapped. A separate subprocess control preserved that `SIGILL` observation.
An explicit sentinel guard now returns the original missing-terminator
diagnostic before any block append. The original source/image and failed log
remain preserved. Three later test expectation mistakes were corrected
without changing product policy: VM reports are dictionaries, error text
includes its category prefix, and a syntactically valid compiler provenance
hash is not a runtime proof. Their failed run also remains preserved.

Subsequent development runs passed 17 component controls, all seven generic
graph controls and the unchanged 75-test native-selected panel. The final
candidate adds retained nested-suite and actual-machine controls. Independent
review, combined native-owner integration, and a fresh complete source-bound
cold/full regression remain required before this component can support any
broader delivery claim.
