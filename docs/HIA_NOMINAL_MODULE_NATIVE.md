# Native nominal module producer

`nominal_module.hiaasm` owns the complete module-production policy formerly
in `_Elaborator.lower`: original function order, helper suffix placement,
late whole-module inventory admission, scalar export eligibility, ASCII name
sorting, schema mapping and the complete returned Core object graph.
The unchanged original body remains `_reference_lower` for independent
comparisons while the product-wide replacement is still incomplete.

## Owner and bridge

The ordinary HIA entry requests each already-admitted original function in
document order. The fixed bridge invokes that function producer once and
retains its complete returned dictionary in a private external-value pool.
After all functions, HIA requests a stable outer snapshot of the produced
helpers. It checks the original 1,024-function and 4,096-block limits only
at this point. A function callback exception propagates unchanged; preceding
function/helper/type state is retained, and no export query takes place.

Only after the inventory check succeeds does HIA request the held signature
inventory. Descriptors contain the held type's kind and primitive flat layout;
IDs are assigned by object identity without nominal-key expansion or semantic
type comparisons. Admitted primitive types have exactly their key as their
one flat slot. HIA applies the original primitive-and-SCALARS predicate to
every parameter and return, then sorts the eligible function names by their
ASCII bytes. Native output chooses every module field, schema, export array
and function/helper array placement.

The adapter contains no opcode dispatch, Core-function reconstruction, export
predicate or sorting. It decodes the complete graph using the shared generic
external-value transport. Exact function/helper dictionary identities are
retained. Only the returned outer functions array is new. A later append to
the owner's helper list cannot alter that completed array.

This boundary assumes the existing admitted function owner: raw document
metadata is stable while those producers execute, and completed produced
objects are privately held without later mutation. It is not an adapter for
arbitrary user-supplied Python callbacks. Function/type admission and function
production remain separate owners and do not become native merely because
module aggregation is selected.

## Continuation protocol

The entry ABI is `(source: readbuf, output: mutbuf, workspace: mutbuf) -> u32`.
Private capacities are 256 MiB, 8 MiB and 8 MiB respectively. The workspace
retains a module-specific phase, exact monotonically increasing sequence,
function index, signature/export tables and private pool IDs. Only its initial
ownership word is required to be zero. A closed state refuses another call.

Initial immutable input is `[schema, module, function_count, nonce]`. The nonce
is a private 32-character context identity. The four complete typed children
are retained byte-for-byte and checked on every continuation, including their
exact extent. A hash is not used as an identity substitute. Function/helper
steps use only this small metadata packet. The signature step extends it with
the held type descriptors and signature rows at the original late query point.

The output region initially carries a fixed eight-u64 acknowledgement:
magic, sequence, action, index, pool ID, count, body size and reserved zero.
Function acknowledgements carry that completed function's block count;
helper acknowledgements carry all helper block counts. HIA verifies the
expected action, sequence, index, pool ID and body extent before advancing.
The result has magic, semantic error, requested action, index, sequence,
graph size, expected final pool extent and reserved zero. Continuations and
refusals contain a null graph. Success contains the complete module graph.
The only module semantic refusal is the original inventory E_HIA_LIMIT.
Malformed private frames are transport refusals, with no hosted fallback.

Graph tag 11 concatenates the private singleton-function arrays and the helper
snapshot, in the order selected by HIA. Previously generated instructions,
arguments and terminators are not serialized again and do not acquire a new
whole-program expansion quota at this boundary. A large complete function
can therefore pass through with a small wire receipt while the unchanged
later Core verifier retains its own original limits and refusal order.

## Capacity

Public admission remains 8 MiB, 262,144 value nodes, depth 64, 1,024 functions,
4,096 blocks, 128 cached nominal instantiations, 512 slots per nominal layout,
32,768 elaborated value slots and 8,192 generated names. Signature inventories
are not charged to the elaborated-value-slot budget.

Only signature-referenced types are projected here. Primitive descriptors can
occur at most once per source type occurrence; nominal and partial descriptors
share the existing at-most-128-entry type cache. Thus `D <= N + 128`, where
`N = 262144`, is below the 524,288-entry private type table. Counting all type
rows, their flat layouts, signature rows and argument/return IDs conservatively
as `8*N + 128*512 + 8*1024 + 64` gives fewer than 2.2 million typed nodes,
below the shared 8,388,608-node input bound. Even charging 24 bytes per node,
four complete public payload allowances and the cached flat-layout strings
stays below 96 MiB, within the 256 MiB input region. Private envelopes remain
below depth 128. The original 128-character identifiers are unchanged.

Fixed tables end at byte 4,227,080, within the 8 MiB workspace. The complete
output contains at most 1,024 export strings and 1,025 pooled-array IDs, well
within 8 MiB; earlier Core objects are held without a deep copy. Helper metadata
allows 262,144 entries, above the original generated-name limit, and reports
the original late inventory refusal instead of adding an earlier semantic
limit. These capacities describe this private protocol, not a larger language.

## Selection, packaging and evidence

Select a source/image-bound manifest with
`HEPTA_HIA_NOMINAL_MODULE_MANIFEST`. A selected missing, changed or malformed
source/image is refused. Installed wheels carry the ordinary HIA source and
run without importing the Python authoring tools. The common cold builder's
candidate name is `nominal-module`; tests accept a matching-source cold report
through `HEPTA_HIA_NOMINAL_MODULE_COLD_REPORT`. A development manifest is
explicitly separate and cannot override cold source custody.

Development controls compare the complete original modules for all four
nominal schemas, actual public Core verification, complete independent
VM/native frames and retained workspace bytes, callback exceptions and their
exact prefixes, late inventory refusal, 1,024 functions/exports, large held
argument arrays, replay/metadata/acknowledgement corruption, private bounds,
nonzero scratch and canaries. The unchanged original 75-test resource/partial
record/returned-loan suite runs with `_reference_lower` disabled. Installed
wheel controls and a real machine-code allocator/refusal/cleanup program also
disable that original owner. Manifest tampering is refused.

The first actual development image was compiled by retained predecessor
compiler `0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8`.
Its source digest is `57179a503f08a450e748088467753697d35cf48b1aab7d307a339b21c0785592`
and image digest `3ba4be206cf1266df3cab208cecc661d96cafe8cc32db7171f40c62b38629d17`.
It is development evidence. Whole-profile fresh cold qualification, combined
native-owner composition and full retained regression remain separate gates.
No native default, live-worker migration or old-stack deletion is claimed.
