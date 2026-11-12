# Complete Worker initialization sequence — private service ABI draft r2

This is NEW, UNEXECUTED development source. No HIA generation, VM entry, B3
compile, native entry or ordinary Worker qualification has occurred for this
sequence owner. The separate initialization-values component has its own
independent four-group CI submission. Its result must not be inherited here.

Author: tools/generate_hia_agent_worker_init_sequence.py, r2.
Exact reference: 0ef HIAAgentService.__init__, _profiles and _examples;
hepta/hia_agent_service.py 100742 bytes, SHA256
684caf496de7e3e7c8db1fd80ef616139cf13717aa5879bbd2d6ebf834df9330.

## Scope and remaining joins

The HIA code owns the complete original call order, seven-profile and
nineteen-resource loops, all attribute-publication points, path short-circuit,
fresh examples verification/render/assembly ordering, actual digest comparison,
and complete local error strings. It does not implement a host-readable
semantic plan. Each request is a single complete typed service invocation.

The service table below is a NEW private join ABI. It does not assert that
current namespace/Path/catalog services already implement it. Catalog,
installation, namespace, generic value custody and general public assembly
must be supplied by actual native owners and exact source-bound wrappers.
The fixed carrier only forwards actual HIA requests and actual peer replies.
It must never manufacture successful handles, parse values or replace a
service with a Python business callback.

The initializer uses 19 typed service selectors. This is not evidence that 19
complete peers have been joined. A foreign-fixture test can establish this
owner's ordering and state only. Ordinary initialization remains OPEN until
those joins execute under the fixed native carrier.

## Source, configuration and invocation lifetime

Retained ABI is RWW; the wrapper borrows argument two read-only. Semantic
arguments are immutable source Graph R, actual private peer reply R and
initializer workspace W. Minimum workspace is 8192 bytes. The initial second
input is empty. The initial workspace is zero except 24 u64 words at offset 128:

| Word | Meaning |
| --- | --- |
| 0 | HIAWIC01 |
| 1, 2 | nonzero invocation and call |
| 3, 4 | issued source Graph lease and exact bytes |
| 5 | source root ID |
| 6 | actual integer digit setting, zero or at least 640 |
| 7..23 | zero |

The source is an already-issued complete HIAGRF01 Graph. Its selected root is
[state_root_string, ordered_artifact_root_strings]. This is the ordinary
Worker's parsed administrator-input domain. It is not a new public admission
API for arbitrary PathLike objects or foreign Graph arenas. Complete Graph
and UTF-8/surrogatepass validation belongs to its actual input issuer.
The sequence kernel checks framing, selected node bounds and required kinds.

The source mapping and config remain immutable. Saved headers correlate the
same lease; they are not a cryptographic/content authenticator. A short
workspace or any BAD return must make the fixed caller retire the invocation,
even when the kernel cannot safely write poison or refresh an event.

The only variable workspace is 16 bytes per configured root after offset 8192.
It is reserved after Store.open completes, before the first resolve. There is
no new root count, command, output, node or byte language quota. All layout
arithmetic is checked against u64; allocation failure remains the carrier's
bounded physical-resource outcome.

## Actual typed reply

A service wrapper produces HIAWIR01 in its own readonly result mapping. It is
not a header that a Python dispatcher synthesizes from values. The initializer
receives that complete mapping as its second input.

Success is exactly 256 bytes, 32 u64 words:

| Word | Meaning |
| --- | --- |
| 0 | HIAWIR01 |
| 1, 2, 3, 4 | initializer invocation, call, pending event sequence, exact peer |
| 5 | zero success; one complete issued semantic exception |
| 6 | result-kind tag |
| 7 | actual native return observation, as bound by the service wrapper |
| 8, 9, 10 | up to three actual immutable value handles |
| 11 | actual typed authority handle when the selected service returns one |
| 12, 13, 14 | zero for success; issued exception lease, offset, bytes for failure |
| 15 | exact whole reply mapping extent |
| 16..19 | actual 32 digest bytes for kinds 7 and 11; otherwise zero |
| 20..31 | zero |

A semantic exception frame may append its complete issued exception at an
offset at least 256, within the exact mapping. Its exception lease is nonzero.
The initializer forwards that original exception view, without reclassifying
it as a post-service Worker UNKNOWN. Constructor failure precedes the outer
Worker's service_entered transition.

The successful kind and used handle fields are checked at the exact phase.
Unused success result handles and authorities are zero. Kind 5 is the single
boolean exception: result word 8 is exactly zero or one and authority word 11
must equal the actual pending resolved-Path handle.

A Graph value handle is not a Graph node ID, namespace capability or file
descriptor. The fixed issuer's typed registry owns the actual mapping, node
root, source/image identity, scope and lifetime. Namespace and Path authority
handles are different registry types. Matching header integers do not create
authority; no current namespace ABI is weakened to accept them.

## Native event and source views

Return 2304 places HIAWIE01 at workspace 2048, 32 u64 words:

| Word | Meaning |
| --- | --- |
| 0 | HIAWIE01 |
| 1 | 0 complete; 1 GROW; 2 pending service; 3 semantic exception |
| 2..5 | invocation, call, event sequence, continuation phase |
| 6, 7 | exact peer and pending sequence for action 2 |
| 8 | exact required workspace bytes for GROW |
| 9..12 | source lease, root, actual digit setting, current namespace authority |
| 13 | selected peer operation |
| 14..19 | six exact typed arguments |
| 20..22 | optional source-view owner, offset, bytes |
| 23, 24 | native literal offset 5120 and exact bytes |
| 25, 26 | partial-state snapshot offset 4096 and 512 bytes |
| 27..31 | error class, view owner, lease, offset, bytes for action 3 |

A view owner of 1 means the original source Graph; 2 means this workspace;
error owner 3 means the actual reply mapping. The carrier bounds every view,
holds it readonly for the service call, and does not interpret its contents.
No semantic operation is repeated for GROW.

Event sequence increments for every valid event. A pending service binds that
exact sequence. GROW after Store.open consumes and preserves that successful
reply before resizing, then resumes the local reserve/resolve phase. It never
opens the store again. Completion and semantic failure are single-use. ABI
refusal poisons every full-size subsequent entry.

## Full typed service mapping

| Peer | Complete operation / native result kind |
| --- | --- |
| 1 CATALOG | Actual installed tool catalog read, original json.loads semantics, all vocabulary checks and actual raw SHA; kind 1 returns catalog and digest value handles. |
| 2 TOOLS | Exact original name-to-tool comprehension, including ordinary duplicate/key behavior; kind 2. This occurs after catalog attributes publish. |
| 3 INSTALL | A fresh complete installed-source scan/hash observation, not the outer Worker's earlier result; kind 2. |
| 4 OPEN | Complete AgentStore(state_root), including all its original operations; kind 3 typed namespace authority. The request borrows the original source Graph and root ID. |
| 5 RESOLVE | Path(value).absolute().resolve(strict=True); kind 4 actual resolved-Path authority plus its issued internal text value. No directory test is hidden here. |
| 6 ISDIR | Complete original Path.is_dir behavior and result; kind 5 boolean with the same pending Path authority. |
| 7 ROOTS_VALUE | op 0 constructs the completed Path tuple from the native 16-byte path/text pairs, kind 6 tuple authority; op 1 performs the later ordered str(root) list construction, kind 2. The list conversion is after every is_dir succeeds. |
| 8 DIGEST | Complete ordinary wire(value) then native SHA-256 and lowercase digest value; kind 7. It retains original wire limits and first-error order. |
| 9 VALUES | Modes 1..6 of the complete initialization-values projection; kind 2. The actual generic registry/merge wrapper converts issued value handles into the projection's original Graph ID arguments, entirely in HIA. |
| 10 MAPS | Complete native generic value construction/update, described below. No namespace mutation. |
| 11 PROFILE | Complete Store.profile(name,body), including its own json/put/wire/decode/SQL order; kind 9 returns profile and artifact value handles. |
| 12 STATIC | Source-bound complete initial discovery values, selectors 1..6 in the exact order below; kind 2. |
| 13 FILE | Current installed resource read at the requested original stage; kind 10 byte-value handle. Files are not replaced by bytes cached during installation scanning. |
| 14 PUT | Complete Store.put(actual_bytes,'discovery'), including metadata/hash/publication/SQL behavior; kind 2 artifact reference. |
| 15 JSON | Complete Store.json(value,'discovery'), including every original wire/put step; kind 2 artifact reference. |
| 16 VERIFY | Complete verify_program(example_document); kind 11 verified-program, normalized-Core and digest value handles plus actual digest bytes. |
| 17 RENDER | Complete public render_assembly(verified_program), including its internal full verify and round-trip admission; kind 12 string and byte-value handles. |
| 18 ASSEMBLE | Fresh independent public assemble_program(returned_assembly); kind 11 and actual digest bytes. No cached first admission substitutes for this call. |
| 19 LOOKUP | Native exact dictionary lookup of the requested profile body; kind 2. |

MAPS op 1 creates two distinct empty maps and returns kind 8/two handles.
Op 2 updates both current profile maps under the exact native key, returning
kind 8/two new current map handles. Op 3 constructs the initial resources map
from six records [keyOffset,keyBytes,valueHandle,0], then literal key bytes;
the record offsets are relative to the request view. Op 4 updates one current
resources map under the native key. Ops 3 and 4 return kind 2/one handle.

No MAPS operation performs Store.profile/json/put or acquires namespace
authority. Intermediate immutable generations remain issued until the fixed
owner can release them without invalidating any current value or pending view.

VALUES normally receives identities/catalog digest/root strings/root digest/
actual example Core/actual assembly in its six argument words. Mode 3 additionally
borrows three handles in order: profiles, profile artifacts, resources. The
complete actual projection still receives all nine roots under its own ABI.

STATIC selectors 1..6 are schema_registry(), WORKLOAD_SCHEMA,
OBJECTIVE_SCHEMA, COST_POLICY_SCHEMA, PLAN_SCHEMA, proof_contract_description().
Their whole values retain current fields and negative/unsupported claims.
Root's language catalog is not a substitute for the eleven-tool catalog.

## Exact original state and order

Constructor phases 1..14 execute catalog, tools, fresh installation, Store.open,
all strict resolves, tuple publication, ordered is_dir, ordered string-list
creation and complete root-list digest. A later resolve error therefore occurs
before any earlier is_dir result. The empty roots case still constructs the
empty tuple and digests the empty list at the original points.

Phases 30..35 build all seven bodies, then create both empty profile maps and
publish each pair only after that complete Store.profile returns. The fixed
profile order is compiler,target,backend,artifact,validation,lowering,plan.

Phases 40..43 perform all six initial resource value/JSON calls before resources
becomes present. Earlier completed Store effects survive a later failure.
Phases 44..47 do each current installed file read, complete put and map assignment
in order. The ten exact original filenames are embedded in the HIA source.

Phases 60..69 publish macro guidance, construct the exact discovery example,
perform verify/render/fresh assemble, compare all 32 actual digest bytes in
HIA, build the complete example return and publish it. The original RuntimeError
is emitted on mismatch: discovery example does not round-trip.

Phases 70..74 publish diagnostics, construct the final complete manifest from
current maps, then perform its separate final Store.json. Only the final actual
returned artifact reference assigns manifest.

The 512-byte HIAWIP01 snapshot contains invocation/call and a presence mask.
Bits 0..8 mean catalog+catalog_sha256,tools,identities,store,artifact_roots,
profiles,profile_artifacts,resources,manifest respectively. Zero absence is
different from an issued empty map. Subsequent words hold those actual current
handles, resolved/dir/profile/resource counters, root-array view and internal
root-list/digest/body handles. The fixed registry must materialize complete
values only for independent comparison; it cannot decide what state to publish.

Local semantic error class 1 is AgentRejected with the complete
E_HIA_PROFILE: configured artifact roots must be directories message and its
original code/default retry semantics. Class 2 is the original RuntimeError.
Class 0 forwards the complete actual peer exception. Fixed Worker report code
must preserve those domains and the original service_entered timing.

## Next mandatory proof

Fresh original-limit generation/B3 compile; compare the entire ordered trace
and exact partial attributes against the full original constructor on empty and
multiple roots, every peer failure, every profile/resource publication boundary,
example verify/render/assemble/mismatch, wrong/replayed ACK, source replacement,
GROW and sequence overflow. No earlier component PASS is counted again.

Then connect actual native value projection/Graph merge/ordinary wire/SHA,
catalog/vocabulary/installation, Path, namespace and full assembly owners in the
fixed executor. Synthetic successful frames may be used for clearly labelled
private control tests only. This draft does not report that those joins exist.
