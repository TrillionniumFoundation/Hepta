# Worker initialization values — native projection ABI r1

Development source only. The exact Service constructor, profiles/resources
sequence, filesystem/namespace effects and three independent installation
observations remain separate integration obligations. This component constructs
the complete profile bodies, diagnostics, final manifest and example/guidance
values. It does not interpret a reduced Worker API.

## Exact source and immutable data

The authoring data generator reads exact 0ef service and macro-discovery sources.
It extracts their original dictionary/list expressions. Only the nine declared
dynamic values become opaque markers; all static fields, ordering, schemas,
negative capability claims, integers and binary64 0.0 remain original.
The generated data is part of the source-bound application, not externally
supplied configuration. Its whole bytes/hash and the native image are pinned
together before mapping. It is never modified during execution.

The HIA projection receives two read-only private mappings: an issued HIAGRF01
source value arena and the immutable compiled literal packet. The latter has a
64-byte HIAWVT01 header, six 128-byte records, then exact Graph data. The record
contains mode, Graph offset/extent/lease, nine placeholder IDs and three reserved
zeros. HIA validates its structural boundaries and derives every output offset.
Matching headers are correlation only, not a content authenticator.

Modes are complete values:

1. All seven profile bodies in original order, including actual installation,
   catalog digest, resolved-root count and actual root-list digest.
2. Complete original diagnostics discovery document.
3. Complete final manifest containing actual installation, catalog identity,
   all profile references/artifacts and all nineteen resource references.
4. The exact initial discovery_identity program.v6 document. Its shared
   parameter list is retained. This does not itself admit the program.
5. The complete examples result with actual admitted Core and actual assembly.
   Verification, the renderer's internal verification/round-trip and the fresh
   explicit assembly/hash comparison remain mandatory upstream witnesses.
6. Complete macro_policy_guidance value with actual installation contents.

Mode 6 concerns the value serialized immediately by Store.json. It does not
claim generic Python object identity compatibility for calling the standalone
deepcopy-based helper and subsequently mutating the returned in-memory values.

## Command, workspace and event

Retained calling convention RWW. The entry borrows the second input read-only,
therefore semantic arguments are source R, literal packet R, private workspace W.
Minimum workspace is 4096 bytes. The first 4096 bytes are zero except the
24-word configuration at offset 128:

| Word | Meaning |
| --- | --- |
| 0 | HIAWVC01 |
| 1, 2 | nonzero private invocation and call |
| 3, 4 | actual source Graph lease and exact extent |
| 5 | complete value mode 1..6 |
| 6 | nonzero output Graph lease |
| 7 | actual installation Graph root |
| 8 | actual catalog digest string root |
| 9 | ordered resolved-root list/tuple root |
| 10 | actual canonical root-list SHA-256 string root |
| 11, 12, 13 | actual profiles, profile-artifacts, resources map roots |
| 14, 15 | actual admitted example Core and actual assembly roots |
| 16..23 | zero |

Only markers used by the selected mode require their corresponding roots.
Digest roots must contain exact lowercase 64-character ASCII SHA-256 text.
Container inputs use the node-based identities emitted by the actual DataGraph
and existing private Graph capture/merge issuers. The component does not accept
an arbitrary Python object graph as an independently authenticated artifact.

The native result is return 640 with a 128-byte HIAWVE01 event at workspace 512:

| Word | Meaning |
| --- | --- |
| 0 | HIAWVE01 |
| 1 | 0 complete, 1 GROW, 2 ABI refusal |
| 2, 3, 4 | invocation, call, monotonically advanced event sequence |
| 5 | selected mode |
| 6 | exact required workspace bytes |
| 7, 8 | output offset 4096 and exact output Graph extent |
| 9, 10 | actual output root ID and output Graph lease |
| 11, 12 | source and literal Graph node counts |
| 13 | first ABI refusal reason |
| 14, 15 | zero |

A return 0xfffffffd takes precedence over any stale event. After the first
full-workspace ABI refusal every entry returns BAD. A workspace shorter than
4096 cannot safely hold poison; the fixed caller must immediately discard it.
Completion is single use. GROW copies the entire old workspace, holds both
original input mappings immutable, then calls this same image again. GROW does
not repeat any namespace, filesystem, JSON/wire, hash or assembly operation.

## Projection and capacity

Every existing source node keeps its original ID. HIA appends the complete
selected constant Graph, relocates all node/edge/pool offsets, substitutes its
dynamic edges with the actual source roots and writes canonical little-endian
root-count magnitude itself. Static opaque marker nodes may remain unreachable;
they are not published as output values. The output root points to the complete
new value. Scalar bytes, dictionary order and shared container references remain
unchanged.

Output nodes = source nodes + selected template nodes.
Output edges = source edges + selected template edges.
Output scalar pool = both complete scalar pools + at most 8 root-count bytes.
Required workspace = 4096 + 64 + 64*nodes + 8*edges + scalar-pool bytes.
Every sum and product is checked for u64 overflow before output writes.
There is no new 8 MiB, node, command-count or descriptor-count quota here.
The original ordinary wire/Store.json limits still occur at their original
later service calls. The fixed caller owns physical allocation failure.

Structural Graph checks run before the initial capacity decision. This is not a
new public admission API: complete string validity and the identity of actual
namespace/file/source results still come from their issued private services.
The fixed caller must not substitute a different same-header arena on GROW.

## Required next evidence

Fresh source generation and original 0e09 B3 compilation with the unchanged
10 CPU / 20 wall / 256 MiB compiler gate. Actual image cases must compare all
six complete values and their full ordinary wire bytes against the original
service methods, with old value construction disabled during native entries.
Tests must retain dynamic identities, Unicode, zero/large root counts, shared
source objects, exact/one-short growth, header/extent/placeholder mutations,
completion replay, poison and source/canary checks.

The initializer FSM must separately enforce all resolves before is_dir, build
all bodies before the first profile write, publish exact partial prefixes,
perform all nineteen resources and complete _examples witnesses, then submit
the final manifest. Foreign Store or file fixtures prove only this owner's
decision ordering, never an ordinary initialized Worker.
