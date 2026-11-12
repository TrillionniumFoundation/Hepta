# Initializer native table operations — private ABI r2

NEW UNEXECUTED source. This component does not inherit generation, B3, native
or ordinary Worker results from initialization-values or initialization-sequence.

## Semantic scope

The kernel constructs the exact string-key dictionaries needed by the complete
ordinary initializer, from actual issued immutable HIAGRF01 values. It replaces
the pure-value work behind sequence peers TOOLS, MAPS and LOOKUP. It does not
open a namespace, call Store.profile/json/put, parse a tool catalog, validate
catalog vocabulary, resolve a path or grant authority to a foreign Graph.

The source-bound current catalog uses string names. Profile/resource keys are
the original fixed strings. Missing lookups or non-string/unhashable keys in a
fabricated private input are ABI refusals, not a new public KeyError/TypeError
policy. Full catalog loading and original exception timing remain a separate
complete service. This is not a general Python mapping API. It adds no ordinary
language quota or root, node, scalar, command or output total limit.

All source nodes remain at the same IDs in an emitted Graph. Original edges and
pool bytes remain exact; only scalar offsets shift to the new pool location.
Every new dictionary points directly to the original source key and value IDs.
Repeated values and nested container aliases therefore remain shared. A new
immutable map generation does not mutate an older mapping or borrowed source.
The full initializer publishes current generations at its original attribute
update points; no earlier namespace effect is performed here.

## Input and command

ABI wrapper is RWW and borrows the second argument read-only. Semantic arguments
are source Graph R, exactly 192-byte command R, and private workspace W. Minimum
workspace 4096 bytes. The complete initial workspace is zero.

The command is 24 little-endian u64 words:

| Word | Meaning |
| --- | --- |
| 0 | HIAWMC01 |
| 1 | BEGIN 1; same-operation GROW continuation 2 |
| 2, 3 | Nonzero invocation and call |
| 4 | Zero initially, preceding native event sequence on GROW |
| 5 | Operation 1..6 |
| 6, 7 | Actual source Graph lease and exact extent |
| 8 | Fresh nonzero output Graph lease, distinct from source; zero for lookup |
| 9..12 | Source IDs a, b, c, d |
| 13 | Source string key ID |
| 14..23 | Zero |

The source has the exact established Graph layout. All node/edge/extents,
container identities, scalar integer magnitude representation and reserved
words are validated using six exact source helpers extracted from frozen
initialization-values r2 (SHA256
9a786c3d3982b736bd068eb522b8b8d7649da80bd4813f9c235e2c83461a95ac).
Complete string UTF-8/surrogatepass validity and semantic dictionary issuance
remain properties of the actual fixed source issuer. Header checks correlate
that immutable lease; they do not authenticate a replaceable external arena.

## Operations

| Op | Inputs | Exact output |
| --- | --- | --- |
| 1 | a = current complete catalog; other arguments zero | The original comprehension {t["name"]: t for t in catalog["tools"]}. Duplicate string names retain their first insertion position and first equal key ID; the last complete tool object supplies the value. |
| 2 | All argument IDs zero | Two distinct empty dictionaries. |
| 3 | a,b = current profile and profile-artifact maps; c,d = actual complete returned values; key = original name string | Two new current maps after the ordered same-key assignments. An existing key retains its position/key ID; a new key appends. |
| 4 | a = ordered list of two-element list/tuple bindings [key,value]; others zero | Complete resources dictionary. The ordinary initializer supplies the original six bindings; no six-element transport quota is added. Duplicate strings follow the same first-position/last-value rules. |
| 5 | a = resources map; c = actual returned artifact reference; key = original name; b,d zero | New current resources map after one assignment. |
| 6 | a = complete profile-body map; key = original requested fixed name; b,c,d zero | Exact original value root borrowed from the source Graph, without new allocation/copy. |

Map operands are required to be actual semantic string-key dictionaries.
The kernel checks uniqueness and string keys of each map it updates or looks
up. The catalog and bindings constructors deliberately perform last-value
replacement in source order. No namespace artifact schema is manufactured.

The API is a Graph operation component. Sequence HIAWIR01 publication still
requires the actual native generic registry/merge wrapper to join independent
issued sources and register the returned roots as typed value handles.
A Graph ID is never treated as an already-issued namespace or Path capability.
No Python dictionary construction is permitted in that eventual runtime join.

## Event and memory

Return 640 places a 16-u64 HIAWME01 event at workspace offset 512:

| Word | Meaning |
| --- | --- |
| 0 | HIAWME01 |
| 1 | 0 complete; 1 GROW; 2 private refusal |
| 2..5 | Invocation, call, event sequence, operation |
| 6 | Exact workspace requirement |
| 7 | Result owner: 1 original source, 2 current workspace, zero without result |
| 8, 9 | Result Graph offset and exact extent |
| 10, 11 | First and optional second result root IDs |
| 12 | Actual source lease for lookup, requested fresh output lease otherwise |
| 13 | First refusal reason |
| 14 | Constructed unique binding count |
| 15 | Zero |

BAD 0xfffffffd takes priority over any stale event. Completion and refusal are
single-use. Every valid event advances sequence; overflow retires the workspace.
A short workspace cannot safely retain poison and must be retired by the caller.

Ops 1/4 use a native pair table at 4096, reserving sixteen bytes per source
record. The output Graph follows that table. All other emitted operations
begin the output at 4096. Node/edge/pool totals and every addition/multiply
are checked in u64 before allocation. Source pool and complete old graph are
copied in disjoint ranges, using the existing CopyBuilder byte-span intrinsic.
The new graph contains one or two additional map nodes, and the exact new
dictionary edges; it does not add a copy of every referenced value subtree.

GROW only repeats this pure construction against the same immutable source
and command (apart from BEGIN/CONT and the event sequence). It never repeats
an actual Store call. A smaller-than-needed resize continues to return GROW;
the caller preserves all state bytes and never treats a partial result as
published. Resource exhaustion is a physical carrier result, not a new
language-level rejection.

## Revision history and required tests

The first unexecuted draft used a manually packed tools literal with an
incorrect numeric constant. Revision 2 derives both tools and name bytes via
the author's existing ASCII magic function. No execution result is invented
for that static correction; r1 remains a separate Git blob.

Required fresh tests compare complete ordered values, key/value source IDs,
nested alias custody and source immutability for all six operations, including
duplicate catalog names, replacement/append, empty maps and Unicode keys.
Exact/one-short growth, invalid command/state/IDs, source changes, stale
continuations and terminal reuse need actual entry controls. Large borrowed
scalar/pool tests must retain the original 90 CPU / 180 wall / 1 GiB group gate.
Compiler limits remain 10 CPU / 20 wall / 256 MiB with exact historical f50 B3.
