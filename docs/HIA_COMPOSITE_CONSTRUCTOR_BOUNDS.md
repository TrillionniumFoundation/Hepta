# Constructor candidate: bounds and outer-owner interface

This is an implementation argument for the isolated constructor candidate. It
does not establish current-source cold qualification, activate a default path,
or justify removing the retained implementation. The recovered implementation
base is `f50b37543d1a379353267ce0ab7111242806b8b4` plus the frozen full-function
overlay. The older design document records the pre-restart design context;
the current source identities are in the development stage manifests.

## Original input bounds

The public verifier admits a detached exact JSON tree before nominal
elaboration. Let `N <= 262144` be its value-node count and `B <= 8388608` its
canonical JSON byte count. Dictionary keys are not additional value nodes,
but there are at most `N - 1` dictionary edges/keys. The typed packet uses a
16-byte header per value/key, 8 bytes per container count, and scalar payload
bytes no larger than their canonical JSON spelling. Thus the complete
`[document, legacy_bool]` packet is at most

`40*N + B + 41 = 18874409 bytes`.

This is below the unchanged 64 MiB generic input region. The packet wrapper
adds one nesting level; the generic transport's 128-level/1048576-node framing
ceiling is above the original public structural ceiling, including key nodes.
It does not replace the public source bound. Exact unsupported Python objects
are not another admission route.

## Constructor arena charging

The HIA constructor stores source references and issued type IDs. It never
expands a type layout or Core body. The arena begins at `64 MiB + 65536` inside
a 192 MiB workspace, leaving 134152192 bytes. Allocation is rounded to 8 bytes;
the following charges include this rounding.

For each successfully admitted formal parameter, the response ID costs 8
bytes, its complete parameter-row IR and linked-list segments cost 192 bytes,
and its name hash table costs less than 64 bytes per parameter. A zero-entry
table costs 32 bytes and is charged to the function constant. Each formal has
at least three source value nodes (the parameter object, name, and type).

For every return reference, its request IR costs 160 bytes, the response ID
costs 8 bytes, the retained ID vector costs 8 bytes, and its return-list IR
costs 64 bytes: 240 bytes total. In v4, a null origin adds 16 bytes of checked
slot metadata and 64 bytes of IR, for a total charge of 320 bytes per return.
This includes the implicit null-origin case, which adds no annotation source
nodes.

A nonnull v4 origin adds at most 352 bytes: 16 checked-slot bytes, at most 144
bytes for a length-prefixed 128-byte ASCII parameter name, and 192 bytes of
origin pair/list IR. Together with its return, that is at most 592 bytes. A
successful nonnull annotation requires at least three additional source value
nodes (annotation object, parameter name, and field-path list). Its combined
592-byte charge is therefore below 320 bytes per source node. Invalid origin
responses are refused; an ordinary native origin error emits no origin payload
and cannot exceed the successful allocation case.

These return and parameter nodes are disjoint source occurrences. Repeated
immutable strings and repeated type references still count separately in the
public source budget. A typed request is issued once per source occurrence;
response replay and phase changes refuse. No memory bound relies on input
object deduplication or caching a previous admission.

The remaining fixed IR, request envelopes, zero-parameter tables and registry
rows fit conservatively in 4096 bytes per function. Every concrete task uses
one resolution and one protocol request; 4096 bytes per declaration covers
both and their response IDs. A further 65536 bytes covers the global function
name table, initialization, final state envelope, and fixed list heads. With
the unchanged `F <= 1024` functions and `D <= 128` definitions, a conservative
total arena bound is

`320*N + 4096*F + 4096*D + 65536 = 88670208 bytes`.

This leaves 45481984 bytes below the actual arena capacity. The proof is about
the HIA arena, not the Python interpreter's RSS. Source custody indexes,
materialized objects and the separately bounded 128 MiB native type state are
distinct allocations. The temporary constructor arena is released before the
complete function session allocates its own arena. Final state and typed
request streams use fixed 64 KiB chunks; no additional total-output quota is
introduced.

## State and continuation boundaries

Initialization stages preserve absent attributes separately from empty maps:
no owner fields; document/counters/profile; committed native type owner and
returned-loan flag; and finally all five ordered inventories. A v4 origin row
is committed before effects, while its function and signature are committed
after effects. Every return resolves before the stored-loan gate. Unused task
validation happens after all signatures and follows declaration order.

The bridge publishes only native-issued complete state. Requests use a
detached packet index; final source references use an exact, byte-bound index
of the caller's already detached objects. This preserves document/function
identity aliases while isolating service inputs. The complete source packet
is read back before committing source references. Native type cache/work
changes are never rolled back.

Visible resume phases are 10, 30, 41, 50, 81, 82 and final 2000. Request kinds,
request sequence, initialization stage, issued phase and profile must agree.
A response is consumed once. Malformed native frames refuse at the bridge;
malformed input/response buffers poison the HIA workspace itself. Both levels
need actual boundary tests; a source-level argument alone is insufficient.

## Future complete outer `lower` owner (design only)

The retained outer method still controls source-function order, appends helper
functions, checks Core function/block inventories only after all functions,
sorts eligible primitive exports, and constructs the final program envelope.
These semantics are not part of this constructor change.

A future indivisible HIA outer owner should hold the source function cursor,
the persistent native function session and helper append identities. It must
request every complete function in source order before applying the existing
final inventory check. Early per-function output-size refusal is incorrect:
a complete function can exceed 8 MiB, and a later function error must still
precede the final outer expansion refusal.

The generic codec can retain complete native-issued function objects under
opaque, single-session object identities. HIA would choose the final function
and helper reference sequence and return the entire program IR. The host
would only materialize those issued objects, without interpreting an assembly
plan, counting blocks, choosing exports, or sorting names. Function/block
counts must originate in the native function owner. Export classification
must read its issued native type descriptors, and sorting must be HIA-owned.
The public primitive verifier must still independently admit the completed
Core. This proposed interface needs separate correlation, large-output,
error-order and installed-package evidence before activation.
