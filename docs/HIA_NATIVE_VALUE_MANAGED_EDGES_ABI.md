# Native managed Value edges and deferred operations

This checkpoint adds actual managed capability edges to the one Value arena. It
does not claim completed public callable invocation or Future cycle integration.
Those require the fixed native providers and their independent coupled gates.

## Construction

The new component format is HIABVP07: 14 roles, a 136 byte header, and the mode
word at offset 128. The 14 lengths start at offset 16. Existing HIABVP06 and
earlier packer sources remain unchanged.

Role order is owner, core, import, export, capture, format, number, dict_iterator,
classes, class_mro, records, resources, protocols, callables. The last role
currently implements the managed edge operations below. A role name is not a
qualification claim for public function execution.

The six word entry and 256 byte Value context remain unchanged. Its fixed
mechanical bridge contains the original syscall and role calls, captured native
finalizer dispatch, captured code-provider dispatch, and a call back into its
own entry. Requests never select a function pointer or a Value context. The
code-provider context slots 192–223 and Future-provider slots 224–255 are
reserved for enclosing native initialization. No provider is opened merely by
the existence of these slots.

## Actual graph ownership

A normal capability is an external root. Private adoption transfers one
existing capability token to a native resource object's managed edge list. The
token continues to identify the same Value object, but the collector traces it
from that actual resource rather than treating it as an independent root.

Capability node offset 40 records its owning resource; 64 and 72 link the
resource's list. Resource object offsets 112 and 120 hold the list head and
count. Arena offset 1072 counts managed tokens. Publication and transfer happen
under the actual Value mutex. There is no host graph or reconstructed pointer
table.

The collector traverses these native edges, including when the resource is on
the finalizer queue. A finalizer ACK cannot retire a resource while its managed
token list remains nonempty. The actual native producer must release its
result/exception/environment tokens, with confirmed consumption, before ACK.
This is necessary for a Future that stores itself or participates in a larger
cycle; the full Future cycle gate is a separate requirement.

## Private Q05 operations

All requests use the existing 128 byte header: magic at 0, operation at 8,
reserved zero at 16, A/B/C triples at 24/48/72, tail length at 96, arguments at
104/112, and reserved zero at 120. These operations have no tail. Unused
triples and arguments must be zero.

| Operation | Inputs | Actual operation |
| --- | --- | --- |
| 77 | A strong native resource Value, B ordinary Value token | Transfer B from an external root to A's managed edge list. Repeating the same transfer to the same owner is idempotent. |
| 78 | A ordinary or managed Value token | Consume the actual object capability, perform ordinary graph collection, and defer native resource finalizers for this entry only. Actual context tokens are rejected. |
| 79 | A owner, B its managed token | Restore B as an external root without allocating or replacing the token. |
| 80, argument 0 | A strong native resource Value | Return its weak identity. This is an object offset and two actual random tags, not an owned capability. |
| 80, argument 1 | A weak triple from mode 0 | Search the actual live object list, verify binding and tags, and publish a fresh ordinary strong capability. Queued resources cannot be revived. |
| 91 | A ordinary or managed object capability | Publish an actual ordinary retained capability without running resource finalizers during this entry. |
| 92 | A nonzero actual context-token capability | Consume that real token without running resource finalizers. This operation does not accept an object capability or the zero anchor shortcut. |
| 93 | No capabilities or arguments | Retry actual arena mapping retirement without draining the native resource queue during this entry. |

Operations 77, 78, 79, 92, and 93 return HIABVR02. Pending, known, and
consumed appear at 80, 88, and 96. For 77/79, consumed means the actual ownership
transfer occurred; it does not mean B's capability token was deleted.

Operations 78, 91, 92, and 93 additionally return:

| Offset | Meaning |
| --- | --- |
| 104 | Actual arena mapping retirement is pending. |
| 112 | Native resource queue custody is pending. |
| 120 | 1: this entry deferred resource finalizers. |

The global pending field at 80 is the union of the actual states. Native
producers may clear a token they actually consumed even when the enclosing
Value resource queue is still pending. They retain local arena-retirement
custody when 104 is nonzero. They must not treat their own enclosing resource's
112 queue entry as an unconsumed local token and wait for themselves.

Operation 91 uses HIABVR01, ordinary kind at 16, retained capability at
24/32/40, size at 48, and the explicit fields above. A published capability
remains delivered independently of pending cleanup. Before-publication failure
returns known 1, consumed 0, and no capability.

Operation 80 uses HIABVR01, kind 8, triple at 24/32/40, and actual native
resource kind at 48. A dead or mismatched weak identity returns status 3; an
already queued resource returns status 6. The weak triple is private native
coordination data and must not become a public authority bypass.

## Private Q06 profile

HIABVQ06 preserves the complete ordinary request and response format, including
a variable-length payload. It changes only the resource-drain phase of that one
entry. The fixed bridge records the profile in its private stack, after the
HIA owner validates the request. There is no shared-context skip-finalizer
flag for another thread to inherit.

The precise allowed operation set is:
2, 4, 7, 8, 9, 10, 17, 19, 21, 26, 32, 36, 37, 38, 39, 49.

These are the actual operations required by the managed Future profile:
scalar/dictionary construction; kind, length, byte copy and identity;
dictionary get/set; token creation; inherited-object inspection; canonical
class, actual type, isinstance, class metadata and attribute lookup; and
trusted native resource extraction. Their original validation and publication
rules remain in effect.

Retain/drop/token release/retry use the explicit operations 91/78/92/93,
rather than broadening the Q06 set. Public enclosing transports must reject
the entire Q06 magic and the private Q05 operations. Only a captured native
consumer can select this profile.

Q06 never grants permission to run user code under a Future mutex. If a future
implementation adds custom equality/hash or callable behavior to an operation,
that invocation must be scheduled outside the Future lock. Current default
Value dictionary operations do not execute user code.

## Resource kinds and fixed bindings

Future is canonical class 37 and native resource kind 7. Kind support still
requires the actual enclosing native support mask; this Value component does
not turn on kind 7. Its native producer must supply real, unforgeable compound
carrier custody and release it through the fixed finalizer.

The current finalizer binding at context 128/136/144/152 requires extent 256.
A provider with a different context extent therefore needs a fixed native
adapter with its own captured provider entry/context/nonce. A request cannot
supply such a binding. The Future provider slots 224–255 are independent and
may capture the actual 512 byte provider context.

## Qualification scope

The component's new gate calls the Value entry captured by a real native
Runtime/Lease owner. It creates actual carrier resources and verifies adoption,
restoration, dead/queued weak identities, 64 KB Q06 payloads, all 16 allowed
operations, eight-thread contention, malformed private frames, actual
getrandom refusal, and actual native unlink EIO followed by successful
outside-lock cleanup. It does not edit native locks, capabilities, bindings,
node headers, or finalizer receipts.

The ordinary token-creation failure gate confirms that strict successful
transport with a valid HIABVR01, nonzero status, and a zero returned triple
has not published a token. Nonzero triples must always be preserved; malformed
or uncertain transport is not evidence of non-consumption.

Original component gates, original six campaign budgets, callable source-code
execution, public exceptions, and Future graph cycles are separate recorded
qualification fields. The whole public runtime remains unqualified until the
enclosing task closes all of them.
