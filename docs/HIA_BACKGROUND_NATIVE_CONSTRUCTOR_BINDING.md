# Background constructor verification and runtime binding

This is an offline source checkpoint. The original authoring verifier accepts
all three HIA sources, and development source/effect checks pass. The HIA
components have not been compiled and executed on the native build host. The
complete BackgroundOptimizer constructor, worker lifecycle and public class
carrier remain open.

## Position in the original constructor

The original constructor checks the actual runtime class first, then exact
options and bridge keys. It iterates the real bridge dictionary while each Path
conversion and resolution runs. Only after those steps does this component run:

1. Invoke the captured complete native verifier on the actual baseline value.
2. Read the actual function value and require an exact string in the freshly
   verified program's scalar entrypoints.
3. Clone the actual runtime reference and obtain one actual locked snapshot.
4. Hash the fresh canonical Core and original input bytes with the captured
   stream SHA role, and bind them to that snapshot's baseline and current source.
5. Transfer independent baseline, function and runtime references after cleanup.

The enclosing constructor must perform the preceding stages. Provider clone 3
does not prove the original isinstance predicate. The current public runtime
class gate is still missing; a generic provider failure is not a wrong-class
exception. The bridge result must contain actual Path objects, not merely the
internal resolved string representation.

The function check uses the original `VerifiedProgram.scalar_entrypoints`
semantics: explicit exports when present, otherwise all functions whose
parameter and return types are scalar. It imposes no sixteen-function MV limit.
Function strings are read as the value owner's actual WTF-8 bytes. A lone
surrogate is a nonmember and produces the ordinary function rejection; it is
not prematurely passed through a JSON encoder. A function whose byte size
exceeds the complete Core wire cannot equal any decoded name in that wire and
can be rejected without allocating its full representation.

## Closed component

The fixed six-word entry is `hia_background_constructor_binding`. The
mechanical adapter has two fixed HIA roles, policy and checks, and no imported
library functions. It performs only actual syscalls, checked view relocation,
byte copies and captured six-word calls. HIA controls every allocation length,
dependency call, phase and ownership transition.

The HIA packer accepts HIABCBP1 with exactly those two components. It retains
the existing 4 MiB component and 16 MiB text domains. The generated bridge is
516 bytes; local mechanical assembly has no external relocation. Mechanical
assembly is not qualification of the HIA policy.

## Request

The request is exactly 128 bytes. Operation 0 runs the constructor segment;
operation 1 resumes only a retained cleanup frame and accepts zero capabilities.

| Offset | HIABCBQ1 | HIABCBQ2 |
| --- | --- | --- |
| 0 | Request magic | VerifiedProgram request magic |
| 8 | Operation | Operation |
| 24 / 32 / 40 | Actual baseline value capability | Actual canonical-bytes capability |
| 48 / 56 / 64 | Actual function value capability | Same |
| 72 / 80 / 88 | Actual runtime capability | Same |
| 96 / 104 / 112 | Zero | Optional actual structured-bytes capability |
| Other words | Zero | Zero |

The second shape is used only by the enclosing actual VerifiedProgram class
carrier. It does not trust the contents: the complete verifier freshly checks
both canonical and structured values through its new HIABVFY4 profile. The
ordinary shape uses HIABVFY3. New verifier profiles are still awaiting native
qualification as part of the explicit-consumption migration.

## Captured context

W is an independently owned, exclusive 16384-byte frame. Its context magic is
HIABCBX1. The enclosing native class owns all code, context records, descriptors,
threshold data and input capabilities until this call and any retained cleanup
finish. No public request supplies these bindings.

| Offset | Captured binding or private state |
| --- | --- |
| 8 / 16 / 24 | Actual value entry / context / extent |
| 32 | Complete verify_program entry |
| 40 / 48 / 56 | Immutable payload entry / context / extent |
| 64 / 72 / 80 | Runtime provider entry / context / extent |
| 88 | Actual dynamic JSON capture entry |
| 96 | Actual stream SHA entry |
| 104 | Owned sealed normalizer descriptor |
| 112 / 120 | Captured integer threshold pointer / extent 10100891 |
| 128 | Lossless value transport entry |
| 136 | Checked sorted freezer entry |
| 144 | Typed structure entry |
| 152 | Complete value-freeze entry |
| 160 | Complete verifier process entry |
| 168 | Original raw preflight entry |
| 176 | Captured integer conversion limit: 0 or 640..INT_MAX |
| 184 / 192 / 200 / 208 | PID / retained flag / original output identity / quarantine kind |
| 216..255 | Zero |
| 256..2175 | Saved private continuation |
| 4096..8191 | Private HIABVYC2 verifier context |
| 8192..9375 | Private stream SHA state |

The fixed new verifier reply HIABVFR2 is checked for both cleanup at 56 and
quarantine kind at 64. Only kind 1 permits its cleanup operation. Kind 2 and
contradictory headers retain the whole frame and are never replayed. A nested
cleanup can return a real owned payload; the binding owner receives and releases
that payload instead of treating cleanup as an empty acknowledgement.

O is at least 262144 bytes. The verifier uses a separate owned output mapping,
so its private state cannot alias this owner's control fields. Core capture and
checks use capacities computed from the actual fresh input. Snapshot generation
and epoch bytes retain full length; the owner adds no word-width or small output
limit to those counters.

## Result and ownership

The public extent of the private reply is 256 bytes, magic HIABCBR1.

| Offset | Meaning |
| --- | --- |
| 8 | Status: 0 complete, 1 original exception, 5 allocation, 6 lifecycle, 7 dependency, 8 OS, 9 retained/invariant failure |
| 16 / 24 / 32, 40 | Successful owned complete HIAVCF01 payload and byte length |
| 48 / 56 / 64 | Successful independent runtime reference |
| 72 / 80 / 88 | Successful independent function value reference |
| 96 / 104 / 112, 120 | Original exception payload and byte length |
| 128 | Error format: 1 trusted native driver diagnostics, 2 original typed class/code/message, 3 original provider type/message |
| 144..175 | Actual canonical Core SHA256 on success |
| 176..207 | Actual original-input SHA256 on success |
| 208 / 216 | Quarantine kind / detail |
| Other bytes | Zero |

Formats identify the fixed producer of an error. They do not turn an arbitrary
JSON dictionary into an exception. The enclosing constructor performs the
existing trusted exception conversion before exposing an actual public error.

Kind 1 retains known cleanup and permits operation 1 with the same W and O.
Kind 2 is isolated and rejects ordinary retry. Neither path redoes verification,
snapshot acquisition, path conversion, publication or a successful clone. A
cleanup failure before binding completes cannot later become a false successful
constructor result with empty ownership fields.

Value release uses the new HIABVQ02 operations 29 and 31, including the strict
producer status domain. An unconsumed reference with a pending mapping preserves
both facts and isolates the continuation. A consumed reference is cleared before
remaining mapping cleanup. The legacy immutable payload's proven pre-consumption
statuses 1/5/6 may retain a retry; unknown outcomes isolate. The runtime provider
currently has no consumption proof on failed drop. Every nonzero runtime or
provider-reply drop is therefore isolated, and its old nonce is not replayed.

## Evidence and remaining gates

The source probe runs the original Python Core verifier and scalar-entrypoint
property. It compares 80 member-selection cases, including more than sixteen
functions, explicit exports, scalar signatures and surrogate strings. Its 37
modeled effect traces cover actual-source phase order, ownership transfer,
100001-digit snapshot counters, allocation failure positions, known and unknown
retirement outcomes and nested verifier cleanup. Those traces model dependency
responses; they are not actual native calls or OS-fault qualification.

The remaining gates are native construction and byte rebuilding, complete
original constructor comparison with real runtime/provider/value/verifier
dependencies, private and actual failure matrices, live ownership races, the
runtime class gate, final actual Path objects, and allocation/start/rollback of
the full BG controller. The whole constructor and release remain unqualified.
