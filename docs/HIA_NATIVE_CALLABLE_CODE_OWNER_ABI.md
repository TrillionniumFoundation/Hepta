# Native HIA callable code owner

## Qualified scope

This component owns compiled HIA code and suspended invocation frames. Its
fixed compiler parses captured canonical HIA source and produces the code that
is actually executed. Compilation, executable mapping, continuation state,
capability validation, reference accounting, and retirement run in HIA and
fixed mechanical effects.

The qualification is limited to this code owner. Value function construction,
bound methods, argument tuples, keyword dictionaries, exception Values, custom
language protocols, and whole runtime fusion require the separate Value
callable driver. They are not claimed by this component.

The qualified flat product is 911408 bytes, SHA-256
5c697d03e0f9308b3ca92052646b5dd7ec542610bcb1b7ff301c239da3b4dc64.
HIA_NATIVE_CALLABLE_CODE_OWNER_COMPONENT.json binds construction sources,
all compiled roles, both packed products, and all 25 qualification groups.

## Entry and construction

The exported six-word entry is hia_native_callable_code_owner:

(source, source_length, output, output_length, context, context_length) -> u32

The context is exactly 256 bytes and starts entirely zero. Ordinary output is
at least 8192 bytes. Source, output, and context must not overlap.
Initialization obtains the real PID and a nonzero random provider nonce,
creates the metadata mapping, and binds the context to its actual address.
Moving or copying a context, or using it after fork, does not create an owner.

| Fixed role | HIA source under examples/hia_bootstrap |
| --- | --- |
| owner | native_callable_code_owner.hepta |
| registry | native_callable_registry.hepta |
| buffers | native_callable_buffers.hepta |
| compiler | selfhost.hepta |

The native_callable_code_packer.hepta packer accepts HIACOP01, count 4 at
byte 8, four lengths at bytes 16/24/32/40, mode at byte 48, and role bytes
starting at byte 56. Mode 1 produces a flat image; mode 0 produces an ELF
object. Its fixed bridge is tools/hia_native_callable_code_bridge.S.
Every role and the packer were compiled twice with the pinned original
compiler; both native products match independent byte constructions.

The existing limits remain 128 functions, 1536 blocks, 8192 operations,
120 seconds per compile, 4 MiB per role, and 16 MiB per product.
The new owner uses 26 functions, 436 blocks, and 1811 operations.

## Code-owner wire

HIACODQ1 has a 128-byte header. All numbers are little endian.

| Offset | Meaning |
| --- | --- |
| 0 | Eight-byte magic |
| 8 | Operation |
| 16 | Zero |
| 24, 32, 40 | Capability triple when required |
| 48 through 88 | Zero |
| 96 | Tail byte count |
| 104 | u32 feedback for resume 9; zero otherwise |
| 112, 120 | Zero |
| 128 | Tail |

A code or invocation capability is an actual registry token plus two random
words. Requests contain no function address, compiler address, executable
pointer, alternate owner context, or host callback.

| Operation | Behavior |
| --- | --- |
| 0 | Initialize; ready identical owner returns its actual nonce |
| 1 | Capture and compile canonical HIA source from the tail |
| 2 | Create an independent capability to the same code or invocation |
| 3 | Consume one capability and attempt eligible retirement |
| 4 | Create and advance an invocation using immutable tail input |
| 5 | Retry actual pending code, source, frame, and metadata retirement |
| 6 | Destroy a quiescent owner; failed unmap retains retry custody |
| 7 | Return locked registry statistics |
| 8 | Validate a capability and return captured metadata |
| 9 | Resume an invocation with the actual child operation return code |
| 10 | Fence new work only when caps, objects, and execution are empty |
| 11 | Roll back the quiescent fence |

Source and invocation input are each limited to 1 MiB. Source begins with a
canonical v9 program header and this exact entry signature:

fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)

The signature check precedes real native compilation; it does not replace
validation of the complete program. Source is captured and protected read-only.
Code changes from writable to read-execute only after compilation succeeds.

### Response and custody

The response starts with HIACODR1.

| Offset | Meaning |
| --- | --- |
| 8 | Primary status |
| 16 | Kind: code 1, invocation 2 |
| 24, 32, 40 | Newly published capability when applicable |
| 48 | Body action; initialization instead returns provider nonce |
| 56, 64 | Suspended request address and length |
| 72 | Suspended response address |
| 80 | Actual pending retirement, 0 or 1 |
| 88 | Whether ownership outcome is known |
| 96 | Whether requested capability was created or consumed |
| 104 | Suspended response capacity |
| 112 | Independent cleanup status |
| 120 | Owner lifecycle state |
| 4096 | Captured first 128 bytes of terminal body response |

Statistics use bytes 48/56/64 for cap/object/executing counts and byte 72 for
pending-object count. Metadata operation 8 returns captured registry fields
starting at byte 256.

Status 1 rejects a stale or invalid capability, 2 rejects an incompatible kind,
3 rejects invalid source or body framing, 5 reports allocation failure,
6 reports an incompatible lifecycle state or busy owner, and 11 reports an OS
or cleanup failure. Callers use explicit known/consumed/pending facts rather
than inferring custody from status alone.

Consuming the last code capability while an invocation still owns the code
reports consumed and pending. Code stays executable until that invocation
retires. Failed munmap keeps the exact remaining mapping and cannot become
successful retirement through a statistics refresh.

## Body execution and continuations

The compiled entry receives captured immutable input, an independent 1 MiB
output area, and an independent 1 MiB mutable workspace. A terminal body
returns 0 and writes HIACBR01 at output byte 0. Its first 128 bytes are copied
into the outer response.

A body requesting a Value operation returns 1 with:

| Body output offset | Meaning |
| --- | --- |
| 0 | HIACVA01 |
| 8 | Request length, at most 524160 |
| 128 | Actual Value request bytes |
| 524288 | Reserved 512 KiB response area |

The owner returns these captured buffers and an independently owned invocation
capability. Resume 9 uses the same immutable input and workspace; its u32
feedback is placed at body output byte 112 before execution. A terminal
invocation cannot be resumed.

No body-selected native function pointer is dispatched. The Value driver must
use the unique captured Value entry, validate the requested Value domain, own
all live arguments and temporary capabilities, and hold the invocation until
its response has been consumed. These tests validate real yield/resume
transport, not the as-yet-unconnected complete Value driver.

## Fixed resource finalizer

The same entry accepts private 128-byte HIAVRFQ1 requests and a response
capacity of exactly 128 bytes. A fixed stack adapter copies only the completed
128-byte receipt and preserves public output guards.

| Request offset | Meaning |
| --- | --- |
| 0 | HIAVRFQ1 |
| 8 | Drop 0 or retry 1 |
| 16 | Actual code-owner nonce |
| 24 | Resource kind 3, 4, or 5 |
| 32, 40, 48 | Actual code capability |
| 56 through 120 | Zero |

An invocation cannot be finalized as code. A wrong nonce, kind, or reserved
field cannot select another entry or context. Retry carries the known prior
consumption and performs actual retirement; it never consumes the token twice.

HIAVRFR1 returns status/known/consumed/pending at 8/16/24/32, then carrier
status/child return/retained/final return at 40/48/56/64. Remaining bytes are
zero. Actual forced munmap EIO was verified for kinds 3, 4, and 5: first
known 1, consumed 1, pending 1; the later fixed retry performs real unmaps
before pending becomes 0.

Final fusion reserves Value context bytes 192/200/208/216 for the fixed code
entry, actual context, extent 256, and provider nonce. Native initialization
generates the nonce at code context byte 128; trusted enclosing initialization
captures it after operation 0. Code context bytes 136/144 are reserved for
the same Value context and fixed Value entry. Public requests cannot set them.

The common finalizer validates the Value resource nonce, copies the 128-byte
frame to private scratch, substitutes the actual code-owner nonce, and calls
its fixed provider relocation. Production kind 3/4/5 support remains disabled
until Value construction, invocation, and GC integration are qualified.

## Closing the enclosing owner

After Value's actual destroy fence succeeds, retry code retirement with 5,
then establish the quiescent code fence with 10. Failed enclosing close rolls
that fence back with 11 alongside Value's rollback. Successful enclosing
retirement proceeds to code destroy 6 before either captured context or the
Value anchor is released.

State 1 retains failed metadata unmap, state 3 means actual metadata
retirement, and state 4 is the quiescent fence. A destroy failure preserves
custody and requires retry; it never permits freeing the context early.

## Native evidence

The 25 groups cover original-compiler byte equality, actual RX execution,
immutable source/input, suspended state, reference lifetime, malformed wires,
fork refusal, real metadata growth and ENOMEM, eight-thread execution, fences,
all construction and continuation mapping/protection failures, initialization
nonce failure, and three fixed-finalizer retirement failures.

Faults are real kernel errors at the fixed native syscall instruction.
No test replaces native replies, writes ownership counters or lock words, or
supplies host callbacks. The prior v2 arena-retirement failure and diagnostic
remain preserved. Version 3 fixes native pending overwrite and reruns the
original assertion unchanged, with the original limits and failure domain.
