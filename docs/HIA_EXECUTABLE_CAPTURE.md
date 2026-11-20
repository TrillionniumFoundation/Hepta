# Explicit HIA executable capture

## Status and actual boundary

This is an additive static candidate for the complete policy in
`hepta.hia_program_selfhost._sealed_executable`. The original function, its
call sites, compiler-v1 manifest, ordinary CLI selection, process supervision,
deadlines and cleanup remain unchanged. No ordinary route invokes this candidate.

HIA owns creation-to-transfer control: partial-write iteration, nonpositive
write refusal, executable mode, the seal-add/get sequence, the original seal
short circuit, a complete readback byte comparison, and one close on a confirmed
ordinary failure after descriptor creation. HIA also owns the operation-specific
EINTR decision and requests the original signal check before retrying.

The seven-operation native image performs exactly one Linux syscall per
admitted packet. It has no retry loop, cleanup branch, artifact policy or
callback to the old Python business function. Its request and receipt are
separate from the existing four-operation raw capture-descriptor v1 ABI; no
old operation or rejection domain changes.

The mechanical Python adapter allocates and owns buffers, supplies the original
exact bytes, performs strict current-source admission, validates complete native
receipts and records delivery. It transports HIA-selected audit, signal and
exception effects through CPython's existing public C ABI. It does not decide
whether to write again, accept seals, compare the captured executable, close on
failure, or return a descriptor.

## Explicit profile and selection

The actual host ABI profile is **CPython 3.14.10, GIL enabled, Linux x86-64 LP64**.
It is a new opt-in component restriction; the old helper and package
`requires-python >=3.11` declaration are unchanged.

```python
from hepta.hia_executable_capture import load_executable_capture

owner = load_executable_capture(
    "/operator/chosen/capture/manifest.json",
    "<exact separately approved manifest SHA-256>",
    allow_development=False,
)
fd, seals = owner.capture(admitted_executable_bytes)
```

A development bundle requires an explicit `allow_development=True` as well as
its exact expected digest. A compiler-v1 manifest does not confer this new
authority. There is no environment-selector fallback, implicit upgrade or
automatic use from the ordinary compiler. A future public integration needs
an independently reviewed manifest/version boundary.

Both immutable images, the construction receipt, all declared component
sources and the **complete current production Python inventory** are bound.
The runtime inventory excludes package-data copies under `hepta/_data`, just
as the existing installation identity does. Added or removed runtime modules
reject selection. Every capture performs fresh source/image/manifest reads;
healthy mappings do not hide changed files. A source-based Python installation
identity remains source-based: no generated image is silently added to its hash.

## Kernel and CPython effects

| HIA action | Fixed mechanical effect | Retry policy in HIA |
|---|---|---|
| MEMFD | `memfd_create("hia-selfhost-compiler", 3)` | No EINTR retry |
| WRITE | `write(fd, remaining_bytes, remaining_count)` | EINTR → signal check → same write |
| CHMOD | `fchmod(fd, 0500)` | Original audit once, then EINTR signal/retry |
| ADD_SEALS | `fcntl(fd, 1033, 15)` | Original audit once, then EINTR signal/retry |
| GET_SEALS | `fcntl(fd, 1034, 0)` | Audit third argument is **None**, then EINTR signal/retry |
| PREAD | `pread64(fd, raw_length + 1, 0)` | EINTR → signal check → same pread |
| CLOSE | `close(fd)` | Exactly one attempt; no EINTR retry |

The HIA audit ports use real `PySys_Audit` with the original `iii` or
`iiO` formats, not a replacement Python audit policy. The signal port calls
`PyErr_CheckSignals`. Negative syscall receipts select
`PyErr_SetFromErrno(PyExc_OSError)`; the original
`SelfhostBuildRejected` constructor handles the two explicit capture refusals.
These are retained hosted ABI responsibilities, so this component does not make
the ordinary entry Python-free.

The original CPython 3.14.10 sources were read statically:
`Modules/posixmodule.c` Git blob
`3ea1073a2cd887ff0b091c3852ee122e3e44605f`,
`Modules/fcntlmodule.c`
`690882e34a8e2c13f78b1f6d7a78a45c75b2ea8d`, and
`Python/fileutils.c`
`d5495ecf34d0a3304118a6db7d482693445bdccd`.
In particular, treating every errno as retryable, omitting audit events, or
using an audit GET argument of integer zero would change the original behavior.

## Protocols and resource ownership

The HIA request is a 128-byte header plus original bytes. The 128-byte reply
binds version, event sequence, action, descriptor, offset/count/operand,
opaque exception handle, nonce, state phase and checksum. The workspace is
256 control bytes plus `raw_length + 1` pread capacity. All invalid initial
or continuation inputs reject before modifying output/state.

The raw request and receipt headers are 96 bytes. Every raw primitive validates
its entire fixed operation domain before the syscall. It persists a pending
phase and the request identity first; then it stores the actual signed result
and complete receipt before marking completion. The raw `.text` is one
entry-zero function with no unresolved relocations.

One operation frame owns input, both images, all buffers, actual persisted fd
results and a whole-operation delivery record. Each HIA/raw invocation has a
separate handoff and complete-receipt confirmation. A confirmed per-port result
does not acknowledge the whole operation. Actual audit/signal callback resources
are separately reserved and kept until the whole terminal acknowledgement;
resource loss is rechecked at subsequent boundaries. No image-global lost flag
poisons unrelated workspaces.

The frame records an observed foreign effect immediately at the real handoff.
Preparation failures before any actual handoff do not invent a syscall.
Missing/corrupt native receipts retain the frame and fd-bearing workspace.
There is no retry, finalizer-close or diagnostic registry clear on UNKNOWN.
The raw memfd result remains reachable even if Python never stores the fd in
the policy state.

Ordinary provider errors enter the HIA error continuation inside the actual
Python except region. If the HIA-selected close fails, the close error keeps
the real primary error as context. A complete known-error receipt can retire
healthy custody and propagate that exact exception. A swallowed or replaced
actual child loss cannot be acknowledged as an ordinary refusal.

## Independent finite evidence, not an all-input claim

The new frozen domain contains **109 scenarios × two outer-exception states =
218 ordered invocations**. Two fresh executions of the complete preserved
original bodies must finish and be byte-equal before a VM or native-policy
factory is constructed. The input table covers empty data, partial writes,
zero writes, seal short circuits, complete/short/long/different readbacks,
the operation-specific errno/EINTR behavior, nine audit/signal exception
families, and close-error replacement. Every declared fault must actually fire.

The original-only OS model implements primitive results and CPython's audit/
signal boundary. It does not reimplement the capture loop or cleanup choices.
The corresponding candidate uses the actual HIA policy with the same primitive
values. This finite model is explicitly **not arbitrary monkeypatched Python
`os` provider equivalence**.

The added native methods separately exercise real original/native kernel
capture through 1 MiB, actual mode/seals/readback, post-memfd receipt loss,
same-workspace rejection and unrelated-workspace success, strict admission,
and an actual wheel with source/inventory rejection. Development is never
reported as current matching cold.

The original test modules and all their inputs/assertions/budgets remain intact.
The separate original gate inventory is part of the external package. In
particular, `_run`, real `Popen`, WNOWAIT, output limits, deadlines and the
original three-second cleanup are not replaced by raw process operations.

## Open qualification boundaries

No generator, AST, product, VM, native, compiler, SQL, test, reader or GC execution
was performed while producing this candidate. The generated
`examples/hia_bootstrap/executable_capture.hepta` is intentionally absent
until root generates it; an empty or guessed generated artifact would not be
admissible. Core/SSA/compiler-profile limits and both actual image receipts
remain pending.

New Python transport frames, ctypes objects, pre-reserved buffers and different
allocation boundaries are observable. This source does not prove arbitrary
GC counts, traceback topology, audit-hook temporary lifetimes or injected
MemoryError equivalence. An asynchronous exception after a native effect but
before a complete host receipt remains UNKNOWN; it is not converted to a
fabricated original error. Real signal delivery timing needs independent
qualification beyond the finite errno/signal model. These limits prevent a
default cutover or deletion of the original helper.

There is no claim of complete CLI, compiler, VM, worker, 249-module, or
whole-stack native closure.

## R2 receipt and prewrite successor

R1 remains an unexecuted, independently reviewed predecessor. Its review found
two concrete blockers: a self-consistent earlier active receipt could acknowledge
a later invocation, and a malformed raw count could reach a ctypes canary write
before the actual allocation was checked. R2 changes the transport adapter and
adds independent controls. No execution of R2 is reported here.

### One current invocation, one complete acknowledgement

Before the policy child is confirmed, the adapter binds all of the following:

| Boundary | Required relation |
| --- | --- |
| Initial request | Event 0, sequence/action/result/error all zero; prior workspace header entirely zero; no earlier accepted receipt. |
| Initial return | Active MEMFD, sequence 1, fd sentinel, offset 0, actual input length; zero seals, error, retry, close, reason and audit state. |
| Continuing request | Its sequence and action equal the previously accepted active workspace; the whole header equals that immutable prior snapshot. |
| Continuing active return | Returned sequence equals the request sequence plus one. |
| Terminal return | Returned sequence equals this request sequence; action, offset, count and argument are zero. |
| Kind | Reply kind, embedded kind and workspace kind are identical. |
| Identity | Nonce, sequence, action, descriptor and error handle agree across the complete reply and workspace; declared input length equals actual bytes. |
| Error observation | Event 1 preserves the previous handle; event 2 has result zero and the next handle (at most two). An error terminal identifies the actual current exception before confirmation. |
| Descriptor | Preserve the prior descriptor, except a successful MEMFD result must become that exact descriptor. The close flag cannot move backwards. |
| Integrity | Original status, complete request bytes, canaries, reserved words and both checksums remain mandatory. |

The opcode action projection validates the fixed private ABI. It does not
reimplement the policy's retry loop, write progress, audit order, seal/readback
decisions, error selection or close selection. Those remain in the unchanged
HIA generator. The ordinary selfhost caller and its process owner are unchanged.

### Raw mechanical admission precedes every write

The adapter accepts only the exact currently acknowledged tuple, the same
workspace header, and one of the seven raw actions. It checks fd range, offset,
count, fixed argument and actual immutable payload length before packing a
header, clearing memory, copying bytes, writing a canary or invoking native code.

| Raw action | Mechanical projection |
| --- | --- |
| MEMFD | fd = unsigned sentinel; offset/count 0; flags 3. |
| WRITE | real signed-int fd; offset = workspace progress; count = actual length minus progress, positive; argument 0. |
| CHMOD | real fd; offset/count 0; mode 320. |
| ADD_SEALS | real fd; offset/count 0; seals 15. |
| GET_SEALS | real fd; offset/count/argument 0. |
| PREAD | real fd; offset 0; count = actual length + 1, at most 1,048,577; argument 0. |
| CLOSE | real fd and current error/close continuation; offset/count/argument 0. |

The actual ctypes arrays must contain request header plus WRITE payload,
96-byte output, and 96-byte raw state plus PREAD capacity, each with its full
16-byte canary. PREAD also checks the actual policy-state allocation before its
copy. A complete positive PREAD result cannot exceed the admitted count or
destination extent. Locally captured buffer objects are the objects checked,
written and passed to the primitive. A transport inconsistency is UNKNOWN; it
is never converted into a fabricated Linux errno or sent to the primitive.

The no-fd sentinel remains valid for the hosted errno action after a failed
MEMFD and its ordinary error terminal. It is not admitted to raw actions 2-7.
A complete negative kernel receipt follows the unchanged HIA error continuation
and is not classified as delivery loss merely because its result is negative.

### Additive control scope

The original 109 scenarios in two outer-exception states (218 invocations), both
original passes, original Source3/Native5 file, generator, primitive assembly and
builder are retained byte for byte. The 72 new logical controls are frozen
independently; none supplies replacement expected output for those originals.

* Source2 runs 24 actual VM policy corruptions and all 31 synthetic mechanical
  prewrite guards. Three valid extents (0, 1 and 1 MiB) prove that valid prewrite
  admission reaches its first write. These three probes stop there and do not
  claim kernel effects or original equivalence.
* Native4 runs those 24 policy corruptions after actual policy/kernel returns,
  all 31 prewrite guards against an admitted bundle, all seven actual raw actions
  with withheld and inconsistent completion (14), a complete real negative
  syscall result, and two actual nested child losses.
* Callback controls explicitly use a fake parent kernel to reach the audit or
  EINTR signal cutpoint. Their nested child executes actual MEMFD before its
  receipt is withheld. Swallowed/replaced errors cannot authorize later parent
  policy entry or an ordinary terminal.
* No control calls record.loss, publish or failed to manufacture its expected
  loss. Real records acquire loss only from their original native/foreign
  handoff. Lost descriptors remain in process custody until the owned diagnostic
  child exits; the product does not retry or perform guessed cleanup.

Each complete new group uses the old 180-second owned-child limit and 3-second
cleanup, with complete planned/started/stopped IDs, real counts, raw output,
source pins and final rereads. New Source2 and Native4 are separate from the
unchanged Source3 and Native5; their counts must not be combined into an old
qualification claim. The outer gate remains 1800+3 seconds.

### Qualification still pending

There has been no generator, AST/import, compiler, assembler, VM, Native, test,
SQL, GC or qualification-reader execution for this static successor. The root
must generate the actual HIA, enforce the original complete Core/SSA/compiler
profile (including 2048 SSA names per function), build a fresh source-bound
component and run every old and new gate. DEV remains explicitly diagnostic.

The old finite comparison does not independently bind its raw-traceback streams
into a sidecar authority. That remains an explicit evidence gap, not a reason
to replace first/second observations, normalize tracebacks or change old
equality rules. Arbitrary MemoryError, asynchronous signals, callback object
lifetimes, traceback/frame topology and visible GC equivalence remain open as
described above. No default cutover, Python-free entry, whole native closure or
permission to delete the retained original body is asserted.
