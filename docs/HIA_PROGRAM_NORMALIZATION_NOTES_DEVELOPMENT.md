# Fixed CPython note transport — development candidate

This candidate adds no claim of complete native public normalization. Five HIA
images continue to own normalization, raw JSON admission, materialization and
binary64 representation. Exception-note formatting remains an explicit hosted C
mechanism bound to the actual CPython interpreter. The selected public owner
still has an open physical-recursion compatibility boundary.

## Ownership and protocol

The native coordinator uses HIANORQ2 / HIANORP2 / HIANORS2. Its initial packet
contains the admitted interpreter note capability (zero or one). This is an
immutable runtime ABI observation, not a cached foreign-object classification.
The HIA parent frame owns the value-child note permission and consumes it before
a note operation is launched. A key encoding, items capture, tuple-shape or sort
error does not receive a note for that same mapping frame. Enclosing value frames
can still receive their own notes.

Actions 63 and 64 invoke one fixed dictionary or sequence note. HIA specifies the
actual exception handle, original parent identity, and original key handle or
index. The bridge does not reacquire items, keys, type names or representations.
For an internally detached builtin parent, the empty builtin shape supplies only
the original builtin type to CPython's %T formatter.

Action 65 pins an already held key handle to its parent's capture scope; action
66 consumes that pin before releasing it. This preserves the same acquired key
identity through child-scope release and parent-note formatting. The pin map
holds integer handles; it does not build another foreign key object or call
repr. The actual parent capture stays live until after its note and key-pin
release. This preserves the intended destructor boundary; exact foreign
reference-count observations remain a separate validation obligation.

A note can return the same exception or a replacement from repr/note-publication
failure. Native phase 237 admits its actual handle. If it differs, HIA first
retains the new object and then uses action 67 to release only the old transport
owner. Natural __cause__/__context__ references stay intact. No exception-wide
or root-wide pool cleanup is introduced. The existing confirmed terminal
handoff remains the only path that releases the delivered error's transport
owner; unknown outcomes retain fenced custody.

Note permission, key release and old-error release are each consumed before
their effects. An interrupted effect or acknowledgement cannot replay that
operation. Cleanup handoffs with an unconfirmed outcome terminate through the
existing unknown-custody boundary instead of reconstructing permission.

## Explicit hosted mechanism and interpreter identity

The fixed C body receives no JSON payload and performs no business traversal.
Its only external calls are Py_IncRef, PyErr_SetRaisedException,
_PyErr_FormatNote and PyErr_GetRaisedException, through a private table bound to
the current interpreter's actual exported addresses. The three format strings
are the original CPython strings. Python 3.12/3.13 do not emit these notes; the
current C mechanism admits exactly CPython 3.14.4 with the GIL. Other 3.14 patch
versions have not been qualified by this candidate.

The C image uses the existing copied RW-to-RX mapping. Its API table is written
once and then made read-only, without execute permission. Admission checks each
address with dladdr, records the actual exporting image and executable bytes,
and rechecks those bytes before return. The mechanism manifest records source,
flat-image and interpreter identities; current process addresses are captured
from that interpreter rather than reused from a previous process.

This is a hosted CPython/C runtime dependency. It is not an HIA owner, does not
close the C JSON diagnostic dependency, and does not supply the still missing
physical C-stack/recursion continuation. No complete source-cold, installed-wheel
or repository-wide qualification is inherited from prior images or the earlier
shared-object prototype.

## Evidence boundaries

The preceding immutable r5 candidate completed 51 full comparisons: 45 matched
and six retained Python 3.14 note differences. Its Unicode codepoint-order and
temporary-capture lifetime repairs passed their specific controls. This new
coordinator draft has not yet been regenerated, compiled or executed.

The new flat mechanism must independently pass current-interpreter note and
handled-exception-context controls, actual kernel mapping checks and real
write-refusal child probes. Earlier .so controls are inputs for new execution,
not qualification of the flat image. After that gate, the new coordinator must
reexecute all retained comparisons plus replacement-error, key repr,
parent-capture release and lost-acknowledgement controls.

The original r3 authoring rejection, r4 character-order failures, r4 held-error
temporary-reference failures, six r5 note differences and previous reporting
failures remain unchanged. Frozen source resources that still use historical
.hepta filenames contain HIA v8 assembly; their final integration must reconcile
the current Core-only .hiaasm inventory without mutating this development run.

## Revision r7: actual r6 failures retained

The r6 execution completed 73 observations, with 71 matching. The two recorded
differences involved a replacement exception escaping under an outer/nested
handled exception: callback events and replacement identity matched, but the
final Python raise replaced the original primary context with the handled
outer exception. The run then stopped on the replacement-lifetime assertion:
root, primary and replacement were still alive after the caller released the
delivered exception with cyclic GC disabled. That second lifetime case executed
but failed before its row was recorded; the four ACK controls were not reached.
This is a failed original run, not a qualification.

The r7 candidate keeps the HIA state machine unchanged. The flat hosted entry
gains mode 4 with a complete guard: non-null API/error, kind 4, null unused
container/key fields, and zero index. It only increments the existing error,
sets that same object as CPython's raised exception and returns NULL.
PYFUNCTYPE, holding the GIL, propagates it through the normal C error result.
This preserves the exception's existing context instead of performing a new
Python raise. No context/cause attribute is rewritten in Python.

The note and delivery bridges now clear only their own temporary arguments and
returned-object locals in finally. A traceback from a repr callback can retain
an intervening transport frame through f_back even if C caught that callback's
error; the transport must not leave its returned exception in that frame.
HIA scope, pin and error-owner custody are unchanged. No GC or broad pool
cleanup is introduced.

These are new source changes and a new flat image; the previous 27-mechanism
pass does not qualify them. New mechanism controls must reexecute all 27 and
add delivery/context/invalid-frame/lifetime controls, then the complete original
78 coordinator controls must run again. Full public normalization, exact
foreign reference-count compatibility and physical recursion remain open.


## r8 late error development revision (not yet qualified)

The frozen r7 actual-machine extension recorded 14 original observations,
5 equal and 9 different. Four late integer cases lost the original builtin
decimal-limit ValueError and its parent note. Five malformed mapping item
cases lost the original C encoder ValueError and its parent note. Their
callback and destructor traces matched; the original report and source stay
immutable. The earlier 78 comparisons retain their own precise coverage.

This revision lets HIA issue the existing consumed action 62 only after its
own decimal-limit or physical tuple-shape refusal. Kind 3 invokes the
builtin int repr slot for one native-proved failing scalar, without a
subclass override or a Python-local borrow. Kind 4 invokes a private
single-item C diagnostic using the exact previously acquired malformed
item. It does not call the caller's items method again, sort multiple
keys, or walk a payload child. The private item's extra borrow is released
before HIA exception unwinding. Parent note eligibility and key pins still
come from the native frame state.

These are explicitly hosted interpreter exception mechanisms. Physical
recursion and the full accepted object domain remain unqualified. No
deadline, public source limit, native compiler limit, or original reference
implementation changes in this revision.


### HIA-produced note/delivery bytes

The r8 declaration uses `hepta.hosted.cpython-note-hia-packer.v1`.
Production source custody covers
`examples/hia_bootstrap/cpython_note_packer.hiaasm` and the fixed interpreter
bridge. The selected image is the actual 298-byte HIA-produced mechanism.
The 302-byte C-produced r7 image and its independent 35-control result remain
reference evidence; they are not the selected production input.

The manifest includes sibling packer-image and production-receipt names and
SHA256 digests. Fresh admission binds the current packer HIA source, actual
compiled packer, compiler identity in the original receipt, six completed
emission controls, and exact emitted note image. It checks integer receipt
fields without accepting booleans, then rereads every consumed file before
returning the held immutable mappings. This development receipt explicitly
does not establish a current-source cold proof. The independent `.S`, linker
script and C sources remain reference/authoring artifacts, not runtime
production inputs.

The fixed mechanism still calls the same four pinned CPython API addresses.
Its independently repeated 35 controls passed against the HIA-produced image;
that result covers only the tested mechanism boundaries, not whole-domain
normalization or physical recursion.


## Permanent r9 integration draft

The new r9 selection removes the unexecuted packet dependency and uses the
HIA-produced note image with the same four-pointer runtime ABI. Its strict
builder admits an actual matching-source cold report before output creation;
the old development receipt remains explicitly development. The new producer
receipt is bound to the installed complete-source contract and current actual
inputs. CPython 3.14.4-only admission is now an owner-level precondition.

Core-front and independent nominal source resource names become .hiaasm in
this new revision; all frozen earlier .hepta-path observations keep their
original identities. Permanent tests retain the original source definitions
and assertions with hashes. Their new execution is pending and does not inherit
r8's 108 result. Physical recursion, exact full-domain reference-count behavior
and whole normalization are still unqualified.
