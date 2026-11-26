# Native Clang Value adapter ABI

This component supplies actual HIA Value coercion, owned Clang preparation,
exception capability transfer, and acknowledged retirement. Its policies are
native code compiled from HIA by the original compiler. The mechanical bridge
provides fixed calls, pointer views, atomics, and Linux syscalls. Python authors
and qualification drivers are development tools.

This component qualification does not qualify the complete public Runtime or
the public HIAProgramLLVM record, command-log, and static-budget interfaces.

## Binding and ownership

The function convention is six unsigned machine arguments:
input pointer/bytes, output pointer/bytes, work pointer/bytes. Work is aligned to
eight bytes and has exactly 538968064 bytes (514 MiB). Its last 512 MiB belongs
to the fixed inner producer. The actual shared Value context remains external;
this component does not contain a second Value arena.

hia_clang_value_bind accepts a private 128-byte parent-generated binding.
HIAMVCB1 carries the actual Value entry at 8, context at 16, context extent 256
at 24, and nonce at 32; bytes 40 through 127 are zero. The fixed parent must
hold its actual owner borrow throughout binding. A real Q06/21 context token
is captured before the binding is acknowledged.

HIAMVCB2 has the same fields and carries the actual source-directory descriptor
at 40; bytes 48 through 127 are zero. The adapter performs F_DUPFD_CLOEXEC on
that descriptor and fstat on the owned duplicate, requiring a directory.
Closing the parent's descriptor or renaming the captured directory does not
invalidate the adapter's owned directory. A failed dup or fstat leaves the
actual context token and any successfully acquired descriptor available for
real retirement.

HIAMVCBR is the 128-byte binding reply: status at 8, detail at 16, known at 88,
and delivered at 96. A failed binding is not permission to discard its work.
The parent must retire a partially bound work area and observe the real
acknowledgment.

The private hia_clang_value_bind_owner helper captures the same binding from
an existing live native owner, checking its self pointer, process, ready state,
fixed entry, and actual embedded Value context. HIACVOB1 is a 32-byte request
with zero tail. HIACVOB2 carries a source-directory descriptor at 8 and zero
words at 16 and 24. These helpers never accept an entry address in their
request. They are used by qualification with actual native owner borrows;
production parents may construct the same private binding in their fixed
native prefixes.

## Compilation requests

hia_clang_value_compile accepts two separate 256-byte header profiles.

| Offset | HIAMVBC1 | HIACVPC1 |
| --- | --- | --- |
| 0 | Profile magic | Profile magic |
| 8 | Build 0, retire 1 | Build 0, retire 1 |
| 16 | Zero | Target: x86-64 0, AArch64 1, RV64 2 |
| 24 | Outer deadline information | Kind: shared 0, object 1 |
| 32 | Outer cancellation information | Layout: canonical 0, guarded-outline-v1 1 |
| 40 | Nonempty Core byte count, at most 8388608 | Same |
| 48 | ABI byte count, at most 5136 | Same |
| 56 | Nonempty absolute filesystem output-path byte count | Same |
| 64, 72, 80 | Actual Clang Value capability | Same |
| 88 | Zero, reserved structured payload | Zero |
| 96 through 255 | Zero | Zero |

The tail is Core bytes, ABI bytes, and absolute output-path filesystem bytes.
The capability is a real same-arena Value, cloned by native Q05/91 before use.
The response capacity is at least 1049088 bytes.

HIAMVBC1 retains its original field domains. Its outer deadline/cancellation
information never shortens the original discovery/compilation/reap budgets.
The parent performs cancellation checks at the original pre-prepare and
commit boundaries. There is no new cancellation poll inside Clang.

HIACVPC1 is a private handoff after public language/type/origin validation. It
does not turn caller-supplied bytes into a VerifiedProgram or HIAProgramLLVM
record. Guarded outlining still requires the original admitted complete guard;
ordinary scalar Core with a requested guarded layout is rejected.

Both profiles require a real Clang driver. Default clang is resolved through
the actual process environment and executed. The original 10-second version,
10-second target, 60-second compile, and 3-second reap behavior is retained.
The original HIACLB01 profile, its 25-role packer, and its 24 executable
role bodies remain unchanged. This adapter shares those executable bodies;
its fixed source catalog additionally covers the new native source files.

For B2 bindings the adapter invokes the separate HIACLB02 producer. It retains
the original raw header layout, with a borrowed owned-directory FD at 72 and
zero bytes 80 through 255. Its fixed catalog names are resolved through
/proc/self/fd/<owned-directory>/<logical-name>. The implementation identity
still commits to logical names and actual source bytes, not the physical
installation pathname or the sealed image's /proc/self/fd pathname.

## Real object protocols and exceptions

The adapter uses actual Value operations to perform type lookup, canonical
function binding, __fspath__ calls, POSIX path-part traversal, subtype base
capture, and filesystem encoding. A user exception raised by __fspath__ is
retained as the actual object. It is never substituted by a JSON description.
The qualified cases include string/bytes subclasses, true PosixPath subclasses,
invalid returns, missing/noncallable methods, exact type-name truncation,
surrogate filesystem encoding, live PATH changes, and growing path buffers.

hia_clang_value_exception accepts a 128-byte HIAMVCE1 request. Operation 1
queries and operation 0 transfers the pending exception capability once.
Words 16 through 127 are zero. HIAMVCER reports disposition at 16, the
transferred capability at 24/32/40, known at 88, delivered at 96, and independent
cleanup status at 104. Queries do not clone or deliver. A second transfer
returns no object. An untransferred exception is actually dropped during
retirement.

Canonical TypeError, MemoryError, and HIAProgramLLVMRejected objects and
propagated actual user exceptions are covered by this checkpoint. The complete
OS, capture, publication, and inventory exception surface remains a subsequent
qualification obligation.

## Replies and retirement

HIAMVCR1 preserves the actual inner header and receipt; it does not invent a
replacement receipt. The following additional observations are captured from
the actual producer while it remains live:

| Offset | Meaning |
| --- | --- |
| 104 | Actual target |
| 128 through 159 | Actual input SHA-256 |
| 320 | Input hash present |
| 328 | Actual artifact kind |
| 336 | Retired 0, known pending 1, unknown 2 |
| 344 | Custody known |
| 352 | Actually retired |
| 360 | Pending |
| 368, 376 | Independent cleanup error and errno |
| 384 through 511 | Zero |

A retire request has operation 1, exactly 256 bytes, and zero words from 16
through 255. Its output capacity is at least 512 bytes. A successful compile
does not retire the work. The parent first transfers any exception it needs,
then retires, then releases the work mapping only after known=1, retired=1,
pending=0.

The adapter retires the actual which context, inner producer, all acquired
mappings, its directory descriptor, every owned Value capability, and the
actual context token. Deferred Value drops clear slots only after consumed=1.
Mapping and descriptor failures remain pending until an actual retry. A
successful close_range or fallback close is required before clearing the
directory descriptor. An uncertain fallback close is quarantined and never
reported as retired. No host polling or host prefix repair grants ownership.

A binding supports one build followed by retirement. Copying its prefix or
using it after fork does not create authority. Static malformed frames are
rejected before output or context mutation.

## Native packaging and evidence

HIACVPP1 packages 36 fixed roles, with a 312-byte header and mode at 304.
Each role retains the original 4194304-byte bound and combined text retains
the original 16777216-byte bound. Both native object and flat modes are compared
byte-for-byte with an independent development serializer. The native linker
creates the actual ELF shared image.

HIA_NATIVE_CLANG_VALUE_ADAPTER_COMPONENT.json binds the actual double-compiled
sources, native products, compiler, unchanged legacy roles, 31 protocol cases,
16 advanced cases, 13 sealed-origin/retirement cases, and 82 negative packer
controls. Failed fixtures and the disk-exhaustion interrupted campaign are
retained separately and are not counted as passes.
