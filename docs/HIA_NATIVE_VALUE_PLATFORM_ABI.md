# Native platform values and exception slots

HIABVP09 packs sixteen actual HIA roles into the sole Value entry. The original
fifteen roles retain their order and the new platform role follows them.
The frame header is 152 bytes: magic at 0, count 16 at 8, sixteen lengths
at 16, mode at 144, then the role bodies. Each role and the complete Value
text remain at most 4 MiB. The older HIABVP08 producer and its original
15-role/16-MiB structural refusal tests are unchanged; their old format is
tested separately and is not published as the new platform Value.

## Request and delivery facts

All operations below use HIABVQ05 and a 128-byte header without a tail.
A, B and C are capability triples at 24, 48 and 72. Selector is at 104.
Fields 16, 96, 112 and 120 and unused capability triples are zero.
Inputs are borrowed. A successful result publishes an independent capability.

| Operation | A | B | Selector | Result |
|---|---|---|---|---|
| 101 | zero | zero | canonical ID 48–70 | Actual class |
| 102 | list or tuple of six fields | optional true subclass of 53 | 0 | Frozen CaptureFailure record |
| 103 | list or tuple of five fields | optional true subclass of 54 | 0 | Frozen CaptureResult record |
| 104 | actual OSError class or subclass | actual args tuple | 0 | OSError instance or actual range-error exception |
| 105 | actual exception | zero | 0 errno, 1 strerror, 2 filename, 3 filename2, 4 characters_written, 5 args | Strong field capability |
| 106 | actual exception | new value | 0 cause, 1 context, 2 suppress_context | Strong None capability after atomic mutation |
| 107 | actual exception | zero | 0 cause, 1 context, 2 suppress_context | Strong slot capability |

The reply is HIABVR01: status at 8, kind at 16, capability at 24–40,
ordinary size at 48, disposition at 64, total pending at 80, known at 88,
primary capability delivered at 96 and cleanup status at 104. Fields 112
and 120 are zero. Disposition 1 returns a value; 2 delivers the actual
constructor-raised ValueError. A nonzero cleanup status does not invalidate
a delivered primary capability. Field 96 never consumes an input in this
new domain. Undelivered replies carry an all-zero primary triple.
Malformed requests retain the existing 0xfffffffd refusal and canary rules.

## Canonical classes

| ID | Class | Direct base ID |
|---|---|---|
| 48 | CaptureRejected | 24 |
| 49 | ToolIdentityRejected | 24 |
| 50 | PublicationRejected | 24 |
| 51 | ELFSharedABIRejected | 24 |
| 52 | ObjectSymbolsRejected | 24 |
| 53 | CaptureFailure | 1 |
| 54 | CaptureResult | 1 |
| 55 | ConnectionError | 25 |
| 56 | BlockingIOError | 25 |
| 57 | BrokenPipeError | 55 |
| 58 | ChildProcessError | 25 |
| 59 | ConnectionAbortedError | 55 |
| 60 | ConnectionRefusedError | 55 |
| 61 | ConnectionResetError | 55 |
| 62 | FileExistsError | 25 |
| 63 | FileNotFoundError | 25 |
| 64 | InterruptedError | 25 |
| 65 | IsADirectoryError | 25 |
| 66 | NotADirectoryError | 25 |
| 67 | PermissionError | 25 |
| 68 | ProcessLookupError | 25 |
| 69 | TimeoutError | 25 |
| 70 | UnicodeDecodeError | 43 |

CaptureFailure fields are command, returncode, stdout, stderr,
stdout_total_bytes and stderr_total_bytes. CaptureResult fields are
returncode, stdout, stderr, raw_stdout and raw_stderr. As with the original
frozen dataclasses, annotations do not coerce or validate supplied fields.
The caller supplies all six or five already bound fields; arbitrary iterable
argument binding and default argument dispatch remain enclosing responsibilities.

## OS and exception graph behavior

Operation 104 preserves actual args, errno, strerror, filename and filename2.
Only the canonical OSError class auto-selects an errno subclass. Only the
canonical BlockingIOError class applies its index-sized characters_written
branch; actual subclasses retain their original construction behavior.
A filename of None keeps the original args tuple. A non-None filename
normalizes args to its first two entries and keeps filename aliases.
The written count -1 denotes absence; other admitted negative counts are
retained. Overflow delivers a real ValueError with the actual type name.
An actual custom __index__ method returns the explicit enclosing-protocol
status 27: this component does not call user code while holding the arena lock.

Cause and context accept None or an actual BaseException. Suppression accepts
only bool. Setting cause, including None, also sets suppression to True;
setting context leaves suppression unchanged. Defaults are None, None and
False. These fields live in a real private tuple held by the existing fifth
managed edge. They are not dictionary tags. Chain mutations allocate and
publish their result before the non-failing edge swap under the same arena
mutex. Actual ENOMEM preserves the old slots. Ordinary exception payloads
are upgraded without losing namespace, args, name or class references.
Real self and mutual cycles are reclaimed by the original native collector.
__notes__ remains the original ordinary namespace attribute; add_note
argument dispatch is not claimed here.

## Verified scope

The frozen image passed all original six component groups and six campaigns
with their original 300/660-second budgets, all previous Value protocols,
call/custody/managed-edge/LLVM record/deferred-domain gates, and 17 new
platform groups. The new groups include 144 errno cases, original argument
and subclass comparisons, actual cause/context setter comparisons, real
getrandom and mremap failures, and seven operations retaining their primary
capability after actual code-munmap EIO during final cleanup.

Public owner exposure, arbitrary __index__ constructor dispatch, complete
Unicode exception descriptors, traceback/formatting and whole public LLVM
remain separate unfinished scopes. No component receipt claims them complete.
