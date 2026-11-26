# Native public LLVM capture-log codec

This pure HIA role produces a new attempted row or a dictionary update from
actual captured facts. It does not invoke a process, hold Value references,
append a public log, authorize a compilation or claim the enclosing API is
complete. The enclosing native logger must append before the capture and
update the same strongly held row.

The six-word entry takes request bytes, output bytes and a workspace of at
least 128 bytes. Success returns the output byte length; the output is JSON
with original WTF-8 strings retained, so adjacent lone surrogates are not
silently joined. It returns 0xfffffffd for a bad frame/text, 0xfffffffe for
short output and 0xfffffffc for an unrepresentable length. Bad or short
requests leave output untouched. Every accepted frame is measured before
any output write.

## HIALLGQ1

The request header is 128 bytes. Fields are eight-byte little-endian words:

| Offset | Meaning |
|---|---|
| 0 | HIALLGQ1 |
| 8 | Operation: 0 attempted, 1 completed, 2 capture_failed |
| 16, 24 | Capture-frame and cwd byte lengths |
| 32, 40 | Retained stdout and stderr lengths |
| 48, 56 | Original total stdout and stderr byte counts |
| 64, 72 | Returncode known flag and signed returncode bits |
| 80, 88 | Actual error type name and message byte lengths |
| 96, 104 | Textual code and separate capture_error byte lengths |
| 112 | Operation-specific facts flags |
| 120 | Reserved zero |

Tail order is capture frame, cwd, stdout, stderr, type name, message, code
and capture_error. The eight lengths must cover the request exactly.
A completed or failed update has zero frame and cwd lengths.

Attempted input contains the actual HIACAP01 argv frame emitted by the
closed Clang producer: inherited environment, no explicit cwd/stdin and
whole-second timeout. The argv entries retain their length and terminal NUL
framing. Cwd and argv are interpreted with the original POSIX filesystem
surrogateescape rule. An attempted row includes original argument order,
cwd, four exact limits, attempted status and the original None fields.

For completed input, flags 2 and 4 mean actual raw stdout and stderr.
A missing raw stream uses its original normalized text fallback. Both raw
stream fields are updated before either fallback is inserted, preserving
the original observable dictionary insertion order. Returncode is known.
Totals equal the supplied stream lengths in this profile.

For failure input, flag 1 means an actual CaptureFailure; flag 8 means a
textual code is present, including the empty string; flag 16 means a
capture_error is present, including the empty string. Without flag 1,
all stream/returncode fields are zero. With flag 1, retained byte counts
cannot exceed their actual totals and an unknown returncode is preserved
as None. Error code and capture_error remain independent. Error type,
message and textual metadata use actual WTF-8; they are not filesystem
byte strings.

The codec's code input is explicitly text or None. An arbitrary exception
code object, such as SystemExit(7).code, must be inserted by the enclosing
logger as the original strong Value reference. It must not be stringified
or reconstructed through JSON. This component does not claim that direct
capability path has been wired yet.

## Evidence

The original CPython 3.14.4 _run_logged is the formatting oracle. Native
comparisons cover every filesystem byte, raw streams versus text fallback,
signed returncode boundaries, retained-prefix and total-length differences,
unknown returncodes, independent secondary failures, 250 fixed random
argv/cwd/stream inputs, exact capacity and canary refusals. Three real
subprocess captures exercise successful bytes, strict UTF-8 rejection and
actual stream limits. Sixty actual Value JSON imports confirm the codec
preserves original strings and dictionary field order, including adjacent
lone surrogates.

The first native candidate exposed a real fallback insertion-order bug and
is preserved. The corrected candidate performs both raw stream updates
before fallback fields. This evidence is only for the pure codec; native
Value log custody, prelaunch append, same-row update, actual exception-code
edges and the full public LLVM boundary remain under construction.
