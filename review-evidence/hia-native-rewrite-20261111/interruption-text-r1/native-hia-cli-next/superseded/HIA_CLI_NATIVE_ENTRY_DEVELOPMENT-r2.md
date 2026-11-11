# Native CLI entry development r2

This is newly authored source, saved during an unavailable execution environment.
It is not a reconstruction of any previously executed controller or executor.
The four source blobs in cli-entry-interruption-new-drafts.json were read back
exactly from GitHub. No HIA generation, compilation, assembly or ELF execution
has happened for this entry revision.

## Runtime ownership

The controller calls six independently developed HIA components: OS byte
capture/decoding, argv parsing, argument/help formatting, shared program
metadata, JSON pretty layout, and bounded input-file policy. A seventh image is
the controller itself. The dedicated HIA packer writes the complete ELF and the
seven-role image table. Its fixed template contains no JSON or CLI option
parser, language manifest interpretation, program admission, catalog generation,
hash algorithm, or error-message construction.

The source-only controller currently completes help, version, argument errors,
capabilities/catalog, and bounded-file refusal presentation. Successful file
admission produces an explicit business-service handoff; the development
executor does not yet bind that operation and refuses it privately. This is not
the public CLI language result for successful file admission. It must not be
installed as the complete fifteen-action entry.

This component does not change capabilities' existing implementation or false
qualification/activation claims. Source-bound development compilation, an
independent execution comparison, full remaining business services, publication,
installed dispatch, and matching-source cold qualification are still required.

## Captured OS input

The executor freezes the actual startup argv and environment C-string bytes,
excluding their terminating NULs but retaining every list entry and order. It
also records the actual stdout TIOCGWINSZ result or raw errno. No option/env-name
interpretation happens there. The source buffer is made physically read-only.

The capture packet is the established HIACOS01 96-byte header, contiguous
sixteen-byte rows, then contiguous raw strings. The HIA capture owner applies
UTF-8 filesystem surrogateescape, skips argv[0], chooses the first COLUMNS
entry, and supplies terminal width to the parser. This component's current
profile is Linux x86-64, CPython 3.12-era UTF-8 filesystem/Unicode 15.0 behavior,
and the default 4300-digit conversion setting. Arbitrary alternative Python
startup locale/digit configurations are not silently claimed equivalent.

## Controller/executor framing

HIACLI01 initializes the private controller: eight u64 words
[magic, 1, actualCaptureBytes, 0,0,0,0,0]. Its workspace is 65536 bytes.
Initial physical mappings are slot 0 (read-only, logical capacity zero), slot 1
(the captured packet, read-only), slot 2 (controller workspace), and slot 3
(128-byte unused peer output). Every later capacity comes from an actual
mechanical allocation ACK, including all component GROW continuations.

Events use the existing HIACDE01 sixteen-word framing. ACKs use HIACDA01 with
the exact lease, monotonically increasing request sequence, requested opcode,
raw syscall/component return, and up to 256 observed bytes copied from the
actual requested view. The generic slot operations are 1 call, 2 grow, 3 clear,
4 copy, 5 release, 6 protect, and 14 observe. The opcode-16 extension executes
one requested raw Linux openat/fstat/read/close operation. The carrier neither
retries a primitive EINTR nor invents a policy result; HIA builds and validates
the exact existing HIAFRA01 reply, chooses retries, and preserves close/error
precedence.

The fixed process owns at most one opened input descriptor. CLOSE consumes it
even when Linux reports an error. Fatal/private failures terminate this process;
Linux then releases its owned descriptor and mappings. This is not a claim of
a reusable nested execution context's cleanup. Transport writes retry EINTR.

Terminal event opcode 7 has words:
[HIACDE01, 7, lease, lastSeq, exitCode,
 stdoutSlot, stdoutOffset, stdoutBytes,
 stderrSlot, stderrOffset, stderrBytes, 0,0,0,0,0].
The executor only checks extents/read-only rights, writes those actual views,
and exits with the HIA-chosen code. It adds no binary success header to the
public streams. Private unresolved/protocol failure is exit 126; mechanical
allocation/I/O failure is exit 74. These development failures are not claimed
to reproduce all ordinary Python infrastructure exception paths.

## Fixed role and buffer maps

Role 1 capture, 2 parser, 3 formatter, 4 metadata, 5 pretty, 6 bounded-file,
7 controller. Role 3 through 6 borrow both inputs read-only; all components
receive a distinct mutable workspace. The fixed executor temporarily protects
borrowed mappings and restores their original rights after the actual call.

Slot 4 stores the completed argv packet, 5 capture scratch, 6 parser state,
7 formatted argument output, 8 command bytes, 9 metadata state, 10 pretty state,
11 file state/input, and 12 the exact raw file reply. Remaining slots are not
implicitly authorized business services.

The HIA packer's private input contains a 64-byte HIACLP01 header, seven exact
image sizes, and their complete bytes. Images are limited to the existing
compiler's 1 MiB image output bound, not a new public program limit. HIA writes
all ELF/padding bytes and image-table addresses. The build fixture must freeze
and verify current source, compiler, images, packer and emitted ELF before
publishing a development receipt. This packet by itself is not external image
authentication or source qualification.

## New draft history

The first source-only executor blob add2a3c043e841b9391b42bdb4d6091af410471c
had a static environment-pointer mistake in byte counting. The new r2 blob
7d13a2bf3f7ee518cd952d5497fc9ff701d3ca1c corrects that pointer before any
assembly or native execution. The earlier draft remains separately retained.

The pending workspace patch for the controller has no observed completion
receipt. The separately saved source-only r2 controller corrects diagnostic
literal lengths (45 and 48), places literals beyond the largest possible
escaped diagnostic scratch, and validates actual Linux fd result ranges.
No previously observed native result is attributed to these new source bytes.
