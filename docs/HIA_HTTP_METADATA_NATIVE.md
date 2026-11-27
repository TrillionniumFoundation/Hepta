# Native HTTP metadata and complete diagnostic delivery

This component connects `request_history`, `request_archive`, and `usage_stats`
to the existing authenticated native HTTP service. It also carries complete
large parameter diagnostics through the native child frame, HTTP response,
private event cache, and event replay. The implementation adds no native source
path or executable role. The existing Worker tool catalog remains unchanged;
the public service exposes its eleven tools plus the three metadata tools.

## Authority and original boundaries

HTTP authentication retains the original `X-Hepta-Runtime-Token` header and
account-owned private token file. Query ownership comes from the held private
credential and held root. Callers cannot supply a controller, generation, root,
or owner. The existing session and task generation checks remain in the child
frame and event routing. The original history/archive/usage query ABIs are used.

The input bound remains 4 MiB for HTTP. The original 8 MiB canonical query and
three-second absolute metadata deadline remain unchanged. Ordinary child
responses retain their 8,389,120-byte bound; ordinary parent responses retain
16,777,216 bytes; ordinary HTTP response/cache buffers retain 16,777,728 bytes.
Only an SDK-admitted tools/call metadata descriptor can mark its held task as
eligible for the metadata response bound of 72 MiB plus 512 bytes. This is the
existing complete stdio diagnostic bound and does not enlarge HTTP inputs.
Process state remains 384 MiB.

The fixed child output frame is still `HIAHCO01`. A complete frame header,
including its slot and generation, precedes any large body. The existing child
response file is private until the request finishes and all four Linux memfd
seals are applied. Partial writes, short reads, and EINTR preserve offsets.
Cancellation resolves before publication. The parent separately captures and
seals the complete framed response before using it.

## Bounded HTTP and cache output

Large metadata replies are copied in at most 64 KiB chunks. The existing small
response path retains its original limits. A bounded prefix identifies the
original HTTP status, and the final byte is independently checked for the
expected JSON line terminator. Event output is written directly into the
session's private cache file, then into the existing connection response file.
No complete diagnostic is copied into an undersized in-memory response buffer.

Large cache entries have an explicit `HIAHEV02` marker with all reserved fields
checked. Existing `HIAHEV01` entries retain their original bound and behavior.
The cache length is published only after every byte has been written. Existing
session routing, generation checks, 60-second expiry, and event indexes are
retained. Index zero replays priming plus the final event; index one replays the
final event; index two returns an empty stream. The new file continuation closes
the connection and resumes the owning task cleanup after I/O or seal failure.

HTTP/1.1 retains chunked SSE output. HTTP/1.0 retains its close-delimited SSE
body. Stateless requests with complete inline protocol metadata receive the
original SSE shape without event IDs. Missing protocol capability metadata
still fails before typed parameter processing. Cancellation retains the
original HTTP empty-event tombstone behavior.

## Construction and evidence

`HIA_HTTP_METADATA_NATIVE_QUALIFICATION.json` pins the exact source inputs,
native products, full original Rust observations, and component control reports.
The builder takes explicit bootstrap, controller bundle, and audit executable
paths. It checks the copied controller manifest, the prior controller source
pins, the audit construction report, and every audit source pin. Four fixed
native bootstrap roots construct the div-word compiler and every HTTP role.
The native HTTP packer is checked against the complete mechanical ELF template
and all embedded bodies, including three malformed composition refusals.

The Rust diagnostic reference is the unmodified Runtime at
`ae1c7ea593da45f7299c692a2acd44605c35be09`. The new HTTP-sized observation uses
4,193,292 canonical parameter bytes and produces a complete 29,353,061-byte
error object. Its raw input, stdout and error JSON are retained as compressed
files. Native comparisons check the complete error code, message length,
message hash and serialized error hash; no abbreviated expected message is
used. Previous original Unicode and parameter observations remain available in
the usage/history fixtures.

Actual socket controls cover all three metadata routes, discovery,
authentication, large history/archive/usage errors, cache replay, stateless
metadata, HTTP/1.0, the exact 4 MiB input boundary and one-byte-over refusal.
Real process controls stop a worker after partial private output, answer an
independent ping, verify final seals, and cancel another partial response. A
stopped audit process demonstrates the original three-second query deadline
and stale response drain. Additional credential controls check held ownership,
same-credential reconnect/restart, session cache isolation, and foreign cursors.

Native continuation controls separately exercise ordinary and metadata bounds,
short I/O, EINTR, EOF, generation/session mismatch, malformed cache versions and
reserved fields, expiry, and cleanup after publication failure. They are
explicit syscall-result controls; the separate socket observations establish
real transport behavior. Failed observer fixtures and noexec construction
attempts are retained with their original logs instead of being counted as
passing observations.

## Integration scope

These are component construction and public HTTP controls. They do not qualify
a complete cold release, installed Worker, or the whole Runtime. Final native
authority, Worker identity, release identity and the complete delivery chain
must be generated from the integrated source head.

Archive/usage pending-index batching and the complete original concurrent
publication/replacement matrix remain a separate Runtime parity item. Their
original `request_archive_index`, `request_archive_content`, archive batch and
usage batch sources and tests are tracked independently; HTTP delivery success
does not close them.
