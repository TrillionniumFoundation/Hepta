# Native CLI publication parent, development revision 1

Status: **new authoring and tests, not yet generated, compiled or executed**.
The published public-A parent and prior component runs remain unchanged. This
revision cannot inherit their PASS counts. Its target is a new same-process
fixed native entry with real publication; activation, cold qualification and
the remaining CLI businesses are separate gates.

## Ownership and finite tables

The packer has 140 role entries: fourteen parent roles, one 63-role A service
table, and one 63-role E service table. This is table capacity, not a claim that
140 nonzero business images are exercised. The first new integration binds the
real source-qualified A table and a single private policy-2 query issuer in E
role 56. That issuer does not implement edit preparation or application.
The actual nonzero image count is recorded in the bundle.

| Parent role | Owner |
|---|---|
| 1–6 | Retained capture, argv, formatter, metadata, pretty JSON and file input |
| 7 | New HIA parent and publication continuation |
| 8 | Exact native verified-publication transaction |
| 9 | Exact native Path prefix and mkdir/resolve order |
| 10 | Retained actual HIA SHA stream |
| 11 | Exact native staging BufferedWriter/flush/fsync/close |
| 12 | Native temporary-directory creator |
| 13 | Native complete FD-safe temporary cleanup |
| 14 | Native path/error quoting and final text encoding |

The mechanical carrier retains the original service suffix byte for byte.
CLI → service → program → ordinary remains a fixed, bounded call graph with
independent context state and one active sibling service. The new carrier only
adds raw fcntl(F_DUPFD_CLOEXEC), clock_gettime and getpid, taking complete
HIA-issued descriptors. It neither parses JSON nor chooses publication policy.

Parent operation 19 has the original twelve-u64 argument shape:
kind, FD token, first slot/offset/extent, integer A,
second slot/offset/extent, integer B, zero, zero.
Primitive kinds 1–22 remain unchanged; 23 duplicates an owned FD into a fresh
token, 24 writes the real 16-byte clock structure, and 25 returns the real PID.
Raw errno stays in HIACDA01 word 5. CLOSE consumes before the syscall.
No new descriptor/call/session quota is added. Child table rights are unchanged;
the parent two-read mask is 0x7b78.

## Real transaction and cleanup order

After a real service publication request, the parent first performs the exact
Path prefix. Policy 1 retains canonical Core without an added line feed.
Policy 2 formats the already-issued complete compact query as sorted-source
indent-2 JSON with ensure_ascii=True and a final LF, after the Path prefix.
The pretty owner does not sort; the service owns the already validated order.

HIA then creates the private temporary directory, writes and flushes the stage,
fsyncs and closes it, performs the complete native publish_verified operation,
and cleans the whole temporary directory. Only after successful cleanup does it
resume the service. Cleanup failures override an earlier body failure, matching
the original context-manager order. No success receipt is manufactured after a
failed write, verification, link or cleanup.

All saved object references are offsets in live parent-owned buffers. The
temporary owner work stays readonly while raw syscalls borrow its paths, then
returns RW for its next HIA entry. A GROW replays the same immutable command and
reply and never repeats an OS call. The cleanup event is the full 256 bytes;
all other transaction events are 128 bytes. SHA requests execute the real
native stream in 8 MiB chunks, with no new total payload quota.

The active slot allocation is:

| Slots | Contents/lifetime |
|---|---|
| 4, 6, 11 | Existing argv, parser and initial program input |
| 13, 14, 15 | Existing business command, lease-vector and copied yield |
| 20, 21, 22 | Path command, current complete reply, Path state |
| 23–26 | Creator, writer, verifier and cleanup state |
| 27–29 | Raw OS result, SHA input and SHA state |
| 31 | Complete quoted absolute destination JSON |
| 32–36 | Creator/writer/verifier/cleanup commands and completed HIACPR |
| 37–40 | Policy-2 pretty command/state, presentation state/command |
| 41, 42 | Final encoded stdout/stderr readonly copies |

The existing raw SHA output is slot 3. It remains the only writable second
operand of a parent R/W/W CALL. Source/command/state aliasing is rejected by
the unchanged mechanical operand rules.

HIACPR01 is 128 bytes followed contiguously by two complete JSON values:
the quoted absolute destination and the actual compact sorted publication
receipt. Its sixteen words are magic, version, service ID, service lease,
previous child yield sequence, logical request, parent sequence, policy,
destination offset 128, destination bytes, receipt offset, receipt bytes,
total bytes, and three zero words. The final parent sequence is computed for
the actual COPY/PROTECT/COPY/PROTECT/RESUME path. The service validates it and
the actual digest; the carrier only forwards readonly leases.

## Presentation and output codec

Role 14 receives a complete immutable byte source and 96-byte HIAPSC01 command:
magic, version 1, lease, sequence, kind, number, has_path, source bytes, four zero
words. It returns a 128-byte HIAPSE01 event at work offset 256. Action 1 requests
exact dynamic work growth; action 0 yields a complete readonly offset/extent;
return FD and poison reject malformed private frames.

Kinds 1–5 produce complete ensure-ASCII JSON path quoting, exact Linux OSError
text with filesystem-byte repr, BufferedWriter BlockingIOError text, fixed
publication errors, and filesystem repr respectively. The generated tables
are bound to CPython 3.12.14, Unicode 15.0.0 and the English C/C.UTF-8 locale.
They contain Unicode printable intervals and actual Linux errno texts;
production decoding, quoting and decimal formatting execute as HIA.

Kind 6 performs the configured development profile's UTF-8/surrogateescape
stdout encoding. Kind 7 performs stderr UTF-8/backslashreplace. Both accept the
private internal UTF-8/surrogatepass representation. Kind 6 returns semantic
error flag 1 in event word 8 with full UnicodeEncodeError text when necessary.
Other kinds require that flag to be zero. A prefix of DC80–DCFF surrogates is
consumed before reporting the first unencodable member, while the exception
end remains the end of the consecutive surrogate run, matching the actual
CPython UTF-8 encoder. The parent formats an actual encoding failure as the
original CLI E_DRIVER JSON; no partial stdout is published.

Source reference: CPython v3.12.14
[Objects/stringlib/codecs.h](https://github.com/python/cpython/blob/v3.12.14/Objects/stringlib/codecs.h),
[Python/codecs.c](https://github.com/python/cpython/blob/v3.12.14/Python/codecs.c),
and the exact retained hepta/cli.py and hepta/artifact_publication.py.
These are development/reference sources, not runtime fallbacks.

## New execution plan and original evidence

The new test runner will execute, without inheriting older results:

- 207 native presentation cases, including errno 1–133, full path/error text,
  malformed filesystem UTF-8, all surrogate classes, large text, and both final
  output codecs; plus 14 permanent-poison/private GROW controls.
- 44 public A normalize/publication cases: all 25 frozen program inputs,
  seventeen Path scenarios, an FD-zero case, and a private umask case.
- 11 explicitly private issued-query policy-2 publication cases. The separate
  oracle invokes the original publish_json_view, but the native ELF runs the
  real complete parent; this does not qualify E semantics.
- One actual HIA 140-entry ELF packer invocation with complete expected bytes,
  readonly source/canary checks, and all unchanged service suffix bytes checked.

Nine new B3 compilations retain 10 CPU seconds, 20 wall seconds and 256 MiB.
The old profile maxima remain 128 functions, 1536 blocks, 8192 operations and
16 block parameters. ELF children retain 90 CPU seconds, 1 GiB and 30 wall
seconds, PDEATHSIG with the parent race check, and complete kill/wait cleanup.
The outer CI bound is unchanged.

All new process stdout/stderr/wait4 records and complete buffer bytes use
lossless zlib CAS, with a full decompression/hash readback. Filesystem snapshots
record every observed mode/type, exact regular-file byte digest and bytes,
symlink target, and separate inode/timestamp observations. Equality compares
semantic effects, not unrelated inode allocation or clock values. Reference
and native use the same absolute fixture path sequentially, resetting only
after preserving the whole observed state. Physical symlinks are never followed
into the evidence archive.

The old 967 components, 193 CLI entries, 75 A fixture jobs, and component
publication/Path/writer suites are not rerun and are not counted as this result.
A failure preserves the complete new attempt and does not become a prior PASS.

## Explicit remaining boundaries

This stage does not claim whole-CLI, installed activation or cold qualification.
Real E service table integration is still separate from the policy-2 issuer.
Nondefault startup integer-digit configuration and nondefault text locale or
stream encoding require the corresponding startup owner. The existing Path
owner's over-PATH_MAX getcwd fallback and Python's unhandled resolve-symlink-loop
RuntimeError traceback remain explicit compatibility work. The parent does not
forge those tracebacks as ordinary E_DRIVER errors. Foreign Python object
capture, audit hooks, allocator failures and arbitrary executable images are
not authenticated by private frame headers.
