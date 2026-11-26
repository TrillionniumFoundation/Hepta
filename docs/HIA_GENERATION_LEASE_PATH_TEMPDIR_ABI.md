# Generation owner native absolute paths and temporary directory cache

This component qualification covers real HIA policies, fixed mechanical bridges,
native packing/linking, and the actual operating system behavior recorded in
HIA_NATIVE_GENERATION_LEASE_PATH_TEMPDIR_QUALIFICATION.json. It does not qualify the
public ScalarMultiversionRuntime constructor, arbitrary __fspath__ methods, or
native exception object construction. Those enclosing interfaces must retain
these components until their actual cleanup acknowledgements.

## Absolute paths

Entry: hia_generation_lease_owner_absolute. The native six-word ABI is
(input pointer, input length, output pointer, output length, workspace pointer,
workspace length). Output is at least 128 bytes; workspace is at least 200704
bytes, initially zero, at its stable native address. The fixed bridge rejects
overlapping ranges and malformed requests before writes.

The 32-byte request has magic at 0, operation at 8, body length at 16, and zero at
24. Operation 0 is followed by exactly body-length bytes of WTF-8.

| Magic | Operation | Meaning |
| --- | --- | --- |
| HIAGPAQ1 | 0 | Lexical pathlib.Path.absolute: retain dot-dot, do not resolve input symlinks |
| HIAGPAN1 | 0 | Separate posixpath.abspath normalization: collapse dot-dot |
| HIAGPAQ1 | 1 | Retry/abort a known pending cleanup; exactly 32 bytes, all other words zero |

Both paths use the actual cwd. The cwd fallback walks real parent directory FDs
when the cwd exceeds the ordinary getcwd buffer. File system bytes use surrogate
escape; the input WTF-8 representation preserves lone surrogates and NUL because
lexical input processing does not open the caller's path. Normalization preserves
the special double-slash root.

The 128-byte HIAGPAR1 reply has status at 8, raw negative errno at 16, failure
phase at 24, transferred output FD at 32, byte length at 40, seals at 48, pending
at 56, unknown-close bit mask at 72, and cleanup errno at 88. Absent FD is UINT64_MAX.
Successful output is a native sealed memfd with F_SEAL_SEAL, F_SEAL_SHRINK,
F_SEAL_GROW and F_SEAL_WRITE, and FD_CLOEXEC. The recipient owns the transferred FD.

A failed close_range retains the exact known FD for explicit retry. ENOSYS uses
actual close. An error from close is ownership-uncertain: the exact slot is
quarantined, never retried using a possibly reused FD number, and operation 1
rejects without modifying the pending operation. Copying the workspace or using
it after fork does not create another cleanup authority.

## Temporary directory

Entry: hia_generation_lease_owner_tempdir. The same native six-word convention
uses at least 128 output bytes and an exact, stable, initially zero 204800-byte
workspace. The bridge owns a private 4096-byte call scratch; the caller's output
does not substitute for that scratch.

Every request is exactly four little-endian u64 words: HIAGTDQ1, operation, zero,
zero. No environment pointer, native entry, callback, or context pointer is
accepted in a request.

| Operation | Meaning |
| --- | --- |
| 0 | Get the cached directory, or select and probe it using the current environment |
| 1 | Retire the context and all its actual owned resources |
| 2 | Retry known pending cleanup without beginning a new directory selection |

The first selection reads the current libc environ through a fixed dlsym boundary,
captures nonempty TMPDIR, TEMP and TMP, then captures cwd before probing. Candidates
remain in the original order: those environment choices, /tmp, /var/tmp, /usr/tmp,
then captured cwd. The exact environment value "." retains its relative spelling;
other choices use the separate posixpath.abspath profile. Actual getcwd failure
uses the original "." fallback.

Each candidate uses native getrandom names, exclusive no-follow opens with mode
0600, an actual fstat identity, the actual four-byte "blat" write, close and unlink.
EEXIST follows the original 20-attempt per-directory bound. Cleanup verifies the
original inode before removing a remaining pathname. A replaced inode is preserved.
The selected WTF-8 directory is cached in an owned sealed memfd and returned by
actual F_DUPFD_CLOEXEC. Changes in the environment or later deletion of the selected
directory do not invalidate this context's cache.

HIAGTDR1 is a 128-byte reply:

| Offset | Field |
| --- | --- |
| 8 | Status: 0 success, 4 operating-system error, 6 state refusal, 8 no candidate, 11 cleanup/error |
| 16 | Raw negative errno |
| 24 | Failure phase |
| 32 | Transferred result FD, or UINT64_MAX |
| 40 | Result byte length |
| 48 | Result seals, 15 when a result FD is present |
| 56 | Pending cleanup |
| 64 | Whether a cached directory remains owned |
| 72 | Actual context-retired acknowledgement |
| 80 | Whether cleanup ownership is known |
| 88 | State: 1 ready, 2 known pending, 3 closed, 4 quarantined |
| 96 | Candidate index |

Status and delivered FD are independent. The real result FD can have been
published before a later futex-wake error. A caller must consume/retain/close every
present result FD even if status is nonzero. A nonzero status never authorizes
forgetting the FD.

Retirement is complete only after operation 1 returns retired=1 with pending=0.
A known pending operation retains the selected cache, input captures, probe FD,
inode, and owned mappings required for retry. An uncertain close quarantines the
context; it does not claim retirement or retry an uncertain FD. The enclosing
owner must retain the context mapping and code image in both cases.

The mutex covers selection, cleanup, and cache duplication. PID plus the actual
workspace address prevents copied or forked workspaces from acquiring authority.
No host-side policy, Python role callback, forged syscall result, or mutable lock
word is used in the native qualification.

## Native composition and evidence

The absolute capsule has one HIA role and uses the existing fixed
hia_native_path_resolve_bridge.S. The temporary-directory capsule statically
links its HIA policy, the exact absolute capsule, and the HIA FS/WTF-8 codec.
Its bridge's only external import is dlsym for the current libc environment.

The published build receipts capture HIA and mechanical assembly as native
source dependencies. Generator and qualifier hashes are development provenance;
production execution does not import them.

The evidence directory is
/home/qian-qi/hia-followthrough-evidence-20261126-620a/generation-lease-path-tempdir-v1.
Absolute qualification has 7 groups. Temporary-directory qualification has 12
groups, including 3588 byte/WTF-8 round trips, all 2048 surrogate code points,
actual long cwd and invalid FS bytes, cache concurrency, fixed syscall failures,
replacement-inode preservation, real seccomp-notified mutex contention,
close_range ENOSYS fallback, uncertain close quarantine, and publication before
futex-wake failure. Unknown-close tests explicitly retain custody until process
exit; they do not record a false native cleanup acknowledgement.

The enclosing constructor still has to connect its actual Value inputs,
verification order, original Clang build, directory lifetime, and exception
objects. Its qualification flags remain false here.
