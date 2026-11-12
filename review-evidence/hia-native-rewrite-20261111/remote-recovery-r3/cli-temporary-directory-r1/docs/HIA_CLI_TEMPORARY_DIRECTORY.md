# Native TemporaryDirectory creation and cleanup for CLI publication

Status: new authoring revision 1. No generation, VM or native execution result
is assigned at this checkpoint. These two images are separate from the already
qualified Path prefix, staging writer and verified-publication images.

## Exact reference and policies

Reference is CPython 3.12.14 on Linux x86-64: Lib/tempfile.py,
Lib/shutil.py, Lib/os.py, Modules/posixmodule.c, and the exact 0ef954 Hepta
publish_program/publish_json_view functions. The current hepta/cli.py Git blob
e81e607dcb052c77e3c1cf9fe946f70109e5d8e9 was read back byte equal to 0ef954.

Policy 1 uses .hia-publish- plus eight characters, and stage program.hia.
Its payload is independently verified canonical Core without an added newline.
Policy 2 uses .hepta-json-view- plus eight characters, and stage view.json.
Its parent must first produce sort_keys=True, indent=2, ensure_ascii=True,
allow_nan=False JSON, followed by exactly one LF. This creation image does not
pretend that policy 2 is equivalent to policy 1 or to CLI display formatting.

Both policies create the directory with mode 0700, subject to the process umask.
The original Linux TMP_MAX=238328 collision bound is retained. Only EEXIST
retries mkdir; mkdir EINTR is an ordinary original OSError, not silently retried.
The generated name alphabet is abcdefghijklmnopqrstuvwxyz0123456789_.
The private generator uses actual nonblocking getrandom and preserves partial
reads and EINTR. Failure to obtain entropy enters the same non-throwing
time/pid fallback category as Random(None). It does not reproduce CPython's
private PRNG state or seed expansion. No deterministic name, input-derived
name, process-global sequence, or cryptographic authentication claim is made.

## Private creation command and event

R/R/W entry uses an immutable command, immutable last reply, and owned mutable
workspace. Minimum workspace is 1024 bytes. All 64-bit fields are little endian.
Command HIATDC01 is 64 bytes followed by absolute filesystem parent bytes and
one terminal NUL:

magic, version 1, lease, initial sequence, parentBytes, totalBytes, policy, zero.

The policy is exactly 1 or 2. The parent is the actual normalized output from
the Path owner. This header does not authorize an arbitrary external path.
The fixed parent must keep the entire command immutable through GROW/retry.

Return is 128 for an event, FD=0xfffffffd for permanent refusal, or
FE=0xfffffffe for GROW. Event HIATDE01 lives at workspace offset 256:

magic, action, lease, sequence, filesystem op, errorCode, errno, created,
pathOffset, pathBytes, countOrStageOffset, flagsModeOrStageBytes,
failedCollisionCount, zero, requiredWorkspace, phase.

Actions are 0 terminal, 1 GROW, 2 syscall, 6 refused. Error code 1 is the actual
mkdir OSError with full candidate path; error code 2 is EEXIST with the original
No usable temporary directory name found message and no filename. Success
returns the complete owned directory and stage byte views. NUL is present in
the workspace but excluded from successful view lengths. GROW publishes no
directory and does not advance a syscall sequence.

Reply HIATDA01 is 64 bytes plus the actual syscall payload:

magic, lease, sequence, op, errorStatus(0/1), result, errno, payloadBytes.

Primitives match publication's fixed syscall vocabulary: 11 mkdir,
15 getrandom; new raw-only 24 clock_gettime and 25 getpid. Clock records are
the actual 16-byte Linux timespec. Creation chooses every retry and pathname
in HIA; the development Python peer only forwards the issued primitive.

## Exact fd-safe cleanup order

Cleanup command HIATRC01 is 64 bytes plus absolute root bytes and NUL:

magic, version 1, lease, initial sequence, pathBytes, totalBytes, zero, zero.

Minimum workspace is 4096 bytes. Event HIATRE01 at offset 256 is 256 bytes,
with the first nineteen words:

magic, action, lease, sequence, op, resultKind, errno, errorOperation,
pathOffset, pathBytes, token, capacity, integerA, integerB,
requiredWorkspace, globalPhase, liveDescriptorCount, currentPhase, otherToken.

All remaining words are zero. Terminal resultKind 0 succeeds, 1 preserves the
real OSError category/errno/full filename, and 2 preserves the exact custom
Cannot call rmtree on a symbolic link error. Structured terminal data is not
yet the public CLI OSError text renderer.

Reply HIATRA01 uses the same eight-word shape as creation. Linux stat payloads
are exactly 144 bytes; directory records are complete actual getdents64 bytes.
Malformed framing permanently poisons the workspace. After a reply requires
GROW, its entire header remains pinned before either success or error branches.
Actual immutable reply bytes must still be retained by the fixed issuer;
matching a header alone is not external authority.

The native algorithm retains CPython's original stack and exception order:

- lstat / open(O_RDONLY|O_NONBLOCK) / fstat binds the directory inode before
  traversal. Open receives O_CLOEXEC through the same Python FD profile.
- A directory-removal job is appended only after the stat identity agrees.
  Its close job is appended even when fstat fails or identity differs.
- Scandir uses an independently duplicated owned descriptor. Complete entries
  are saved before any entry is unlinked. Its iterator-close errors are ignored,
  as in the C iterator. ENOENT returned by the directory stream ends iteration.
- Non-directory entries are unlinked in stream order. Directory jobs are pushed
  in that order and later popped in reverse order. DT_UNKNOWN uses no-follow
  stat; cached stat results are reused by the corresponding walk.
- Symlinks are never walked as directories. Full filesystem byte names,
  including surrogateescape names, are copied into owned growable storage.
- FileNotFoundError is ignored exactly at the callback. PermissionError performs
  the original parent/path permission reset, unlink attempt, directory test and
  nested _rmtree call. The repeated-root guard is preserved.
- A failing per-entry unlink callback is caught again by the original outer
  directory step. Its filename becomes the current directory before that second
  callback. This ordering is not replaced with a generic first-error rule.
- On failure, pending non-close jobs are discarded and pending closes are
  consumed. If a close callback itself raises during this final unwind, that
  exact last callback error stays authoritative; remaining owned descriptors
  receive quiet close-only disposal before the native context returns. This
  last disposal corresponds to ownership cleanup at a fixed-process boundary;
  it does not perform further unlink/rmdir/chmod or replace the original error.

There is no added tree depth, total entry, byte, descriptor or syscall quota.
Storage and job/context stacks grow with actual data. The implementation does
not claim identical Python allocator failures, audit hooks, signal handlers,
or Python callback RecursionError behavior in an embedding process.

Existing primitives 1/2/3/7/8/10/12/16/17/18/20/21 are reused.
New primitive 23 is only F_DUPFD_CLOEXEC: HIA supplies an issued source token and
fresh target token. The fixed carrier must publish the actual new FD token,
consume each close once, and preserve FD 0. No host directory parser or removal
policy is allowed. The new mechanical carrier extension is still a separate
integration obligation.

## New evidence plan

The new test performs two original-limit B3 compilations and separate actual
native pipelines:

- 12 controlled-name physical creation comparisons, two policies across six
  parent/collision conditions, against original tempfile.mkdtemp.
- 2 real-entropy creation cases proving name shape, mode and actual OS creation.
- 18 full physical cleanup comparisons with original TemporaryDirectory._rmtree,
  including missing/file/link roots, nested permissions, external hard/symlink
  targets, FIFO, Unicode/non-UTF8 names, 900 entries and 40 directory levels.
- 21 malformed reply/permanent-poison controls, including success-to-error
  replacement across an actual reply GROW.
- 3 separately labelled controls: the last collision's private near-boundary
  state, partial/EINTR entropy, and actual clock/pid fallback after an injected
  entropy failure. The private boundary control does not claim 238328 physical
  collisions.

Every native entry preserves full source, reply, workspace before/after and
canaries in losslessly compressed content-addressed storage. Physical source
trees have raw-name/type/mode/content/link-target manifests; original syscall
receipts are retained. Original compiler 10 CPU / 20 wall / 256 MiB and test
90 CPU / 1 GiB limits remain unchanged. No old suite result is reused.

Whole fixed publication, policy-2 formatting, parent HIACPR construction, public
OS-error presentation, and final successful A/E CLI publication remain OPEN
until the actual complete parent integration executes.
