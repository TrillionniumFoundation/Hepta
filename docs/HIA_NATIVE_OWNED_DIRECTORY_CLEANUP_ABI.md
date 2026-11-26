# Native owned-directory recursive cleanup

This capsule recursively deletes a directory through captured file descriptors.
The HIA policy owns traversal, identity checks, pending custody and retirement.
The fixed x86-64 bridge supplies syscalls, atomic mutex operations and bounded
memory copies. It has no external imports and accepts no callbacks or function
pointers in requests. The original HIA compiler limits and the 4 MiB role /
16 MiB product limits are unchanged.

## Entry and spans

The exported entry is `hia_native_owned_directory_cleanup`, with the existing six-word ABI:

`(input, input_bytes, output, output_bytes, context, context_bytes) -> u32`.

The context is an initially zero, stable, 8-byte-aligned 4096-byte span. The
output span is at least 128 bytes. Input, output and context must not overlap.
A context records its actual PID and address; copied or inherited contexts
are rejected without modifying the caller's output or context. An output
shorter than 128 returns `0xfffffffe`; invalid wire or span returns
`0xfffffffd`. The bridge's private 65536-byte scratch is not a caller
allocation or part of the persistent context.

## Requests

All integers are little-endian u64. Every request begins with eight ASCII bytes
`HIARMTQ1`.

| Offset | Operation 0: begin deletion | Operations 1 and 2 |
| --- | --- | --- |
| 8 | 0 | 1: retry; 2: retire resources only |
| 16 | Borrowed root-directory FD | 0 |
| 24 | Borrowed parent-directory FD | 0 |
| 32 | Leaf byte count | 0 |
| 40–127 | All zero | All zero |
| 128 onward | Exact raw filesystem leaf bytes | No tail |

The leaf is nonempty, contains neither slash nor NUL, and is neither dot nor
dot-dot. No UTF-8 conversion is performed. Linux applies its ordinary per-entry
name restrictions. Borrowed descriptors may be 0 or 1 and remain caller-owned.
The policy takes real `F_DUPFD_CLOEXEC` captures and compares the captured root's
device/inode/type with `fstatat(parent, leaf, AT_SYMLINK_NOFOLLOW)`.
It then opens dot relative to that captured root with
`O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` and compares identity again. This fresh
open file description prevents traversal from consuming or depending on the
caller's directory offset.

Operation 1 continues a known pending state. It does not duplicate or drop an
already-owned descriptor again. After an actual `ENOTEMPTY` at directory removal,
it rewinds the held traversal FD with a real `lseek` and enumerates again.
A failed rewind retains the same traversal state for another retry.

Operation 2 stops deletion and retires only the capsule's own FDs and mappings.
It can therefore succeed at retirement while the root and its remaining files
still exist. It preserves the original primary error for diagnosis.
Both operations return a stable retirement acknowledgement for an already
retired context. Reusing a retired context for a new operation 0 is refused.

## Replies

A successful ABI invocation returns zero and writes a 128-byte
`HIARMTR1` response. An ABI return of zero alone does not mean deletion or
retirement succeeded.

| Offset | Field |
| --- | --- |
| 8 | Status |
| 16 | Primary raw negative Linux errno, encoded as u64 |
| 24 | Phase where the primary failure occurred |
| 32 | Ownership known: boolean |
| 40 | Pending custody: boolean |
| 48 | Context resources actually retired: boolean |
| 56 | Root actually removed by this capsule: boolean |
| 64 | Currently owned FD count |
| 72 | Currently owned mapping count |
| 80 | Enumerated non-dot entry count |
| 88 | Entries actually removed by this capsule |
| 96 | Current directory depth |
| 104 | Additional cleanup raw negative errno |
| 112–127 | Zero |

Status 0 means successful completion of the requested operation. Status 4
records a primary operation or lock error; retirement must still be checked.
Status 6 refuses an incompatible context state. Status 11 retains pending
custody or quarantines an uncertain result.

The caller may release the stable context and code image only after a
trustworthy response has `known=1, pending=0, retired=1`. Deletion success
additionally requires `root_removed=1`. The root-removed bit is set only after
the capsule's actual `unlinkat(..., AT_REMOVEDIR)` returns success. An absent
name, resource retirement, or process exit does not fabricate that bit.

A release can finish and a subsequent mutex wake can fail. The returned fields
continue to report the actual retirement facts independently of status.
Consumers must preserve those facts rather than inferring custody from status
alone.

## Traversal and failure semantics

Every active directory level owns a 36864-byte native mapping and an FD. Its
frame contains a 256-byte header and a 32768-byte `getdents64` buffer. Child
names borrow their still-held parent's buffer. Parent state is saved before
descending, and the parent frame remains mapped until the child has retired.
This avoids building an absolute path or imposing a fixed recursion depth.
Allocation, kernel FD limits and filesystem errors remain real failures.

Entries are examined with `fstatat` without following symlinks. Directory
children are opened with `O_NOFOLLOW` and checked against their observed
device/inode/type before descending. Nondirectories, including symlinks, are
unlinked relative to the held parent. Before removing each directory name,
the policy rechecks that it still identifies the held directory. A replacement
observed by that check yields `ESTALE` and retains custody. These are actual
Linux descriptor and identity checks, not an atomic conditional-unlink
operation supplied by the kernel.

Known `close_range(fd, fd, 0)` failures retain the exact FD. `ENOSYS` selects a
real `close(fd)` fallback. A failing fallback is treated as ownership-uncertain;
the capsule quarantines the original custody and refuses automatic retry,
rather than risking closing a descriptor that may have been reused.
Unmap failures likewise retain the exact mapping and continuation. An unknown
reply never grants a retirement acknowledgement.

## Permission recovery

The native policy follows the observed Linux `TemporaryDirectory._rmtree`
permission recovery behavior. A real `EACCES` or `EPERM` during traversal or
deletion starts one permission repair attempt for the current entry. The held
directory is changed to mode 0700 with a real `fchmod`. An entry requiring its
own permission repair is first examined without following symlinks, captured
with `O_PATH | O_NOFOLLOW | O_CLOEXEC`, and compared by device, inode and type
before changing that exact captured object to 0700. Symlink targets are never
changed.

The preferred operation is `fchmodat2(captured_fd, "", 0700, AT_EMPTY_PATH)`.
A real `ENOSYS` or `EINVAL` selects `chmod` through the actual owned descriptor's
`/proc/self/fd/<number>` path. This fallback still identifies the held object
rather than reopening the mutable directory entry. If that real operation
fails, the FD and continuation remain owned for operation 1. The fallback does
not hide a missing procfs or any other kernel error. A hardlink refers to the
same inode, so the mode change is visible through its other names, as in the
original Python behavior.

The root's externally borrowed parent is not chmodded. Initial root identity
failure never grants permission to change an unverified object. A captured
entry whose identity differs from the preceding observation is closed and
reported as `ESTALE` without chmod. Directory replacement after capture does
not redirect the permission repair to its replacement.

Permission captures are counted in the existing FD custody field. Failures in
`fchmod`, `fchmodat2`, the descriptor-path fallback, or descriptor close preserve
the actual continuation. Operation 2 retires those captures without pretending
that the remaining tree was deleted. Permission repair uses context offsets
400–456 for continuation and inode facts, with the actual permission FD at 416;
the existing 4096-byte context and public request/reply layout do not change.
The current Linux oracle has no `chflags` operation; this qualification does not
claim a BSD file-flags implementation.

## Native packaging and qualification

The independent packer consumes `HIARMTP1`, role count 1, one length at offset
16, and the actual policy bytes beginning at offset 24. It produces an ELF
relocatable containing the fixed bridge and policy. The native linker produces
the shared product. The capsule's extracted text has no external relocations;
an enclosing native product can bind its entry statically.

The qualification receipt records the exact source, bridge, product, native
compiler and evidence hashes. The original 15 groups cover the packer domain, real
nested deletion, a 160-level tree beyond 4096 total path bytes, original
directory-offset preservation, identity and no-write guards, actual kernel
failures, retry and abort, fallback close and unknown custody, real notification
races, `ENOTEMPTY` rescan, mutex contention, and borrowed FD 0/1. All 15 were
rerun against the permission-aware product without changing their assertions.

An additional 16 groups compare actual Python permission recovery with native
behavior for root/child mode 000, hardlinks, symlinks and an unwritable external
parent. They also cover 112 nested mode-000 directories beyond 4096 total path
bytes, real kernel permission syscall failures, the real ENOSYS fallback,
retained permission FDs, abort-only retirement, and three notification-controlled
inode replacement races. All gates run under the unprivileged service account.

The Python author and qualification driver are development provenance only.
Neither is read or executed by the native capsule. This component's
qualification does not declare the complete public Runtime, Clang outer, or
repository migration complete.
