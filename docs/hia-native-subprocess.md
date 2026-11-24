# Native HIA subprocess owner

`hia-subprocess` owns one sealed workload from admission through a durable terminal
receipt. `examples/hia_bootstrap/subprocess.hepta` chooses every syscall and every
lifecycle transition. `tools/hia_subprocess_syscalls.S` maps the bounded request,
calls that policy, translates buffer offsets to syscall addresses, and dispatches
the selected syscall. It does not contain a second scheduler or terminal policy.

The executable has no command arguments. Its descriptor 0 is a regular memfd with
all four immutability seals (`F_SEAL_SEAL`, `F_SEAL_SHRINK`, `F_SEAL_GROW`, and
`F_SEAL_WRITE`). The workload's stdin is a different descriptor carried in the
request. There is no path lookup for the workload executable: the owner executes
its supplied, sealed descriptor with `execveat(AT_EMPTY_PATH)`.

## Request

The header is 128 bytes, little endian, equivalent to `struct <8s15Q`:

| Offset | Field | Contract |
| --- | --- | --- |
| 0 | Magic | `HIASUB01` |
| 8 | Parent PID | Exact current parent, checked before and after installing the parent death signal |
| 16 | Deadline | Absolute `CLOCK_MONOTONIC` nanoseconds |
| 24 | Executable FD | Sealed regular memfd, nonempty, at most 64 MiB |
| 32 | Workload stdin FD | Sealed regular memfd, at most 512 MiB; rewound before execution |
| 40 | Stdout capture FD | Empty private regular file or memfd |
| 48 | Stderr capture FD | Empty private regular file or memfd |
| 56 | Working directory FD | Open directory used by `fchdir` |
| 64 | Receipt FD | Empty private regular file or memfd |
| 72 | Argument count | 1 through 64 |
| 80 | Environment count | 0 through 64 |
| 88 | Stdout byte limit | 0 through 512 MiB |
| 96 | Stderr byte limit | 0 through 16 MiB |
| 104 | Termination grace | 1 millisecond through 5 seconds |
| 112 | Address space limit | 0 disables the additional limit; otherwise 64 MiB through 16 GiB |
| 120 | Owner lock FD | 0 omits it; otherwise a private regular file with one link |

The header is followed by all argument strings, then all environment strings.
Each string is an unsigned 64-bit byte count, the exact bytes, and a NUL byte.
Interior NULs are rejected. A string may contain at most 8192 bytes. `argv[0]`
must be nonempty. Other empty arguments are retained. An environment entry must
have a name matching `[A-Za-z_][A-Za-z0-9_]*` before `=`; duplicate names are
rejected. No ambient environment is inherited. The entire request is bounded at
65536 bytes. A request ends after the final NUL or after the following explicit
descriptor trailer.

The optional trailer is `HIAPFD01`, an unsigned 64-bit count, and that many
unsigned 64-bit descriptor numbers. It may name at most 16 regular-file or
directory descriptors. The list must contain no duplicate numbers. It may name
the cwd descriptor, but must not name the executable, stdin, capture, receipt, or
owner-lock descriptors, including a different descriptor for any of those
protected inodes. Each entry is checked with `fstat` before any child is created.
After `close_range(CLOSE_RANGE_CLOEXEC)`, the child clears `FD_CLOEXEC` only for
this explicit list. This carries pinned directory authority into source capture
and publication tools without reopening an ambient path or inheriting unrelated
descriptors. An absent trailer retains the original version-01 behavior.

Every supplied nonzero descriptor must be at least 3. Descriptor numbers and
underlying device/inode pairs must be distinct. Writable outputs must belong to
the owner's effective UID, have no group or other permissions, and have at most
one link. Append mode and read-only outputs are rejected. If supplied, the owner
lock is acquired using `flock(LOCK_EX | LOCK_NB)` on the original inherited open
description and remains open for the owner's whole lifetime.

## Execution and terminal ownership

The HIA policy validates the entire request before forking. It prepares separate
stdout, stderr, and exec-error pipes, a pidfd, a timerfd, and a signalfd. The child
starts a new session, installs `PDEATHSIG=SIGKILL`, verifies its original parent,
sets explicit stdin/stdout/stderr and cwd, disables core dumps, applies the
optional address-space limit, marks other descriptors close-on-exec, and executes
the sealed ELF.

The owner consumes output with nonblocking pipe reads and bounded positional
writes. Counts distinguish bytes observed from bytes retained. Reaching a capture
limit continues draining and marks the capture incomplete. A capture I/O failure
records its errno and initiates cancellation. `SIGTERM`, `SIGINT`, or the original
parent's death initiate cancellation; deadline expiry initiates a timeout. Both
send `SIGTERM` to the original process group and to the original pidfd, then
escalate to `SIGKILL` after the requested grace.

The child stays unreaped until the owner has stopped its original group. This
keeps the child's process identity from being recycled while group cleanup is in
progress. The owner reaps that child with `wait4`. A descendant that holds a pipe
after termination is given one additional second to drain; the owner then closes
the pipe and marks output incomplete. A host cgroup is still responsible for
containing a workload that deliberately creates a separate session or escapes
the original process group. The native publication pipeline uses fixed admitted
workloads; the owner does not claim unrestricted descendant containment.

## Receipt

The terminal receipt is exactly 128 little-endian bytes, equivalent to
`struct <8sq14Q`. Only `exit_code` is signed:

| Offset | Field |
| --- | --- |
| 0 | Magic `HIASBR01` |
| 8 | Workload exit code; negative signal number; -256 if deadline was already expired before spawn |
| 16 | Stop reason: 0 ordinary completion, 1 deadline, 2 cancellation, 4 owner I/O failure |
| 24 | Raw wait status |
| 32 | Original child PID, or 0 when no child was created |
| 40 / 48 | Stdout bytes seen / stored |
| 56 / 64 | Stderr bytes seen / stored |
| 72 / 80 | Stdout / stderr errno, or 0 |
| 88 | Child setup or exec errno, or 0 |
| 96 | Output complete flag |
| 104 | Both output files fsynced flag |
| 112 | Elapsed monotonic nanoseconds |
| 120 | Original child reaped flag |

The owner fsyncs both capture descriptors, writes the full receipt with positional
writes, and fsyncs the receipt. Exit status 0 means this receipt was published; it
does not mean the workload succeeded. A caller accepting a build product must
check its workload exit code, stop reason, exec errno, capture completeness,
durability, and expected child reaping. Admission failure exits 65 before spawn.
A failed terminal publication exits 74. Admission/setup failures before fork do
not claim a terminal workload result.

The caller owns creation of the output names and their directory durability.
Publishing a receipt or build product by rename, syncing the containing
directory, verifying hashes, and switching a release pointer remain operations
of the surrounding HIA publication policy.

## Native build and verification

The member alias is `hia-subprocess.hepta`, backed by `subprocess.hepta`; its
packer is `subprocess_packer.hepta` with magic `HIASUPK1`. The native
`source_filter_member.hepta` registry admits the exact module and source alias.
The ordinary source builder compiles the HIA policy and packs the resulting
object. The optional authoring generator is not used by that production path.

`tests/test_hia_subprocess.py` exercises real sealed descriptors and static test
workloads. Set `HIA_TEST_SUBPROCESS_EXE` to the built executable to enable the
tests. They cover binary I/O above 64 MiB, arguments/environment/cwd, deadlines,
cancellation, TERM-to-KILL escalation, capture limits and I/O failures, exec
failure, admission refusals, expired requests, original lock custody, parent
death, explicit FD authority and conflict refusals, and an execution trace
containing no Python or shell in the owner chain.
The test workload's assembly and its assembler are test fixtures, outside the
production runner.
