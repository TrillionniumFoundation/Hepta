# Native staging-file writer — development revision 1

This HIA owner implements the fresh binary staging-file block used by the
original publish_program: exclusive open, write(payload), flush, fsync and close.
It is not the parent publication policy, a directory-cleanup owner, a standalone
CLI, or an installed entry point.

The command borrows one private immutable source lease. Its 64-byte header is
eight little-endian u64 words:
[HIASWC01, 1, lease, initialSequence, pathBytes, payloadBytes, sourceBytes, 0].
It is followed by an absolute filesystem path, one NUL, and the entire payload.
The path uses actual filesystem bytes, including surrogateescape bytes. A
same-header comparison checks continuity; it is not source authentication for an
arbitrary externally supplied byte buffer.

The HIA entry has two read-only inputs (command and actual primitive reply) and
one 1,024-byte mutable workspace. The mechanical wrapper borrows the second
argument read-only. There is no GROW or session call/byte quota in this owner.

## Primitive continuation

The 64-byte reply is:
[HIASWA01, lease, sequence, operation, errorFlag, result, errno, payloadBytes],
followed by any actual fstat payload. Error replies require result=0, errno
1..4095 and no payload. Success requires errno=0 and the operation's exact
result/payload shape. Open returns one issued private live-FD token, not an
untrusted raw file descriptor.

Operations are private writer operations, not the numeric HIACDE01 carrier
opcodes: 1=open, 2=close, 3=fstat, 5=write, 6=fsync. Open flags are actual
O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC and mode0666, subject to the process umask.
fstat is the original x86-64 144-byte stat result.

The 128-byte event is at workspace offset256:
[HIASWE01, action, lease, sequence, operation, errorKind, errno,
 charactersWritten, sourceIndex0, viewOffset, viewBytes, flagsOrWritten,
 modeOrDataOffset, dataBytes, liveFD, phase].
action2 requests a primitive, action0 completes, action6 is permanently BAD.
The normal return is128; private ABI refusal returns0xfffffffd.
Completion is allowed only after the FD token was consumed by close.
A close is never repeated on EINTR. Other original retry points retain EINTR
behavior. Semantic failures keep their exact error class/errno/path and
BlockingIOError characters_written. A later close error overrides an earlier
write/flush/fsync error, matching the original context-manager path.

The HIA policy reproduces fresh BufferedWriter direct-versus-buffered writes,
partial/zero writes, direct EAGAIN buffering, explicit-flush failure followed by
close-flush, and raw FileIO behavior for the original zero-buffering corner.
The fstat-derived buffer selection follows CPython3.12.14's original integer
assignment. This does not introduce a new buffering or payload limit.

The parent will turn structured errors into the full public CLI diagnostic.
The final verified-publication owner still independently re-reads and hashes
the actual staged bytes. This writer's accepted result does not substitute for
that later check.

## New verification scope

The new test deliberately separates two kinds of evidence:

* 192 scripted primitive sequences run the actual HIA owner against real
  CPython3.12.14 io.BufferedWriter. Both sides compare exact write requests,
  bytes written, fsync/close order, exception text/class/errno and
  characters_written. Scripted primitive outcomes are not physical filesystem
  authority.
* 11 real Linux filesystem scenarios use actual open/fstat/write/fsync/close
  syscalls and compare Path.open("xb") against the HIA policy, including
  existing files, a non-directory parent, a missing parent, a dangling symlink
  and a filesystem-surrogateescape path.
* 10 private malformed-ACK controls require permanent refusal, including a
  correct reply supplied after the bad reply. Every normal terminal is also
  followed by an explicit illegal re-entry control.

All command/reply/full-workspace bytes, canaries, raw syscall observations and
source/image pins are recorded with lossless content-addressed compression and
exact decompression readback. The physical fixture tree is preserved as a full
lstat/name/target/content manifest; symlinks are not flattened into regular
archive members or followed during evidence capture.

The exact retained B3 compiler has SHA256
35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b.
Its original limits remain10 CPU seconds /20 wall seconds /256 MiB. The new test
process is limited to90 CPU seconds /1 GiB. The10000 loop guard is a finite test
harness guard, not a production quota.

Local authoring generation and HIA verification had completed before an
environment interruption; the started local compiler's result is UNKNOWN and is
not reused. This delivery is a fresh CI candidate with zero confirmed native
test results. TemporaryDirectory selection/cleanup, Path integration, full
parent HIACPR assembly and ordinary CLI publication remain open.
