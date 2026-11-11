# Verified publication native transaction, development ABI 1

This is a new HIA transaction owner for the exact-byte, non-replacing hard-link
part of publication. It is not yet an installed CLI, a complete publish_program
path/staging owner, or a cold-qualified component. No former native wrapper
qualification is inherited.

## Input custody

Entry is R/R/W, exposed by the normal R/W/W wrapper which only borrows the
second input. Both input buffers are private immutable leases from a fixed
coordinator. The original command is held throughout a transaction and across
GROW. Header equality is correlation; it does not authenticate a separately
supplied mutable path/payload.

The first lease is exactly:

- 64-byte header, eight little-endian u64 values:
  HIAPVC01, version 1, nonzero lease, nonzero initial sequence,
  stage byte length, destination byte length, expected byte length, total bytes.
- Stage filesystem bytes and one NUL.
- Destination filesystem bytes and one NUL.
- Complete expected bytes.

Stage and destination are the parent's already-normalized absolute filesystem
paths, including surrogateescape encoding where necessary. Their first byte is
slash and they have no embedded NUL. This ABI does not replace Path.absolute,
mkdir(parents=True), resolve(), temporary-directory creation or cleanup.
The owner derives destination.parent; a host cannot supply a different parent.
Zero expected bytes and equal stage/destination are ordinary original
E_PUBLISH_INPUT refusals. There is no new byte quota.

Workspace starts at 4096 zero bytes. The owner requests exactly enough space
for its private destination-parent bytes. GROW preserves the complete existing
workspace and replays the same immutable command and empty reply. It does not
advance sequence or issue an I/O operation twice.

## Events and exact replies

A 128-byte HIAPVE01 event lives at workspace offset 256. Its 16 words are:

0 magic; 1 action; 2 lease; 3 sequence; 4 requested primitive;
5 semantic domain; 6 publication error code; 7 errno;
8 first-view source; 9 first-view offset; 10 first-view bytes;
11 second-view source or OPEN flags; 12 second-view offset; 13 second-view bytes;
14 required workspace; 15 current native phase.

Source 0 is the original command; source 1 is the current workspace. Views last
only until the next call/GROW, and callers borrow from the current allocation.
Actions are 0 DONE, 1 GROW (return FE), 2 filesystem, 3 HIA SHA256, 6 permanent
ABI refusal (return FD). A short workspace below 4096 cannot be poisoned safely
and is a caller-level lease failure. Other ABI failures persist in word 1 of
the workspace. The fixed coordinator discards the session on any FD.

Filesystem primitives are 1 lstat, 2 stat, 3 open, 4 fstat, 5 read, 6 close,
7 link, 8 unlink. Hash primitive 9 is the complete expected-byte SHA256 service,
whose implementation must use the actual bound HIA SHA owner. Descriptor token
1 represents the one outstanding private descriptor, including actual OS fd 0.
The fixed carrier consumes that token before CLOSE and never retries CLOSE.

For path operations, first view includes the terminal NUL. OPEN word 11 is
O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC (657408). READ word 10 is the requested
count. LINK has stage in first view and destination in second view. HASH has
the complete expected byte view. No primitive inspects a JSON/CLI field.

Replies are HIAPVA01, lease, sequence, primitive, status, result, errno,
payloadBytes followed by exactly that payload. Status 1 requires errno 1..4095,
zero result and no payload. Success requires errno zero. STAT/FSTAT success
has result zero and the actual 144-byte Linux x86-64 stat bytes; OPEN returns
token 1; READ's result equals its complete payload length and cannot exceed
the issued count; CLOSE/LINK/UNLINK return zero; HASH has result zero and 32
actual digest bytes. Only the outstanding exact primitive consumes a reply.

## Original ordering retained by HIA

The owner validates ordinary stage identity, opens without following symlinks or
blocking on FIFO substitution, follows the Python FileIO constructor fstat
behavior, checks fstat identity, consumes expected-length-plus-one bytes, checks
post-read fstat, closes, and checks pathname identity. A detected byte mismatch
does not skip a later read error. CLOSE failure retains the original context
manager priority; constructor error cleanup does not replace its own error.

After the first complete read, HIA checks destination.exists(), then
destination.is_symlink(), then destination.parent.is_dir(), in that order.
Ignored pathlib errno values are ENOENT, ENOTDIR, EBADF and ELOOP. Other errors
at those three calls remain raw OS errors, not PublicationRejected.

HIA then requests the no-replace link. It reads stage a second time, compares
stable dev/inode/mode/size/mtime while allowing the link-created ctime change,
and reads destination with the complete post-link identity. Failure after a
successful link removes only a destination that is still an ordinary file with
the initial stage's dev/inode; cleanup errors do not replace the original
publication refusal.

Only after all three reads does it hash the complete expected bytes and emit
the exact compact sorted receipt {"bytes":N,"sha256":"..."}.

## Results and still-open parent work

Domain 0 is success; first view is the full receipt in workspace. Domain 1 is
PublicationRejected; first view is the complete original fixed diagnostic
text. Error codes 1..9 map to the nine original reasons in the source.
Domain 2 is an unwrapped original OSError from a pre-link pathlib query:
errno and its original path view are returned to the parent OS-error formatter.
The parent must format it natively before claiming complete CLI error equality.

HIACPR01 is assembled only after this actual transaction and the outer staging
cleanup both succeed. It remains the agreed 128-byte correlation header plus
the complete JSON-encoded absolute destination and this exact receipt. No
placeholder receipt is allowed. Initial revisions have no activation path and
do not replace the explicit open publication refusal in the CLI parent.
