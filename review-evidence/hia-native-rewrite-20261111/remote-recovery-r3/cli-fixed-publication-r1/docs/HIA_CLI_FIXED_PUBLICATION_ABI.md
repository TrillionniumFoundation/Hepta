# Fixed native verified publication and filesystem development contract

Status: new source revision, not yet assembled or executed at this checkpoint.
The previous transaction component has a separate actual PASS. Its original
sources and evidence stay unchanged. This revision does not inherit that
component's execution counters.

## Ownership

HIA role 8 is the unchanged complete publish_verified transaction. HIA role 10
is the source-bound native SHA256 stream owner. The new HIA parent at role 7
translates their issued immutable views and continuations into fixed raw
filesystem operations. No Python process services the running ELF.

Path.absolute, recursive mkdir, resolve, temporary staging and public OS-error
presentation are separate unfinished owners. The development entry reads one
private command-file pathname from the captured argv bytes. It freezes that
file into an owned readonly command mapping. This is not a replacement for the
public CLI's path, grammar or input budget semantics.

The passed finite carrier is pinned at SHA256
f06b915cdfb415894e05c8c4a3e7bbdba9fe9c0bc5b8791878516f91cdfa66de.
The extension preserves the complete original service interpreter suffix.
Parent CALL accepts roles 1..6 and 8..10, never recursive role 7.
Parent two-read mask is 0x378 (roles 3,4,5,6,8,9). Role 9 is reserved for the
future path owner and remains an absent image in this development bundle.
Both existing A/E service tables, role masks and bounded internal child graph
are unchanged.

## Packer v2

The HIA-only packer accepts HIACBP02, version 2, three role tables, 136 lengths.
The 64-byte header is followed by 136 u64 image lengths and the complete images.
The first image starts at packet offset 1152. Rows 0..9 map parent roles 1..10,
rows 10..72 map A roles 1..63, rows 73..135 map E roles 1..63.
Parent role 7 and each service root 56 are required; the development service
roots are explicit unused HIA refusals. They are never claimed as implemented
A/E businesses. All supplied source/image bytes are bound before native packing.
The existing per-image 1 MiB and original compiler profile limits are retained.

## Operation 19

The normal 128-byte HIACDE01 frame remains unchanged. Its twelve argument
words are:

kind, token, firstSlot, firstOffset, firstExtent, integerA,
secondSlot, secondOffset, secondExtent, integerB, zero, zero.

The actual raw Linux x86-64 syscall result is returned in the original ACK's
word 5. No carrier-level EINTR retry, errno translation or policy occurs.
HIA obtains output buffers through the existing complete descriptor/view ABI.

| Kind | Primitive | First view | Second view | Token and integers |
|---:|---|---|---|---|
| 1 | open | RO NUL path | empty | new token; A flags, B mode |
| 2 | close | empty | empty | existing token |
| 3 | fstat | RW exactly 144 B | empty | existing token |
| 4 | read | RW exact capacity | empty | existing token |
| 5 | write | RO exact bytes | empty | existing token |
| 6 | fsync | empty | empty | existing token |
| 7 | stat | RO NUL path | RW exactly 144 B | no token |
| 8 | lstat | RO NUL path | RW exactly 144 B | no token |
| 9 | link | RO NUL old path | RO NUL new path | no token |
| 10 | unlink | RO NUL path | empty | no token |
| 11 | mkdir | RO NUL path | empty | B mode |
| 12 | rmdir | RO NUL path | empty | no token |
| 13 | readlink | RO NUL path | RW exact capacity | no token |
| 14 | getcwd | RW exact capacity | empty | no token |
| 15 | getrandom | RW exact capacity | empty | A flags |
| 16 | openat | RO NUL path | directory token in slot word, other words zero | new token; A flags, B mode |
| 17 | newfstatat | RO NUL path | RW exactly 144 B | directory token; A flags |
| 18 | getdents64 | RW exact capacity | empty | existing token |
| 19 | fchmod | empty | empty | existing token; B mode |
| 20 | chmod | RO NUL path | empty | B mode |
| 21 | unlinkat | RO NUL path | empty | directory token; A flags |
| 22 | fchmodat2 | RO NUL path | empty | directory token; A flags, B mode |

No arbitrary raw process FD is accepted. Tokens index a dynamically grown
private table; fresh rows contain -1, actual FD 0 is valid. Open reserves an
empty token before syscall and commits it only on success. Close retires the
token and live count before its single actual syscall. The carrier never
retries a consumed close. Only explicit *at operations permit token MAX as
AT_FDCWD. Normal terminal and business-context entry require zero live tokens.
Fatal process exit relies on Linux process cleanup for still-open actual FDs.

Every output descriptor is checked before syscall, must be writable, must use
slot >=4, and cannot be a currently pinned business lease. Every path is a
complete readonly logical view with exactly one terminal NUL and no earlier
NUL. Empty unused descriptors and reserved numeric fields are checked.

## Native transaction join

The controller does not inspect filename meaning or file status policy. It
binds each HIAPVE01 event to the current publication lease and exact sequence.
It temporarily protects the real publication workspace while a path is
borrowed from it. Actual syscall output is copied into a complete HIAPVA01
reply; that immutable reply is passed back to the actual publication image.
GROW repeats the same original command and reply; it does not repeat an OS
action. Native hash calls use actual init/update/final and complete digest
bytes, never host hashing as a semantic service.

The private development result is:

- 64 B HIAPFX01 telemetry: magic, version, publication entries, raw filesystem
  calls, hash entries, workspace grows, input reads, complete result bytes;
- the actual 128 B terminal publication event;
- its complete published receipt, diagnostic or raw OS path view.

This result is not the public CLI output. The eventual parent presentation
and HIACPR01 reply owner must consume the actual result only after all original
path/staging and cleanup steps have completed.

## New evidence plan

The new fixed-runtime corpus contains 24 publication comparisons: 23 complete
ordinary filesystem outcomes plus an actual FD-0 success. These are a new
runtime integration panel, not a repetition/renaming of the previous 29+11
component suite. A separate HIA utility script calls every one of the 22 raw
kinds, grows a live FD table through token 512, and checks FD-0 close exactly.
Seventeen malformed private frame controls exercise bounds, rights, NUL
extent, token lifecycle, and live-FD handoff refusal.

Planned total: 43 new native processes, 20 native packer calls. Every compiled
image retains the original 10 CPU / 20 wall / 256 MiB compiler gate. Each
fresh native ELF retains 90 CPU / 1 GiB and the 120-second outer wait bound.
No previous 967 component or 193 CLI entry tests are rerun here.
The source-only plan is not an execution claim.
