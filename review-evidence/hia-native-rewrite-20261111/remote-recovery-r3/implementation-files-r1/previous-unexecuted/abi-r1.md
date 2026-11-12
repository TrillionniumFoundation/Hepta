# Native implementation-file custody, development revision 1

## Status and purpose

All new sources in this delivery are **unexecuted**: zero Python AST checks,
HIA generation, B3 compilations, VM entries, native entries, or C builds.
The existing Emitter and object-inventory successes do not qualify this route.

This component implements the ordered implementation fingerprint inside the
exact original `hepta/hia_program_native.py::_implementation_hash` (46,917
bytes, SHA256 `bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c`).
HIA selects all twenty filenames, constructs each pathname, issues every
open/fstat/read/close, and feeds the actual bytes to the independent HIA SHA
stream. The fixed carrier performs only descriptor, view, image-call, and
raw Linux syscall mechanics. It does not know the filename list or choose
a digest value.

This is a compatibility leaf for the old implementation identity. It does
**not** require a final native installation to retain Python modules or run a
Python fallback. The future native installation inventory must bind the actual
HIA implementation sources, images, policy, and trusted build recipe. That
new inventory and its public outer integration remain separate work.

## Private input and output

Both roles have R/W/W entry signatures:

| Role | Responsibility | First | Second | Third |
| --- | --- | --- | --- | --- |
| 1 | File and hash continuation | Issued source or actual ACK, read only | 128-byte command output | Private 65,536-byte state |
| 2 | Incremental SHA | HIA-generated read-only command | 32-byte digest output | 1,184-byte SHA state |

The initial immutable source is 64 bytes followed by the exact filesystem
bytes of the directory containing the implementation files. Its eight
little-endian u64 words are:

`[HIAIFI01, 1, lease, request, 64, directoryBytes, 64+directoryBytes, 0]`.

Lease and request are nonzero. The directory contains no embedded NUL.
It is a private, correlated input issued by the eventual installation owner.
A matching header does not authenticate an external directory or module
inventory. It is not a public path normalization or authorization API.

The owner constructs paths using the issued bytes and the fixed ASCII names,
adding one slash only if the directory is nonempty and does not already end
in slash. It follows the original open behavior, including symbolic links;
it adds no regular-file, no-symlink, or eight-MiB input policy.

The terminal HIACDE01 command has opcode 7. Its args 2, 3, 4 designate a
read-only 128-byte HIAIFR01 result descriptor in slot 9. The descriptor's
sixteen u64 words are:

| Word | Value |
| --- | --- |
| 0–3 | HIAIFR01, version 1, lease, request |
| 4 | 0 success; 1 OS error; 2 read-all None/type-error condition |
| 5 | Number of completely read, closed files |
| 6 | Number of actual file bytes accepted |
| 7 | Number of bytes fed to the native hash, including names and NUL delimiters |
| 8–10 | Error operation, errno, file index; zero on success |
| 11–12 | Selected slot and logical byte length |
| 13 | Actual close errno, if one occurred |
| 14 | Filename belongs to the OS exception |
| 15 | Reserved zero |

Success selects slot 7, length 32, containing the complete read-only native
SHA256 digest. Errors select the still read-only slot 4 pathname without its
trailing NUL. Error operations are 1 open, 2 read, 3 close, 4 fstat EBADF,
5 directory detected by fstat. Full Python exception text is **not** rendered
by this owner. The differential gate compares the actual errno and filename
bytes for physical errors and preserves the reference's complete text as
reference-only evidence. It does not claim full public exception equivalence.

## Buffer and filesystem mechanics

Slots 0, 1, 2, 3 are empty input, initial source, controller state, and current
command. Slots 4–10 hold pathname, read chunk, SHA command, digest, SHA state,
result descriptor, and fstat bytes. Grow copies the complete old logical
buffer; all writable operands exclude reserved controller/input slots.
Every actual image call uses guard pages/canaries and hardware read-only
permissions for its first operand.

Opcode 19 is a raw filesystem request:

| Primitive | Arguments after primitive number | Actual syscall and ACK |
| --- | --- | --- |
| 1 | pathname slot, offset, NUL-inclusive bytes, O_CLOEXEC, zeros | openat(AT_FDCWD); successful actual FD becomes opaque token 1 |
| 2 | token 1, output slot, offset, byte count, zeros | read; actual returned count or negative errno |
| 3 | token 1, zeros | consume the owned descriptor before close; close once |
| 4 | token 1, output slot, offset, exactly 144 bytes, zeros | fstat; complete zero-initialized actual stat bytes are observed |

The descriptor table explicitly allows actual FD 0. There is at most one
owned implementation-file descriptor. A private abort consumes and closes
any live descriptor; a successful terminal requires none live. Negative
errno is passed as its u64 two's-complement representation. The carrier
never retries a semantic syscall. HIA owns open/read EINTR retries.

HIA handles the selected CPython 3.12.14 FileIO behavior: fstat EBADF and
directory checks, read errors, read-all EAGAIN with partial data or None, and
close completion. The official original FileIO source is included as a
fixed reference. The initial test suite does not claim real signal-driven
EINTR or arbitrary nonblocking-device equivalence; the successful domain is
the actual static implementation files, with separately measured physical
missing-file/directory/path errors. General concurrent mutation and arbitrary
special-device behavior remain unqualified.

The read window is 65,536 bytes. It is a streaming size, not a total file
quota. The SHA owner retains its existing less-than-2^61 byte domain. Both a
single 8 MiB + 1 file and a total inventory exceeding 8 MiB are planned actual
tests. These are separate original-budget groups.

Every issued command snapshots the exact private continuation fields,
capacities, pending phase/action/args, name bytes, and hash scratch into a
984-byte pin. Re-entry compares that state before accepting any ACK. This
is an internal consistency check, not a public authenticity mechanism.
Reusing a poisoned state remains permanently rejected. The SHA image is an
actual called peer, never a host digest callback.

## Differential and evidence gates

The planned first run builds both canonical HIA documents and images afresh
with the exact original 669,556-byte 35ee B3 compiler. Each compilation keeps
10 CPU seconds, 20 wall seconds, and 256 MiB. Every document is checked against
128 functions, 1,536 blocks, 8,192 operations, 256 blocks per function, 16 block
parameters, and numeric SSA suffix below 2,048. Operations per block are
recorded, with no invented 128-operation gate. The builder saves aggregate
and per-function/block profile evidence before applying the original gates.

The eleven groups contain 90 cases, including 49 private controls:

| Group | Cases | Private |
| --- | ---: | ---: |
| Two full-mechanics crosschecks | 2 | 0 |
| Normal files, exact reference files, names and links | 12 | 0 |
| Missing each of twenty files, three directories, path length | 24 | 0 |
| Single file above 8 MiB | 1 | 0 |
| Aggregate files above 8 MiB | 1 | 0 |
| Actual FD 0 in the complete-operand harness | 1 | 0 |
| Initial frame and short buffers | 16 | 16 |
| ACK framing | 10 | 10 |
| Issued private continuation mutation | 12 | 12 |
| Impossible actual-syscall reply values | 8 | 8 |
| Actual SHA return controls | 3 | 3 |

All reference fingerprint evaluation occurs before target execution. The
original function is then disabled in its isolated oracle module while the
target runs. Host SHA remains permitted only for evidence checks and the
independent oracle. The fixed process makes forty calls across physical
cases; fifty-two cases additionally or exclusively retain every byte of all
three operands before and after each image entry in paged CAS. Two cases
compare both mechanics implementations: every native return, every command
and ACK byte, every final slot byte and permission, and all raw syscall
payload/errno/logical-result values. Actual process-local FD numbers are
retained and validated separately, rather than incorrectly compared across
two processes.

The fixed C runner retains actual image bytes, the complete source, every
command and ACK, every raw syscall return and complete path/read/stat payload,
and every final slot byte. It enforces read-only permissions and guards at
each call. Its trace does not retain intermediate full workspaces and is
never credited as that stronger evidence.

Each successful group receives a separate zero-target-execution readback.
That reader reconstructs every CAS snapshot, reads every compressed original
byte, correlates all entry records, validates the complete fixed trace and
all final slots, and compares all input-file bytes/modes before and after.
Temporary aliases are recorded with exact target bytes before being retired;
all referenced ordinary file contents remain in the archive.

Closed raw trace and final-slot files may be losslessly xz encoded only
after all comparisons. Full streaming decompression is compared to every
original raw byte, and length/SHA/mode identities are written to a complete
encoding manifest before those exact temporary raw files are retired.
Failed comparisons keep their raw originals. Encoding time is recorded and
remains inside that group's budget.

Each builder, test group, and readback keeps 90 CPU seconds, 180 wall seconds,
1 GiB, and no core files. The parent-plus-children CPU total is checked.
The outer CI scheduling window does not increase any component limit.
The final archive uses a complete JSONL ledger and streaming tar readback,
clearing TarInfo caches after each member; no buffer region is omitted.

## Remaining integration

The C runner, ctypes harness, Python authoring, exact Python oracle, and
system gcc are declared development trust roots. No installed C/host-policy
fallback is introduced. The real public sequence still needs its fixed
entry owner: target validation, native implementation identity before,
actual program admission/re-verification and canonical/input receipt
correlation, borrowed-export normalization, checked plan, Emitter and object
inspection, native implementation identity after, and complete public
result/error presentation. The independent post-Core backend join has not
already supplied those predecessor authorities. Public build, linker,
publication, installation, and full cold qualification remain open.
