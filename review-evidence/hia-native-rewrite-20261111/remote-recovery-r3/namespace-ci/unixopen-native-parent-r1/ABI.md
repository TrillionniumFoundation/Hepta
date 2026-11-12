# Selected Linux unixOpen native parent: authoring revision 6

## Scope and status

This is new, unexecuted authoring. It has not passed AST, generation, B3,
CoreVM, original C compilation, or actual native execution. It replaces the
selected Linux POSIX unixOpen and fillInUnixFile *control flow* in HIA.
All 18 requested effects remain explicit foreign peers in the first component
gate. This is not an ordinary Store, SQL31, migration, full file publication,
or installed worker completion claim.

The reference is the exact SQLite 3.46.1 os_unix source, Git object
9e7ba05d6882b1f3c310b99102e8ecbf7f830af2 and SHA256
83e4f995c0cfc1362b46320d979b38349ac5b1c6a7c0b12cbc2c4577c6c13ef9.
The six original bodies fileHasMoved, verifyDbFile, robustFchown, robust_close,
fillInUnixFile and unixOpen are copied without byte edits. A deterministic
C test scaffold supplies their effects, stable pointer identities and named
state observations. Original assertions use the release-disabled policy;
the scaffold's own assertions remain active. This is the selected Linux
POSIX/HAVE_FCHOWN path, not macOS locking styles or a new arbitrary-VFS API.

The fixed private issuer is responsible for immutable filename allocation,
Store/process context and actual effect-result leases. Header nonces,
scope numbers and Graph IDs do not authenticate an external caller.

## Exact behavior owned by HIA

HIA determines process PID checks and PRNG reset ordering, main-file
findReusableFd before allocator use, the 16-byte selected UnixUnusedFd
allocation, NULL-name temporary-name continuation, POSIX flags and creation
mode lookup, robust open and read-only fallback, reusable FD adoption,
new-journal EACCES/access behavior, root-only fchown, out-flags publication,
preallocated-record fields, delete-on-close unlink ordering, URI PSOW,
unix-excl flags, inode registration while the global serialization scope is
held, failed-open close/log ordering, method installation, OpenCounter,
and optional new-file verification warnings. It determines free-on-error
and direct early-return paths without inventing an extra cleanup.

The exact original behavior includes:

* Failed findCreateFileMode returns directly after the earlier preallocation;
  the test records that live allocation instead of adding a cleanup.
* Read-only fallback does not occur after EISDIR. On other initial read/write
  failures, the read-only flag change precedes the second reuse/open attempt.
* A reused record on fallback is freed while its FD remains the selected FD.
* Unlink and fchown return values do not create new semantic errors.
* out-flags and preallocated fields are published before fillInUnixFile.
* Main inode failure closes the FD while global serialization is still held.
  A close failure logs before local h becomes -1 and before leaving that scope.
* fileHasMoved checks the original C's inode comparison; it does not add a
  device comparison that the selected C body does not perform.
* verifyDbFile performs its own actual FSTAT only on the original success
  branch. The earlier registration's exact single FSTAT is not duplicated.
* Original NULL filename and the effective temporary path remain separate.
  URI lookup receives the original complete allocation and pointer offset.
  Non-NULL filenames have no new 512-byte quota. The original temporary-name
  storage remains 512 bytes.
* Clean failure does not fabricate initialized allocator payload fields.
  Field comparison observes those fields only after original publication.
  Every VM/native byte is still compared without a mask.

## Private wire framing

All scalars are little-endian u64 unless explicitly a status u32. The entry
is R/W/W. BEGIN is 512 bytes plus the entire immutable SQLite filename
allocation. ACK is 512 bytes plus any returned temporary-name payload.
Workspaces have a 4,096-byte header and a copied immutable allocation.
Output requires max(1,024,512+allocation bytes). These are derived capacities,
not new public record/filename quotas. GROW returns 2, pending effect returns
1, completed control flow returns 0, and permanent protocol refusal returns
0xfffffffd. The sticky bad magic is HIANUB01.

BEGIN fields by byte offset:

| Offset | Meaning |
|---|---|
| 0, 8 | HIANUO01, command 1 |
| 16, 24, 32 | scope pair and nonzero call sequence |
| 40, 48, 56, 64 | filename lease, SQLite flags, explicit NULL marker, full allocation bytes |
| 72, 80, 88 | out-flags requested, VFS identity, selected unix-excl flag |
| 96, 104, 112 | mmap configuration bits, default PSOW, initial errno |
| 120, 128, 136, 144 | prior randomness PID, original mxPathname 512, temp-directory lease, OpenCounter |
| 152, 160, 168, 176 | actual FS scope pair and FS/syscall watermarks |
| 184, 192, 200 | process lease, filename pointer offset, initial out-flags u32 |
| 208..511 | reserved zero |
| 512.. | exact immutable allocation, including URI data |

A NULL allocation requires zero allocation length and pointer offset.
Non-NULL allocation must contain the initial C string at its issued pointer.
The full allocation is retained for URI consumers. The selected input
contract accepts valid flags emitted by the ordinary selected SQLite VFS
caller; it is not an independent external SQLite flag admission endpoint.

A pending request occupies output bytes 256..511, followed by complete
request path bytes. Request header fields are: HIANUQ01/1 at 0/8;
scope/call/action at 16/24/32/40; operation/stage at 48/56; six operation
arguments at 64..104; payload length/path-mode at 112/120; original filename
lease at 128; actual FS scope/watermarks at 136/144/152/160; logical peer at
168; process lease at 176; errno at 184; reserved zero at 192..255.
Path modes distinguish no path, effective C string, full temporary
allocation, full original URI allocation, and original C string.

ACK command 2 repeats scope/call/action/operation/stage. It carries errno
at 64, six result words at 72..112, actual FS/syscall sequence at 120/128,
payload length at 136, and actual peer/context/generation/serial/source
lease at 144..176. Bytes 184..255 are zero and 256..511 reproduce the
entire issued request header exactly. Only the temporary-name result carries
a variable payload in this first contract. Raw FS operations require exact
watermark advancement; pure value operations preserve them; composite peers
have explicit nonregression rules. These checks correlate an already issued
private result, not prove external authenticity.

## All pending effects

| Stages | Operation | Effect / future peer |
|---|---:|---|
| 10, 11 | 1 | Actual getpid through shared FS |
| 12 | 2 | Process random-state reset |
| 20, 33 | 3 | Global inode findReusableFd, including returned unused-record identity |
| 21 | 4 | Recoverable 16-byte unused-record allocation |
| 22 | 5 | Original temporary filename creation |
| 30 | 6 | findCreateFileMode policy |
| 31, 35 | 7 | robust_open policy |
| 32 | 8 | Actual access |
| 40 | 9 | Actual geteuid |
| 41 | 10 | Actual fchown |
| 50 | 11 | Actual unlink |
| 60 | 12 | Original URI boolean lookup |
| 61 | 13 | Actual fillInUnixFile inode registration continuation |
| 62 | 14 | Actual close, with original failure errno/log ordering |
| 70 | 15 | Actual verification FSTAT |
| 71 | 16 | Actual verification STAT |
| 36, 63, 72 | 17 | Original error/warning log effect |
| 34, 80 | 18 | Free unused-record allocation, including NULL |

Operations 1, 8..11 and 14..16 use logical peer 6; 3 and 13 use the
correlated inode/global service; 7 uses robust peer 7; 6/12 use creation/URI
peer 8; random reset uses 10, allocation/free 11, temporary names 12, and
logging 13. Logical peer numbers are internal dispatch selectors, never raw
file descriptors. The next physical composition must bind all effect
requests to real completed peers and their complete immutable result
capsules. Current scalar fixtures are expressly foreign.

Workspace state includes file h/VFS/original path lease/control flags/mmap
configuration, lastErrno, method kind, inode/dev/ino, preallocated identity
and initialization state, global serialization held marker at 496, and
process/OpenCounter/watermarks. Completed clean calls may be followed by
call+1 only with preserved scope/process/randomness/OpenCounter and
nonregressing actual watermarks. Duplicate or altered ACKs permanently
poison the state. BEGIN and ACK GROW retain their exact source and do not
reissue a completed effect.

## New complete component gate

The fresh gate has 85 deterministic original-C scenarios: read-only and
read/write variants, all selected file kinds, both PID paths, reuse with
FD0, allocation failure, initial and fallback open errors, EACCES/access,
EISDIR, journal permissions, uid-root fchown, ignored effect failures,
NULL temporary filenames and full 512-byte boundary, original URI prefix
and pointer offset, unix-excl/PSOW, registration errors with close warnings,
verification errors/warnings, non-UTF8 bytes, 8,193-byte non-NULL names, and
fixed-seed randomized combinations.

It additionally runs 42 private protocol controls, including every reply
identity field, extra/short reply extents, duplicate consumption, short
workspace, BEGIN shape, changed BEGIN across GROW, ACK GROW before
consumption, the next valid call, and completed-call replay. Protocol setup
executes one additional original C call and two complete semantic C cases.
Therefore the authored expectation is 88 returned C calls in total, not 85;
these are expected future counts, not observed results.

Each VM invocation is fresh, with 4,000,000 steps, 32 MiB arena and original
call-depth 64. Only an immutable verified entry descriptor is retained.
Each native invocation uses the actual newly B3-compiled image, guard pages,
a truly readonly source mapping and full output/workspace canaries. Complete
return/output/workspace bytes match the VM with no byte masking.
C comparisons cover all initialized named fields and full effect sequence,
argument/path bytes, errno and global serialization state.

The newly compiled canonical .hiaasm, full document, profile, source/image
digests, exact B3 request/receipt, original C bodies/source/shared library,
all cases, before/after pins, complete entry ledgers and errors are saved.
A frontier record and full before-input are flushed before each VM and native
call, so a future timeout has an observable location.

No limits are enlarged. The profile remains 128 functions / 1,536 blocks /
8,192 instructions / 256 blocks per function / 16 block parameters.
B3 remains 10 CPU / 20 wall / 256 MiB / 1 MiB output and workspace.
Every component process is 90 CPU / 180 wall / 1 GiB / zero core; all fresh
build, semantic batches and protocol execution share a 900-second aggregate.
The existing failed physical 42-group target is not rerun by this new
component gate.

## Remaining closure

The next work is actual shared-FS and global-inode capsule framing, robust
and creation peer binding, real random/tempname/allocation/log peers, then
the complete high-level put/get/31-operation transaction and durable Store.
Original failures, budgets, and historical sources remain unchanged.
