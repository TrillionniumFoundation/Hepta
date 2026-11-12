# Physical implementation-after continuation for native C/build

## Status and exact responsibility

This is a new, inactive development component. At this source checkpoint it has
not been parsed by Python, generated to HIA, compiled by B3 or C, run by a VM,
or executed natively. Full Git blob GET readback and textual inverse checks
prove only the saved source identities.

The component connects two existing HIA responsibilities in their original
order: an admitted-Core backend reaches successful independent ELF inventory,
then the implementation-file HIA reads the actual twenty files and computes
their ordered SHA256 stream. The backend compares that actual result with its
previously issued before digest. No after digest is supplied by a fixture or
host as an input to this new protocol.

This is a precursor of the public C/build transaction. It does not implement
the first implementation-file read, public Core admission/re-admission, public
path presentation, the independent second complete emission required by
compile_program_machine, staging/readback/publication, or withdrawal after a
failed publication recheck. The caller must eventually provide those steps in
the same actual native transaction. No existing component PASS qualifies this
new composition.

The twenty names remain the exact original compatibility inventory in
hia_program_native._implementation_hash. They describe compatibility with the
reference implementation's source-file witness. They do not require Python to
execute in the native target, and are not a claim that a final HIA installation
should depend on a Python source inventory.

## Original order being preserved

The reference is exact commit 0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5,
hepta/hia_program_native.py, Git 1d0e0344f8300b11b5dd505cbea655170aba5be1,
46,917 bytes, SHA256
bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c.

For emit_program_machine, the reference checks the target, reads the first
implementation witness, validates the VerifiedProgram, verifies the immutable
program again, retains its input/Core identities, normalizes foreign exports,
checks an optional machine plan, emits the machine object, applies the artifact
size gate and independent object inventory, and only then reads the second
implementation witness. A changed witness fails before successful machine
metadata is returned.

The old private backend input HIABBI01 accepted both witnesses as issued
prerequisites. That was sufficient for its private value-level tests, but could
not prove the real timing of the second read. This component replaces only that
second-read prerequisite. Earlier semantic failures return through the original
backend branches and issue no file-child syscall.

The later public compile_program_machine path performs another complete
emission and whole-image equality check. Its object output uses os.path.abspath,
checks that the destination is new and its parent already exists, creates a
.hia-direct- temporary directory, writes program.o with write_bytes, reads and
checks the actual staged artifact, repeats independent object inspection and
implementation-file checks around publish_verified, verifies the published
identity, withdraws its own publication if the recheck fails, and cleans up.
Those are later transaction obligations. The old publication policies for
Path.absolute, mkdir/resolve and xb/flush/fsync cannot silently replace this
contract.

## Exact producers

The new author composes the exact parent author
7041aff7dd3111c996da0fac870a213667e6f693 / 35,648 bytes /
35ce9e9fccfb0601d3d000834c241ae9140eb70449fabc2747ae19e84c1d2a05,
the exact child forwarder
c7566ec8de704b13a078300c20f40aecabc8961d /
d089e80fc78c8c3e2d2234aea587c38bbd5caa757178bf1f93845b15c2fe474c,
and common e56539a9cb76f95010ea6ca995737f40ab6e1850 /
fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1.

The implementation-file owner is unchanged:
964c46106607ae8bef292ce81b1e97ad8206e882 / 17,161 bytes /
a7fc5e1f656fdf4bacc3e35b754cc6f113c0b257b49dcc13c9a03fa5a23fc871.
Its generated HIA must reproduce the existing 196,675-byte source with SHA256
c77b262cac0e34c2b1db0db0ef5c28471a6546a3c7ad85764d6589b74eea4069
and its existing 203,390-byte image with SHA256
b8268f47b1f3295a968ec44b54626373cbc4c35dd6b19ea8dc3348820ae47b13.
The physical role number changes its table placement, not its HIA bytes.

The original backend parent must first be regenerated as 287,979 bytes,
SHA256 546a98d68c3c393b3e747596a1c907e28201475164abbadebd3e76c337366bb0,
before the new author is generated. This is an exact source reproduction gate,
not a repeat of its old semantic qualification.

## Fixed role and slot composition

| Physical role | Responsibility | Second operand |
| --- | --- | --- |
| 1 through 19, 21 | Exact existing backend peers | Original role policy |
| 20 | New backend parent with real after-file handoff | Writable output |
| 22 | Unchanged implementation-file owner, internally logical driver 1 | Writable output |
| 23 | New HIA file-child forwarding continuation | Writable output |

Role 19 is the actual original incremental SHA image. The file child's logical
CALL 2 is forwarded to physical role 19. Role 23 may call only physical 19 and
22. Role 20 retains the original peer-call set 1 through 21, excluding itself.
Neither parent may invoke role 23 as an ordinary CALL. The only shared-context
SWITCH edges are 20 to 23 and 23 to 20.

Both fixed root entries use the same parent controller workspace, event output,
lease and monotonically increasing parent sequence. HIA owns the child lease
and its independent command/ACK sequence. A fixed carrier implements only the
two allowed SWITCH edges and the usual operand mechanics. It does not inspect
Graph, JSON, code, file names or hashes.

| Child logical slot | Parent physical slot | Lifetime |
| --- | --- | --- |
| 0 | 0 | Existing immutable empty view |
| 1 | 39 | New complete HIAIFI01 command plus directory bytes, then read-only |
| 2 | 40 | Private 65,536-byte file-owner workspace |
| 3 | 41 | Private 128-byte file-owner event output |
| ACK | 42 | Dedicated 320-byte ACK buffer, read-only during child entry |
| 4 through 10 | 43 through 49 | Child path/chunk/SHA/result/stat buffers |

All physical slots 39 through 49 must be vacant before the handoff. They are
retired in numerical order after the complete result has been copied. Actual
backend output/registry/metadata and its child views remain live and read-only
throughout the file operation. No complete machine object is copied to create
the file request.

Parent fields occupy [32000,32184), the saved child event [32256,32384),
terminal [32384,32512), and descriptor [32512,32640). Assertions bind these
ranges below the original 1 MiB parent workspace and above its old O_* fields.
The file child has its own independent original workspace, including all of
its source/channel pin ranges.

## Private init HIABFI01, version 2

The input is a 320-byte header, one complete actually issued immutable Graph,
then exact OS directory bytes. It is not a public JSON or foreign Graph entry.
All original requirements for the Core, plan and foreign captures remain.

| Byte offset | Type | Meaning |
| --- | --- | --- |
| 0 | u64 | ASCII HIABFI01, little endian |
| 8 | u64 | Version 2 |
| 16 through 88 | ten u64 | Original outer lease, request, Graph lease, Code lease, plan lease, emitter lease, Graph root, Graph bytes, structured flag and digits |
| 96 | u64 | Directory offset, exactly 320 + Graph bytes |
| 104 | u64 | Directory bytes, exactly the remaining input extent |
| 112 | u64 | Nonzero file-child lease, distinct from outer, plan and emitter leases |
| 120 | u64 | Zero |
| 128 through 159 | 32 bytes | Actual admitted normalized Core SHA256 |
| 160 through 191 | 32 bytes | Actual original input SHA256 |
| 192 through 223 | 32 bytes | Actually issued before implementation SHA256 |
| 224 through 255 | 32 bytes | All zero; supplying an after digest is rejected |
| 256 through 319 | 64 bytes | All zero |

The exact directory bytes may be empty or relative if their private producer
issued that meaning. No new size quota is introduced. Embedded NUL is rejected
before the file child begins. Source/header checks bound all arithmetic and
require one contiguous directory span without trailing hidden bytes.

The original Graph parser and later owners see only the exact Graph span, not
the appended directory. The native parent copies the immutable directory to a
new HIAIFI01 child input after object inventory succeeds.

A caller cannot gain admitted-Core or file-before authority merely by writing
matching header numbers. That provenance must be supplied by the eventual
actual parent and immutable borrowed views.

## Continuation and event ordering

The original object inventory completes through phases 43 and 44. Phase 45
now starts the file handoff. It constructs the exact child header, copies the
actual immutable directory, protects the child input, and issues SWITCH to
role 23 at phase 14000.

Role 23 creates and clears the child's private workspace and output, then calls
actual role 22. Each issued child event is copied to the shared private saved
event before any transport operation. It validates exact child lease, strictly
consecutive child sequence, unused arguments, logical slot roles, requested
ranges and read/write status. GROW completion updates only the parent logical
capacity; it does not repeat the previous child call or syscall.

The child accepts CALL, GROW, ZERO, COPY, RELEASE, PROTECT, VIEW and four fixed
raw filesystem primitives. CALL may only be the original SHA operation with
its exact first/output/workspace/observation roles. Syscall events use parent
opcode 19, while the returning HIACDA01 ACK is rebound by HIA to the child
lease and sequence before being copied into read-only slot 42.

When role 22 emits its terminal, role 23 observes and validates the complete
128-byte HIAIFR01 descriptor from actual read-only result slot 9. On success it
requires exactly twenty completed files, the actual read-only 32-byte SHA view,
and all original zero/error fields. It observes and copies all 32 bytes to the
parent's saved after-hash area. On an OS/read-all error it copies the complete
actual path and numeric error fields before any file slot is released.

Only after all file-owned slots have been retired does role 23 SWITCH back to
20 at phase 453. The parent checks returned state and every retired capacity.
For success it copies the real after digest to the actual native post command,
then resumes the original implementation_checked branch. The original stale
error is produced before machine metadata/hash success. There is no host
digest comparison controlling the target.

## Raw filesystem transport

The C carrier is development mechanics. Its original backend source is
9a0770eb18dd1a9b0a1777db1645d47aef5c3794, 10,431 bytes, SHA256
dae66f88b96826384c6c278e4f391754acdd43c51c989f963bd90e6bc83d764c.
Its syscall block derives from the exact implementation carrier
294fe43871dd11c06e6f01c7d21caf4b976b04e2, SHA256
0886ad565d13beb22e62e81652ba98b68e83bf841d4f9f8048c1f27d77de533b.

The four primitives are openat(AT_FDCWD,path,O_CLOEXEC), read, consume-once close,
and fstat. The actual raw descriptor is retained in fixed private carrier
metadata and represented to HIA by logical token 1. Descriptor zero is valid.
Close consumes ownership before the syscall and is never retried. Open/read/
fstat likewise execute once; HIA retains the original EINTR/error policy.

Every pointer/count is checked against the actual logical view before the OS
call. Open requires a complete read-only NUL-terminated span with no internal
NUL. Read/fstat require a writable destination and exact requested range.
Fstat requires and returns the complete original 144-byte stat buffer, including
the original zeroed buffer on failure. The fixed carrier records the actual
raw return/errno and exact syscall payload. It does not decide regular-file
policy, name order, hashing, size semantics or public error text.

The original image mappings, hardware RO protection, guard bytes, call operand
roles, source extent checks, PDEATHSIG parent-race check, process limits, full
controller command/ACK records and all final slot bytes remain. New SWITCH
events require no live owned file descriptor. A fatal path consumes and closes
an owned file descriptor before exit; this emergency cleanup is distinct from
a successful HIA-issued close.

Trace record kinds 9 and 11 contain each actual raw syscall observation and its
full payload; kind 10 is exceptional final cleanup if required. Existing kinds
1 through 8 retain their original meanings. The compact C trace never claims
to contain every intermediate full workspace. Separate small-case full-CAS
native calls must compare all complete operand bytes, guards and permissions;
the two evidence scopes remain explicit.

## Error capsule and remaining presentation obligation

A child OS error produces a complete read-only HIABFE01 payload: 128-byte
header followed by the exact path without its terminal NUL. Header words are:
magic, version 1, outer lease, request, child lease, kind, operation, errno,
file index, close errno, filename-present flag, path offset 128, path bytes,
total bytes, zero, zero.

Parent terminal domain 5 contains an OS error and uses errno as its code.
Domain 6/code 1 contains the original nonblocking read-all None case. This
capsule is a typed private error, not the final public Python exception string.
The public parent must apply the exact existing Unicode/errno presentation
contract. This component does not claim public error-text equivalence for
those new domains.

Original backend errors retain their exact original text views and precedence.
They must occur without any file-child syscall when they precede the after-read.

## Required actual qualification, not yet observed

Each new parent, unchanged file owner and new forwarding owner must be generated
with full canonical HIA/documents retained, rendered/assembled exactly, and
compiled under original B3 10 CPU seconds / 20 wall seconds / 256 MiB limits.
The unchanged file source/image and the original parent-source reproduction
must match the identities above. Profiles retain the actual 128 functions,
1536 blocks, 8192 operations, 256 blocks per function, 16 parameters per block
and SSA suffix below 2048. There is no invented 128-operations-per-block limit.

All target, source/readback and semantic groups keep original 90 aggregate CPU
seconds / 180 wall seconds / 1 GiB limits. Authoring, reference computation,
native execution and each group's complete raw evidence are inside that group.
Separate storage encoding is reported as such and cannot enlarge a subject
budget. A PASS_BUILD_ONLY is never a semantic PASS.

The complete new gate must cover exact normal machine results with actual file
bytes, changed implementation witnesses, late open/read/stat/close errors,
precedence of pre-file backend errors, actual command/ACK/slot byte comparison
between the independent full-CAS path and C mechanics, no-IO GROW continuation,
reserved-slot and stale-lease rejection, and permanent refusal after bad
private framing. All new fixtures retain original input and error strings.
Large boundary scopes must not replace small-case full intermediate evidence.

The eventual public transaction remains open until one actual fixed native
entry issues the before read, current Core admission and Graph capture, this
complete backend and after read, the second full emission and equality check,
staged object readback/inspection, publication checks and cleanup in original
order. Nothing in this checkpoint claims installed, cold-start, whole CLI or
complete native-build closure.


## Exact new development gate now authored, still unexecuted

The first independent composition gate is intentionally separate from every
old suite. It has 20 subjects and 47 new cases: 25 ordinary reference comparisons
and 22 private framing/ACK controls. Three ordinary cases run both independent
fixed C mechanics and per-entry full-CAS mechanics, comparing every native
header return, complete command/ACK, raw syscall payload/logical result/errno,
and every final slot's bytes and permissions. Process-local FD numbers are
validated in each process's own exact lifecycle; they are not sent to HIA.

| New subject | Cases | Private cases | Actual scope |
| --- | ---: | ---: | --- |
| Two cross subjects | 2 | 0 | Empty/varied file contents, full backend and whole mechanics comparison |
| Machine plans v1 through v4 | 4 | 0 | Original raw plan input and exact complete machine outputs |
| Borrowed exports | 3 | 0 | Arity 1, arity 8, combined scalar and borrowed exports |
| Directory byte paths | 4 | 0 | Relative, trailing slash, parent symlink and surrogateescaped bytes |
| Two stale subjects | 3 | 0 | Physical first/last/middle file change after first digest; one full crosscheck |
| Two file error subjects | 5 | 0 | Actual late ENOENT and EISDIR at different inventory positions |
| Earlier error order | 4 | 0 | Plan False, reserved name, scalar unit and unselected borrowed export return before any after I/O |
| New private initial header | 13 | 13 | Directory range, lease, no after digest, NUL and unclaimed extent |
| Four SWITCH subjects | 4 | 4 | Bad actual handoff ACK fields and permanent refusal |
| Three file-peer subjects | 3 | 3 | Bad actual file-owner event lease, sequence and reserved field |
| Two OS ACK subjects | 2 | 2 | Bad context/fstat observation, consuming actual live FD during abort cleanup |
| Total | 47 | 22 | New composition only |

Every ordinary case first runs the actual unchanged implementation-file HIA
and actual SHA image through the fixed two-role carrier. These are logical
aliases of new roles 22 and 19, with identical image bytes. It records their
actual 32-byte first digest before creating the private admitted Core fixture.
The exact original emit_program_machine then runs as the oracle. Its hash
method is observed without changing its implementation; selected owned file
fixtures change immediately before that method's second call. The target
receives the native first digest and no after digest. On an earlier reference
error, an owned file is made missing only after that reference error, proving
that the target returns without incorrectly performing the later read.

This is not a replacement public admission protocol. The tests still issue
their admitted Core/Graph from the exact reference as an explicit private
fixture. The standalone first digest process does not yet prove that a single
installed public parent issued that digest and the Core in the right order.

The compile plan is 23 fresh B3 invocations: 20 unchanged backend peers, the
new parent, the unchanged file owner and the new forwarding owner. All 20
unchanged peers must equal the complete source/image identities recorded in
the original FOLLOW54 build panels. That old run's whole backend status remains
FAIL. Its original parent is reproduced as source before any new parent edit;
it is not compiled as a 24th image or reused as the new parent.

Two development C carriers are compiled under separate original bounded
subjects: the original two-role file carrier and the new 23-role carrier.
Expected actual C process counts are 35 first-digest processes and 25 backend
processes. Actual HIA entry counts are measured from complete traces, never
predicted. Every one of the 20 new test subjects has a separate zero-target
readback subject that reads all recorded trace/CAS/final-slot bytes and checks
source/image/fixture snapshots. Expected evidence scopes are 25 full-CAS cases,
3 whole C/full-CAS comparisons and 120 losslessly encoded complete raw files.

Source/readback/target limits remain strict success below 90 parent-plus-reaped-
children CPU seconds and below 180 wall seconds, with 1 GiB address space.
Every new successful subject persists its post-output budget measurement
before the CI driver parses that field. Failures in output, source-after
checks or final cleanup preserve the first exception and attempt a final FAIL
receipt. The enclosing process receipt checks the complete returning process,
including those writes.

The new streamed evidence seal has its own separate forked 90 CPU / 180 wall /
1 GiB scope, PDEATHSIG parent-race check, whole-member bytes/mode readback,
cleared tar-member cache and aggregate parent/child postchecks. This does not
change or retrospectively assign a gate to the old 166-CPU sealing observation.
Nor does a successful-return postcheck prove a hard asynchronous interruption
of an indefinitely blocked parent metadata write; the enclosing job remains
the final independent storage boundary.

These 47 cases establish only their named slice if they actually pass. They do
not newly cover every read/stat/close errno branch, nonblocking read-all None,
every public diagnostic, or the subsequent transaction obligations. Such
uncovered behavior and the complete public C/build transaction remain OPEN.
