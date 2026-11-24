# Native HIA job ownership

`hia-job-supervisor` is the long-lived Linux x86-64 owner selected by controller
schema `hepta.hia.mcp.controller.v25`. Its HIA program owns admission, the original
lock description, process creation, deadline and cancellation decisions, bounded
stream capture, original-child reaping, and durable job records. The mechanical
adapter executes the syscall plan and a linked `sha256_stream` call. It contains
no JSON, scheduling, lifecycle or publication policy.

The existing SSH/systemd bootstrap verifies the controller release and binds
immutable input and executable bytes to sealed descriptors. It then replaces
itself with this native owner using `execveat`, retaining the systemd MainPID.
The SSH bootstrap and remote status transport still use host Python. They are
separate from the native owner; this component does not claim that those host
transports have been rewritten.

## Installed worker location

The runtime seals the executable bytes and retains a read-only descriptor for
the original installed entry. It adds that descriptor to the explicit `HIAPFD01`
inheritance table and sets `HEPTA_RUNTIME_WORKER_ENTRY_FD` for the entry policy.
No inherited descriptor outside the table gains execution-time authority.

The entry's HIA program admits a single bounded decimal descriptor, checks its
regular-file metadata, effective owner, link count, protected mode, read-only
access and exact ELF extent. The adapter compares every byte of that descriptor
with the currently executing immutable ELF. Only an exact match may supply the
physical installation directory through `/proc/self/fd/N`. The selector is
removed from the environment and the descriptor is closed before the embedded
launcher executes. Public worker arguments, stdin and transport identity remain
unchanged. Ordinary direct invocation still resolves its own installed entry.

This preserves relocation and relative package paths without replacing sealed
execution with a later pathname lookup. Missing, malformed, changed, writable
or multiply linked entry authority fails before input is forwarded. The entry
packer binds its three calls to the same HIA object and verifies all three
relative call placements.

## Sealed request

The executable takes no arguments. Descriptor 0 must be a regular sealed memfd
with all four Linux seals. The complete frame is at most 65,536 bytes.

The first 128 bytes use the subprocess-owner header (`<8s15Q>`), with the magic
`HIAJOB01`. Fields after the magic are parent PID, absolute monotonic deadline
in nanoseconds, executable FD, input FD, stdout FD, stderr FD, cwd FD, binary
receipt FD, argument count, environment count, stdout cap, stderr cap,
termination grace in nanoseconds, address-space limit, and owner-lock FD.
The owner-lock field must be zero: this owner opens and retains its own lock.

Parent PID zero selects a durable job that survives the submission parent.
A nonzero PID keeps the generic owner-parent binding. In both modes the original
workload child has a parent-death kill binding to the native owner. The standalone
`HIASUB01` subprocess ABI and its frozen executable are unchanged.

Bytes 128 through 215 add `<QQ32sQ32s>`: job-directory FD, job-ID length,
32 lowercase hexadecimal nonce bytes, invocation-ID length, and 32 invocation
bytes. Invocation length is zero or 32; absent invocation bytes must be zero.
The following 1–128 job-ID bytes may contain only ASCII letters, digits, `-`,
`.` and `_`. Then come the generic argument and environment strings, each
encoded as a 64-bit length, exact bytes and a NUL terminator. The optional
`HIAPFD01` descriptor table retains the generic bounded explicit-inheritance
rules. Main descriptors retain the generic sealed-input, private-output,
non-aliasing, regular-file and directory checks.

The job directory is an already-authorized descriptor for a private directory
owned by the effective user. It may equal the cwd descriptor. It cannot equal a
stream, executable or binary-receipt descriptor.

## Identity and publication

HIA opens `owner.lock` without following links, checks its type, owner, mode and
link count, and takes a nonblocking exclusive flock. After acquisition it checks
that the lock pathname still denotes the original device and inode. It holds
that original open description for its entire lifetime.

Existing owner, child or terminal records and their temporary names reject a
fresh execution, including dangling symbolic links. HIA reads the boot UUID and
the original process start ticks, then publishes `owner-intent.json` and
`started.json` before it forks. The owner records are byte-identical. The child
record binds its PID and original start identity while it remains unreaped.

Each JSON publication creates a private exclusive temporary file, completes its
write, synchronizes and closes it, renames with `RENAME_NOREPLACE`, and synchronizes
the already-held job-directory descriptor. HIA captures and synchronizes both
logs before publishing `exit.json`. The linked native SHA program hashes the
exact exit bytes, including the trailing newline, for `exit.witness.json`.

The binary `HIASBR01` receipt retains the 128-byte generic observation layout.
The JSON terminal carries actual stream counts, EOF, errors, synchronization,
truncation, timeout and cancellation facts. Timeout is reported as exit 124;
an incomplete supervision observation is 125 with an explicit unknown outcome,
non-authoritative status and no automatic retry. Failed publication after the
original child is reaped exits 74 and never sends a signal to a potentially
reused PID. A missing or partial witness cannot become confirmed completion.

## Native build and verification

The native named source builder accepts the alias `hia-job-supervisor.hepta`
with module `job_supervisor`, plus `sha256_stream.hepta`, using `HIAMUL01`.
Its source packer consumes `HIAJOPK1`, two 64-bit object lengths, and the policy
and SHA objects. It emits a static ELF containing the mechanical adapter and
the two native HIA objects. No assembler or Python execution is part of this
native source compilation and packing path.

`tests/test_hia_job_supervisor.py` exercises the real ELF, actual locks and
processes, binary I/O, timeout, cancellation, capture failure, tombstones,
metadata refusal, exact witness hashing and syscall ordering. The runtime bridge
has also been exercised through real user systemd units and the detached backend,
including submission-parent exit and immutable replay. A v25 controller must
add the exact `hia-job-supervisor` role to its manifest; mismatched inventories
and changed executable pins are rejected before service traffic is admitted.

`tests/test_hia_installed_worker_entry.py` executes both ordinary and sealed
entries, including original public input and identity, installation relocation,
invalid selectors, changed anchor bytes, writable descriptors and hard links.
The end-to-end MCP diagnostic gate uses the v25 runtime, this native owner and
the sealed installed entry. It verifies the real binary receipt and durable
witness, then requests the same operation after sealing the diagnostic sink.
The original response deadline remains part of that gate. A test against an
older Store establishes entry/owner transport compatibility; the final combined
release still needs its own full tool and cold-recovery qualification.
