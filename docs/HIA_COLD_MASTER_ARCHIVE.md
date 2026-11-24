# Native cold stopped-phase archive

The archive role is a finite HIA syscall policy, built through the independent
assembly, Core projector and typed seed toolchain. It does not invoke the target
compiler, Python, Rust, a shell, or a native linker at runtime. The ELF adapter
only translates the policy action buffer to Linux syscalls and the HIA SHA role.

## Request and receipt

Sealed stdin is exactly 128 bytes with magic `HIAQARQ1`. Its little-endian words
are parent PID at 8, absolute CLOCK_MONOTONIC deadline at 16, private stopped
phase directory FD at 24, journal FD at 32, sealed 64-byte driver receipt FD at
40, sealed plan FD at 48, plan bytes at 56, nodes at 64, new private empty archive
FD at 72, and plan SHA256 at 80. The final 16 bytes are zero. All five descriptors
must be distinct. The sealed plan and receipt require all four Linux seals.

The role checks the actual journal size and SHA against `HIAQOK01`, decodes every
`HIAQAZ01` chunk using the same lossless format, and independently counts every
complete logical node with a sequential index and valid header. A forged receipt
count cannot change the number retained from the actual journal.

Archive format is `HIAQAR01`, file count, retained nodes, plan bytes and plan
SHA256 (64-byte header). Each byte-lexicographically sorted entry has name length,
file size, SHA256 and a zero-padded 128-byte ASCII name (176-byte header), followed
by every file byte. At most 4096 flat files are admitted. Symlinks, subdirectories,
hardlinks, leading-dot names, foreign owners and group/world permissions fail.
Files are hashed before copy, checked again while copied and checked for identity
and size changes. A second directory pass detects additions, removals and repeats.
The journal must still match the driver receipt during inventory. The archive
stream SHA recorded before writes must equal a complete reread after fsync.

After verification, phase files and archive are mode 0400 and the phase directory
is 0500. Success emits exactly 128 bytes: `HIAQAS01`, file count, archive bytes,
retained nodes, plan SHA256, journal SHA256 and archive SHA256. Refusal emits no
success receipt. Invalid admission uses 65, I/O or integrity failure 74, deadline
124. The scheduler must only release phase dependencies after successful archive
receipt and process cleanup. This role itself launches no child processes.

## Actual qualification

The v2 independent image is 212888 bytes, SHA256
`04b1dbadacad86773be181b5cfcc07951bb69f0d50f0159486545767b591d4c4`.

The positive fixture is a fresh actual v10 driver plan with five nodes, a 1 MiB
zero artifact, a three-byte artifact and the complete compressed journal. Its
1,051,491-byte archive restores every file byte exactly and retains all five
nodes. Nineteen gates include actual concurrent writes to the input file, journal
and output archive; all three produce failure without a PASS receipt. Rehashed
malformed logical headers, truncated chunks, forged counts and custody failures
also fail. The initial trace fixture with an incorrect parent PID is retained as
a refusal; the corrected detached trace preserves the real parent identity.

This component is not the complete cold replay proof. The master scheduling,
whole-run cleanup, source export and report admission remain distinct gates.
