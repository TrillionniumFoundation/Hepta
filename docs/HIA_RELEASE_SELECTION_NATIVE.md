# Native release selection, rollback and restart observation

`hia-select` is an explicit Linux x86-64 executable. HIA owns argument
admission, durable selection bytes, the sequence/current compare-and-swap,
previous-release rollback, metadata identity policy and JSON receipts. A fixed
syscall adapter holds the root, lock and state descriptors, captures bytes,
performs atomic publication and reports syscall outcomes. HIA SHA-256 computes
both package and selection-record digests. No Python, libc, dynamic interpreter
or child executable is required at runtime.

Before either mutation, the application runs the **actual immutable-release
verifier** against the operator-supplied package and its pinned target hash.
It embeds the unchanged `release_install_policy.hiaasm` and `sha256_stream`
images. The selection generator mechanically includes the installer's existing
package capture/hash, safe root traversal, installed directory/file readback,
exact directory inventory and identity checks. It does not substitute a file
existence test, accept a selected source manifest on trust or execute a helper
process. Tests check exact shared verifier bytes and exercise real installed
release corruption.

This adds the release-selection owner. It does not replace the default `hia`
CLI, change a running service, migrate the Agent journal, grant a release any
execution authority, remove old releases, recover abandoned stage files or
prove that the package's executable bytes are qualified HIA. It does not close
whole-native product delivery. The authoring and source-bound build driver
remain hosted bootstrap/custody components.

## Explicit operator interface

```sh
python -B -m tools.build_hia_release_selection \
  --compiler /qualified/B3.image.bin --cold-report /completed-current-cold.json \
  --output /new/private/selection

/new/private/selection/hia-select status /absolute/private/releases
/new/private/selection/hia-select activate /absolute/private/releases 0 - TARGET_SHA256 < target.hiapack
/new/private/selection/hia-select activate /absolute/private/releases 1 CURRENT_SHA256 NEXT_SHA256 < next.hiapack
/new/private/selection/hia-select rollback /absolute/private/releases 2 NEXT_SHA256 CURRENT_SHA256 < target.hiapack
```

`status` takes only a root and never reads stdin. It observes sequence, current
and previous selection without creating a lock or selection file, changing
modes, renaming, fsyncing or executing a release. Its `release_verified:false`
is intentional: observing selection metadata does not freshly inspect the
selected package's contents. Use the installer's explicit `verify` with the
original pinned package for that independent observation.

A mutation requires a canonical unsigned decimal expected sequence and exact
expected current identity. Sequence zero requires `-`; every positive sequence
requires 64 lowercase hexadecimal bytes. Target identity is always 64 lowercase
hexadecimal bytes. The stdin package has the unchanged 64 MiB inclusive ceiling,
256-file limit, safe entry syntax, exact modes and exact exhaustion checks of
the immutable installer. Hash or argument refusal precedes filesystem changes.

The root has the installer's same existing-directory, effective-owner,
permission and no-symlink traversal contract. The root and target release must
already exist. A supplied package cannot choose the root or mutate its installed
release. Selection metadata lives directly in the held root, separately from
every content-addressed release directory.

## Native state and transition policy

The selected object is the ordinary file `.hia-selection.current`, not a
symlink or executable dispatch shim. It has exact mode `0400`, the effective
UID, one link and exactly 192 bytes. Its little-endian record is:

| Bytes | Meaning |
| --- | --- |
| 0–7 | `HIASEL01` |
| 8–15 | Sequence, 1 through `2^64-1` |
| 16–23 | Last action: 1 activate, 2 rollback |
| 24–31 | Reserved zero |
| 32–95 | Current release hash, 64 lowercase ASCII hexadecimal bytes |
| 96–159 | Previous release hash; all zero bytes only at sequence 1 |
| 160–191 | Raw SHA-256 of bytes 0–159 |

Absent state means sequence 0 and no current or previous release. A present
empty, truncated, oversized, malformed, changed-identity or checksum-invalid
record refuses; it never becomes a fabricated empty state. Sequence 1 must be
an activation with no predecessor. Later records require a different valid
previous hash. Unknown versions and reserved fields refuse.

`activate` requires both expected values to match current state, refuses a
no-op target, increments the sequence by exactly one and records the old
current as previous. `rollback` additionally requires the target to equal the
recorded previous release; it is a single-step reversible selection and records
the replaced current as the new previous. It cannot invent historical release
history or roll sequence 1 back to absence. Both operations refuse sequence
exhaustion rather than wrapping. Every rollback target is independently
package-verified again before publication.

The protocol provides a monotonically increasing sequence within the retained
local state. It does not claim freshness when an administrator restores the
entire root and its selection metadata together. An external anti-rollback
anchor or historical request journal is a separate responsibility.

## Serialization and publication

`.hia-selection.lock` is an ordinary zero-byte file, exact mode `0600`, owned by
the effective UID with one link. Mutations may create it with their own private
`0077` umask. Status only opens an existing lock; if the lock is absent but a
state file exists, it refuses that incoherent observation. No lock file is ever
removed or replaced by this program.

The kernel's nonblocking `flock` serializes cooperating mutators with an
exclusive lock and status readers with a shared lock. A busy lock returns exit
18; it is not a queued mutation or a success. The held lock inode is compared
to its name after acquisition and before and after publication. Process death
releases the kernel lock without stale-PID ownership inference.

Under the exclusive lock, the native application:

1. Reads and checks existing state and the expected sequence/current pair.
2. Runs complete actual installed-release verification against captured input.
3. Creates a random, exclusive, nofollow `.hia-selection-stage-…` file containing
   only the new HIA-produced record. It fixes its mode to `0400`, fsyncs the
   file, and checks its inode, size, mode, owner and named identity.
4. Rechecks the named old state and the held lock. Initial publication uses
   `renameat2(RENAME_NOREPLACE)`; a successor atomically replaces only the
   previously checked selection metadata while the exclusive lock is held.
5. Fsyncs the root directory, reopens the new state, checks its full checksum,
   bytes and published inode, rechecks the root and lock, then writes a receipt.

Installed release files are never opened for writing or renamed. The program
never creates a `current` symlink or changes another installation. Failed or
interrupted private stages remain for a separately authorized administrative
recovery operation; a prefix is not treated as deletion authority.

The lock is advisory and the root belongs to the same operating-system user.
These checks establish point-in-time observations and serialization among this
protocol's cooperating processes. They do not protect against a hostile same-UID
writer ignoring the lock, later changes after readback, compromised kernels or
all possible storage-device power-loss behavior. Inode/time changes detected
during the actual operation refuse without silently overwriting release data.

## Receipts, failed acknowledgments and restart

A successful activation returns, for example:

```json
{"schema":"hepta.hia.release-selection.v1","operation":"activate","sequence":1,"current":"...","previous":null,"release_verified":true}
```

The sequence and selected hashes are actual readback, not a planned future
state. A successful status has `operation:"status"` and
`release_verified:false`. Writes retry `EINTR`; a complete receipt write is
required for exit 0. Receipt output is not an atomic transaction with the
selection state.

If stdout fails or the process dies after rename, selection may already have
changed. Root-fsync failure can also leave a visible new state without the
operation having established durable success. A new `status` invocation reads
what exists after restart. Compare the observed sequence/current/previous to
the attempted transition. Reissuing the old expected sequence cannot apply the
transition again: it returns a conflict. Do not invent a new expected sequence
merely to turn an uncertain request into a new action.

Status provides current-state resolution. It is not a historical receipt API:
after further successful transitions it cannot attribute every earlier lost
acknowledgment to an individual request. The Agent's historical operation
journal and deployed Runtime continuity remain separate owners.

| Exit | Meaning |
| --- | --- |
| 0 | Requested observation/mutation and complete receipt write succeeded |
| 10 | Root, state, lock or release object type/mode/owner/link/extent refusal |
| 11 | Package bytes/hash/inventory or state content/checksum refusal |
| 12 | Observed inode/time identity changed |
| 14 | Private stage creation or atomic publication failed |
| 15 | Mapping, descriptor, synchronization or receipt I/O failure |
| 16 | Argument or internal policy-state refusal |
| 17 | Input package exceeds 64 MiB |
| 18 | Kernel lock busy |
| 19 | Expected sequence/current conflict or no-op activation |
| 20 | Rollback target is not the recorded previous release |
| 21 | Sequence exhausted |
| 64 | Wrong argument count |

A failure exit is not proof of no filesystem effect. Original observations and
failures must remain attached to the actual source and execution identity.

## Qualification

`ReleaseSelectionSourceTests` executes an independent Core VM before any native
seed for argument conversion, canonical sequence bounds, exact state bytes,
checksum comparison, CAS, rollback, exhaustion, receipts and all ELF packer
bytes. It preserves the language's existing return/list budgets by observing
long receipt bytes in bounded independent views.

`ReleaseSelectionKernelTests` builds a real B0/B1/B2 fixed point for explicitly
labelled development, or requires the current completed cold report when
`HEPTA_HIA_RELEASE_SELECTION_COLD_REPORT` is supplied. It uses the actual native
installer, real immutable releases, independent record decoding, contention,
two process CAS, truncation/corruption, symlinks/hard links, modes and release
readback. `ReleaseSelectionFaultTests` requires actual `strace` fault injection
for stage/root fsync failures, lost stdout acknowledgment, `EINTR`, and SIGKILL
before and after publication. Missing ptrace access is a failed environment
observation, not a skipped or passed native qualification.

The source-bound builder refuses missing or stale complete cold manifests before
creating its output directory and rechecks all original sources/images/report
bytes before publishing. Passing a development test does not qualify a later
merged source, activate a default CLI, migrate a live worker or authorize
retiring an unported production owner.
