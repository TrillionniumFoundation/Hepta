# Native immutable release publication

The explicitly built Linux x86-64 `hia-release` application installs a complete
bounded collection of already-built applications and source/data files, then
independently reads it back. HIA owns package/argument admission, SHA-256,
directory and file identity policy, exact byte comparisons, complete directory
inventory and receipt construction. A fixed Linux syscall adapter performs
descriptor transport. A HIA packer emits the executable ELF, patches calls and
copies the two HIA images. There is no Python, libc, dynamic interpreter or child
executable at runtime.

This replaces the installation byte/publication boundary for this explicit
package profile. It does not compile the package, select the default `hia`
entry, implement the eleven-tool worker, migrate its journal, upgrade a service,
activate a release, delete old owners, or establish that packaged code is HIA
or qualified. The initial build/custody driver and authoring-time fixed-adapter
assembler remain hosted components.

## Invocation and authority

```sh
python -B -m tools.build_hia_release_install \
  --compiler /qualified/B3.image.bin --cold-report /completed-cold.json \
  --output /new/private/installer

/new/private/installer/hia-release install /absolute/private/root EXPECTED_SHA256 < release.hiapack
/new/private/installer/hia-release verify /absolute/private/root EXPECTED_SHA256 < release.hiapack
```

The installer requires the operator to supply the exact lowercase SHA-256 of
the entire package. That hash authorizes bytes; it is not a signature, source
qualification, provenance proof or permission to execute its contents. Package
contents cannot select the installation root or replace a default executable.

The existing root must be an ordinary directory owned by the effective UID
and not writable by group or others. The HIA root policy checks that ownership,
directory type and absence of group/other write bits; it does not require the
owner-write bit for a read-only verification. Kernel permission checks still
govern opening and using the held descriptor. Installation requires the actual
write/search access needed by its creation and publication syscalls; `verify`
can use an owner-readable/searchable `0500` root without writing to it.
The absolute path is limited to 4,095 bytes;
empty, `.` and `..` components and trailing slash are refused. `/` is a valid
lexical root, still subject to its actual owner and permissions. Each component
is opened with `O_PATH | O_DIRECTORY | O_NOFOLLOW`; ancestors need search
permission, not directory-read permission. The held final root is then opened
for descriptor-relative installation and fsync. No symlink component is
followed. The held root descriptor identifies the destination during the
operation; this does not lock the external pathname against another owner.

The published release name is exactly `EXPECTED_SHA256`. No arbitrary package
entry can choose a directory, pathname traversal, symlink or publication name.
Existing files, directories and dangling symlinks at that name are never
overwritten. A new version has another content hash and leaves all prior
releases in place. There is no automatic `current` update.

## Exact package format

The binary input is little-endian and includes no implicit padding:

| Field | Encoding |
| --- | --- |
| Magic | Eight bytes `HIAREL01` |
| Entry count | u64, 1 through 256 inclusive |
| Reserved | u64 zero |
| Each entry | u64 name length, u64 mode, u64 payload length, exact name bytes, exact payload bytes |

The entire package is at most 64 MiB, inclusive. The transport reads an extra
byte solely to reject oversize input. Entry names are 1–127 ASCII bytes matching
`[A-Za-z0-9][A-Za-z0-9._-]*`, unique across the package. Names are single path
components. Mode is exactly `0400` for data/source or `0500` for an executable;
there are no ownership/set-id/ACL/xattr instructions. Empty files are allowed.
All declared lengths and final stream exhaustion are checked before any
filesystem mutation. A payload is an exact byte string; an executable mode does
not mean its bytes have passed a machine-code verifier.

## Publication and readback

For `install`, the application obtains a 128-bit random staging name and creates
one private directory beneath the held root. This child fixes its own umask to
`0077`, without changing its caller. HIA admits only an owned `0700` stage or
the `02700` mode inherited from an SGID parent; the held stage descriptor is
then changed to `0700` before files are created. The operator root is unchanged.
Each file is created with
exclusive, nofollow, descriptor-relative opening, written from the captured
package, assigned its exact mode and fsynced. HIA checks regular-file type,
effective owner, single link, size and the exact device/inode/time identity.
The stage is changed to `0500` and fsynced. Before publication, every file is
reopened and compared byte for byte with the captured package; the entire
directory enumeration must contain exactly the declared files. Extra entries,
substituted inodes, changed modes, symlinks, hard links and corrupt bytes refuse.

`renameat2(RENAME_NOREPLACE)` publishes the complete directory in one namespace
operation. The root directory is fsynced. A second complete readback checks the
held release and its published name before any success receipt. A successful
install therefore observes file, stage-directory and root-directory fsync;
this is not a claim of testing every storage device's power-loss behavior.

`verify` performs the same package-hash admission, safe root traversal, exact
mode/owner/content checks, complete directory enumeration and named-directory
identity check without creating files, changing modes, fsyncing, renaming or
executing package contents. It is the explicit read-only resolution path after
a process interruption or lost success receipt. It establishes current bytes
and identity, not that a prior failed operation had acknowledged completion.

Success writes one JSON receipt:

```json
{"schema":"hepta.hia.release-install.v1","sha256":"...","files":2,"bytes":1234,"published":true}
```

`published` is false for `verify`. The receipt names the whole package's byte
count, not the sum of its payloads. Receipt writes retry EINTR, but are not
atomic. A failed or interrupted stdout write may leave a fully published,
durable release. Never interpret missing receipt bytes as proof of no effect.

| Exit | Meaning |
| --- | --- |
| 0 | Operation and complete receipt write succeeded |
| 10 | Path, file type, mode, owner or required object refusal |
| 11 | Package hash, bytes, size or exact inventory mismatch |
| 12 | Observed inode/time identity changed |
| 14 | Stage creation or no-replace publication failed |
| 15 | Mapping, descriptor, synchronization or receipt I/O failure |
| 16 | Argument, package or internal policy-state refusal |
| 17 | Input exceeds 64 MiB |
| 64 | Wrong argument count |

No failure recursively removes a stage. A failure or SIGKILL before publication
can leave a private `.hia-stage-*` directory, containing only whatever bytes the
operation had reached. Successful rename consumes that name. The product does
not infer ownership from a stage prefix, remove a competitor's substituted
path, or offer an automatic retry/cleanup command. Administrative staging
recovery, reference-aware retirement and activation are separate unfinished
release-lifecycle responsibilities.

These checks provide point-in-time local consistency. A same-UID writer can
still modify files after a check or race namespace operations; permissions and
readback do not grant immunity from that writer. No existing release is
overwritten to repair a failed observation.

## Required evidence

`tests.test_hia_release_install.ReleaseInstallerSourceTests` runs independent
Core-VM package, argument, hash, stage-name, receipt and every-packer-byte
controls. The kernel suite actually installs, reads, executes a copied installer
under an empty PATH, checks all symlink components and search-only ancestors,
refuses corruption/extra files/hard links, exercises entry/name/wire limits and
preserves existing releases.

Actual `strace` fault controls inject file/directory/root fsync failures, lost
receipt writes and EINTR, and kill the process before and after publication.
Those controls require ptrace-capable execution; an environment refusal is
retained as a failure, not skipped or counted as a product pass. A supplied
`HEPTA_HIA_RELEASE_INSTALL_COLD_REPORT` requires the genuine completed current
source contract and native compiler image. Without it, the suite records an
explicit B0/B1/B2 development build after independent VM execution. That result
does not qualify a later joint source or close whole-native delivery.
