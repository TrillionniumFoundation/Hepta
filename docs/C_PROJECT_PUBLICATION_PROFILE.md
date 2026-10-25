# Captured C-project publication: private-parent POSIX profile

Publication copies caller-validated bytes from retained source file descriptors
to exclusive, no-follow, newly created regular target files. Every copy/digest
is bounded by its validated byte length plus at most one growth-detection byte.
The publisher never derives a new expected digest from a mutable source name.

The four mandatory artifacts are source.hepta, bridge.rs, generated.rs and
migration.json; a caller-qualified libtranslated.so is optional. Exact inventory
and hashes are checked. Data files can be visible while the bundle is being
prepared. The FINAL migration.json name is different: its entire ready inode
must already be copied, verified and fsynced inside the held private target
directory before exclusive no-replace link publication of that final marker.
The ready inode is retained by FD; it is not an external-stage pathname link.
This preserves complete runtime commit-marker contents, but is not a power-loss
atomic directory transaction.

## Admission, not permissions repair

Requires POSIX directory FDs, no-follow, exclusive creation and exact capability
checks. The publisher anchors each parent component. Ancestors must be owned by
the effective UID or system UID0 and not group/other writable, except an
intermediate UID0 sticky directory whose next opened component is owned by UID0
or the effective UID. Direct output parent and sibling stage must be owned by
the effective UID and not group/other writable. Symlink ancestors and ambiguous
paths are refused. No existing directory is chmod/chown'ed to make it pass.

This discretionary-access profile excludes malicious same-UID/privileged writers,
hostile mounts and post-return mutations. POSIX mkdir returns no descriptor:
the code binds the OPENED output directory, not an unobserved original mkdir
inode. A malicious same-UID empty real-directory replacement during acquisition
is not proved impossible. Foreign entries found on acquisition are rejected and
never deleted as publisher-owned. If arbitrary-writer acquisition safety is
required, this profile is unsupported, not a complete filesystem-safety proof.
Windows is unsupported; there is no silent path-based fallback.

## Failure and cleanup

The possible final manifest alias is bound to its held ready FD BEFORE the link
syscall, including the case where link succeeds just before an exception. Cleanup
first handles final-marker absence. If an owned marker cannot be removed once,
or absence is unknown, or a foreign marker is present, do not delete its possible
data dependencies. Report cleanup uncertainty and keep data/marker consistent;
never retry a possibly denied/after-effect operation. Otherwise remove only names
whose identity still matches held publisher-owned FDs, then the owned empty
directory when safely identifiable. Replaced/foreign entries are not deleted.

Every owned FD gets one close attempt; later FDs are still closed if an earlier
close reports an error. Primary exceptions and cleanup evidence are retained.
An otherwise committed bundle with unknown FD closure is NOT returned as a
successful qualification: the public report is rejected with cleanup uncertainty
and the complete marker/data retained. Do not infer success from a residual
manifest alone after a reported failure.

## Qualification separation

50 local filesystem/mocked-frontend profile tests are not native C tests. A
separate source-bound native probe uses the already pinned compiler/container
stack to migrate one actual scalar identity C project with verify_native=True,
publish its real Rust cdylib, compare report/manifest/file hashes, and execute
separate original/generated scalar smoke binaries. It does not prove arbitrary
C equivalence, pointer/record ABI safety or whole-filesystem write isolation.
The original six-case and typed13 attribute/layout oracles remain separate and
retain every original scientific assertion and 12+20 layout comparison.

Focused qualification preselects fresh private /tmp roots in the SAME approved
container before native work. Admission failure is unsupported/HOLD, never a
fallback to another directory/UID/toolchain or a permissions change. Execution
reports keep real private paths. After owned-process cleanup, byte-bound copies
into artifact archives record original-to-archive mappings and before/after
digests; archived locations are not misrepresented as execution locations.
Unknown process cleanup yields snapshot-only/unqualified evidence and retains
the possibly live private root.

Every combined commit must rerun these exact-head probes plus the unchanged
full36 release gates. Previous focused/full results do not transfer to new source.
No hardware, model run, namespace permission change, manual workflow rerun or
crash-atomicity claim is implied.


Qualification archives use separately precreated sibling control directories;
archive mkdir errors are never retried, even if directory creation took effect.
Reserved archive metadata names are rejected before copying original evidence.
Post-run evidence admission checks byte and file/entry totals before bounded
hashing. This is not a monitored runtime disk-write cap; existing supervised
wall-time and command-output limits still apply. The new native scalar smoke
also requires exact report/model/extern-C uint32 signature binding and observed
new distinct publisher target inodes before compiling/executing its drivers.
