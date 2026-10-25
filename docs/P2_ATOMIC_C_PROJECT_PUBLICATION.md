# P2: atomic, no-replace C project migration publication

Base: PR #60 exact source head 4e4cd6a5d0ec6b4027040ffd17f5088421559185,
stacked on PR #14. This increment **changes only the publication protocol**,
not migration acceptance, source semantics or ABI qualification.

## Problem

The previous no-follow file-by-file linker made the output directory visible
before the last required artifact was linked. A reader not using an explicit
manifest/commit protocol could observe a partially populated migration bundle.
A rename / replacement between mkdir and open could also cause the publisher
to operate on a different directory than the newly created output directory.

## New commit protocol

The existing caller stages the complete project bundle in a temporary
directory under the destination parent, on the same filesystem. The new
publisher requires Linux and:

1. Opens the parent and stage through O_DIRECTORY|O_NOFOLLOW directory FDs,
   verifies the mandatory artifact set, all staged entries are regular files,
   and fsyncs those file descriptors and the staged directory.
2. Checks that the source pathname still resolves to the opened stage inode.
3. Atomically publishes the *entire directory* with Linux
   renameat2(RENAME_NOREPLACE), refusing an existing path or dangling symlink.
   No per-artifact publication and no unsafe ordinary rename fallback.
4. Checks the destination inode and fsyncs the parent directory.
5. If the final identity/fsync fails **after the rename may have committed**,
   raises PublicationRecoveryRequired rather than pretending no output exists.
   The migration caller reports status=recovery_required,
   publication_may_have_committed=true and the recovery path. Consumers must
   examine the directory before retrying or deleting any material.

The stage folder is moved, not copied or relinked; its original inode and
file contents are preserved. The output directory has the restrictive
permissions of the temporary staging directory. The parent-directory fsync
provides the local durability step subject to the underlying filesystem and
power-loss semantics; no general recovery protocol is claimed.

## Local executed checks

Python 3.13.5 on Linux, actual POSIX temporary directories:
python -m unittest discover -s tests -p 'test_c_project_publish*.py' -v

Result: 17 passed, 0 failed, 0 skipped. Controls include real no-replace
rename, full directory visibility, fixed inode identity, planted directory
and symlink races at the publication call, swapped stage before commit,
missing manifest, staged symlink, non-sibling path refusal, unavailable
rename syscall, original content equality, and failed parent-directory fsync
after a completed rename. Python syntax compile also passed. These results
are scoped to the standalone publisher. The complete C-project migration
pipeline and compiler tests have **not** been run against the combined
branch in this environment.

## Unclosed limitations

This is a Linux-only publishing profile; unsupported OS/filesystem configurations
reject. It is not a sandbox against a hostile process with write access to the
staging tree or parent directory, and cannot prove recovery under every crash
point, arbitrary filesystem behavior, malicious same-user modifications,
source-to-source migration equivalence or foreign ABI soundness. A failed
final fsync must remain recovery_required until the filesystem state is
inspected. P0–P7 and original P01–P12 whole-project blockers remain open.
