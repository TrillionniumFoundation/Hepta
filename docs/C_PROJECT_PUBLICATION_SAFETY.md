# P2 captured C migration: anchored bundle publication

This change addresses one narrow publication-path integrity defect in the
existing C-project migration pipeline. It does not translate additional C
constructs or certify pointer contracts.

## Why path-based publication was insufficient

The former flow created an output directory and then linked each staged
artifact using a new path resolution of destination/file. An uncooperative
filesystem actor could rename/replace the destination with a symlink after
directory creation and before the next link, redirecting artifacts into a
different directory. The preflight destination.exists()/is_symlink() guard
does not cover this later window. This is an output-path security defect,
not a claim of arbitrary overwrite (os.link is still no-replace).

## Fix and guarantees

hepta/c_project_publish.py anchors the parent, stage and newly created output
directories with POSIX descriptors and O_DIRECTORY | O_NOFOLLOW. It checks
regular file identities within the source FD; requires the four expected
artifacts; creates a new output directory via the anchored parent FD;
publishes files with os.link using explicit src_dir_fd/dst_dir_fd,
follow_symlinks=False; fsyncs the output and parent directories, and verifies
the final path still refers to the originally opened output directory.

If a publish step fails, it only unlinks entries whose inode still equals
their staged source file, and only removes the directory while its name still
refers to the original inode. It never follows a newly planted output symlink
during cleanup. The manifest remains last.

This implementation **requires POSIX dirfd primitives** and fails closed
when they are missing. Windows output publication is not qualified. It is not
a power-loss atomic multi-file transaction, nor a defense against arbitrary
malicious same-user renaming after the final identity check. The actual native
Hepta frontend and migration qualification stages remain separate.

## Executed tests

Standalone Python 3.13.5 real-filesystem tests/test_c_project_publish.py:
5/5 PASS, including positive hard-link identity, pre-existing/dangling symlink
refusal, post-creation rename+symlink injection before the first hard-link,
mandatory manifest refusal, and symlink inside the stage. The source/test Git
blobs match the exact local executed files.

Not executed here: whole Hepta C migrator native run (requires the full
PR #14 checkout), arbitrary live adversarial filesystem schedules, power-loss
injection, multiple target platforms, general C/C++ source equivalence and
production model/hardware performance. Remaining original P01–P12 and P0–P7
blockers remain open.
