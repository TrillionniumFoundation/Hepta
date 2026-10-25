# P4 C++ bridge staged-publication fault boundary

Development branch `assistant/hepta-p4-bridge-publication-20261025` is stacked on P3 PR #116 at exact `724bc38b0ba63532e95804e0e549086aea4ef33e`.

## Failure mechanism

The original bridge wrote directly into final `.cpp` and `.hepta` destinations. It remembered a file's expected final SHA-256 and attempted rollback by unlinking only a completed, hash-matching file. A short write, ENOSPC, filesystem error or unexpected partial serialization left a truncated final file whose hash did not match and therefore was not removed.

## Corrected publication

Both outputs are now written into output-filesystem-local private staging directories with completed byte writes and file fsync before either destination exists. Atomic `os.link(stage, destination)` publishes each full file without overwriting an existing file or leaf symlink. If a subsequent link/fsync fails, rollback removes only published paths with the same device/inode as the owned staging files. Operating-system errors return a structured rejected bridge result instead of an uncaught exception.

There is **no** cross-directory two-file crash transaction: between the two hard links a sudden power loss may expose one complete file. Resolving that class of failure requires an immutable bundle and a single atomic reader-visible reference, as in the existing P6 Workspace design.

## Evidence scope

The repository test `tests/test_cpp_bridge.py` now includes staging fsync failure, second link failure, and existing destination preservation, alongside the original native C++ handle lifecycle/exception tests.

An independent local POSIX Python probe executed four staged-publication controls (successful pair, staging fsync fault, second-link fault, existing second destination): **4/4 expected results**. It exercises this publication algorithm but is not the complete Hepta bridge parser/compiler test and is not a crash/power-loss qualification.

No arbitrary C++ ABI, classes/templates/STL source equivalence or whole-language memory-safety claim is made. `whole_project_blockers_closed=false`.
