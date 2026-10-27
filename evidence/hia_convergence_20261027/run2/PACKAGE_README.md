# Retained Hepta qualification evidence

This archive contains the reports, logs and artifacts the producers left on
disk at packaging time. It does not claim to contain every binary that was
executed. Some producers explicitly report native_binaries_retained=false;
their reports are preserved unchanged. Missing temporary artifacts and
external source/toolchain dependencies are recorded in dependencies.json.
Each package contains one original run; packaging a failed attempt never
relabels it as a passing run or transfers its evidence to another source SHA.

Original JSON bytes and absolute paths are not rewritten. path-mapping.json
maps original files to archive-relative names. Cargo build cache is excluded,
except the existing debug/hia-core-shadow executable (or .exe), when present.
No symlink is followed while walking run/support; omitted links/special files
are recorded. The identity scan follows only path+sha256+bytes objects, and
may encounter negative controls or other identity schemas it does not follow.

Existing external native artifacts are supplemented only from the task's run,
repo/artifacts, or /tmp/hepta* paths, with matching size/hash and native-file
magic. Toolchains, arbitrary system files, source dependencies and installation
caches are not copied through this mechanism. Raw run/support regular files
are retained regardless of whether they are native artifacts.
Supplementing an archive file does not recursively preserve its thin-archive
members, shared libraries, or other dependencies unless separately identified.

inventory.json records SHA-256 for every archive file except itself; its own
digest is in the outer archive-manifest.json. This packaging does not change
the producers' qualification scope or infer missing execution evidence.
