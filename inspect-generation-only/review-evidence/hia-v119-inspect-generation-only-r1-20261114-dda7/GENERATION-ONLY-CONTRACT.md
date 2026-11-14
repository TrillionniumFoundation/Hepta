# Separate inspect generation-only stage

Status: authored, not executed. The frozen fourteen-file R1 kit and its 1 GiB complete-run preflight remain unchanged.

## Fixed source and runtime

Use prepared R20 tree f137ac1733a4f6d1e434ef10531952a139c4015a, all 3,177 files, plus the exact original eight-path inspect overlay. This is distinct from the formal R20 tree 84df4b42f1e20fd7d0c7229e658cf3b458984ffb. The authored view has 3,184 files; the only possible additions are the three declared generated files. Use the fixed actual CPython 3.14.4 invocation and its actually mapped library from the original execution kit. The existing runtime-context helper constructs one exact environment for child and supervisor. No ambient LD/PRELOAD is copied.

The ordinary B3 is only reread as a frozen identity. It is never invoked here and supplies no current-source cold authority. Each of the three generator invocations uses the original process owner at 180 seconds plus 3 seconds cleanup. No Source, Native, VM, compiler or CLI test is run.

## Small write surface

Create one exclusive attempt. Share all original source bytes through hardlinks on the same filesystem. The one existing overlay, hepta/hia_program_tools.py, must be checked and unlinked in the attempt before creating its private replacement. Seven new overlay files are created exclusively. All eight overlay inodes are private; the other 3,176 paths retain the original shared inodes. Never chmod or write a shared link.

Hardlinks are not intrinsically immutable or a security sandbox. Creating them intentionally changes original nlink/ctime, which are recorded; original bytes, POSIX modes, inode identities, sizes and mtimes remain exact. Atime can change due to reads and is not used as authority. After preparation, all file metadata including nlink/ctime is also held stable through every generation.

The reviewed generator's only writes are its three Path.write_bytes calls. Its actual command accepts --output/--ports/--identity. Generation 1 writes three new files under results/1; generation 2 writes three new files under results/2. A third actual invocation performs --check against results/2. The same generator code runs through runpy with its actual __file__ and command arguments, under a cooperative Python audit fence that permits those external writes and one child result only. The fence rejects writes or mutations to the source views and child process creation; it is not a malicious native-code sandbox. Source content is not patched or replaced to provide this fence.

Every step rereads all 3,177 original files and all 3,184 authored files, checks full SHA/Git bytes, exact POSIX0644/0755, and stable held inode metadata. Complete maps are deduplicated by content, not omitted. Failures preserve per-path errors and actual partial outputs.

Both rounds must have all three files, full raw bytes must match, and --check must leave their bytes and metadata unchanged. Only after all three authoritative owner receipts and readbacks pass are the actual second-round bytes copied into three absent canonical source paths using new private inodes. The final 3,187-file map is captured and all earlier files remain exact. No shared link or external result file is reused as a writable canonical output.

## Storage contract

This is a separate task-specific storage gate, not a modification to any product limit or to R1. Actual overlays are 93,585 bytes (106,496 bytes at 4 KiB allocation). There are 254 parent directories plus the source root, 255 directories in total. A conservative envelope reserves 16 MiB for directory metadata, 128 KiB for overlays, 12 MiB for the two external triplets and final private triplet, 12 MiB for deduplicated full maps/receipts/logs, and 32 MiB of headroom: 72.125 MiB, rounded to an 80 MiB entry gate. Generated Python sizes are not yet observed; the 12 MiB component is an estimate, not a new output/language cap.

After preparation, generation 1 requires 64 MiB free. After observing the first output set's actual allocation-sized S bytes, generation 2 requires 44 MiB + 2*S; check requires 40 MiB + S; installation requires 36 MiB + S. These are instantaneous free-space checks, not reserved filesystem capacity. External writers can still exhaust disk; any missing/truncated receipt, failed source guard or partial output is failure and stops the sequence. No output is silently deleted to make room. All original source bytes, outputs, receipts and failures remain.

## Stops and qualification

No automatic retry, no resume over an existing attempt, no overwrite of previous results. Failure or incomplete process-owner cleanup stops before the next owner. The result is only GENERATION_ONLY_PASS after both actual generations, actual --check, full byte equality and private canonical installation succeed. This grants no Source10, old3/CLI43, Native17, VM12, installation, current-cold or whole-CLI qualification.

The full R1 kit still has the explicit unexecuted machine-entry busy-boundary control. A failure there would stop before VM12; this generation-only stage neither fixes nor hides that boundary.
