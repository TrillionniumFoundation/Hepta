# Windows compiler identity timestamps

The bounded compiler-byte reader compares a pathname snapshot with an open
descriptor, then verifies the descriptor after reading and the pathname after
closing it. All comparisons retain device, inode/file ID, size and modification
time. The digest and compiler source filename/NUL/raw-bytes/NUL envelope are
unchanged.

## CPython API mismatch

The Windows failures observed in the integer-admission workflow used Python
3.12.10 and 3.13.17. Their pathname and descriptor APIs assign different meanings
to `st_ctime_ns`:

- `win32_xstat` copies creation time into pathname `st_ctime`, retaining legacy
  behavior: [3.12.10](https://github.com/python/cpython/blob/v3.12.10/Modules/posixmodule.c#L2139-L2151),
  [3.13.17](https://github.com/python/cpython/blob/v3.13.17/Modules/posixmodule.c#L2218-L2230).
- `_Py_fstat_noraise` passes `FILE_BASIC_INFO` to `_Py_attribute_data_to_stat`,
  which assigns `ChangeTime` to descriptor `st_ctime` and creation time to
  `st_birthtime`: [3.12.10](https://github.com/python/cpython/blob/v3.12.10/Python/fileutils.c#L1108-L1131),
  [3.13.17](https://github.com/python/cpython/blob/v3.13.17/Python/fileutils.c#L1129-L1152).
- Python 3.11 uses creation time for both APIs and has no Windows
  `st_birthtime_ns`: [3.11 source](https://github.com/python/cpython/blob/v3.11.9/Python/fileutils.c).

A stable file whose metadata changed after creation can therefore fail a direct
pathname/descriptor ctime comparison. This is not evidence that its bytes were
replaced. The workflow prints both native snapshots and their differing fields
so that a host result can be distinguished from this source-level explanation.

## Comparison boundaries

Only the cross-API comparison substitutes Windows `st_birthtime_ns`, falling back
to `st_ctime_ns` when birthtime is unavailable. It does not ignore or truncate
device/file IDs, timestamps, or sizes. Unexplained differences still fail closed.

The post-read descriptor is compared against the initial descriptor using the
original ctime-bearing key. This retains detection of metadata-only changes
during reading even if size and mtime are unchanged. The final pathname is
compared against the initial pathname using its original key. POSIX comparisons,
no-follow/nonblocking flags, ordinary-file checks, byte limits and streaming
behavior are unchanged.

These remain snapshot checks, not atomic observation or toolchain attestation.
In particular, Windows pathname creation time cannot detect a same-size write
with restored mtime outside the descriptor-check interval; this limitation also
exists with Python 3.11. This fix does not claim to close that race.

## Validation

`tests.test_native_tool_identity_cross_api` has nine no-skip portable tests:
positive split-ctime and Python 3.11 controls; independent per-field rejection
controls; descriptor-only ctime and final-path ctime mutations; POSIX ctime
comparison; rewritten-file hashing; and original compiler-source byte envelopes.
The host workflow runs them on Windows and Linux with Python 3.11, 3.12 and 3.13
at the exact PR head. Existing native tests additionally run with their declared
platform/toolchain skips, and existing POSIX source-identity controls run on Linux.
