# HIA P7 — fail-closed release source snapshot identity

## Exact patch boundary

Parent PR #294 `a78509ff02c4e9e85d88619404e33e697cfed2ca`.
Only the existing `tools.release_check.snapshot` source-inventory reader,
a focused test module and this note are changed. No compiler, HIA verifier,
LLVM lowering, target ABI or proof authority is introduced.

## Fixed risks

The previous collector used `Path.is_file() -> Path.read_bytes()`.
The first follows symlinks, a regular file can be replaced between check and
open, `read_bytes` materializes arbitrary source file sizes, and a substituted
FIFO can block before its type is checked. This undermines the **availability
and identity** of evidence asserting that a release used one unchanged source
snapshot.

The source has now been read using `O_NOFOLLOW|O_NONBLOCK` plus stable inode,
size, mode, mtime and ctime checks on both descriptor and pathname before and
after a bounded, chunked SHA-256 hash. Each source file is capped at 64 MiB
(the current complete candidate source set's largest source file was about
1.6 MiB). Empty ordinary source files remain legal. The original hash
serialization and excluded generated-evidence paths are unchanged; only the
file admission contract is stronger. Every enumerated non-excluded symlink or
special file now refuses instead of disappearing from the manifest.

## Independent executed controls and pending exact-source suite

An independent Linux CPython 3.13 file-hashing reconstruction executed five
positive/negative control methods successfully: ordinary and empty hashes,
symlink refusal, FIFO refusal, swapped-in FIFO nonblocking open, and oversized
sparse file refusal. This was **not** the exact committed `release_check`
module nor a full native build; the committed test file contains six methods
including a symlink-swap refusal.

```sh
python -m unittest tests.test_release_snapshot_identity \
  tests.test_release_file_identity -v
python -m unittest tests.test_release_evidence tests.test_release_collection -v
python tools/release_check.py
```

The complete checkout is unavailable in this container (GitHub DNS) and the
pinned Rust/Cargo toolchain is unavailable, so these exact-head tests remain
**NOT RUN**. A point-in-time inventory does not prove the absence of
arbitrary concurrent directory replacement, a malicious filesystem, later
edits, or compiler/LLVM correctness. General P0–P7 release and formal blockers
remain OPEN; `whole_project_blockers_closed=false`.
