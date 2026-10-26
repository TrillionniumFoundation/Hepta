# P0/P4 HIA L1 bundle staging race hardening (2026-10-26)

This is an incremental hardening of the **existing** `hepta.hia_bundle_atomic` publication authority, stacked on the current checked v6 / C+C++ L1 integration. It does not add a new migrator, object publisher, parser, or HIA Core.

## Concrete precommit hazards

1. Between `lstat` and `open`, an otherwise regular staged filename could become a FIFO. The old blocking `O_RDONLY` open may hang indefinitely before `fstat` can reject the unexpected file type. Require `O_NONBLOCK` in the guarded open, and retain `O_NOFOLLOW` + exact regular-file `fstat`.
2. Reading until EOF without a byte budget can keep processing a concurrently growing staged file. Read **no more than expected length plus one sentinel byte** and reject any byte count or digest mismatch.
3. A same-inode, same-size staged rewrite after hashing and before `fsync` was not compared with the **pre-read** file timestamps. The post-read fd and current pathname might agree with one another yet both have drifted from the source bytes. Require `dev, ino, size, mtime_ns, ctime_ns` equality across before/opened/after/path snapshots before the no-replace rename.

The no-replace `renameat2` publication point, fsync ordering, final-byte reread and the distinction between precommit `AtomicBundleRejected` versus postcommit `AtomicBundleUncertain` remain unchanged.

## Exact locally executed qualification

An isolated Python 3.13.5/Linux checkout was recreated with the **exact Git blobs** from integration PR #197:

- Original `hepta/hia_bundle_atomic.py` = `aa0dba61c8954bf131b29e3fda25ac833cf672fb`.
- Existing `tests/test_hia_bundle_atomic.py` = `68eade98acee3dddd59b8b6a674f02766ae9c5cf`.
- Modified module tested = `7758ca1558ec646283c47dc89fea6386d1b80e93`.
- New adversarial tests tested = `5129080bddc50b3ffd898745bcb9ff2e442521f3`.

```sh
python -m unittest tests.test_hia_bundle_atomic tests.test_hia_bundle_atomic_hardening -v
# Ran 15 tests; OK (zero failures/errors/skips).
python -m compileall -q hepta tests
```

The tests actually exercise Linux filesystem operations: FIFO name swap during `os.open`, same-inode content mutation during `os.fsync`, concurrent appends during `os.read`, real renameat2 no-replace, source replay refusal, post-rename uncertainty, and actual `fork`/`_exit` at the rename boundary.

The isolated runtime contains the **unmodified, blob-identical existing publisher tests** plus the new three regression tests; no source compiler, pinned rustc, Clang20 or full Hepta project execution was available in this container. Therefore these are real publisher tests on the exact blob bytes, **not** HIA C/C++ migration native qualification or arbitrary concurrent-writer proof.

## Remaining bounds

These checks narrow the verification-to-publish window and stop bounded staging-file races, but cannot atomically snapshot bytes against a fully adversarial concurrent writer with write access to the same inode. A file modification after final verification or malicious filesystem/hardware implementation remains out of scope.

Complete P1/P2 operational Memory/Provenance SSA, Rust/LLVM semantics refinement, C/C++ L2/L3 migration, cross-toolchain ABI, real AI-model A/B, physical DMA/GPU and sustained performance remain open. CI state is not a planning stop signal.

`whole_project_blockers_closed=false`.
