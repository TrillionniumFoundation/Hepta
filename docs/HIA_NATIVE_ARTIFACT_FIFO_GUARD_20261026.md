# P0/P2 HIA native-artifact FIFO race guard

This is an exact-scope change to the existing `hepta.hia_program_llvm._read_artifact` source/native LLVM publisher. The verifier, Core ISA, emitter, object layout/exports, bounded reads, compiler identity, source replay, and publication authority are unchanged.

## Concrete hazard and fix

`path.lstat()` already requires a bounded regular file. But between that check and a blocking `os.open(path, O_RDONLY)`, the leaf could be replaced by a FIFO, blocking forever before the existing `fstat` regular-file identity check can reject it.

Add `O_NONBLOCK | O_CLOEXEC` to the existing guarded `os.open`. For regular files `O_NONBLOCK` does not change byte semantics; a FIFO swap now returns immediately and fails the existing exact `dev,ino,size,mtime,ctime` comparison. Preserve `O_NOFOLLOW`, `st_size + 1` read bounds and staged-artifact verifier unchanged.

## Narrow local verification (not CI)

Three actual Linux tests exercise a legitimate regular artifact, name-swapped FIFO, and same-inode same-size file mutation between lstat/open. The repository regression bytes are `b1591a816ca2d54496291094cdbef38db43ced78`.

An isolated local Python 3.13.5 execution used the exact new regression test file, importing a standalone copy of the 32-line `_read_artifact` helper with the same O_NONBLOCK/O_CLOEXEC change (not the 42 KB full source module). Result:

```
python -m unittest tests.test_hia_native_artifact_open -v
Ran 3 tests
OK
```

The whole HIA native module, its Clang20 driver, Rust reference, object validator and source/native pipeline were not executed here. Therefore this is a **targeted OS-file-descriptor behavior check**, not full compiler qualification.

## Integration

Stacked after P0/P4 bundle precommit hardening so both L1 migration bundle publisher and direct HIA LLVM artifact reader refuse FIFO-liveness races without adding a second file integrity authority.

General C/C++ translation, compiler semantic refinement, Owned/Loan/Provenance SSA, all-target ABI, physical GPU/DMA, actual AI-model A/B and production measurements remain unclosed.

`whole_project_blockers_closed=false`.
