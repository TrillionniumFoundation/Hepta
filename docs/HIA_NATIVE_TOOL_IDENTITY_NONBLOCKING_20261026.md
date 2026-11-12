# P0/P2/P5/P7 exact compiler executable identity: nonblocking file race gate

This changes the **one existing** `hepta.native_tool_identity.digest_executable` shared by C capture and HIA/LLVM native compiler paths. No new compiler identity implementation, FFI verifier, source parser or backend is introduced.

## Correctness / liveness defect

The previous helper checked `path.lstat()` for a bounded regular file, then used blocking `Path.open("rb")`. A path rebind to a FIFO during that gap may block indefinitely before the existing `fstat` identity check. Additionally, reading until EOF could process a continually growing file up to the global one-GiB cap even when its originally observed size was much smaller.

The same implementation now:
- Opens through `os.open` using `O_NONBLOCK`, `O_NOFOLLOW`, `O_CLOEXEC` when present (and `O_BINARY` for Windows raw-byte compatibility).
- Rejects POSIX systems lacking a nonblocking open capability instead of silently performing a blocking compiler-file read.
- Maintains exact `(device,inode,size,mtime_ns,ctime_ns)` comparisons before/open/after/read and final pathname replay.
- Reads **at most originally observed size + 1 byte**, in 1 MiB maximum chunks, and rejects short/growing/mutated files; no increased memory budget or fallback.

Because this replaces `Path.open`, the existing two race tests now intercept the exact `os.open` call; neither race coverage nor semantics are discarded. Adds FIFO swap and append-after-open regressions.

## Real local verification, not CI

The original code and test file were materialized manually from the **exact Git objects** `231e44d443a0bd77bb9caf30072d1ba3d7dcc8db` and `0a245df1414c69e6512f52d2a8a7c0229f1fe28d`; their local git hash-object values matched.

Final code blob **`edbeb5d8ee8b3eaf2328c1538a3e56cb5c68b8ad`**, new tests blob **`3d2d89ba48f47ea1e467cd958421882d261a10c1`**.

```bash
python -m unittest tests.test_native_tool_identity -v
# 10 tests, OK, zero skips (Python 3.13.5, Linux x86-64)
```

Tests include a *real installed Clang* binary digest against independent `hashlib.sha256(actual.read_bytes())`, symlinks, FIFOs, spoofed lstat/open path races, same-inode truncation, file append, sparse oversized input and exact-binary identity.

This is **actual execution of the complete tested helper and its test suite**, not full Hepta compiler qualification or adversarial native-toolchain attestation.

## Boundaries

The file hash is only a stable content identity. It does not attest a malicious compiler, an adversarial filesystem/kernel, or source/LLVM soundness. All P0–P7 production blockers remain open or partial, including full Memory/Provenance SSA, C/C++ L2/L3 and all-target ABI, agent model A/B and hardware GPU/DMA.

`whole_project_blockers_closed=false`.
