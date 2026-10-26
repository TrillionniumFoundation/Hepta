# HIA P2/P7: narrow native syscall-policy convergence

Date: 2026-10-26. Exact parent is PR #230 at
`d7fb522e3f07773d78e7720847108d9ea7792227`. This is a
**reviewed incremental hardening candidate**, not an alternative HIA native
worker, LLVM backend, interpreter, verifier or production OS sandbox.

## Audit and delta

PR #230 already blocked the practical Linux x86-64 network and write-mode
filesystem attacks against the native differential worker. Its newer
`O_DIRECTORY` fix must remain intact, as must `stdin=DEVNULL`, the
sealed source memfd, seccomp-before-dlopen, process-group cleanup and
the strict scalar JSON output contract.

The current incremental patch **retains those exact upstream mechanisms**.
It closes a distinct signal-to-foreign-process loophole: unrestricted
`tgkill(tgid, tid, sig)` remained allowed because glibc `abort()` needs
`tgkill`. The filter now checks both destination identifiers against the
worker's own PID and TID (which are captured before loading the DSO).
Wrong destinations result in kernel SIGSYS; own-thread `tgkill` remains
available, keeping native SIGABRT trap semantics. With clone/fork forbidden
by the inherited filter, the worker is single-threaded at native load time.

Other rejected syscall entrypoints include xattr mutation,
`fallocate`, memfd creation, perf/BPF/userfaultfd, io_uring,
selected mount APIs, and process memory/FD mutation. Each is a
best-effort capability reduction for this **finite oracle**, not a full
system-call allowlist. Read-only dynamic linker directory opens retain
the upstream correct `__O_TMPFILE`-only mask (0x400000).

## Actual locally executed independent Linux kernel controls

A separately constructed Linux x86-64 seccomp worker with the same
BPF guard sequence was run against Clang 17-compiled shared objects.
14/14 independent observations behaved as expected:
- normal scalar return, read-only file opening, self-thread
  `tgkill(..., 0)` returned seven; ordinary `abort()` produced SIGABRT;
- writable `open/openat`, `socket`, `unlink`, `kill`, foreign
  `tgkill`, `memfd_create`, `openat2` and `ftruncate`
  produced SIGSYS, with no file modification;
- an ELF constructor attempting file creation produced SIGSYS
  **before** any marker was written.

These were **standalone system-call mechanism controls**, not tests run
through the repository's final HIA compiler and LLVM. The new
`tests.test_hia_native_signal_guard` native integration suite is committed
for exact-head execution; it was not run on a full repository checkout
in this session. Unknown or unexecuted checks are never declared passed.

```sh
python -m unittest tests.test_hia_native_signal_guard \
  tests.test_hia_native_side_effects \
  tests.test_hia_native_seccomp \
  tests.test_hia_native_differential -v
python tools/release_check.py
```

## Unresolved security and language gates

This filter is NOT a sandbox for hostile binaries; it still exposes read
access to much of the host filesystem and does not exhaustively forbid
every undesirable system call, passed/inherited descriptor side effect
or a malicious library fabricating a valid scalar JSON response.
Production isolation requires filesystem/network/mount namespaces,
cgroups, trusted toolchains and target-specific kernel qualification.

General Memory/Provenance SSA, compiler semantic refinement, unqualified
C/C++ L2/L3, real model/provider A/B, SIMD/GPU/NPU, physical hardware
DMA/IRQ and sustained p99 remain OPEN. The native HIA verifier's sole
source of admission truth remains `hia_program.verify_program`.

`whole_project_blockers_closed=false`; CI queue is not an engineering
stop but has no power to prove a test that never executed.
