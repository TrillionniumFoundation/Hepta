# HIA P2/P7: converged native syscall-policy hardening

Date: 2026-10-26. **Base is PR #230**, whose follow-up at
`1d3206ada0c245bff933ed3d9a781bfa5025b442` implements stricter
self-PID, self-TID **and SIGABRT-only** `tgkill` validation. This branch
preserves that upstream fix unchanged rather than replacing it with an
inferior alternative.

## Reviewed integration decision

PR #230 already blocks socket and writable-file attacks before ELF
constructors and has a tested `O_DIRECTORY` compatibility correction,
`stdin=DEVNULL`, sealed DSO memfd, bounded process-group cleanup, and
a strict native oracle output protocol. Earlier drafts of this branch
allowed `tgkill(..., 0)` for the worker's own thread. That allowance is
**superseded and must not be retained**: PR #230's newer guard admits
only `tgkill(worker_pid, worker_tid, SIGABRT)`, preserving libc abort
without an unnecessary extra signal permission. The new acceptance tests
explicitly reject `tgkill(...,0)` even for the same worker.

This delta is restricted to syscall families the upstream filter had
not yet enumerated: xattr mutations; `fallocate`, `memfd_create`,
perf/BPF/userfaultfd, extra io_uring entries, selected mount operations,
and process/runtime resource mutation entrypoints. All are rejected
by the existing Linux x86-64 seccomp program with SIGSYS before
loading foreign code. The filter remains a syscall denylist, **not**
a comprehensive untrusted-code sandbox.

## Independent local execution evidence

A standalone Linux x86-64 kernel seccomp worker with the merged BPF
guard sequence was executed against real Clang 17 C shared objects.
**16/16 controls passed**, including: normal return, read-only open,
ordinary SIGABRT, write-mode open/openat, socket, unlink, kill,
memfd creation, both own-thread signal-0 and foreign tgkill refusal,
openat2, ftruncate, xattr, mount and io_uring syscall rejection.

A separate ELF-constructor file-creation control also produced SIGSYS
without creating its marker in the earlier candidate. These observations
are **independent syscall-policy controls**, not exact-HEAD HIA
source/Core/LLVM semantic verification. The committed
`tests.test_hia_native_signal_guard` must execute on a full exact
repository checkout and cannot inherit the standalone result.

```sh
python -m unittest tests.test_hia_native_signal_guard \
    tests.test_hia_native_side_effects \
    tests.test_hia_native_seccomp \
    tests.test_hia_native_differential -v
python tools/release_check.py
```

## Still-open blockers

This is not a hostile-code sandbox. Read-only data access, unusual
syscall side effects, inherited FD side effects, exact output forgery,
kernel/driver trust, hardware and multi-target environment qualification
remain explicit limitations. Production isolation still requires an
independently validated OS namespace/cgroup/network/filesystem policy.

Full Rust Owned/Memory SSA soundness, verified compiler refinement,
general C/C++ L2/L3 migration, GPU/NPU/physical DMA/IRQ, true model
Agent A/B, unbiased throughput and p99, and final signed release remain
open. The original `hia_program.verify_program` stays the sole
executable HIA admission authority.

`whole_project_blockers_closed=false`. CI scheduling is not a source
development stop, and not-run qualification remains not-run.
