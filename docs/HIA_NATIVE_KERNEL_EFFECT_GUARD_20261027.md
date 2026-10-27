# HIA P7: native differential kernel-effect boundary (2026-10-27)

Status: source hardening on the existing HIA scalar oracle, **NOT** complete
hostile-code isolation, Rust/Core/LLVM proof, or a production release.

## Observed admission weakness

The finite Linux x86-64 native observer installs a classic-BPF seccomp
kill filter before calling `ctypes.CDLL` on the pinned shared object.
The prior blacklist covered fork, network, direct file mutations, a subset
of process signals and kernel-worker creation. It did **not** block:
- System V IPC (shared memory, semaphores, message queues): 29-31, 64-71, 220;
- persistent kernel keyring operations: 248-250;
- process scheduler/priority mutations: 141, 142, 144, 203, 251, 314;
- fd duplication/rebinding via dup, dup2, dup3 and fcntl: 32, 33, 292, 72;
- POSIX message queues (separate from System V): 240-245;
- legacy Linux asynchronous I/O contexts, including io_setup/io_submit:
  206-210.

These are not operations required by the explicitly supported finite i32/u32
scalar oracle. Some can affect OS objects or same-user processes outside the
worker's temporary private process group. An attacker could return the
expected numeric value after attempting one of these calls.

## Exact implementation

The **existing** `hepta.hia_native_differential._WORKER` filter now
kills attempts to enter all 36 listed syscall numbers with SIGSYS before
their argument parsing or side effects. The original x86-64 architecture
and x32 checks, SIGABRT self-only tgkill policy, loader environment isolation,
read-only file access, sealed native memfd, and post-exit group cleanup
remain unchanged.

`fcntl` is forbidden in full, rather than incorrectly treating F_GETFD as
harmless while admitting F_DUPFD or F_DUPFD_CLOEXEC on the same syscall.
This can reject otherwise benign native libraries using read-only fcntl;
the finite oracle prioritizes fail-closed correctness over broad FFI coverage.

## Evidence boundary and tests

A **standalone** Linux x86-64 + Clang 17 kernel seccomp control was executed
against a compiled DSO using a reduced filter. Before the new deny set,
invalid-argument calls passed to the kernel and returned to the function.
With the updated set, **all 36/36 tested syscall entrypoints terminated with
SIGSYS (-31)**. The healthy scalar function and read-only file open returned
normally, while explicit abort produced SIGABRT (-6). This is a direct
kernel-policy control, **not** a run of the full in-repository Hepta oracle.

The committed `tests/test_hia_native_kernel_effect_guard.py` exercises the
actual original sealed-memfd observer and pinned worker, with 36 distinct
invalid-argument syscall probes, normal return, read-only and SIGABRT controls.
Execute on a full exact branch checkout:

```sh
python -m unittest tests.test_hia_native_kernel_effect_guard -v
python -m unittest tests.test_hia_native_side_effects \
  tests.test_hia_native_seccomp tests.test_hia_native_signal_guard \
  tests.test_hia_native_startup_isolation -v
```

No exact-head Hepta native/LLVM integration test has been executed in this
tool session. The worker still runs untrusted DSO code in its own address
space with read-only host filesystem access and many allowed syscalls. It is
**not a complete untrusted-code sandbox**. Stronger isolation requires
privilege separation, independently checked seccomp allowlist, filesystem
namespaces, cgroups and cross-host fault controls; full P0–P7 remain OPEN.
`whole_project_blockers_closed=false`.
