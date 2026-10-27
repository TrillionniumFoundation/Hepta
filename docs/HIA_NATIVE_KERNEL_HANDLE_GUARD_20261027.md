# P7 native observer: reject kernel IOCTL, process-memory reads and handle APIs

Exact base is PR #261 commit `63c74114912e8ec255f90557bdf8b13ffb258fa9`.
This is a conservative extension of the **existing** Linux x86-64 seccomp
filter in `hepta.hia_native_differential._WORKER`, not a new worker
or an alternative HIA Core/LLVM checker.

## Previously admitted syscall classes

The denylist guarded process creation, filesystem writes, sockets,
process_vm_writev, keyring, IPC and scheduling, but still permitted:

| syscall | x86-64 number | Reason to reject |
|---|---:|---|
| ioctl | 16 | Read-only FDs can still issue terminal/device control commands |
| prctl | 157 | Can mutate ptrace/dumpability and other process security policy |
| fanotify_init | 300 | Creates global-kernel filesystem notification state |
| fanotify_mark | 301 | Mutates marks/event subscriptions |
| name_to_handle_at | 303 | Reads filesystem handles/identities |
| open_by_handle_at | 304 | Handle-based open bypasses ordinary path/flag assumptions |
| process_vm_readv | 310 | Cross-process memory read; writev was already denied |

All seven now receive the existing seccomp `SECCOMP_RET_KILL_PROCESS`
action (`SIGSYS`), without granting any new open/exec/IPC operations.

## Direct Linux kernel control

An independent x86-64 test installed minimal real seccomp BPF filters in
fresh subprocesses. Invalid-argument probes for all seven syscall numbers
returned an ordinary kernel error before filtering (exit 0), and
**7/7** probes were terminated by actual `SIGSYS` (exit -31) once blocked.
That is **14/14** expected outcomes. The open_by_handle_at probe specifically
uses a null handle to avoid a potentially unbounded invalid-address case.

This independently tests the kernel behavior; it does **not** establish
full Hepta worker execution, HIA-native scalar behavior or verified LLVM.

The existing in-repository `tests/test_hia_native_kernel_effect_guard.py`
now exercises all seven via actual compiled Clang DSO calls through the
original artifact-pinned native observation path. Healthy 7, readonly
`/proc/self/status` and defined SIGABRT controls remain unchanged.
Source regression tests are committed but have **not** been executed on
the exact integrated full-Hepta checkout.

```sh
python -m unittest tests.test_hia_native_kernel_effect_guard \
  tests.test_hia_native_seccomp tests.test_hia_native_signal_guard -v
```

## Incomplete production boundary

This remains a **denylist** rather than independently audited syscall
allowlist. Native loaded shared objects still have read-only filesystem
visibility and multiple kernel entrypoints; runtime/OS/loader/FFI trust
assumptions remain. A hostile-code sandbox requires namespace/cgroup/
seccomp allowlist, object-format validation, signed exact-head builds and
true end-to-end qualification. CPU/RSS/p99, physical hardware/GPU/DMA,
general provenance and C++ L2/L3 also remain OPEN.
`whole_project_blockers_closed=false`.
