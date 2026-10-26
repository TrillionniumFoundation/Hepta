# HIA P2/P7 — deny native side effects before ELF constructors

Date: 2026-10-26. Base: PR #228 at exact commit
`d5be4d61bee03781b8bc04cdcc3ee6c3d4f5f3d6`.
Status: **scoped Linux x86-64 seccomp hardening candidate**, NOT a
full hostile-code sandbox, whole-language safety proof or production release.

## Gap and production code

Before this change `hepta.hia_native_differential._WORKER` blocked
fork/clone, exec and session escapes but could still load a foreign shared
object that creates a file, alters a file, opens a socket, sends network data
or signals another process and then returns a forged expected integer.
The evaluator is a finite oracle, not an authorization boundary; accepting
such an observation would provide misleading evidence.

The same existing pre-dlopen seccomp filter now:
- Kills on direct network syscall entrypoints, filesystem mutations,
  memfd creation, openat2, signal-to-other-process calls and selected
  privileged kernel interfaces using `SECCOMP_RET_KILL_PROCESS`.
- Checks Linux x86-64 syscall argument offsets for `open` and `openat`;
  write access, create, truncation, append and O_TMPFILE fail before a file
  can be opened, while read-only dynamic-linker operations remain allowed.
- Pins the permitted `tgkill` target to the worker's own PID and main TID.
  `abort()` from the one permitted thread remains observable as SIGABRT.
- Retains all original arch/x32, fork/exec, RLIMIT, sealed memfd,
  WNOWAIT-before-reap, bounded output and result validation.

This does not make an untrusted ELF library harmless. Read-only disclosure,
malicious use of already inherited descriptors, kernel/driver bugs, subtle
filesystem operations, malicious ABI payloads and exact result forgery are
not comprehensively prevented. The dynamic loader, libc, seccomp policy and
Linux kernel remain trusted. This filter has no portable AArch64 implementation.

## Actually executed independent local controls

A separately constructed Python worker used the same BPF rule sequence on
Linux x86-64 with Clang 17 compiled C shared libraries. Observed results:

- Genuine healthy return = 7; read-only open = 7; self `tgkill(...,0)`
  = 7; ordinary `abort()` terminated via SIGABRT.
- Write-mode `open` and `openat`, `socket`, `unlink`, `kill`,
  foreign `tgkill`, `memfd_create`, `openat2` and `ftruncate`
  all terminated the worker with SIGSYS. A separate ELF-constructor test also produced SIGSYS before any marker was written (14/14 independent executed controls in total).

These controls exercised independent Linux/Clang mechanism code, **not**
the exact Hepta checked-source LLVM emitted artifact and not the complete
GitHub-branch checkout. The in-repository positive and negative tests
exercise the existing sealed native observer and are committed as acceptance
inputs, but have not run on the exact integrated Hepta source yet.

```sh
python -m unittest tests.test_hia_native_side_effect_seccomp -v
python -m unittest tests.test_hia_native_seccomp \
  tests.test_hia_native_postexit_group \
  tests.test_hia_native_child_protocol \
  tests.test_hia_native_differential -v
python tools/release_check.py
```

## Remaining explicit blockers

A production-grade native sandbox still needs filesystem/mount and network
namespace isolation, cgroup/PID/FD policy, syscall allowlisting, target-specific
qualification, authentic source→Core→LLVM semantic refinement and signed
exact-head evidence. General C/C++ L2/L3, full Rust executable Ownership/
Memory SSA correspondence, real Agent model A/B, physical GPU/DMA/IRQ and
sustained production CPU/RSS/p99 remain OPEN.

`whole_project_blockers_closed=false`. CI queue is not a development stop,
but no unexecuted native tests or new compile/performance claims become Passed.
