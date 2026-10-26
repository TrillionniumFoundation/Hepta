# HIA P2/P7 — reject native process creation **before DSO loading**

**Exact review base:** PR #224 HEAD `4dce4b6b05f8b42886f42b6839f282abd1ed0760`.
**Scope:** a narrow hardening of the existing sealed Linux x86-64 native differential
transport. Do not claim a language/runtime sandbox or full HIA correctness.

## Why the existing process-group cleanup was insufficient

PR #223 kill-before-reap process groups and #224 reject observed in-group
descendants. A foreign shared-object constructor or exported function can
`fork()`; its child can call `setsid()` and escape that group before the
bounded `/proc` scan. In-group killing and ordinary `waitid(WNOWAIT)`
cannot contain that escaped process. Accepting a scalar result after
unobserved foreign effects is not a qualified finite differential observation.

## Concrete implementation

The existing `hepta.hia_native_differential._WORKER` (run as isolated Python
`-I -c`) now installs an irreversible Linux seccomp-BPF syscall filter after
setting RLIMIT_CORE/FSIZE/AS/CPU and **before** `ctypes.CDLL(lib)`. The filter:

- demands `AUDIT_ARCH_X86_64=0xc000003e` and excludes x32 syscall numbers
  (`0x40000000` bit/range) to prevent alternate-ABI bypass;
- SIGSYS-kills attempted `clone` (56), `fork` (57), `vfork` (58),
  `clone3` (435), `execve` (59), `execveat` (322),
  `setpgid` (109), `setsid` (112), `unshare` (272),
  `setns` (308), `ptrace` (101), and `io_uring_setup` (425);
- requires `PR_SET_NO_NEW_PRIVS` and `PR_SET_SECCOMP`; failure exits
  the worker and the normal observer rejects, **without fallback**;
- uses `SECCOMP_RET_KILL_PROCESS`, rather than EPERM, so native C cannot
  suppress a failed fork, manufacture a normal `return 7` and be accepted.

The already-existing sealed memfd and source inode/byte replay, exact Core
ABI arity, worker CPU/virtual memory/output budgets, WNOWAIT PGID identity
and cleanup, strict stdout/stderr oracle and actual scalar/trap comparison
are unchanged.

**Important:** The seccomp filter intentionally allows many other system
calls. It is a narrowly scoped **no-process-creation** guard, not a secure
isolation boundary for arbitrary hostile DSOs. It cannot prevent direct file
writes, network access or foreign ABI/memory corruption. Namespace/cgroup,
filesystem/network isolation and native call sandboxing remain OPEN.

## Real executed local independent controls

On Linux x86-64 with Python 3.13 + Clang 17, a separately authored worker
used the exact new seccomp-BPF instruction sequence, sealed memfd and
`ctypes.CDLL`:

| Native C control | Actual observed child result |
| --- | --- |
| healthy `return 7` | exit 0, canonical `{"value":7}` |
| `abort()` | SIGABRT |
| `fork()` followed by child `setsid()` | SIGSYS |
| direct `syscall(435, ...)` (`clone3`) | SIGSYS |
| direct `setsid()` | SIGSYS |
| ELF constructor calls `fork()` during dlopen | SIGSYS |

**6/6 independent kernel/loader controls matched expected outcomes**.
These are not complete Hepta source/LLVM/VM executions, nor proof that the
committed in-repo test file passed on the exact combined SHA. Native execution
of `tests/test_hia_native_seccomp.py` and edited existing tests still needs
to be performed on an exact checkout.

## Exact repo acceptance

```bash
python -m unittest tests.test_hia_native_seccomp \
  tests.test_hia_native_postexit_group \
  tests.test_hia_native_child_limits \
  tests.test_hia_native_child_protocol \
  tests.test_hia_native_differential -v
```

The existing timeout test must use a nonforking sleeper: a worker attempting
fork must SIGSYS-kill **before** it reaches the sleep, so it is not a valid
timeout regression. The existing real-fork tests have accordingly been
updated to require SIGSYS; legitimate nonfork timeout remains tested.
This PR is stacked on #224, is kept Draft, and does not change main.

P0–P7 whole-language Ownership/Provenance and cross-backend refinement,
general C/C++ L2/L3 migration, cross-host ABI, true OS isolation,
physical DMA/GPU/NPU, real AI-model Agent A/B and sustained p99 remain OPEN.
`whole_project_blockers_closed=false`.
