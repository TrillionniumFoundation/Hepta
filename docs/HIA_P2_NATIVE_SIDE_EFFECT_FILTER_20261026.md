# HIA P2 finite native evaluator: pre-dlopen side-effect syscall refusals

**Scope:** Linux x86-64 finite native oracle only. Extends the existing
`hepta.hia_native_differential._WORKER` seccomp-BPF policy; reuses the
sealed memfd, typed ABI corpus, source-bound replay, process-group cleanup
and existing native observation logic. No duplicate verifier/IR/backend.

## Exact engineering change

The earlier policy killed fork/clone/exec/setsid/ptrace but admitted socket,
direct file creation/rename/deletion, and signal syscalls such as `kill`.
A native library could return the expected integer **after** a network or
filesystem side effect. This is unacceptable for a finite no-I/O test
oracle even when return values agree.

The Linux x86-64 seccomp filter now:
- kills attempted socket/connect/send/receive/bind/listen and related
  network syscalls with SIGSYS **before** loading the native DSO;
- kills direct filesystem object creation/removal/rename/link and selected
  metadata modifications;
- kills `openat2` rather than attempting to inspect its user-pointer flags;
- checks low 32-bit open()/openat() flags in kernel BPF; only read-only
  opens without O_CREAT/O_TRUNC/O_APPEND or the __O_TMPFILE-exclusive
  bit can pass. Masking the complete O_TMPFILE macro would also reject
  legitimate read-only O_DIRECTORY opens, so that bit is deliberately
  excluded from the mask;
- kills `kill`, `tkill`, queued signals and `pidfd_send_signal`, and
  refuses pidfd_getfd and process_vm_writev. The `tgkill` syscall is
  restricted by BPF to exactly the initial worker PID + native TID and
  signal SIGABRT=6, preserving normal libc abort without permitting
  the syscall to signal other processes or use a different signal;
- redirects inherited stdin to /dev/null so the worker receives no
  uncontrolled parent input FD, preserving sealed memfd and bounded capture.

BPF uses exact x86-64 seccomp_data layout: syscall nr offset 0, arch 4,
`open` flags argument #1 offset 24, `openat` flags argument #2 offset
32. Each accepted open reloads the syscall number before remaining
checks; mismatch skips exactly to the reload. The `tgkill` branch also
reloads the syscall number and compares its three syscall arguments against
PID/TID observed before installing the filter. Bad architecture, x32 and
forbidden syscalls must SIGSYS-kill; EPERM-and-continue is not acceptable
because foreign code might suppress the refusal and return the expected
value.

## Real local kernel execution (independent control)

An isolated Python 3.13 / Clang 17 reproducer installed the **same BPF rule
sequence** before `ctypes.CDLL` and executed actual x86-64 ELF shared
objects. It observed 14/14 controls:

- valid integer return, read-only file open and read-only O_DIRECTORY open:
  exit 0 with value 7;
- ordinary libc abort: SIGABRT (not SIGSYS);
- O_CREAT|O_WRONLY open and openat, O_TMPFILE openat, unlink, socket,
  direct kill, foreign tgkill, self-tgkill with non-SIGABRT, and openat2: SIGSYS;
- marker file remained unchanged and forbidden new file did not appear.

The executable in-repository `tests/test_hia_native_side_effects.py`
uses the real `_pin_native_artifact` / `_observe_native` path and adds
positive/negative ELF-constructor and side-effect controls. **It has not
run on a complete checkout at this exact combined SHA**. The independent
kernel control is not equivalent to a repo-native end-to-end result.

## Limitations (not a general security sandbox)

The worker still has broad read-only filesystem visibility and some
potentially side-effectful system calls (including ioctl, allowed writes
to inherited bounded capture descriptors). Read-only open is not isolation
from confidential host files. The fixed seccomp denylist cannot prove
arbitrary native library code has no external side effects or defend
against all dangerous syscalls, target ABI errors, malicious linkers, or
host-level attacks. Real hostile-code isolation requires a separately
qualified minimal mount/user/network namespace sandbox or equivalent
kernel-enforced environment.

No new whole-language soundness, native/backend refinement, C++ migration,
multi-arch ABI, hardware DMA, AI Agent economics or release completion
claim is made.

```bash
python -m unittest tests.test_hia_native_side_effects tests.test_hia_native_seccomp \
    tests.test_hia_native_differential tests.test_hia_native_postexit_group -v
```

whole_project_blockers_closed=false
