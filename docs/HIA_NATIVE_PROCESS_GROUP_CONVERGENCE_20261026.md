# HIA P2/P7: converge sealed native transport with process-group lifecycle

Status: **review candidate**, not full P2/P7 qualification.

## Exact source integration

Primary, stronger base: PR #221 at
`4e22d632f63caaf91a5ef09918f627dbb3c79a4c`
(tree `10459ece5d8fa107893e3f34f75a98702192e14f`).
Timeout-termination donor: PR #222
`7d60e2d560e128d3a2ee224ced1d998d2754e3a9`.
Both descend through merge commit `d09fe7c8ed0b2e765cf96febddc15ab0169e101a`.
No existing HIA parser/verifier/LLVM emitter, Resource IR, C/C++
migrator or Rust shadow implementation is replaced.

The primary PR #221 already contains:
- no-follow exact regular artifact verification and sealed memfd
  execution through `/proc/self/fd`;
- ABI arity derived from the verified Core, and typed i32/u32 oracle
  return qualification (reject bool == int, float == int and out-of-range);
- kernel child budgets `RLIMIT_CORE=0`, `RLIMIT_FSIZE=4096`,
  `RLIMIT_AS=512MiB`, `RLIMIT_CPU=10s`;
- exact source/Core budget replay and ABI negative tests inherited from
  PR #220. These gates remain intact.

The final process-observation repair replaces direct
`subprocess.run(timeout=...)` with one `Popen` per native case and
`start_new_session=True` while retaining `pass_fds=(pinned_fd,)`.
The native observer **always** sends SIGKILL to the per-case process
group on exit, including after a normal return or SIGABRT, then reaps
the direct child. A timeout is a distinct rejected observation.
Killing the group even after a normal return matters because a native
constructor or callee may fork a descendant and return immediately.
The verifier does not trust the child as a safe or syscall-limited binary.

Unexpected failure to signal the process group rejects instead of
reporting a successful differential. An already-absent group is
permitted as ProcessLookupError. The parent still refuses
4096-byte stdout/stderr captures and does not confuse SIGXFSZ with
an arithmetic trap. No path-based dynamic-load fallback is added.

## Independent local executable controls

A Linux Python 3.13 + Clang 17 standalone C shared library smoke,
using a sealed memfd, the same RLIMITs, file-backed captures and the
new process-group wait/kill sequence, exercised seven checks:

1. ordinary value-return success;
2. virtual-memory-limited 512MiB malloc refusal;
3. genuine SIGABRT distinct from value;
4. stdout write refused at the output limit;
5. timeout of a forked long-running worker;
6. timed-out worker's forked descendant does not write a delayed marker;
7. a *successfully returned* worker's forked descendant also does not
   write the delayed marker.

This proves those Linux transport controls were exercised, **not**
that the exact integrated Hepta Python source, pinned Rust, Clang20
and native Core differential suites have all passed. The repository
regression compiles real Clang C controls and checks both timeout
and normal-return fork lifecycle through the existing module.

## Explicit trust and acceptance limitations

A new session/process group is not a hardened sandbox. A native child
may deliberately create a different session/group, manipulate host
resources not covered by the listed limits, or exploit a hostile
foreign library. Process-group IDs alone are not stable security
capabilities against adversarial PID reuse or group escapes. A
production hostile-code evaluator needs independently qualified
namespace/cgroup/seccomp or equivalent kernel isolation and resource
ledger. This test does **not** prove all descendants are terminated
or arbitrary OS resource usage bounded.

Run on the full exact commit and pinned toolchain before claiming an
actual source-native pass:

```sh
python -m unittest tests.test_hia_native_child_limits \
    tests.test_hia_native_pinning tests.test_hia_native_differential \
    tests.test_hia_v6_differential -v
python -m unittest tests.test_hia_budget_numeric_replay \
    tests.test_hia_program tests.test_hia_program_llvm -v
python tools/release_check.py
```

This change closes a narrow, concrete direct-worker-only timeout
lifecycle defect. P0–P7 whole-project blockers remain open/partial.


## Native child record ambiguity (follow-up)

Even when the worker exits 0, permissive `json.loads(stdout)` accepts
duplicate object fields and trailing whitespace. A malicious or defective
native constructor may also emit unrelated stderr before returning. The
scalar evaluator's source profile has no user I/O effect; neither may be
silently counted as a correct return observation. Similarly, a native
`SIGABRT` with diagnostic stdout/stderr is *not* accepted as the Core VM's
expected checked arithmetic trap (although a silent unrelated SIGABRT
remains indistinguishable from a defined trap without deeper provenance).

The native observation now requires precisely one compact
`{"value":<typed signed-or-unsigned integer>}\n` record with strict
integer/range checking and **empty stderr** for successful returns. Any
stdout/stderr on SIGABRT rejects. Output size limits are still enforced
before parsing. This is canonical transport validation only; a foreign DSO
can still forge exactly the same record or escape a process group.
A true untrusted-DSO sandbox and native root-cause proof remain open.

Additional standalone local Clang17 controls validated 2 successful
normal/silent-abort observations and 5 refusals: stderr followed by
return, stderr followed by abort, JSON with duplicate value keys,
space-modified JSON and trailing-newline JSON. These controls replicate
the transport code but are **not** full in-repository Hepta-native tests.
Run `python -m unittest tests.test_hia_native_child_protocol -v` on
the exact source checkout as an additional acceptance input.

## PID/PGID identity race hardening

The initial group-cleanup code used `Popen.wait()` and only then
`killpg(proc.pid)`. Once `waitpid` has reaped the worker, the numeric PID
may be recycled, potentially making a later group signal ambiguous. The
current Linux-only observer uses

`waitid(P_PID, pid, WEXITED | WNOWAIT | WNOHANG)`

with a monotonic deadline and bounded sleep to observe the worker's
termination **without consuming its PID**. It sends `SIGKILL` to the
per-case session/group before the definitive `Popen.wait()` reap, on
success, trap, timeout and exceptional control flow. The call can fail
closed on unavailable operating-system support; it does not claim
permission to kill unrelated groups. This avoids the specific
wait-then-kill PID recycle race when no external code reaps the child.

The Clang17 independent C controls were reexecuted with this exact
waitid polling/kill-before-reap sequence: 7/7 process/resource and
7/7 output-protocol cases succeeded as classified. A new in-repo test
intercepts `killpg` on a live Linux child process and independently
checks that `waitid(WNOWAIT)` can still see the unreaped worker at the
moment the process-group signal is sent.

Still open: setsid/daemon escapes, hostile native syscalls, untrusted
process isolation, full HIA-source/LLVM semantics, kernel/cgroup
qualification and physical-device execution. Do not call this a
hostile-code sandbox or universal process-lifecycle proof.

`whole_project_blockers_closed=false`
