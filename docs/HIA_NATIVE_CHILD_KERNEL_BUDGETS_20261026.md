# HIA native differential child: kernel-enforced bounded output/memory

## Confirmed finite native-execution gap

On the pinned PR #220 HIA v6 differential source
`hepta/hia_native_differential.py` (blob
`a5904898e943b5ee4de7d92791ba83c44f07b181`), `_observe_native`
captured stdout/stderr in unbounded `TemporaryFile()` objects and only
read 4,097 bytes **after the native child exited**. That read limit does
not restrict how much disk the arbitrary supplied native shared object can
consume before the timeout. Therefore the existing "bounded file-backed
stdout/stderr" description overstates enforcement.

## Actual implementation

The isolated Linux `python -I` worker establishes these resource limits
**before** loading the native shared object:

- `RLIMIT_CORE=(0,0)`: retain existing no-core behavior.
- `RLIMIT_FSIZE=(4096,4096)`: kernel limits *each output file* to
  4096 bytes, not merely the bytes the parent reads. If an attempted
  write fills the file, the parent treats the exact-full capture or
  `SIGXFSZ` as an output-budget violation. This covers Python's case
  where the native library fills stdout, the final JSON `print` receives
  EFBIG and the worker exits with an unrelated nonzero status.
- `RLIMIT_AS=512 MiB`: reject excessive process virtual-memory claims
  before the library can allocate hundreds of MiB or GiB. This is a
  bounded evaluator policy, NOT a language-level heap guarantee.
- `RLIMIT_CPU=10 seconds`: kernel CPU guard in addition to existing
  subprocess wall-time timeout (maximum 10 seconds).

Finite scalar JSON remains far below 4096 bytes. Genuine checked
`SIGABRT` remains distinguished from SIGXFSZ, SIGSEGV, timeout and
budget rejection. No existing Core, resource checker, compiler or
instrumented native ABI is replaced.

## Direct observation in a host Clang17 control

A standalone Python 3.13 child using precisely these RLIMIT values loaded a
real Clang17 C shared object. The four observed cases were:

| Control | Observed result |
| --- | --- |
| `healthy()` | exit 0, JSON scalar 7 |
| `flood()` | exit 120, stdout file exactly 4096 bytes, EFBIG during final Python print |
| `huge()` | 512 MiB native malloc refused, exit 0 with scalar 7 |
| `trap()` | true SIGABRT, exit -6 |

Those are isolated C transport checks, **not** full Hepta v6 repository/native
LLVM or source ABI qualification. The checked-in in-repo acceptance test
`tests/test_hia_native_child_limits.py` exercises the actual updated
module against a compiled C transport library, observes native stdout and
stderr file sizes after both processes terminate, tests 512 MiB malloc
refusal, and preserves genuine SIGABRT behavior. This exact checkout
test has not been executed in the limited container.

## Limits of the fix

`RLIMIT_FSIZE` is per file, not a full filesystem or process sandbox.
`RLIMIT_AS` is a virtual-memory ceiling, not native allocator ownership
tracking or maximum RSS proof. The worker may still use other system calls
and may not be isolated from process creation/network/filesystem access.
The HIA native object scanner and ABI restriction limit exported/imported
symbols, but do not make arbitrary DSO execution a hostile-code sandbox.
The Python evaluator's 16 MiB heap budget remains separate from the
native child address-space limit; a native OOM must be classified as
rejection, not as an equivalent Hepta checked trap.

Next P2 acceptance: exact-HEAD whole-project run, retained native artifact
identities, instrumented allocator/refusal/cleanup differential, and tested
persistent process isolation. Do not upgrade compiler refinement, global
resource bound, whole-language soundness or physical hardware claims.

`whole_project_blockers_closed=false`.

## Timeout cleanup for forked foreign libraries

A plain `subprocess.run(timeout=...)` only kills its **direct** child.
The native shared object accepted by the raw comparison helper is arbitrary
foreign code and could fork before its Python worker is timed out, leaving an
unbounded grandchild alive after the parent is reaped.

The current worker launches with `start_new_session=True`. On a real wall
timeout the parent sends SIGKILL to **that worker's process group before
reaping it**, preventing ordinary in-group forked children from continuing.
The rule does not claim to catch processes that deliberately detach into a
new process group/session, and a worker that exits before the timeout may
still leave descendants; this remains outside a hostile-process sandbox.

Real Linux Clang17 standalone control: a shared library forked a child
programmed to create a marker after 2 seconds while the parent slept 6
seconds; with the new 0.3-second group timeout, the Python parent exited
SIGKILL and no marker was created after 2.3 seconds. The in-repo test
`test_timeout_kills_worker_and_forked_child_process_group` uses a
fresh native C shared object and checks the same condition.

This local C control is not a full Hepta/Core/LLVM native qualification.

## Reconciliation with latest native artifact pinning

The evolving parent PR #220 at exact commit
`fa5484ab6ddc260cd77794910e883a16b7f168e5` already adds a
kernel `RLIMIT_FSIZE=4096` worker guard and sealed `memfd` artifact
loading with exact entry signature replay. This child PR **retains all
of those upstream changes**. Relative to that parent, its remaining
increment is `RLIMIT_AS`, `RLIMIT_CPU`, worker process-group timeout
cleanup, and the two new native-control suites (one source test file
containing file-size, address-space, SIGABRT and fork tests).

The subprocess launch preserves `pass_fds=(pinned_fd,)` and the
`/proc/self/fd/<number>` native library pathname; it does not revert
to loading an untrusted mutable path or bypass ABI arity checks.
The in-repository test uses `_pin_native_artifact` and closes its pinned
descriptor in a `finally` block.

This is still not a proof of arbitrary native sandbox isolation or
general Owner/Loan/Drop provenance soundness.
