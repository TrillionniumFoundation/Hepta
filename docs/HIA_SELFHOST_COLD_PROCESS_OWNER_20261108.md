# Cold replay process ownership and bounded cleanup

The cold replay retains its 180-second qualification deadline. A separate,
disposable Linux supervisor now owns the qualification process and ordinary
descendants, including children that create a new session. A successful cold
replay additionally requires confirmed cleanup. The additional three-second
budget is for cleanup only; it cannot turn a late qualification into a pass.

This repair addresses process lifetime on the timeout path. It does not, by
itself, establish that the full qualification fits within 180 seconds. Scheduling
changes and a fresh complete cold qualification are separately evaluated.

## Observed CI failure and the old cleanup boundary

The exact-source CI for source `14b2c03c` timed out after 180 seconds. Its retained
cold result has `wall_elapsed_ns = 180127351883`, a null return code, no nested
qualification report, and five successful checks out of ten. The source export,
origin hashes and cache isolation checks succeeded. The process and nested
qualification checks did not. The original stdout and stderr files are empty.
This is evidence of the outer deadline, not a failed individual native case.

The selected original files are retained without changing their contents:

| Original member | Bytes | SHA-256 |
| --- | ---: | --- |
| `cold-selfhost` | 26703 | `7747c0feeec3061a64fb9d011b5bf5bdce950b0db1521fcda5f66152de55e24d` |
| `cold-selfhost.log` | 180 | `61d80b9a2e7b56fccb8bfc54f263d298b9f50f0eb8827de7ca0cd5d1881d4213` |
| `cold-selfhost.cold/request.json` | 26162 | `28e20311381e770231e8e25be66e8d9900d0409d9a145bc5c3ba944170c15b3b` |
| `cold-selfhost.cold/stdout.log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `cold-selfhost.cold/stderr.log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

The old `subprocess.run(..., timeout=180)` killed and waited for its direct
qualification child. It did not establish that all descendants had exited.
Adding only a process-group kill would also be insufficient for the existing
normal execution path: `hia_program_native._run_logged` calls
`clang_capture.run_bounded`, whose linker child uses `start_new_session=True`.
That child can be outside the qualification process group. This repair does not
alter the linker, its session behavior, or its input and output validation.

## Dedicated owner and evidence contract

`tools/hia_selfhost_process_owner.py` is a standard-library-only helper. Its
`run_owned` entry point launches a new `python -I -S -B` supervisor. Only that
disposable supervisor sets `PR_SET_CHILD_SUBREAPER`; the caller's process
attributes are unchanged. The supervisor checks the attribute readback, requires
the default `SIGCHLD` disposition and a single thread, and installs a parent-death
notification before launching qualification. All command arguments are passed as
an explicit vector, and qualification receives its existing explicit environment.

The 180-second clock begins before writing the owner's request or starting its
interpreter. A leader exit is admissible only when observed before that absolute
deadline. Qualification stdout and stderr are written directly to files. They
are not held in a pipe that could remain open in a surviving descendant.

After normal exit, failure, interruption or timeout, the supervisor repeatedly:

1. Identifies its actual direct children by a bounded `/proc` PPID scan. Each
   recorded identity includes PID, parent PID, process group, session and Linux
   start ticks. The supervisor does not infer ownership from a reused group ID.
2. Uses `waitid(..., WNOWAIT)` to observe terminal state without relinquishing the
   child's unreaped identity. Live direct children are sent `SIGKILL`.
3. Reaps terminal children with an exact `waitpid`, preserving the leader's real
   return code. Children orphaned by these exits are adopted by the subreaper,
   including descendants in other sessions, and are processed in another pass.
4. Requires the kernel's `ECHILD` result and an empty direct-child scan before
   reporting cleanup complete. An empty metadata scan alone is insufficient.

The three-second cleanup budget starts when cleanup begins. Deadline overrun,
metadata errors, an unconfirmed child or an event ledger overflow prevents
successful admission. The implementation never substitutes a process-group
observation for the final kernel wait result. Its ledger describes the direct and
adopted children actually observed; `historical_descendant_inventory_complete`
is explicitly `false`. Descendants already reaped by their own parent are not a
complete historical inventory.

The parent also bounds its wait for the owner. If the owner does not confirm
termination, the parent requests interruption and returns an explicit
`OWNER_UNCONFIRMED_HOLD` if confirmation is still unavailable. It does not kill
the subreaper first and then claim that its descendants were cleaned up. This
failure state can leave an unconfirmed process and requires separate diagnosis;
it is never a successful cleanup receipt. Likewise, a supervisor cleanup error
or exhausted cleanup budget may leave processes unconfirmed and yields HOLD.

## Cold replay admission

`tools/replay_hia_selfhost_cold.py` retains the original ten checks and adds
`owned_process_tree_cleanup_confirmed`, for eleven checks in total. The existing
process-exit check additionally requires:

- owner status `OWNED_PROCESS_COMPLETED`;
- the leader's exit observed before the qualification deadline;
- no timeout and actual return code zero;
- cleanup positively confirmed.

The nested report is not read or accepted when these conditions fail. A late
report, or a report potentially still being written by an unconfirmed
descendant, cannot satisfy the cold qualification. Source and cache checks remain
unchanged. The result records both budgets, the owner receipt, its request and
implementation identities, and the actual cleanup events.

The helper supports Linux with the required `waitid`, `WNOWAIT`, `prctl` and
readable process metadata interfaces. Other platforms are explicitly refused
before qualification launch; there is no weaker fallback. This is ordinary
same-PID-namespace process lifetime control, not a security sandbox or a proof
against privileged processes, PID-namespace changes, external termination of the
supervisor, or interference by unrelated actors. Kernel scheduling and blocking
operations can delay observation; such delay must not be admitted as an on-time
qualification or confirmed cleanup.

## Retained harmless controls

`tests/test_hia_selfhost_process_owner.py` has seven controls. The final recorded
run passed all seven with zero skips, failures or errors in 1,984,794,007 ns. It
used fresh source copies and isolated Python interpreters. No HIA machine
artifact, native compiler, ELF metadata change or remote process was exercised.

| Control | Observed outcome |
| --- | --- |
| Default budgets | Qualification remains 180 seconds; cleanup remains separately 3 seconds. |
| Normal streams and caller attributes | Exact binary stdout/stderr retained; caller subreaper value unchanged; leader reaped and `ECHILD` observed. |
| Timeout with a child and grandchild in separate sessions | The actual three recorded process identities were observed, killed/reaped, and final `ECHILD` confirmed; result remains `QUALIFICATION_TIMEOUT`. |
| Leader exits zero while the same family remains | Remaining descendants cleaned before success; real leader status zero retained. |
| Leader exits seven while the same family remains | Remaining descendants cleaned; result remains `QUALIFICATION_FAILED` with status seven. |
| Deliberately exhausted one-nanosecond cleanup budget | `CLEANUP_HOLD`, never completed. Its only child was already terminal; no executing fake descendant was deliberately left behind. |
| Unsupported platform and invalid budgets | Rejected before launching a process. |

An earlier retained attempt assumed `/proc/self/task/<tid>/children` was present.
This executor does not provide that file, so that attempt refused before any
qualification child was launched. Its source, errors and failed controls remain
in `attempt-01`. The final implementation instead uses the bounded PPID scan and
still requires kernel `ECHILD`; final raw requests, streams, receipts and exact
source copies are in `attempt-02`. The first attempt is not reported as a native
failure or silently replaced by the successful one.

Final tested source identities:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `tools/hia_selfhost_process_owner.py` | 16872 | `4fb68c370c90a6cb82f1c24f6aa57881ceafe698d6b6571fffaeb57bfc215ecf` |
| `tools/replay_hia_selfhost_cold.py` | 7322 | `732e93ce69fc997e9d9cb11aed89d015045f0a2f06c1962ea1134cc9359da38b` |
| `tests/test_hia_selfhost_process_owner.py` | 7587 | `888a3b0652aed4c8b724d99792bf02b4765a5340fb8b585cc557a1f86a571fab` |

An independent static review of those helper and replay bytes found no specific
counterexample to the direct/adopted-child cleanup or status propagation. That
review did not run native qualification. These seven controls are finite
process-lifetime evidence; final source integration, all native checks and a
fresh cold replay remain distinct acceptance steps.
