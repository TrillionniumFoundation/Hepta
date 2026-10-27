# Native execution after HIA candidate convergence

These observations belong to code commit
`3d647f0`, the three-way convergence of PR #319, PR #318 and PR #115.
`MANIFEST.json` records the complete commit/tree identities and raw-file hashes.
They do not qualify later source changes automatically.

## Completed tests

| Selected suite | Actual result |
| --- | --- |
| C++ composed implementation migration, CLI, C ABI callers and direct LLVM | 28 tests passed, zero skips |
| C/C++ scalar and project migration, L1 HIA composition and migration edge cases | 88 tests passed, zero skips |
| Task/I/O native regressions with ordinary local OS permissions | 12 tests passed, zero skips |
| Local views plus task/I/O in the restricted executor | 17 tests ran, one class-setup error; not a passing suite |

All eleven local-view lowering/native tests completed in the fourth invocation.
The task/I/O native setup failed because the restricted executor returned
`EPERM` from an ordinary local Unix-stream write. The original report and stderr
are retained. The later invocation used the authorized unrestricted local test
environment; no language, runtime, test assertion or admission gate was changed
to obtain its pass.

The 28-test C++ suite actually exercises the three translated compositions,
allocation failure, cleanup order, direct LLVM execution and deliberately wrong
cleanup/return prototypes. It is evidence for the existing finite profile,
not all C++ programs. The tests clean their own temporary directories, so their
native binary bytes are not represented as retained in this evidence package.

## Persistent task/I/O qualification

There are three separate attempts in `task-io-raw.tar.xz`:

1. `integration-task-io-20261027`: restricted executor, one repetition, failed.
2. `integration-task-io-native-20261027`: ordinary native permissions, three
   repetitions using the portable runtime Python. Its CLI printed success and
   returned zero, but the durable report remained `running` and `ok=false` at
   the final native-alias compilation. This discrepancy remains visible and
   **this attempt is not accepted as qualification**.
3. `integration-task-io-system-20261027`: ordinary native permissions, three
   repetitions using `/usr/bin/python3`. All ten planned cases passed with 27
   native executions, including expected fault/timeout controls and the
   compile-time alias refusal. A same-process readback exactly matched the
   returned report; `validate_report(..., minimum_repeats=3)` passed on those
   persisted bytes. A separate process confirmed `ok=true`, `status=passed`.

The successful command used the existing qualifier without relaxing it:

```sh
source /workspace/scratch/d930f2b45e07/toolchains/env.sh
/usr/bin/python3 -m tools.qualify_task_io --repeats 3 \
  --output NEW_DIRECTORY/qualification.json
```

The actual third invocation additionally compared the returned and persisted
reports and validated the persisted result before printing its summary. The
archive retains generated source, actual native binaries, original reports and
every raw stdout/stderr stream from all three attempts. Archive members retain
their original repository-relative names; report paths preserve their original
absolute execution locations. Hashes check retained bytes, not a new execution.

The first two attempts have not been edited to resemble the successful third
attempt. Existing historical #115 reports retain their earlier source identity.

`whole_project_blockers_closed=false`. Complete release qualification, broader
semantic refinement, universal C/C++ migration, performance superiority,
physical-device execution and actual-model Agent benefit are not claimed.
