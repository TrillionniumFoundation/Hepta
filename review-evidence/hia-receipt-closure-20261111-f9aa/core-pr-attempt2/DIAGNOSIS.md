# Hepta PR #891: original second cold failure

## Outcome and immutable identity

This is a readback of the single diagnostic rerun already requested by the parent task. No additional qualification, rerun, source edit, budget increase, test removal or performance repair was performed for this diagnosis.

| Field | Original value |
| --- | --- |
| Run / attempt | 43015503275 / 2 |
| Native job | 130524053433 |
| Declared PR head | 7c20b6cfc792f0147b5418968f94734b8890fcca |
| Actual checkout in the raw log | 71520ff1114b0dd95b78ccc4563864713baccc67 |
| Actual checkout tree | d76c851edfb51fd649aca26a799ed4874af54489 |
| Frozen 7c20 tree | d76c851edfb51fd649aca26a799ed4874af54489 |
| Result | FAIL, cold 6/11 |
| Internal cold wall time | 180.146567810 seconds |
| Qualification / cleanup budgets | 180 / 3 seconds, unchanged |
| Process owner | QUALIFICATION_TIMEOUT, returncode -9, timed_out=true |
| Cleanup | 0.080203272 seconds, complete=true, ECHILD observed, no remaining direct children, no errors |
| Language | Skipped |
| Subsequent native groups | All 14 skipped; zero group tests executed in this attempt |

The source job displayed under attempt 2 retains its original 11:52:20–11:59:12 timestamps; it is a reused successful source result, not a new source-test execution. The cold step ran from 12:31:48 to 12:34:48 UTC. The run completed failure at 12:34:58 UTC.

The actual merge commit has parents 8dae9d0b74f8520d1522548e0a04c0c077b3f074 and 7c20b6cfc792f0147b5418968f94734b8890fcca. The merge tree and frozen head tree are identical. Actual checkout is taken from the original native-job log, not inferred from the workflow run's head_sha.

Sources: [attempt 2](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43015503275/attempts/2), [native job](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43015503275/job/130524053433), the retained original log/API bodies and the original ZIP in this directory.

## Retained original artifact and independent verification

Artifact 13854688251 is retained as artifact-13854688251.original.zip:

- Size: 47,624,762 bytes.
- SHA-256: 426d6a2439aba21ff4c391e9e50783554dee4c4e2f58cf447b3eaf194898fdfd.
- Outer ZIP members: 4,441; every member passed ZIP CRC verification.
- The GitHub artifact API and original upload log independently report the same ID, size and SHA-256.
- All 637 source-export members passed their declared SHA-256 checks. Their exact manifest equals the current 7c20 GitHub support contract plus the support-contract file itself.
- The support JSON's Git blob identity is 5368285d92a69138e68ad9a262b57cfdaad31a83.
- Canonical source-manifest SHA-256 is 11b53efd05532f7d4be4ea35d64bd2275f4a2bbd20908ee9b7f7b1d6f249c87a, also present in the separately inspected Runtime 7924 push/PR cold records.
- The 34 completed phase reports and 34 retained phase ZIPs were individually checked against their process-receipt hashes. Their reports contain 3,758 true checks and no false checks.
- No nonempty stderr.log member was found. No final nested qualification.json exists.

The original hia-cold.json hash is c7679008f85de811e94c6b9b7dda46efbf113e4a66cafd33031ebed4c96194f1. The independently fetched HTTP Range copy agreed byte-for-byte with the later fully verified ZIP member. Range observations were labelled partial until full ZIP validation completed; no Range read was described as a whole-archive hash check.

The cloud file is an independent verification copy of the same already-issued artifact. It does not represent a new qualification run. Earlier slow artifact-transport attempts on the desktop do not alter the CI result; they remain separate transport observations.

## Exact point reached before the deadline

The phase index contains 38 expected entries: 19 families, original and modified compiler variants. Thirty-four entries are completed PASS, with zero phase exceptions.

| Pending entry | Request present | Final phase report present | Process receipt present |
| --- | --- | --- | --- |
| names-original | Yes | No | No |
| names-modified | Yes | No | No |
| exports-original | No | No | No |
| exports-modified | No | No | No |

Names had started. Exports had not reached request creation. A pending entry is not a semantic refusal or a successful completion. The owner terminated the outstanding process tree when the original deadline elapsed; cleanup succeeded.

The five false outer cold checks are dependent on a timely admitted final nested report or clean nested exit. In particular, false isolated_python_without_site and no_ancestor_git_identity do not demonstrate that Python ran with site enabled or that an ancestor Git identity was used: the final report was absent. The retained B0 receipt independently records isolated=true and no_site=true.

## Comparison with Runtime 7924: checked entry differences

Only Runtime 7924a0c3545125f7a1c3c888adc63f6515668063 is used for the following workflow comparison. Later Runtime candidates and their outcomes remain separate records.

| Boundary | Hepta 7c20 Core workflow | Runtime 7924 joint workflow | What this establishes |
| --- | --- | --- | --- |
| Runner selector | ubuntu-latest | ubuntu-24.04 | Actual inspected logs all report Ubuntu 24.04.5, ubuntu-24.04 image 20261101.360.1 and runner 2.338.2. Runner identity/region differs; no hardware or resource cause is inferred. |
| Checkout | checkout@v4, default PR merge checkout | Pinned checkout v7.0.1, explicit Runtime head and frozen Hepta 7c20 in hia-source | Different checkout mechanics, identical relevant Hepta tree and exported source closure. |
| Python | setup-python@v5, 3.14 | setup-python@v5, 3.14 | Actual B0 executable and version hashes match in Core attempt 2 and both Runtime samples. |
| Native packages | binutils, gcc, clang-20, libclang-rt-20-dev, strace | Same packages plus openssh-server | Same LLVM repository and signing-key fingerprint. |
| Python packages | setuptools 78.1.1, wheel 0.46.3, z3-solver 4.15.4.0, jsonschema 4.26.0 | Same pins | No different qualification package pin was found. |
| Outer environment | No workflow-wide CARGO or bytecode selector | CARGO_INCREMENTAL=0, debug flags=0, PYTHONDONTWRITEBYTECODE=1 | These are not inherited by the actual cold qualification environment. |
| Work before cold | Native dependency installation | Dependencies, source controls, Rust 1.95 toolchain and Runtime build | Ordering differs. No cache, contention or CPU explanation is established by this fact. |
| Cold command | python -B tools/replay_hia_selfhost_cold.py --output .../hia-cold.json | Same script and flag, output .../hia-common-cold.json, stderr/stdout piped through tee under pipefail | Different path spelling/log retention, no different qualification option or budget. |
| Failure continuation | Default step success dependency skips later language/native groups after cold failure | Explicit conditions preserve independent language/provider observations even after cold failure | Affects which later evidence exists, not the cold deadline itself. |

The actual seed Python is 3.14.10, executable SHA-256 ee456eb76dd1a7a1b86a41a8002901f24a7b7ae9ca89ea8ceae77dc5a9f94cba. The actual seed linker is GNU ld 2.42 at /usr/bin/x86_64-linux-gnu-ld.bfd, SHA-256 e9ceb054c12207970f2726dfc07e9a66b411602748628baf27399f02a9bbb31b. These identities are identical across the inspected Core attempt 2 and Runtime 7924 push/PR B0 receipts.

The cold script always exports the pinned source into a new directory and invokes the same Python executable with -I -S -B. Its explicit child environment contains only PATH=/usr/bin:/bin, HOME, TMPDIR, LANG=C.UTF-8, LC_ALL=C.UTF-8 and TZ=UTC. The owner uses the same fixed 180-second deadline and 3-second cleanup allowance. The qualifier uses QUALIFICATION_WORKERS=2 and the same ordered 19-family inventory. B0 and each original/modified generation chain remain sequential; independent reference and qualification families receive fresh processes.

No GITHUB event, PR, merge, run-attempt or environment switch selecting a different qualification route exists in the inspected cold replay, process owner or qualifier. checkout_identity is supplementary metadata and rejects attribution to an ancestor checkout; it does not select compilation behavior. The cold source export excludes .git.

## Measured duration differences and limits

The separate Runtime 7924 push and PR cold runs passed in 121.620193704 and 170.448923344 seconds respectively. Their reference intervals were 20.643561877 and 31.108233219 seconds; seed-to-first-phase intervals were 7.910528085 and 11.561344606 seconds; phase-process spans were 91.288987903 and 125.187395976 seconds. These are existing raw observations, not new benchmarks.

Core attempt 2 first entered its qualification phases 50.930475214 seconds after the owner's observed qualification start. Its completed phase durations are longer across multiple families. PHASE-COMPARISON.md and phase-comparison.json preserve the individual observations. The recorded difference is distributed across work; the available data does not isolate CPU scheduling, I/O, host contention, caching, or an algorithmic defect.

No source fix is recommended from this evidence alone. In particular, changing checkout spelling cannot be presented as a compiler-performance repair when the inspected tree/export and execution selectors already agree.

## Smallest next diagnostic, not executed here

If further investigation is authorized, use one controlled job with the frozen head and its identical-tree PR merge, separate fresh output/source exports, the same Python/linker identities, and one sequential original-budget observation for each. Keep 180+3, two workers, all families and all raw failures. Record the planned order and actual CPU/resource accounting alongside wall durations (for example process/cgroup CPU and I/O counters and runner CPU metadata). This can test whether an observable entry difference remains without adding a language feature, widening a budget or discarding failed samples.

A future optimization should be justified by preserved independent-reference inputs/results and original/modified native observations. Fewer tests, cached native successes, deadline increases and relabelled failures are not a remedy.

## Relationship to other outcomes

PR attempt 1 remains a separately retained original 180-second failure. The exact-source Core push attempt 1 success remains a separately retained success. Neither supersedes the other. This second failure does not revoke an independently verified supplied-byte proof obligation, but it prevents claiming that this PR's complete cold/language/native path passed. No all-input compiler, termination, allocator or whole-stack correctness claim is made.

## Fixed-source references

- [.github/workflows/hia-core.yml](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/.github/workflows/hia-core.yml)
- [tools/replay_hia_selfhost_cold.py](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/tools/replay_hia_selfhost_cold.py)
- [tools/hia_selfhost_process_owner.py](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/tools/hia_selfhost_process_owner.py)
- [tools/qualify_hia_selfhost.py](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/tools/qualify_hia_selfhost.py)
- [tools/hia_selfhost_references.py](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/tools/hia_selfhost_references.py)
- [tools/hia_selfhost_contract.py](https://github.com/TrillionniumFoundation/Hepta/blob/7c20b6cfc792f0147b5418968f94734b8890fcca/tools/hia_selfhost_contract.py)
- [Runtime 7924 common workflow](https://github.com/TrillionniumFoundation/hepta-runtime/blob/7924a0c3545125f7a1c3c888adc63f6515668063/.github/workflows/hia-common-native-integration.yml)
- [Runtime push job](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43016837973/job/130509912041)
- [Runtime PR job](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43016939924/job/130510252525)
