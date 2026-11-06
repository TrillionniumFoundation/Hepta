# HIA Linux / NDU follow-through evidence — 2026-11-06

The tested source is `96d01c50ef1920e5b39c52f62b43ef8746d2c621`, tree `c19d9f42caa7e78c192adf442252c9d220515046`. Documentation/evidence publication is a later descendant; none of these receipts is relabelled as execution of that later publication commit.

Read the [full Chinese report](../../reports/hia-linux-ndu-followthrough-20261106/report.md).

## Outcomes

- Final exact-source regressions: Linux 83/83, NDU 97/97, policy/coverage extension 40/40; zero errors, failures or skips.
- Frozen native pilot: 96/96 cells; 24 per arm; 830,472,192 timed calls.
- Preserving HIA bridge / upstream software assembly paired wall ratio median: 1.4381300892515525; all 24 blocks slower.
- Raw C ABI diagnostic ratio: 0.8885109268446373; not an eligible Linux ABI replacement.
- Wrong HIA body: expected exit 1, 270334 mismatches, no timing.
- Pure-u32 Core SMT: unsat; backend/source refinement explicitly NOT proved.
- No kernel build/boot, whole-kernel rewrite, new native NDU campaign, global comparison or production activation is claimed.

## Attempt history

| Source | Artifact directory | Outcome |
|---|---|---|
| `02e421c562ab48a96fb45ff19ff2891186d259c1` | results/qualification-r1 | 83 Linux and 96 NDU tests passed |
| same rejected composition | results/pilot-launch-r1 | 40 extensions executed, 9 errors at the frozen-model byte gate; timing not started |
| `96d01c50ef1920e5b39c52f62b43ef8746d2c621` | results/qualification-r2 | 83 + 97 passed |
| same repaired source | results/pilot-launch-r2 | 40 extensions passed, native pilot completed |
| same repaired source | results/native-pilot-r2 | All 96 cells passed |

The original model blob was restored; new compute-aware recursion is isolated in compute_plan.py. Historical protocol hashes and original result identities were not changed.

## Files

- [Full raw pilot result](results/native-pilot-r2/RESULT.json)
- [Descriptive summary](export-r2/DESCRIPTIVE_SUMMARY.json)
- [Archive metadata](export-r2/ARCHIVE.json)
- [Raw evidence archive](export-r2/raw-evidence.tar.gz)
- [Runtime terminal statuses](runtime-statuses.json)
- [Exact launcher sources](launchers)

The archive contains 491 files, including raw stdout/stderr, command receipts, actual objects/executables, source inputs, SMT and SEAL.json. Sealing rechecked 248 path/hash bindings. It preserves original absolute paths in receipts; those identify the observed execution, not a portable replay destination. Launcher source copies outside the archive retain the exact tool-submitted Python.

Archive SHA256: `f8830e1beecbe10220217b8a3681d7185ca055a8e207d437f2b2749a0914b1d5`.
Archive Git blob: `70fdc4432d464b12a4c4f92f7cd40d034c4c8739`.

Do not sum nested timing intervals or combine historical NDU audit times with this different-workload leaf pilot. The host was shared and frequency was not locked; timing results are descriptive for this one frozen run.
