# Original NDU four-gate records

This evidence-only directory preserves the completed, source-bound four-gate
experiments and their negative findings. It adds no controller implementation,
changes no experimental result, and repeats no timing cohort. Research authority
remains **DENY_ALL**. No production activation or merge qualification is granted.

## Source and evidence identity

The evidence branch has exactly one parent:

- Source commit: `78c0b951adc08b02be60d64b386620c5ac9faf99`.
- Source tree: `a96e501429fa0482330c7d5d477f8549a132bd52`.
- Earlier v1 implementation: `b1746d3e436f001ea5c69d154d766fadf7231136`.
- Source PR: [Hepta #758](https://github.com/TrillionniumFoundation/Hepta/pull/758).

Each original receipt retains the revision that actually produced it. The
evidence commit does not relabel older runs as executions of the later source.
`FILE_MANIFEST.json` records the byte count, SHA-256 and Git blob identity of
every other file added in this directory.

## Findings and limits

The original study completed 288 cells and 864 planned requests. Its 216 recorded
preference counterfactuals did not change numeric preferences or actions; its
wrong-posterior/reset-prior episode diagnostics also tied. Those observations
remain negative coverage findings.

The later registered finite inventory checked **5,736 distinct states** with
**167,976 original-native calls**, zero failed and zero not-run states. Dynamic
native NDU, ordinary same-objective control and the independent exact oracle
agreed. The complete supplied-boundary mesh contains **24 strict preference
action reversals**, while the **2,716 natural-support states contain zero**.
These scopes answer different questions; supplied-state reversals are not a
natural-distribution benefit estimate. The **43/43 physical witnesses** consumed
the selected current actions, with zero abstentions. They do not establish a
physical end-to-end gain or a unique advantage over ordinary control.

The original scientific discussion and all caveats are preserved byte-for-byte
in [the report](original/ndu-scientific-findings-final.md) and
[its machine-readable evidence](original/ndu-scientific-findings-final.json).
Three independently authored internal audits and their scripts are in
`original/`. They are internal checks, not independent external scientific
review. Historical `sandbox:` links and absolute paths remain unchanged inside
those original files; use the restoration layout below to locate their bytes.

## Lossless archives

| Original archive | Bytes | Members | Parts | SHA-256 |
| --- | ---: | ---: | ---: | --- |
| `cohorts.tar.xz` | 71,297,032 | 1,408 | 136 | `d9b5d311884ea9ca34d4702868a1c33d02a3d7393e4cb85e2c18c075b1affe80` |
| `verification.tar.xz` | 14,293,604 | 197 | 28 | `8ba82f04db9f126c4d673065f3cbde441a06b0f4a4ec39a00ca33eb8efd7b095` |

The 136 existing cohort parts are reused without changing their bytes or their
original parts manifest. Verification is split into at most 524,288-byte parts;
concatenation reproduces its original archive exactly. The split size is an
upload/storage choice, not a weakened scientific threshold or a claim about a
repository-wide blob policy. Original member manifests are unchanged.

The archives retain registrations, all final observations, failed/intermediate
build evidence, calibration and development records, original protocol frames,
and validation receipts. `ARCHIVE_AUDIT.json` records a complete member-hash
check. Its four paths containing `private` are only build receipts and command
metadata: source file hashes, compiler flags, command arguments, and stdout/
stderr paths, sizes and hashes. They contain no upstream source bodies or
executables. Credential-pattern checks found no matches; no private upstream
source or executable files are published here.

## Restore and verify

With Python 3.11 or newer, run from this directory:

```sh
python RESTORE.py --output /tmp/ndu-four-gates-restored
```

The output directory must not already exist. The script checks every part's
length, SHA-256 and Git blob SHA, reconstructs each original archive, verifies
the complete archive hashes, rejects nonregular/unsafe/duplicate paths, and
checks every member before writing it. It does not execute any experiment.

Restoration produces:

- `archives/cohorts.tar.xz` and `archives/verification.tar.xz`: original bytes.
- `cohorts/`: original final/development cohort directory names and files.
- `verification/`: original validation, build and native-CI smoke records.

For example, a historical path ending in
`state-coverage-final-v1/RESULT.json` resolves beneath `cohorts/`, and a path
ending in `native-ci-run-1/private/value-build/build-receipt.json` resolves
beneath `verification/`. Some original scripts expect the historical directory
layout and source checkout; restoring evidence is not a claim that those scripts
are relocatable or that native executables are included.

## CI evidence is a scoped observation

The exact-source native feedback job
[127828162757](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42198653917/job/127828162757)
passed. It executed 149 reference cases and 16 native cases, with seven shared
IDs: **158 unique tests, zero failures/errors/skips**. The original job log,
artifact audit and earlier CI snapshots are in `ci/`. The audit references the
hosted artifact ZIP and its hash; that hosted ZIP is not embedded in these two
original archives. The verification archive contains the separately retained
local native-CI records.

The newer [CI snapshot](ci/pr758-ci-audit.json) preserves the original macOS
job cancellation, the queued retry, and the second macOS job's cancellation.
Seven success objects displayed under attempt 2 reuse attempt-1 execution
timestamps, runner IDs and step receipts; they are not seven new executions.
The full HEAD checks were not all green at that observation. Native test and
smoke success does not close scientific net-benefit, full-repository CI, or
production gates. Later CI results must be recorded separately.
