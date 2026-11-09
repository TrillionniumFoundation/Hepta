# Hosted macOS arm64 capacity failures: exact-head evidence

The four original workflow runs below remain **failure**. In each run the only
unsuccessful job is the macOS arm64 row, marked **cancelled** before a hosted
runner was assigned. GitHub's own annotation on **each** job reports:

> The job was not acquired by Runner of type hosted even after multiple attempts

Each job also has three provider notices explicitly warning of macOS arm64
capacity constraints and longer queue times. This identifies the same reported
runner-acquisition failure class across all four runs. It is not an inference
from two branches merely having red checks. These observations do not establish
the provider's internal capacity mechanism or a separately authenticated global
outage.

This is an evidence-only publication with parent
`e632886e3ae63365b509aa29529d0968a228346d`. No source PR head, workflow,
qualification rule, release selection or native program is changed. No workflow
was retried and no native test or experiment was re-executed for this diagnosis.

## Four original failures

| PR / exact head | Workflow run | Cancelled macOS job | Other jobs | Runner / steps / log |
| --- | --- | --- | --- | --- |
| #833 / `e632886e` | [ABI 42629374887](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42629374887) | [129201388240](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42629374887/job/129201388240) | 7 success | runner 0; no steps; log 404 |
| #833 / `e632886e` | [C++ 42629374434](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42629374434) | [129201386032](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42629374434/job/129201386032) | 6 success | runner 0; no steps; log 404 |
| #831 / `45205981` | [ABI 42632077953](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42632077953) | [129210630050](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42632077953/job/129210630050) | 7 success | runner 0; no steps; log 404 |
| #831 / `45205981` | [C++ 42632078153](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42632078153) | [129210630315](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42632078153/job/129210630315) | 6 success | runner 0; no steps; log 404 |

Full #833 head: `e632886e3ae63365b509aa29529d0968a228346d`.
Full #831 head: `45205981457ed5642e5876ee6fb2b91e5fda78ed`.
Every run is attempt 1, and its original run metadata binds that head.
The retained raw job lists contain all 30 jobs: 26 successful non-macOS jobs and
four cancelled macOS jobs. They contain no failed compilation or test step.

The four cancelled jobs have `runner_id=0`, an empty runner name, and an empty
step list. Their creation/cancellation timestamps are preserved; they are not
measurements of program execution. No checkout, initial failure-placeholder
writer, compiler invocation or artifact-upload step ran in these rows.

## Original annotations and unavailable logs

[annotations/FETCH.json](annotations/FETCH.json) is the root collector's original
read-only HTTP retrieval record. It records HTTP 200 responses for all four
annotation endpoints between 2026-11-09 15:09:32 and 15:09:39 UTC, with exact byte
counts and SHA-256 hashes. The original response bytes are retained separately:

- [129201388240.annotations.json](annotations/129201388240.annotations.json)
- [129201386032.annotations.json](annotations/129201386032.annotations.json)
- [129210630050.annotations.json](annotations/129210630050.annotations.json)
- [129210630315.annotations.json](annotations/129210630315.annotations.json)

Each response is 1,454 bytes. The two #833 responses share SHA-256
`0bc6ba71b688630f9be47f82964cf943e946b6ac3905c55e3a0c0698ae7606fb`;
the two #831 responses share
`d5665d5209decf1154b734fea4b4185ecf9ef27a6e3eb0d8f4dbf2c524127c1f`.
The differing head links explain the two identities.

The independent reviewer attempted the original job-log endpoint for all four
jobs. Every attempt returned HTTP 404 with Azure `BlobNotFound`, preserved in
`connector-results/<job_id>.log-fetch.json`. These are retrieval-error records,
**not test stdout or stderr**. The raw log endpoint is
`https://api.github.com/repos/TrillionniumFoundation/Hepta/actions/jobs/<job_id>/logs`.
The retained artifact inventories likewise contain no macOS artifact for these
runs. No empty, reconstructed or baseline log is substituted for the absent
current-job log.

Initially, the connector rejected the annotations endpoint as unsupported and
the browser path was unavailable. Those retrieval limitations were not GitHub
authorization failures. The later successful HTTP collection supplied the
decisive original annotations.

## Workflow comparison and historical control

[workflow-comparison.json](workflow-comparison.json) records exact byte equality
for each workflow across both heads and both bases:
`e632886e...`, `45205981...`, `39dedf9f...` and `2e2afc1a...`.

| Workflow | Identical Git blob at all four refs |
| --- | --- |
| `.github/workflows/hepta-native-hosts.yml` | `2b927bc07c3549d6ceb83e4319faee4e88bce840` |
| `.github/workflows/hepta-cpp-upstream-hosts.yml` | `ea88a334cd721b44218d93e99f411a6d7dfc2633` |

The exact files are retained under `workflow-snapshots/`. Both explicitly
request `macos-15`, declare `contents: read`, disable matrix fail-fast and
disable concurrency cancellation. Their concurrency keys contain the workflow
and exact head. Neither workflow declares an environment approval gate or a
secret prerequisite for these jobs. This checks their published configuration;
it does not claim to inspect private repository billing or runner policy.

The #833 base `39dedf9f7933b9743fb8a6c720e5deb4615296eb` ran these same workflow
bytes successfully on actual assigned macOS arm64 runners earlier that day:

| Baseline | Actual macOS job | Assigned runner | Completed UTC |
| --- | --- | --- | --- |
| [ABI run 42592903358](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42592903358) | [129078543360](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42592903358/job/129078543360) | 1000060719 | 09:25:33 |
| [C++ run 42592903422](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42592903422) | [129078542659](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42592903422/job/129078542659) | 1000060715 | 09:24:15 |

The original baseline job metadata and complete connector-decoded logs are
retained under `baseline/`. The ABI log records `native-host.json` passed and
the actual-host stb component passed, followed by successful evidence upload.
The C++ log records 16 tests, two upstream versions passed and successful
evidence upload. These are historical controls demonstrating that the unchanged
workflow can execute on the intended host. They do not qualify either new
head's missing macOS row.

The combination of each job's explicit acquisition failure, the repeated
provider capacity notices, no assigned runner or executed step, and the
unchanged previously successful workflow supports **hosted macOS arm64
runner-acquisition failure during reported capacity constraints**. There is no
evidence here for a compiler regression, missing local toolchain, repository
permission denial or billing failure. No source or CI-gate change is justified
by this record alone.

## Effect on the current source gates

For #833 at `e632886e...`, [exact source closure 42629363155](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42629363155)
completed successfully. The retained 11-run API snapshot contains nine
successful runs and the two failed host-matrix runs above. That Linux source
qualification remains valid within its recorded scope; it does not supply
macOS execution evidence.

For #831 at `45205981...`, both exact-head paired-cost test runs
[42632067090](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42632067090)
and [42632077984](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42632077984),
[six-outcome source/application 42632077929](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42632077929),
and [verified-native 42632078007](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42632078007)
completed successfully. Its retained ten-run snapshot contains eight successes
and the two failed host matrices. It contains no `HIA exact source closure`
run for that head; the base's source-closure pass is not substituted.

Both PRs therefore retain the two original failed host-matrix outcomes and an
unqualified current-head macOS row. This diagnosis is not a waiver or a green
matrix result. Provider-side capacity recovery would be relevant new evidence
before considering a separately authorized fresh execution; this publication
does not request or perform one.

## Evidence integrity

[DIAGNOSIS.json](DIAGNOSIS.json) maps every finding to the original records.
[MANIFEST.json](MANIFEST.json) inventories every other file in this directory
by exact UTF-8 byte length and SHA-256, including its source and representation.

`raw/` and `source-gates/` preserve GitHub API JSON content returned by the
connector without reformatting. `annotations/` preserves the root collector's
original HTTP bytes and fetch ledger. `connector-results/` stores the original
connector result objects in a declared JSON serialization; those files are not
represented as raw HTTP wire responses. Baseline logs preserve the connector's
decoded log text as UTF-8. Workflow snapshots preserve repository file bytes.
The comparison, diagnosis and this README are derived analysis.

The evidence commit is separate from the two source PR branches. Its parent is
the reviewed #833 head, and its only changes are new files beneath this
directory. All failed and cancelled outcomes remain unchanged.
