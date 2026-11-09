# PR825 first-entry CI readback: 81fe

This immutable package preserves metadata commit `81fe7b59881ed07fb7037aec9e305f6538ec7cd1`, tree `a3fa0ac98769cd4a1aadd8513c4c88d5c3172930`, parent `74063163ad19d096a4ff9a66a6f25728e6ce0d8f`. The terminal run list was observed at 2026-11-09 07:06:39 UTC.

## Result and identity

The fixed two-workflow cohort passed on its first attempts: two public installation jobs and all four CodeQL jobs. All 66 reported workflow steps succeeded; this is not a count of tests. Each full original job log contains `git log -1 --format=%H` followed by the exact 81fe commit. These jobs did not check out a prospective merge commit.

| Workflow | Run | Event | Result |
| --- | --- | --- | --- |
| Public release consistency | [42576902057](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42576902057) | push | 2/2 jobs, attempt 1, success |
| Default CodeQL | [42576904491](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42576904491) | dynamic | 4/4 jobs, attempt 1, success |

## Public selections

The current job records `HIA_RELEASE_SELECTION=current` and `tools/hia_release.py`; its recorded shell case leaves the command unchanged without `--lock`. Successful helper output binds the existing lock SHA256 `9000d6eaa089f6bed92ea07a6561d91381a6f913263f0b1016d4f99e8789c1d3`.

The v16 job records `HIA_RELEASE_SELECTION=v16`, `tools/hia_release_v16_6ecd802.py`, `releases/hia-v16-6ecd802.json`, and explicit `--lock` / `--lock-sha256` arguments. Successful helper output binds original B lock SHA256 `b3c3725e183d98bec2819155f2d4cd525c3f45305d04ec8fa686e13f454e50e0`.

Both jobs report successful source materialization, source-contract verification, and final exact-source/runtime/installation-identity equality. This evidence combines the recorded script, actual job environment and helper output, rather than an independent execve/argv trace. Both helper results explicitly report `production_deployed=false`.

| Selection | Artifact ID | ZIP bytes | SHA256 |
| --- | ---: | ---: | --- |
| current | 13655094143 | 95,810 | `21165c2cbd1ccd44d8e26a2b8533e4c093da3e8449f7165e80863573bb7aef7e` |
| v16 | 13655223754 | 102,165 | `5ca3c004bb9cc0294e322f35373eecc24b91d48f0370351ee4c7e15623a6a3d2` |

Original upload logs and GitHub metadata agree on distinct artifact names, IDs, sizes and digests. This observer did not download the ZIPs or inspect members; the publishing reviewer handles that separate check. `describe.json` was redirected to the artifacts and is not treated as independently inspected here.

## Preserved records and boundary

`initial-*.json` retains the first API observations. The final run/job metadata, commit metadata and artifact metadata retain original returned JSON bytes. `logs/` contains all six full original job logs. `review.json` contains the derived identity and outcome checks. `files.json` hashes every package member except itself.

This remains the first-entry revision's historical acceptance if PR825 later receives substantive evidence changes. The final head and actual main merge require their own CI. No failures, reruns or cancellations occurred in this fixed 81fe cohort. The broad six-track acceptance, online service identity and negative NDU/economic findings are not upgraded by this public-entry result.

The observer performed only read-only metadata/log retrieval and standard-library parsing/hashing. No project tests, native programs, compilers, Lean or solvers ran locally, and no source, branch, PR or CI state was changed.
