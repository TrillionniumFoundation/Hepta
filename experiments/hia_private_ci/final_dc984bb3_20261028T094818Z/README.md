# Exact-head private CI: terminal observation and retained diagnostics

Head: `dc984bb3b3cb21259f838a31f67a7c2983ea9510`. Official API observation: `2026-10-28T09:48:15.597494+00:00`
through `2026-10-28T09:48:18.961541+00:00`. The earlier 06:05 observation remains
unchanged; this directory records the subsequent terminal states.

| Workflow | Run | Terminal result | Complete jobs |
| --- | --- | --- | --- |
| Blocking | [40640810612](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40640810612) | failure | 37: 16 success, 5 failure, 12 cancelled, 4 skipped |
| Architecture | [40640810613](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40640810613) | success | 3 success |
| Original native NDU bridge | [40640810614](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40640810614) | success | 1 success |
| V8 | [40640810611](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40640810611) | success | 1 metadata success, 2 build jobs skipped |

Every collection used `filter=all&per_page=100`, returned no next-page link,
and has unique IDs with the observed count equal to `total_count`.
All runs and all collected jobs have the exact expected head and completed
status. `FINAL.json` retains complete run/job/step data and per-request URL,
time, response date, request ID and pagination metadata. The old 35-job
snapshot is not substituted for the final 37-job inventory.

## Ubuntu Clippy was cancelled after its one-hour limit

[Job 122658682845](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40640810612/job/122658682845)
ended with `cancelled`. The official annotation explicitly says the job
exceeded the maximum execution time of `1h0m0s`. The lint step was cancelled;
upload/cache/clean-worktree steps were skipped. This does not establish lint
success or show whether the code would pass with a different deadline.

## Blocking failures

The five failed jobs are cargo-deny, Windows Bazel test shards 1/4 and 3/4,
the Windows aggregate confirmation, and CI required. The aggregate jobs'
exit-one annotations are retained without inventing an additional underlying
cause.

For [cargo-deny / 122658682490](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40640810612/job/122658682490),
`Run cargo-deny` failed. Its complete annotation collection contains only an
Ubuntu runner-image migration notice; that notice is not evidence of the
failure cause. The one current connector log attempt returned `Transport
closed`. **The cargo-deny root cause remains unknown.** No credentials or
alternative identity were sought, and the log request was not repeatedly
retried.

Both failed Windows shard logs were retrieved through the configured official
GitHub connector. Their complete decoded UTF-8 contents are stored losslessly
as `job_122658682905.decoded.log.gz` and
`job_122658682835.decoded.log.gz`. `LOG_ACCESS.json` records decoded and
compressed byte lengths/SHA-256 plus successful round-trip verification.
These are exact decoded connector contents, not a claim about unobserved raw
GitHub ZIP transport bytes. `DIAGNOSTIC_EXCERPTS.json` binds selected excerpts
to the decoded hash and one-based original LF line numbers; full logs remain
available for findings omitted from the excerpts.

Observed shard 1 diagnostics include a hepta-fleet workspace-root canonical
path rejection, automation migration `real open: Invalid`, Git wrapper child
readiness timeouts, schema fixture failures, a memory contributor assertion,
and supervisor restart-budget assertions. Its Bazel summary contains six
failed targets.

Observed shard 3 diagnostics include agentd
`RegistryOpen("UnsafeStateDirectory")`, evidence outbox `Capacity`, a matrixd
control socket `AlreadyExists` rejection, signed-intent recovery assertions,
and a V8 sandbox-feature true/false mismatch. Its Bazel summary contains ten
failed targets, including additional code-mode, exec-server, queue and TUI
failures retained in the complete log.

These are concrete observed failures, not claims that they are all unrelated
to this work, have already been fixed, or share one proven root cause. Current
local Linux qualification does not substitute for Windows or remote Clippy
qualification. The successful bridge/architecture results do not override
the failed blocking gate, and V8's skipped builds did not execute.

`SUMMARY.json` is the compact machine-readable conclusion. `INDEX.json` binds
all files in this directory. No source, acceptance file, workflow, PR or
repository setting changed. No compiler, model, solver, benchmark or CI rerun
was invoked.
