# Read-only private CI observation, 2026-10-28 05:12–05:13 UTC

Repository: `TrillionniumFoundation/hepta-private-ci`.
PR: [4118](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4118).
Observed head: `4b6391e116949af0c7e59776baead67271856bdb`.
These are timestamped observations, not a statement that the full gate passed.

## Observed workflow state

| Workflow | Run | State at observation |
| --- | --- | --- |
| HIA native NDU bridge | [40632653917](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653917) | completed / success |
| Hepta architecture convergence | [40632653904](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653904) | completed / success |
| v8-canary | [40632653880](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653880) | completed / success |
| blocking-ci | [40632653912](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653912) | in_progress / no final conclusion |

The full `per_page=100` job response contains all **35 jobs**: 15 successful,
one failed, 15 still running, and four skipped. The connector's convenience
wrapper returns only its first page; `BLOCKING_JOBS.json` therefore retains
the complete REST collection rather than treating that partial list as final.

The failed job is [cargo-deny / cargo-deny, 122633256681](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653912/job/122633256681).
Its `Run cargo-deny` step failed. Job setup, action build, checkout, CI setup,
Rust installation and the final clean-worktree check succeeded. The job ran
from 04:32:52 to 04:34:40 UTC.

**The concrete cargo-deny failure diagnostic remains unknown.** The available
evidence does not identify a crate, advisory, license, duplicate-dependency
rule, network error or other cargo-deny cause. It also does not establish
whether the failure is related to the bridge change or present in the base.

## Log and annotation retrieval

The following authorized, read-only retrieval paths were attempted:

- The connected `github.fetch_workflow_job_logs` call again returned
  `Transport closed` for job 122633256681. This is a retrieval error, not a
  Rust or cargo-deny diagnostic.
- The generic GitHub connector rejects the job/log URLs because those paths
  are outside that tool's allowed endpoint set. That does not describe CI
  correctness.
- The official public job HTML was successfully fetched. It reports the job
  failure but requires sign-in to view the logs.
- The official public check-run API was successfully fetched. Its output
  title, summary and text are all null. The annotations endpoint returned one
  **notice** about migration of `ubuntu-latest` to Ubuntu 26. This notice does
  not provide a cargo-deny failure reason and must not be presented as one.
- A public unauthenticated GET of the official job-log endpoint returned
  HTTP 403, `Must have admin rights to Repository.` No attempt was made to
  bypass this boundary or acquire additional credentials.

The raw public API responses, their status/body hashes, normalized visible
public-page text and connector error records are retained in this directory.
The public page was reduced to visible text so irrelevant anonymous web-session
metadata is not published.

## macOS Clippy and remaining checks

[macOS Clippy job 122633257157](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653912/job/122633257157)
still reports `in_progress`, with the `bazel build --config=clippy lint targets`
step running. Its public check-run output has zero annotations and no summary.
The previous test-fixture `unwrap` was replaced by contextual `expect` in this
head, but a successful remote Clippy result cannot yet be claimed.

Other still-running work includes the SDK Bazel build, release builds,
platform test shards and the remaining Clippy jobs. The observation does not
predict their outcomes. The successful dedicated bridge workflow and
architecture workflow do not replace or waive the broader blocking gate.

No frozen source, dependency exception, lockfile or workflow was changed.
No commit, push, workflow rerun or local compiler/performance workload was
performed for this observation. `INDEX.json` records the evidence file hashes.
