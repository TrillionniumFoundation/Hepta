# Exact-head private-ci observation: partial terminal results and blocking failure

Repository: `TrillionniumFoundation/hepta-private-ci`  
Exact run head: `dc984bb3b3cb21259f838a31f67a7c2983ea9510`  
Complete initial collection: 2026-10-28 06:05:33–06:05:35 UTC.

This directory is retained because two runs actually reached terminal states
and the blocking workflow has a concrete failed job/step. It is not an
assertion that all four workflows completed. All four official run objects,
full job/step collections, individual timestamps, URLs, request metadata and
pagination coverage are preserved in `OBSERVATION.json`.

| Workflow | Exact run | Observed state | Complete job collection |
| --- | --- | --- | --- |
| Original NDU bridge | [40640810614](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40640810614) | completed / success | 1 success |
| V8 | [40640810611](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40640810611) | completed / success | 1 metadata job success; 2 build jobs skipped |
| Architecture | [40640810613](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40640810613) | in progress / no conclusion | 1 success; 1 in progress |
| Blocking | [40640810612](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40640810612) | in progress / no conclusion | 15 success; 1 failure; 15 in progress; 4 skipped |

The V8 workflow's success does **not** establish that the two skipped build
jobs ran or passed. Architecture's base-merge job succeeded, while its
source-head job was still running.

## Observed blocking failure

Job [cargo-deny / cargo-deny, 122658682490](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40640810612/job/122658682490)
completed with `failure`; the `Run cargo-deny` step failed. Its cause remains
**unknown** in this observation. One log request through the configured
GitHub connector returned `Transport closed`. One request to the official
check-run annotations endpoint returned HTTP 403 with `API rate limit
exceeded`. No annotation body was retrieved; this must not be described as
an empty annotation list or a clean check. Exact failures and request times
are retained in `ACCESS_LIMITATIONS.json`.

## Ubuntu Clippy remains unverified

Job [Bazel Clippy on Ubuntu 24.04, 122658682845](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40640810612/job/122658682845)
was in progress in the complete initial snapshot. A later read through the
configured GitHub connector at `2026-10-28T06:08:26.122Z` still reports
`bazel build --config=clippy lint targets` as `in_progress`, with subsequent
steps pending. Therefore the explicit Result-assertion change is **not yet
validated by a completed Clippy job** in this evidence.

## Coverage and access limits

Each initial jobs request used `filter=all&per_page=100&page=1`. Each returned
no next-page link. For all four workflows, the collected count matches
`total_count` and job IDs are unique: 1 / 3 / 2 / 35 respectively. Every
collected job belongs to its recorded run and exact expected head. This is a
complete collection at the stated times, not a first-page assumption.
The API was read without an Authorization header.

The later architecture/blocking run and jobs requests were also rate limited.
Their rejected responses are saved separately and do not replace the earlier
complete collections. Pending or inaccessible states are not converted to
success, failure, or finality. No credentials were read or probed, no service
access restriction was bypassed, and no repeated log/annotation retries were
attempted.

No source, protocol, workflow, PR, or repository setting was changed, and no
compiler, solver, benchmark or workflow rerun was executed. `INDEX.json`
contains SHA-256 and byte sizes for this independent evidence snapshot.
