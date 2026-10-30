# Public HIA integration CI: successful final observation

The official GitHub API reports workflow [40639809081](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40639809081)
`completed / success` for the exact public commit
`d5a0bf0e42611309cbc6461b1a414b9f8ece254f`. Its observed commit tree is
`2395f4d8628c2c9ce8a649f129200a71afff083b`.

`FINAL.json` preserves the run observation at 06:05:04 UTC on 2026-10-28 and
the complete job collection observed at 06:05:33 UTC. The run finished at
05:49:08 UTC. The single job,
[verified-native / 122655060017](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40639809081/job/122655060017),
completed all 15 steps successfully. These include the original NDU bridge
build, the native integration/regression gate, finite NDU and migration/runtime
evidence, artifact upload, and cleanup. Exact step names, outcomes, and times
are retained in the JSON; job metadata alone does not establish a test count.

The jobs endpoint was requested with `filter=all&per_page=100&page=1`.
It returned one job, `total_count=1`, and no next-page link. Collected IDs are
unique and the count matches, so this is a complete jobs collection rather
than an assumed first-page result. The anonymous official API used no
Authorization header. Request URLs, observation times, response dates and
request IDs are retained. The commit endpoint was used only to establish the
commit/tree identity; this evidence does not claim an audit of its paginated
changed-files list.

No frozen source, protocol, CI setting or lockfile changed. This observation
performed no compiler invocation, benchmark, workflow rerun or PR write.
The earlier successful `03d463599484ca18c5ff8eebbb4c0fd149cd2d56` run remains
in its own unchanged directory. This result concerns the exact public HIA
workflow above; it neither waives nor replaces the separate private-ci
blocking workflow.

`INDEX.json` records the SHA-256 and byte size of the evidence files.
