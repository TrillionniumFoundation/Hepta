# Public HIA integration CI: successful final observation

The observed workflow [40636856854](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40636856854)
completed successfully for exact public commit
`03d463599484ca18c5ff8eebbb4c0fd149cd2d56` and tree
`383b3c7c8a6b68a3857a87c9acbd86af3ca32c24`.

`INITIAL.json` records the read-only observation at 05:17:41 UTC on
2026-10-28. `FINAL.json` records the terminal `completed / success` state
observed at 05:18:53 UTC. Both use the official GitHub REST run and full jobs
collection; the source head and tree were checked against the published ones.

The single job, [verified-native / 122645709751](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40636856854/job/122645709751),
completed all 15 steps successfully. In particular:

- The original native NDU bridge build with exact source identity succeeded.
- The actual native integration and regression gate requiring no skipped tests
  completed at 05:18:17 UTC.
- The real finite NDU loop and migration/runtime evidence step completed at
  05:18:42 UTC.
- Evidence upload and cleanup completed at 05:18:44 UTC.

There are no failed steps in this run. The JSON preserves the exact individual
step outcomes and timestamps. It does not infer a test count from job metadata.

This observation changed no frozen source, CI setting or lockfile, did not
rerun the workflow, and ran no local compiler or performance workload. Polling
stopped when the run reached its terminal state. The result concerns this
public HIA integration workflow; it does not waive or replace the separate
private-ci blocking workflow.

`INDEX.json` contains SHA-256 and size for each evidence file in this directory.
