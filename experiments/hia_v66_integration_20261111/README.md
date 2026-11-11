# v66 integration observations

This directory preserves integration observations with their actual execution
scope. Component development, source/workflow controls, matching-source cold
qualification and the retained full regression are separate gates. No record
here grants default activation, whole-product acceptance or removal of a
supported retained implementation.

## Initial source/workflow control run

`run-source-controls-r1.py`, `source-controls-r1.log` and
`source-controls-r1.json` preserve the actual first integrated control run.
All 18 loaded tests executed in their original order. Seventeen passed and one
raised a support-contract freshness error. There were no failures, skips,
expected failures or unexpected successes, and the declared source hashes were
unchanged throughout the run. The report status is `FAIL_OR_INCOMPLETE`.

The error came from the complete nominal workflow control calling the actual
`validate_contract()` while the new v66 contract generator/source list had been
edited but the checked-in contract had not yet been refreshed. No assertion or
admission condition was weakened. The run records the actual pre-commit Git
head, changed paths and before/after hashes; those are not relabelled as a later
frozen commit. An independent copy of the entire dirty worktree was not captured
for this failed source-control attempt. The raw log SHA-256 is
`cb9a5034c6629ec6311ea55ef7102337b7753b12cceee34b8c9837e3affc65cf`.

## Original desktop v65 full-run failure

`desktop-v65-originals/` contains eight byte-identical compact original files
from the actual full attempt on commit
`4161e8d12d87906fde144f039da07908ad52d98a`. `CUSTODY.json` is a derived index and
does not replace those originals. The actual execution job was
`1a1c9ffc883-2564-3e4`; its authoritative terminal result was failure/exit 1.

The original source suite passed all 333 loaded/executed tests without unittest
anomalies. The cold owner timed out after 180.501917585 seconds against the
unchanged 180-second gate. Its phase index records 26 completed passing phases,
zero phase exceptions, and twelve pending original/modified signed,
scalar-casts, explicit-traps, cli, names and exports phases. The native and
retained full suites were not executed. The source, harness and prerequisite
pins remained unchanged; owned-child cleanup reached `ECHILD` with no remaining
children. None of the incomplete attestations is labelled as a passing gate.

The separate preservation receipt identifies the verified archive of all 3,741
regular original files (342,138,928 decoded bytes): 32,451,512 compressed bytes,
SHA-256 `cf02335c474101dd054c7b917b198b0dd8f398ea91f09e5f0ba4423c66c3946a`.
Six private toolchain symlinks are recorded through lstat/readlink only. The
archive was verified on the original host and its compact original receipts
were read back; this directory does not claim a second download of that entire
archive. A lost transport response for the archival command is distinct from
the known terminal failure of the full qualification itself.

## Related exact-source evidence

- `../hia_core_ci_4161_20261111/` preserves the separate v65 GitHub push PASS and
  PR timeout, their original artifacts and independent replay.
- `../hia_linked_observer_20261111/` preserves the actual old/new observer
  comparison, including its failed first attempt and corrected comparison.
- `../hia_machine_plan_development_20261111/` preserves the actual plan/witness
  development source, differential controls, original caller run and real wheel.
- `../hia_worker_report_development_20261111/context-r4/` preserves the worker
  context corrections and explicitly records the temporary fixture archive
  lost before upload.
- `../hia_v66_qualification_runner_20261111/` preserves the unchanged original
  guardian/helpers, the v7 controller and actual incomplete-run rejection
  controls. Those controller controls are not a product qualification.
