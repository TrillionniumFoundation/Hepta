# Terminal private CI observation — 2026-10-28 05:47 UTC

The required blocking workflow **completed with failure** at commit `4b6391e116949af0c7e59776baead67271856bdb` (tree `c89b55bed0ed75c3fbd54ba51e1e66a115aa747f`). All **37** final jobs are terminal: **16 success, 7 failure, 10 cancelled, 4 skipped**. Earlier observations counted 35 jobs; the Windows test aggregate and overall `CI required` jobs were created afterwards. This directory preserves a new terminal snapshot and does not overwrite the earlier observation.

[Blocking run 40632653912](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653912) finished at `2026-10-28T05:35:28Z`. Official metadata was observed at `2026-10-28 05:47:09 UTC`, and public job annotations at approximately `05:48:43–44 UTC`.

## Confirmed defect in the fixture edit

[Ubuntu Clippy job 122633257034](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653912/job/122633257034) failed in `bazel build --config=clippy lint targets`. Its public annotation reports `used expect() on a Result value` in `hepta-fleet/src/authority_port.rs:197:9`, in the `ledger.admit_host(...)` call chain. The chain ends at line 210 with the newly introduced `expect("admit the fleet authority test host")`.

`SOURCE_ATTRIBUTION.json` contains the exact Git-object comparison from the initial bridge revision `2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b` to the observed head, including source hashes and the `unwrap()` → `expect(...)` diff. Thus the previous helper edit **did not satisfy the lint gate**. This failure is specifically attributable to our changed line. The observation made no corrective source edit, lint exception, dependency exception, lockfile change, or CI rerun.

## Failed and cancelled jobs of interest

| Job | Terminal result | Publicly established diagnostic |
| --- | --- | --- |
| [cargo-deny 122633256681](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653912/job/122633256681) | failure | `Run cargo-deny` failed. Specific dependency, advisory, or license cause remains unknown; the only visible annotation is a runner image notice. |
| [Windows shard 1 122633256970](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653912/job/122633256970) | failure | Exit 3; `//codex-rs/core:core-unit-tests` failed. Individual test diagnostic unavailable. |
| [Windows shard 3 122633256978](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653912/job/122633256978) | failure | Exit 3; `//codex-rs/tui:tui-unit-tests` failed. Individual test diagnostic unavailable. |
| [Ubuntu Clippy 122633257034](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653912/job/122633257034) | failure | `expect()` on `Result` in the changed fleet fixture; see above. |
| [Windows shard 2 122633257071](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653912/job/122633257071) | failure | Exit 3; app-server unit tests, app-server integration tests, and exec integration tests are named as failed targets. Individual test diagnostics unavailable. |
| [Windows aggregate 122651850457](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653912/job/122651850457) | failure | `Confirm Windows Bazel test shards passed`, exit 1. Dependency aggregation failure. |
| [CI required 122652038382](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653912/job/122652038382) | failure | `Require successful applicable dependencies`, exit 1. Overall required gate failed. |
| [macOS Clippy 122633257157](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653912/job/122633257157) | cancelled | The public annotation explicitly states the job exceeded its `1h0m0s` maximum execution time. The Clippy operation was cancelled; the fixture fix was not validated successfully on macOS. |

All 37 jobs and their steps, including the other nine cancelled jobs, are retained in `JOBS.json`. No common cause is assumed for those other cancellations. The public `just@1.51.0` platform fallback warnings are not independently established failure causes.

## Other workflows at the same commit

The [architecture run 40632653904](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653904), [dedicated bridge run 40632653917](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653917), and [v8 canary run 40632653880](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653880) all completed successfully. Their success does not replace or imply success of the required blocking workflow.

## Evidence and access limits

- `RUN.json`, `JOBS.json`, and `WORKFLOWS.json`: official connector metadata, including exact source identity and final statuses.
- `CHECK_OUTPUTS.json`: official commit check-run metadata for all 37 blocking jobs. The returned output title, summary, and text fields are null; annotation counts are preserved.
- `ANNOTATIONS.json`: eight single unauthenticated public annotation API attempts returned HTTP 403 because the public API rate limit was exhausted. They were not retried.
- `PUBLIC_JOB_ANNOTATIONS.json`: eight official public HTML job pages returned HTTP 200. Only visible summary/annotation text, timestamps, and raw-page hashes/sizes were retained. No protected log endpoint or sign-in was accessed. Generic page text such as “Re-running jobs” is UI chrome, not an action taken.
- `SOURCE_ATTRIBUTION.json`: pinned Git-object comparison establishing the changed helper line.
- `SUMMARY.json`: structured findings and explicit limits on attribution.
- `INDEX.json`: SHA-256 and size of every evidence file except the index itself.

The earlier protected-log 403 was not retried or bypassed. Cargo-deny root cause and the individual Windows test failures remain unknown. This observation performed no remote mutations, workflow reruns, source changes, local compilation, or model requests. Frozen source and model execution were left untouched.
