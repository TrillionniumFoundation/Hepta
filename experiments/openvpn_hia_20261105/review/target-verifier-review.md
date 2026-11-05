# Independent target verifier contract review

Scope: read-only comparison of the target build, matrix writer, workflow, and
independent result verifier. No sudo, provisioning, network experiment, tunnel
execution, or benchmark was run for this review. Python syntax was parsed
without executing the controller. The negative paths below are static
counterexamples to receipt validation, not observations from a target VM.

## Reviewed snapshot

| File | SHA-256 |
| --- | --- |
| `target_host/verify_result.py` | `0db71b317a1108b23bb6eb8caf838cea3425daac11fd2515f2519c7611106bcc` |
| `target_host/run_matrix.py` | `ca05a3a4f7a8603260392aa82f00013711e9a1ab85017c8634e14c7de3cc42d9` |
| `target_host/build.py` | `65962f6a70d632514a53e5379c82c9cbfa7049a33bbe6946b695f5c477ca94c3` |
| workflow | `4877f844e599edac11a2f12a2be4a6c010acd26cbd12a63ed5dae40027be3935` |

The verifier's newer exact count dictionary agrees with the matrix writer:
7 behavior cases, 2 authentication cases, 2 profile cases, 54 performance cases,
and 216 attempted/completed performance workloads with zero failed workloads.
Both directional receiver summaries use the matrix writer's actual schema and
require finite positive bytes, seconds, and bitrate, plus `sender: false`.
The real-tunnel path-delta and kernel-peer field names also agree. No remaining
field or CLI mismatch that must reject every valid first run was found in this
snapshot.

## Validation fixes identified and resolved

1. **Match the full planned case identity, not just case counts.** Performance
   positions are checked against the plan, but behavior, authentication, and
   profile IDs/arms/epoch are only compared between two self-reported receipts.
   Seven behavior rows can therefore have the right counts without representing
   all four epoch pairings and all three common-profile pairings. Replacing the
   C-userspace profile row with a second DCO profile under a different ID also
   preserves the profile count while avoiding the conditional C-userspace PID
   sampling check. Construct the complete expected task inventory from the plan
   and compare each ID, kind, arms, epoch, and performance position.
2. **Require the helper source inventory.** Iterating
   `report['inputs']['scripts'].items()` accepts an empty dictionary and thereby
   skips helper identity validation. Require its keys to match the fixed Python
   helper set, then retain the existing per-file digest comparisons.
3. **Reject contradictory profile/case verdicts.** The profile branch requires
   the inner `profile.passed` flag but does not require its enclosing traffic
   measurement to have `passed: true`, completed status, empty failures, and
   successful checks. A failed traffic measurement with a successful collector
   could therefore be accepted by the verifier if the case-level flags are
   inconsistent. Likewise, require the case receipt's status to be completed,
   not only the matrix row's status. The matrix writer already distinguishes
   these states; the independent verifier should enforce the same contract.

These findings concern incomplete or internally contradictory receipts. The
verifier is not intended to authenticate arbitrary maliciously fabricated
experiment evidence; actual execution remains established by the frozen source,
raw commands, outputs, and runtime observations.

### Final fix review

The updated verifier, SHA-256
`fe3a39325f0d9966d85098389f987c8a1c6d307c1af307b515380e9391fa00e4`,
was read and syntax-parsed after the fixes. All three requested corrections are
present:

- `expected_cases(plan)` constructs the same ordered 65 task identities as the
  controller, including epoch pairings, all common-profile arms, both negative
  clients, both profile clients, and every performance position. Each recorded
  task is compared against that inventory.
- The helper manifest must have exactly the current target directory's Python
  helper filenames before digest validation.
- Case receipts require completed status. Profile measurements additionally
  require a successful/completed enclosing traffic measurement, empty failures,
  nonempty checks, and all checks true.

No remaining must-fix defect was identified within this review's stated scope.
This is approval of the reviewed code/receipt contract for the first real target
attempt, not a passing target-experiment receipt. No runtime or timing test was
added during the fix review.

## Previously found blockers resolved in this snapshot

The matrix now has argument parsing and an actual main entry point. The workflow
adds independent result verification, so a process that exits zero without a
complete result cannot satisfy the job. Raw DWARF stack files now live in
`private-work`; the public profile retains their hashes and bounded symbol
outputs, and the private directory is removed. Public-output scanning rejects
private key extensions, PEM private-key/static-key headers, and raw perf files.

The workflow performs recorded-resource cleanup and transfers public evidence
ownership before verification and artifact collection. The build/matrix CLI
paths remain consistent. Official source closure, fixed compiler package hashes,
same-application linking, and selected module freeze retain the previously
reviewed behavior. These are code-review findings; they do not themselves prove
that the first target VM run has passed.
