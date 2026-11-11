# v7 external qualification runner

This checkpoint records qualification-controller code and its controls. It does
not qualify a HIA product revision, a cold run, a fixture, or a complete retained
regression. No product suite or cold qualification was rerun for this checkpoint.

The frozen runner is `run_hia_qualification_v7.py`, 44,509 bytes, SHA-256
`cfc91fc795039881f6c7408af3f05610c98c58679eae3689ddbcafba83b14593`.
The original v6 runner is retained unchanged, SHA-256
`565537d5eb7b5e49662b21e531eed50affb13924d0cdd1584608ffb9f59339eb`.
`v6-to-v7.diff` contains the complete controller delta.

## Preserved boundaries

The original guardian, process owner, workflow supervisor and prerequisite
admission helper are included byte for byte. Their SHA-256 values are in
`final-gate-controls.json`. The old `suite`, `selected_journal_callers`,
`_pinned_state` and `file_record` functions have identical ASTs. The source
reproduction program, cold command and outer workflow timeout also have
identical ASTs. All old complete module groups remain present and unchanged.

Cold qualification still uses the original 180-second owner and two workers.
The runner still gives the cold wrapper 240 seconds, each ordinary component
1,800 seconds, and full discovery 5,400 seconds. The unchanged external full-run
guardian retains its 10,800-second deadline. No success is inferred from a
timeout or incomplete process cleanup. The final report retains the v5 schema
required by that guardian and identifies its harness revision as v7.

## New mandatory observations

The same fresh cold report selects JSON wire, worker report and machine plan;
their three development-manifest selectors are removed. Every step receives
four distinct, step-specific evidence paths for JSON wire, ordinary wire entry,
worker report and machine plan. The ordinary wire entry uses the existing JSON
wire cold selector and its own `HEPTA_HIA_JSON_WIRE_ENTRY_FIXTURE_EVIDENCE` path.

Five complete modules are added to the original groups:

- `tests.test_hia_json_wire_native`
- `tests.test_hia_json_wire_entry`
- `tests.test_hia_worker_report_native`
- `tests.test_hia_machine_plan_native`
- `tests.test_hia_selfhost_linked_observer`

Two ordinary-caller gates are additional conjuncts in the final result:

- Machine plan: the original four complete caller modules and all 44 loaded
  tests must execute in order, with unique IDs and zero unittest anomalies.
  Native entries must occur, retained owners must be forbidden, and the direct
  Python/HIA source snapshot must match the pinned checkout before and after.
- JSON wire: all nine explicitly named caller modules must load and execute in
  order, with identical loaded/chosen/executed IDs and counts, no exclusions,
  and zero unittest anomalies. All eleven Agent tools must enter selected wire,
  native step counters must be positive, and neither retained decision owners
  nor the host encoder may be entered. The whole matching cold source closure,
  observed source files, manifest and image must remain stable. This gate uses
  the actual complete loaded denominator rather than a hardcoded test count.

Each caller builds from the current cold compiler into a new explicit evidence
directory. The runner reads back the actual manifest, build receipt and image;
it checks image bytes, compiler/source/image digests, the cold report digest,
the full cold source map and the actual native compilation receipt. JSON wire
also retains its explicit ordinary-entry product profile. A warm mapping or a
report's retention boolean cannot replace those reads.

Each of the five modules and both caller gates is independently mandatory.
An unexecuted gate remains false. The report continues to set
`whole_native_delivery_qualified` to false.

## Controller controls

`final-gate-controls.json` binds the frozen runner to 42 machine-caller receipt
controls, 42 JSON-wire caller receipt controls, eight final-conjunction controls
and two step-environment controls. These explicitly inject synthetic child
receipts into the actual controller functions. Their images are nonexecutable
fixture bytes. Positive fixtures verify acceptance of a complete controller
record; malformed, incomplete, excluded, drifting, unretained or failed records
must hold. Synthetic `FULL_RETAINED_PASS` results in this control are not product
qualification results.

`final-suite-controls.json` records five real fresh Python subprocesses using
the actual unchanged embedded unittest observer. Normal execution returns zero;
class-level skip, expected failure, unexpected success and early stop return
nonzero. Early stop is refused even though unittest itself reports success.
The embedded observer SHA-256 remains
`a1afd11410f245dae1e5464188b2638376b94fc38dad982e87a1550942ddb265`.

All prior controller observations are preserved in `controller-originals.tar.gz`.
The retention script independently read all 1,583 members, totaling 2,443,064
uncompressed bytes, and checked their SHA-256, size, mode, UID and GID against
the existing originals. Archive SHA-256:
`37dbf2e2ab3d9c8a61122ce92bdbcdbb4a3d42caadde577385cf842b6deccd6e`.
No original report was overwritten. Earlier records keep their intermediate
runner hashes; only gate r5 and suite r4 bind the final cfc91f runner. The 555d
draft is retained separately. Earlier intermediate runner byte snapshots are
not asserted to be this final version.

The separate `linked-observer-local-retirement-r1.json` records authorized local
retirement of already-published, independently verified duplicate expanded
linked-observer observations. It does not change their original result or
delete the canonical Git archive.
