# Canonical source/native receipt compatibility

The published tree 514b607bd5661abe5ac516ee77d80638c939749c failed its real checked Hepta source → Core → native CI path because the compiler emitted the new entry_layout field and the strict source receipt checker still required the older exact field set.

The correction adds exactly that field and binds its ordinary string value to the independently generated IR layout. Checked source remains canonical. ABI, host, proof-scope, unknown-field and resource-budget refusals remain enabled.

## Retained observations

| Observation | Result |
| --- | --- |
| Original CI run41774368010, job126391150646 | Published same-tree failure retained in its original245740B ZIP |
| First local attempt with main Rust1.95 | Existing pinned-source reference correctly refused the wrong compiler role; retained |
| Same legacy test using genuine source Rust1.90 on unchanged98bd | Original receipt/profile failure reproduced:1 test,1 error,0 skips |
| Preliminary fixed native/refusal/identity suite |44 tests pass,0 failures/errors/skips |
| Final suite, including regression-child CLI mode |45 tests pass,0 failures/errors/skips; final7 source files identical before/after |
| Actual complete two-role identity | Genuine1.95 main role and1.90 source reference;58 sysroot/driver files replayed;1.95 rejected in source role |

The composition CLI now requires --source-rustc explicitly in addition to --rustc. The existing full-execution workflow provisions both fixed roles. The --regression-output child mode still works without the full composition flags. The complete v6 source differential and source reinspection modules are included in composition.

OBSERVATIONS.json records both failed baselines, both fixed validations, real build receipts, source-file hashes, role checks and measured walls. MANIFEST.json inventories every raw member in raw-evidence.tar.gz; the original CI ZIP, exact drivers, operations and all failures are present.

A cached path briefly wrote one test file in the already-completed98bd worktree. Its exact original bytes were immediately restored; no compiler, new campaign or model launched in that interval and no HEAD/index changed. The raw archive retains before/during/restored contents, wall timestamps, explicitly unavailable operation monotonic timestamps, verification monotonic time and absence of generation markers. Completed r2 results and the two zero-answer preparation registrations were not rewritten.

These are targeted correctness and identity checks on a shared host. They do not qualify a complete final composition, establish a performance gain, prove universal safety, or demonstrate Agent productivity. Test timing differences are not benchmark comparisons.
