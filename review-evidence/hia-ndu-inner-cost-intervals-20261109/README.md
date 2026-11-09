# Original transport timing containment

Independent review found five defects after the outer interval repair:
persistent round, startup and transport-close durations could exceed their
corresponding owner attempt, preparation and close; prepared native pump time
could exceed its owner attempt in either campaign. The original five accepted
records and unmodified independent reproduction script are retained here.

The repair requires positive exact integer original transport durations and
checks containment against their producer's enclosing intervals. It also
checks one-shot pump time inside the call and cleanup time inside transport
close, requiring `cleanup_wall_is_nested=true`. Nested time is not added twice.
Clock readings remain unauthenticated and P2 economic acceptance remains HOLD.

Three further aliases let duplicate startup, round and close summaries change
an original integer duration to a Python-equal float. Canonical JSON now binds
their exact types. `summary-types-old-fixed.json` retains all three previous
acceptances and final refusals. The independent reviewer also replays both
unchanged complete original archives successfully: each has 72 cells and
1,020 original responses. These offline checks start no native processes.

Final code: local commit `8e729e0c692ef6e58ed934c6045c9d37e8f1e114`, tree
`61b285883dca405ddb9cb17d48e889c15dec7223`. The cost modules passed 29 tests,
including raw archive mutations of zero, negative, boolean, float and
over-parent durations. The support contract still binds all 251 files.

`native-final-tests.log` records all five complete modules, including the
separate NativePersistentRankerTests: **92 passed**, zero failures, errors,
skips or expected failures, in 6.822 seconds. The harness explicitly exits
unsuccessfully for any skip or a count other than 92. Earlier 85-test evidence
selected only the persistent fixture class; it did not include the three
original-native tests. The integrator's missing-native skip failure is kept.

The original native binary came from successful CI run `42550772601`, artifact
`13645004336`, head `39ae467a5806a9c969133e6e8801f83c96f246aa`. Official archive
SHA256: `17d95cb5dc80380c05ff3d0c4e8bd7c3722f4a44b86810b08642d01d381d9d52`.
The unchanged `_bridge_identity` checked current adapter, builder, lock and
upstream pins. No new build or timing benchmark was performed.

- `HEPTA_NDU_BRIDGE` was `/workspace/scratch/5e86aa42d2b9/ndu-native39ae-selected/native/hia-ndu-bridge`,
  SHA256 `494d198e94f533c8a894dc141a42be2890fa12bce14d9b4b2c849ee5fbf46cb5`.
- `HEPTA_NDU_BUILD` was `/workspace/scratch/5e86aa42d2b9/ndu-native39ae-selected/build`;
  original receipt SHA256 `c71368467c282814d9f034a0120241c54f2cf7eec973b0197b29b52a1c764a81`.
- The receipt names upstream `d3c2d760eca5065fc966820379c35c6e8d56e855`
  and build-input digest `6dbd7f3ea0d9f3211934ec7bc49bcb8ce76374ae95cadedd91211e2abaf3b59d`.

Independent scripts and records are copied without changes and bind actual
checker SHA256 values. Their local refs can be replaced by an available
source-equivalent ref when reproducing; the public old ref is
`aa2bc7bf42b0c794b32e8d90393073e9944835d7`.

Provider charges, energy, full lifecycle costs and stable NDU economic value
remain unestablished. The ordinary control's faster results remain retained.
