# Native cold caller integration

This change composes the 131 native cold callers from `92ba9d876696c0562cd1272c3177519b7309c8f6` with the five builders, three independent readers and original-budget CI wiring from `fe452660545b4bb5207b2ddaad214e23785ec25a` (PR 969).

## Source identity

The original 131-file relation remains byte-for-byte unchanged at `tests/fixtures/hia_native_cold_caller_relations_20261127.json`. A separate v2 integration relation records the current Store delivery test after its independently reviewed source-history inputs were added. The other 130 current records, all 131 predecessor pins and Git blob identities, and every original relation field remain unchanged. Both physical authority files and the pinned restoration helper are captured and reread at terminal admission.

The complete inverse and forward source relations retain all 1,239 original test method identities and their assertion ASTs. `caller-current-source-review.json` records the physical and predecessor identities for every file. The independent file-capture reader now composes the native caller inverse with the existing complete Worker helper relation before accepting that caller. The original helper-count assertion is reconstructed by that original fixed relation.

Producer and independent transport reader each reconstruct the current linked observer through their own complete source algorithm before applying the existing observer relation. Their current-source profile reflects the actual 53,252-byte observer. The previous 47-method physical file cannot replace this current native caller. The original observer inventory, original method bodies, phase inventory and cold qualification checks remain unchanged.

The 1,289 native authority files are byte-for-byte identical to PR 969's reviewed source tree; this host caller change adds no native source or product. The original 240-second complete cold wrapper, 180-second cold owner plus 3-second cleanup, 60 phases, 479,882 nodes, 19 original/modified families, 14 checks, and 11-minute workflow step remain unchanged.

## Executed controls

`final-101/summary.json` and `final-101/controls.log` retain the final actual run: 101 tests, zero failures, zero errors and zero skips. The plan contains the unchanged 74 core controls, 18 original caller/source controls, six physical custody controls, and three new integration controls. The new controls exercise prior authority absence/tampering, physical post-capture drift without cache acceptance, and rejection of the previous observer in place of the new native caller.

Earlier failed and successful intermediate attempts are retained with their complete original logs. They are not relabelled as final passes. The v1 integration run exposed observer and complete-caller composition errors; v2/v3 isolated the remaining Worker relation ordering error. The final run follows the source fix and complete source catalog update.

To repeat the same gate from this checkout:

```sh
python -B review-evidence/hia-core-native-caller-integration-20261127/run_controls.py --output /path/to/fresh-output
```

## Remaining whole-stack gates

This record qualifies caller/source integration only. It does not certify an entire native cold delivery, an installed Worker, complete core CI, the unfinished bootstrap Source equivalence run, current Future/GenerationLease release reconstruction, or retirement of hosted implementations. Those gates must run on the final integrated source tuple. `whole_native_delivery_qualified` remains false here.
