# Original scoped qualification evidence

Local source base: `2e2afc1ad725db85cb8cf7eba69f657cae7c4464`, with the
development changes in this PR present. Reports explicitly record dirty source;
the actual installed implementation, checker, object/final bytes and proof
inputs are bound by retained inventories, not inferred from the base commit.

| Original output | Result |
| --- | --- |
| `adoption-projection-tests.log` | 49 native receipt/tool tests pass |
| `feature-matrix-native-02.json` and `feature-matrix-native.tar.xz` | Actual matrix 9/9; B1=B2=B3; unchanged source closure |
| `feature-matrix-native.json` and `feature-matrix-stale-contract.tar.xz` | Original stale-contract refusal, no native matrix cases |
| `scalar-chain-run1.json` and `scalar-proof-adoption.tar.xz` | All three closed instances pass; 24 finite native consumer observations, 39 cold consumer operations |

`archives.json` records byte sizes and SHA256 for each archive. The scalar
archive retains original tool/consumer requests, stdout/stderr, process records,
transcripts, recursively exported immutable proof/build artifacts and reports.
Only the local private authority state is excluded. The complete retained
artifact graph is exported independently of that authority database.

An earlier ad hoc scalar test during the service edit observed
`E_HIA_IMPLEMENTATION_STALE`; this was a real source-drift refusal. The later
49-test log and three-instance run were performed after source/contract freeze.
That interrupted observation is distinct from the published passing runs.

These are scoped local results. No release lock, online binary or production
slot was changed. Model and solver assumptions and unknown full external cost
are retained; the reports make no general performance or NDU claim.
