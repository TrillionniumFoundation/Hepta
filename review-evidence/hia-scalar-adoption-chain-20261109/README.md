# Capped-add specification and adopted native image: original local evidence

**Status: passing local scoped qualification. Hosted exact-head CI remains a
separate publication gate. P3 general kernel proof and P4/P5 value remain open.**

The complete original four-type packet binds clean source
`b78868a85c9a59ab31bc9344581c01b17a501d37`, tree
`2d6e9ca95d1230dfce84b079652eb661b90dc995`. Its measured worker identity is
`609f13189a269ef9f4dada9e38bc07ea93d33b6f67e76225da3b33a834e1a592`.
The later CI/replay-tool commit does not rewrite those original source identities.

| Original observation | Result |
| --- | --- |
| `u8`, `u32`, `u64`, `usize` capped-add family | All four passed |
| Mathematical-specification obligations | 3 per type, 12 total |
| Supplied Core/object/final/ABI machine obligations | 5 per image, 8 images, 40 total |
| Exact native workload | 125 vectors per type, both images; 1,000 measured calls |
| Adopted and rollback owner calls | 10 per type, 40 total |
| Focused tests on the same clean source | 8 passed, no skips; 10.041 seconds |
| Complete four-type qualification | 17.152677591 seconds |
| Saved-query replay | All 52 queries matched; 157 original files rehashed |

The focused tests include another finite u32 exercise and overlap with the
four-type matrix; their counts must not be added as distinct semantic coverage.
Both separately invoked replay clients used fresh contexts in the same pinned
Z3 implementation, not two independent proof systems. The archive is the one
original native campaign; its replays made no new native calls.

Every canonical and planned image has 13,720 bytes. Their bytes differ, while the
selected artifact-size metric is `unchanged`. No speed, size, optimization,
provider-cost or NDU advantage is established. The original ledgers retain null
and incomplete external, adoption and future-cost fields.

## Contents and replay

`chain-b78868a.tar.gz` is 396,764 bytes with SHA256
`a3f080bb72b9012d01afb7905f00a702978afbbd598a5fb0f3f294a637f76526`.
It contains 158 regular files: 157 original reports, journals, source/plan/ELF
artifacts and solver queries plus their manifest. No transient service database,
credentials or private provider material is included.

After checking the archive digest, extract it into a new directory. The reusable
read-only entry rechecks the selected manifest and all 52 saved queries:

```sh
python -B tools/replay_hia_scalar_adoption_chain.py \
  --input /absolute/extracted/chain \
  --expected-manifest-sha256 4048f142d9661e4db36c35315f21b4c0dc6accf36a5542aad7cc4a6672007841 \
  --output /absolute/new/replay.json
```

The packet also includes the original standalone `independent-replay.py` and its
terminal JSON, the reusable client's terminal JSON, and exact focused-test and
qualification logs. `manifest.json` hashes these exported members.

The all-input statements are conditional on the identified independent
Core/x86/ELF models, pinned solver and existing caller/loader assumptions.
Observed adoption binds actual native execution to the checked image, but does
not prove the Python checker, full hardware ISA, physical stack liveness,
concurrency, the complete compiler buffer workload or production authorization.
