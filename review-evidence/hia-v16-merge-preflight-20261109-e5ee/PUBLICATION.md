# Published candidate following the baseline merge review

The [original local preflight](README.md) and its `files.json` remain unchanged.
Its temporary local commits are not the actual published commit identities.

The publisher independently checked the actual refs and reconstructed the reviewed
tree from the eleven existing entries in `tree-updates-from-ff.json`. GitHub
returned exactly tree `4c51962e030e9ea39c6498224c99eb40fbdd2f35`.

| Published node | Ordered parents | Tree |
| --- | --- | --- |
| `50262236d9d1807ca8df0eccfb9f5f7ee9f6206c` | `e0c1ac3c97bb296e288de3d37b01f65d87772832`, `ff456fd8a4df2b61f34b479c89f96ffcf65a9e5f` | `4c51962e030e9ea39c6498224c99eb40fbdd2f35` |
| `6ecd8023615a6e0b2dc269379fb059c656b38b6f` | `20eace37747fde9aa0fc9c14cdb0159db30f5161`, `50262236d9d1807ca8df0eccfb9f5f7ee9f6206c` | Same tree |

Both actual commit objects were read back through the GitHub API and their trees
and ordered parents checked. The raw objects are retained in
`published-intermediate-commit.json` and `published-candidate-commit.json`.

Only the [PR817](https://github.com/TrillionniumFoundation/Hepta/pull/817) branch
was advanced, from expected head `6a8c297b` to the final candidate, using a
nonforce update guarded by the exact previous head. `publication-record.json`
retains the before-ref observations and successful update response. Neither source
baseline branch, the public default lock, nor the live service was changed by
this publication.

The candidate is a new qualification subject. It needs its own applicable CI,
original source artifact and release lock. The already completed 6a cohort and
this static preflight do not qualify it. The six-track acceptance remains HOLD.

`publication-files.json` binds only this publication supplement. The original
preflight file manifest separately binds the unchanged review package.
