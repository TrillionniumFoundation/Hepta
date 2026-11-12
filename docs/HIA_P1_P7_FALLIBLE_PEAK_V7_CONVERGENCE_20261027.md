# HIA P1/P7 fallible cycle convergence (v7 stays outside v6 budget)

## Exact source lineage

Recipient: PR #315 at `b6b201aa01b37c1f27902030b0228d08ef171386`.
Donor: PR #316 at `f0b92440963147847a86d3b14cc99c929b3ef021`.
Shared preimage: PR #278 exact `64645ceb8f0158e97d06926d02296cf07494bdf8`.

Recipient and donor preimages of both modified files were verified to be the
same exact Git blobs before transplant:

- `hepta/hia_heap_bound.py`: `130d5563c570b47e511573be5c86b3c5596a999f`
- `tests/test_hia_scoped_alloc_loops.py`: `4b08044aa0d68fc3b4bf62c151bb9ca95a03931a`

Transferred donor source/test bytes are unchanged. Other existing code on
the latest v7 Stack, including `hia_program`, `hia_schema`, Rust shadow,
LLVM, C/C++, Agent editor and input/predecode security, remains unchanged.

## Authority boundary

The scoped analyzer's `_ALLOWED_SCHEMAS` is **still exactly v1–v6**.
Allowing block-local `buffer.try_new` in this independently reviewed
payload-byte proof does not qualify primitive v7, composite v2 or Chain.
The new version-negative test verifies that the same operations under v7
remain valid executable Core but cannot obtain a v6 budget receipt.

Existing canonical `verify_program` checks all operations and resource
flow *before* the analyzer, and any optional quota receipt remains limited
to requested simultaneously live HIA buffer payload bytes.

## Qualification

```sh
python -m unittest tests.test_hia_p1_scoped_try_new_v7_guard \
    tests.test_hia_scoped_alloc_loops tests.test_hia_p0p1_v7_guard -v
python -m unittest tests.test_hia_zero_heap_loops tests.test_hia_heap_bound -v
```

No exact-HEAD repository VM/Cargo/LLVM qualification was performed in this
environment; committed tests are not presented as successful executions.
The synthetic interval proof control (32,640 samples) belongs to the donor's
original mathematical scope and does not constitute native evidence.

P0–P7 blockers remain open, especially generalized Provenance/Memory SSA,
Rust/LLVM full refinement, cross-target C/C++ ABI, real models, physical
DMA/GPU and production qualification.
`whole_project_blockers_closed=false`.
