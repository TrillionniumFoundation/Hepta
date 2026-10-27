# P5/P7: converge cross-block Agent SSA context with untrusted-render guards

Primary exact parent: PR #313 `3d41df347ad7576bd5271aa279101b9cce626f77`.
Second reviewed parent: PR #311 `51e1d1d3928c1540dee8349a427235d3c43aca62`.
Common ancestor for source-object comparison: PR #308
`8dec804bcaa747c8fba90e80043541e5a91d9869`.

The two parents modify **the same** two Agent presentation source files, so
neither can simply overwrite the other. This commit retains the P7 recipient's
existing strict display-identifier, opcode, field and index validation; imports
the P5 donor's cross-CFG SSA value-flow closure and batched downstream
deduplication; and adds strict downstream per-block rendering checks.

The donor's test and design documentation files are imported byte-identically
after verifying their paths were absent from the P7 recipient. The existing
`hepta.hia_program.verify_program`, all ISA operations, Rust shadow verifier,
LLVM backend, ABI/C++ migration, and resource accounting are unmodified.

The new display guard accepts only exact downstream records with legal
identifiers, typed parameters, nonempty subset of affected parameters, unique
operation indices, Boolean branch-affect metadata and at most 256 displayed
operations across the original and downstream blocks. It refuses malformed
direct in-memory Agent presentation rather than interpreting newline-bearing
names as new prompt instructions. `render_batch_context` reuses
`render_edit_context` for every nested query before formatting its deduplicated
batch. This remains a presentation safeguard, **not** equivalence or semantic
admission: applying an edit still reconstructs the exact immutable query and
verifies the entire HIA Core.

Regression commands for a full exact-source checkout:

```sh
python -m unittest tests.test_hia_edit_cfg_context \
  tests.test_hia_cfg_render_convergence \
  tests.test_hia_context_render_input tests.test_hia_edit_batch -v
python -m unittest tests.test_hia_bounded_agent_json \
  tests.test_hia_inmemory_json_budget -v
python -m unittest tests.test_hia_program -v
```

The Git source objects, declared parents and reviewable merger code can be
verified on GitHub. The full exact-head Python/Cargo/native suites have
**NOT** run locally, because this container cannot clone GitHub via DNS.
A passing branch merge does not close broader P0-P7 soundness, agent-benefit,
native performance, real C/C++ L2/L3 or physical hardware requirements.
`whole_project_blockers_closed=false`.
