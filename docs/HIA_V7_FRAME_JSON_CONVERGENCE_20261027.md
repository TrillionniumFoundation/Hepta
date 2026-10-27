# HIA P0/P2/P7 convergence: v7 JSON predecode and root-inclusive VM frames

## Immutable donor identities and safe integration

- Recipient PR #283 exact `2ca24bb6adc1411b6632643fe2ebe66b5d9f7d3e`,
  itself based on v7 PR #282 `0dd3d212a3d01a1f69b075dddc1519d987219e7d`.
- Donor PR #284 exact `7bc9aef4903e8ce50ced95e0b553f71c11193f2b`,
  based on that **same** #282 head.
- The seven paths modified/added by #284 were byte-identical to the
  shared ancestor (or absent) in #283. Their reviewed Git blob identities
  are transferred unchanged, except the v7 test updated below.
- Existing HIA v7 Core/schema, canonical verifier, native LLVM, C/C++ ABI
  and migration code are unchanged. This is not an unsafe whole-tree merge.

## Real release-contract mismatch that blocked convergence

`tests.test_hia_v7_call_depth` from PR #284 previously called
`analyze_static_budget` on v7 input. That analyzer **must reject v7**:
recursive chain destruction can perform arbitrarily many allocator operations
or VM ticks inside one `owner.drop` opcode. Therefore treating the v7 test
as a valid assertion was an incorrect version promotion.

The single existing module `hepta.hia_static_budget` now offers a deliberately
separate `qualify_vm_call_depth(program, max_call_depth=N)` admission API.
It reverifies the immutable canonical Core, accepts only audited v1..v7
primitive profiles, uses the complete direct-call graph, and refuses
cycles (including private functions). It counts **only** synchronous HIA VM
call frames, including the root. CFG loops do not increase that stack depth
by themselves. Its policy is strictly typed integer 1..256.

Both the original finite allocator/tick budget API and its v7 rejection
are preserved, and the new typed receipt declares all allocator, CPU,
RSS, native stack, async-task-stack and refinement claims **false**.

## Tests committed (execution still required)

```sh
python -m unittest tests.test_hia_json_preflight tests.test_hia_json_predecode \
  tests.test_hia_p7_v7_json_predecode -v
python -m unittest tests.test_hia_vm_call_depth tests.test_hia_v7_call_depth \
  tests.test_hia_vm_call_depth_only tests.test_hia_static_budget -v
python -m unittest tests.test_hia_program tests.test_hia_program_llvm -v
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
```

New v7 tests validate root-inclusive 1/2-frame limits, a looping CFG
without recursion, a dynamic v7 Chain destructor whose allocator/tick
budget remains **rejected**, direct recursion refusal, strict typed policy
and forged producer claims. They also check versioned receipt identity and
that the standard v7 full resource analyzer remains closed.

**Status:** source/blob identities inspected. The current local
environment has no GitHub DNS for full checkout and no Cargo/rustc.
This integration has **NOT** passed the complete exact-head real HIA VM
or Rust/native suites. No CI waiting state is used to stop development,
and no unexecuted tests or prior SHA are counted passing.

P0–P7 remain open for full Memory SSA/Provenance, LLVM/native refinement,
real C/C++ L2/L3 conversion, cross-target ABI/hardware, held-out Agent
A/B and stable production workload/resource measurements.
`whole_project_blockers_closed=false`.
