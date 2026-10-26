# HIA P1 finite external byte-memory oracle — 2026-10-26

This is an experimental bounded test oracle layered on the **existing**
independently verified Resource IR and the Boolean CFG replay in PR #177.
It is NOT a new source-language authority, LLVM backend, or a native Memory SSA.

The finite profile executes zero-initialized Buffer<u8> byte arrays, linear
allocation/owner move/drop, local shared/exclusive loans, typed u8 reads/writes,
and a monotone mutation token across actual branch paths. Every Resource IR
operation is independently replayed with the existing Resource IR verifier
first. The memory observer checks its operation sequence exactly against that
verified trace, keeps an explicit allocation/free count, and fails closed on
mismatched actions, bounds, wrong types, alias conflicts, and remaining owners.

Crucial limitation: *allocation sizes, indices, read/write requests and values*
are external test actions, **not** inferred from actual checked Hepta source
or canonical SSA. The interpreter does not prove source semantics, any host
allocator/provenance contract, multi-block Memory SSA, native LLVM equivalence,
formal refinement, GPU or physical device correctness.

Local isolated protocol tests (with stub Resource IR): 19/19 total including
six new byte-memory tests. The complete exact-source Hepta native tests were
not run; this is not a production qualification.

To rerun on the actual checked-source checkout:
```sh
python -m unittest tests.test_hia_byte_trace tests.test_hia_boolean_trace \
  tests.test_hia_resource_trace tests.test_resource_ir -v
```
All remaining P0–P7 and P01–P12 production gates stay open/partial;
`whole_project_blockers_closed=false`.
