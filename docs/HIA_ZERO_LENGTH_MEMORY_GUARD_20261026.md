# HIA P1/P2 zero-length bulk memory native semantics

**Source baseline:** HIA v6 recipient PR #194 at
`a5f6340492da727d1387cdb6b39065c56f98a3fc`.
This follows the exact two-parent P0 source-bridge reconciliation with
PR #193 `ef5316b20e748d258e5d6efed7a9cc32c0038318`.

## Real native emission change

In the **existing** `hepta.hia_program_llvm._FunctionEmitter`, the
existing v2 `buffer.fill`, v2 `buffer.copy`, v3
`buffer.move_within`, and v5 `buffer.copy_range` now use the same
conditional-zero semantics already implemented for v6
`buffer.fill_range`.

Their inputs remain validated by the one
`hepta.hia_program.verify_program` authority. The VM does not invoke
native memory intrinsics; it already admits zero count and zero-sized
owners. A successful `buffer.new(0)` is represented by an empty owner
with null pointer in the existing native allocator. A no-op bulk operation
must not form an offset pointer or call a memory intrinsic on that owner
just to perform zero bytes of work.

- `fill`: emit `llvm.memset` only when owner extent is nonzero.
- `copy`: emit both original size<=extent guards first, then
  `llvm.memcpy` only for nonzero count and separate owner roots.
- `move_within`: retain original four subtraction-safe offset/extent
  guards, then emit both GEPs and `llvm.memmove` only for nonzero count.
- `copy_range`: retain four subtraction-safe guards and distinct-owner
  contract, then form offsets and invoke `llvm.memcpy` only for nonzero
  count.
- `fill_range` is unchanged: it already has a dominating zero test.

All nonzero native paths preserve the same intrinsic, memcpy-vs-memmove
selection, optimizer flags, actual resource moves/drops, allocator
behavior and exact Core verification. No HIA schema version change
or new verifier/LLVM backend is introduced.

The no-op guarantee is intentionally stronger than merely hoping
LLVM defines a zero-length `memcpy` on null pointers. The explicit
conditional branch makes no memory intrinsic call or derived address
at all on the zero path.

## Negative and native acceptance

`tests/test_hia_zero_length_bulk_native.py` adds in-repository
positive and negative checks for all four operations, verifying that
`buffer.new(0)` plus zero memory work is legal without an allocation
or free, while invalid nonzero sizes and illegal offsets still trap
with bounds semantics. The test examines **actual** emitted LLVM
blocks and checks both x86-64 and AArch64 IR. On Linux x86-64 with
Clang it compiles actual HIA-emitted LLVM and compares native return
values to the independent interpreter over frozen test inputs.

Run on the exact repository checkout:

```sh
python -m unittest tests.test_hia_zero_length_bulk_native \
  tests.test_hia_program tests.test_hia_bulk_memory \
  tests.test_hia_overlap_move tests.test_hia_offset_copy_v5 \
  tests.test_hia_range_fill_v6 tests.test_hia_program_llvm -v
```

Compilation success, verified Core resource flow and finite VM/native
parity do **not** establish all-target LLVM refinement, source→Core
proof, arbitrary FFI memory validity, DMA safety, C++ L2/L3 conversion
or production resource/performance superiority.

`whole_project_blockers_closed=false`.
