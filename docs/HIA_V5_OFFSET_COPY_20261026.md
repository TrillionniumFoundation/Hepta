# HIA v5: checked range copy across distinct owners (P1/P2)

Status: finite standalone executable HIA profile only; not a whole-language proof.

The existing HIA verifier is the only semantic authority. Schema
`hepta.hia.program.v5` adds a single opcode:

```text
buffer.copy_range(destination: mutbuf, source: readbuf,
                  dst_offset: usize, src_offset: usize,
                  size: usize) -> ()
effects {read, write, trap}
```

The verifier requires two distinct owner roots, a writable exclusive
destination loan, a live shared source loan and exact usize offsets.
Versions v1–v4 reject this opcode; unknown attributes, aliased roots,
wrong operand types and missing effects fail closed.

VM and LLVM perform four guards before any destination write:
`dst_offset <= dst_extent`, `src_offset <= src_extent`,
`size <= dst_extent-dst_offset`, `size <= src_extent-src_offset`.
Only after those guards does LLVM emit `llvm.memcpy.p0.p0.i64`.
The separate allocation roots justify memcpy nonoverlap; moving within
one owner continues to require v3 `buffer.move_within`/memmove.

Run (exact, complete checkout):

```sh
python -m unittest tests.test_hia_offset_copy_v5 -v
python -m unittest tests.test_hia_program tests.test_hia_program_llvm \
  tests.test_hia_swap_v4 tests.test_hia_overlap_move tests.test_hia_bulk_memory -v
```

The test suite checks VM values, resource cleanup, version isolation,
metadata/permission/overflow rejections, LLVM emitter identity and
independent host-native Clang differential and SIGABRT control.

Limitations: only zero-initialized byte owners, two distinct allocations,
finite SSA CFG and target-specific LLVM. No general Memory SSA/provenance,
unbounded pointer arithmetic, source-to-Core proof, C++ ownership
qualification, GPU/physical board or production performance guarantee.
`whole_project_blockers_closed=false`.
