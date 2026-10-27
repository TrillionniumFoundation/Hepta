# HIA v4 finite same-owner byte swap

Schema \`hepta.hia.program.v4\` adds exactly one opcode:
\`buffer.swap(mutbuf, left: usize, right: usize) -> []\`.
Earlier v1/v2/v3 schemas continue to reject it. Only the unique live
mutable loan permits access; two separate aliasing views are never created.

Both indices are unsigned 64-bit and must be **strictly less** than the
owner byte extent. The interpreter checks both before writing and snapshots
both old bytes. LLVM emits two independent strict unsigned bounds guards
*before either load or store*, followed by two byte loads and then two stores.
Swapping one index with itself is permitted. Zero-size owners have no valid
indices. An invalid index aborts; this does not imply cleanup after abort.

The required effects are \`read\`, \`write\` and \`trap\`. The opcode adds no
allocator call, does not support arbitrary raw pointer provenance, and is
excluded from the optimizer's zero-initialization elision whitelist. The
standalone Core checker and the existing LLVM backend remain the sole
authorities: there is **no** second compiler, ownership checker or new source
lowering route. This gives a safe, finite in-place operation useful for
future C/C++ migration, not general C++ equivalence.

## Reproduce

\`\`\`sh
python -m unittest tests.test_hia_swap_v4 tests.test_hia_overlap_move \
  tests.test_hia_bulk_memory tests.test_hia_program \
  tests.test_hia_program_llvm -v
\`\`\`

The new tests include positive byte exchange, strict version isolation,
same-index operation, forged type/effect/attribute rejection, byte OOB trap,
direct verified LLVM IR for x86-64 and AArch64, real native LLVM execution
against the independent VM, and a native abort negative control.

This incremental capability does not close generic Rust pointer provenance,
arbitrary Memory SSA, foreign ABIs/C++ L2–L3 translation, CPU/GPU fairness,
real Agent A/B, DMA/IRQ physical hardware or production p99.
\`whole_project_blockers_closed=false\`.
