# HIA program v2 — typed bulk byte memory ISA

**Status:** finite standalone verifier/interpreter/LLVM addition on the independently
executable HIA branch. This does not close general source-to-Core refinement,
Rust universal parity, C/C++ migration, GPU codegen, or physical hardware.

## Version isolation

HIA v1 keeps its exact existing schema \`hepta.hia.program.v1\` and instruction
contract. New operations are admitted only under \`hepta.hia.program.v2\`.
An old v1 program containing the new opcode rejects with \`E_HIA_OPCODE\`.
The v2 program is otherwise subject to the same closed SSA, owner/loan graph,
source-independent immutable byte admission, effects and native-target limits
as v1. Old code and its LLVM textual output have no new intrinsic declaration.
No historical producer or proof claim is silently upgraded.

## New operations

| Opcode | Operands | Effects | Machine semantics |
| --- | --- | --- | --- |
| \`buffer.fill\` | \`mutbuf, u8\` | \`write\` | Fill the entire live mutable borrowed buffer with a byte |
| \`buffer.copy\` | \`mutbuf destination, readbuf source, usize length\` | \`read, write, trap\` | Check length against both extents, copy the first N initialized bytes |

Both opcodes return zero SSA values and carry empty \`attrs\`. The independent
verifier requires the existing unique mutable loan, absence of suspended
parent loans, and the normal CFG loan lifecycle. Copy further requires the
destination and source to have **different allocation-owner roots**; it never
claims safe overlapping \`memcpy\`. No raw addresses or arbitrary foreign
pointers can be passed into the public scalar HIA entrypoint.

A zero-length copy is permitted. A byte count exceeding either buffer
length has a defined \`bounds\` trap. A fill of an empty owner does nothing.
Normal exits still need \`loan.end\` and \`owner.drop\`. On a program trap,
cleanup is not promised (same as v1).

The interpreter uses bytearray/memoryview for the bounded concrete effects.
LLVM lowering consumes the exact reverified Core and emits typed
\`llvm.memset.p0.i64\` or \`llvm.memcpy.p0.p0.i64\`; copy has explicit unsigned
length guards, while the borrowed-owner proof guarantees nonoverlap.
LLVM intrinsic alignment is 1 and accesses are nonvolatile. The compiler may
select SIMD or target bulk memory instructions without adding a garbage
collector, interpreter or custom ISA hardware.

This is a bulk-memory capability, not the full general Memory SSA token,
FFI-proven pointer safety or a guarantee that these primitives outperform
optimized Rust/C/C++ in real workloads.

## Tests

\`\`\`sh
python -m unittest tests.test_hia_bulk_memory -v
python -m unittest tests.test_hia_program tests.test_hia_program_llvm -v
python tools/qualify_hia_unified.py --help
\`\`\`

Existing LLVM, interpretation and source qualification suites still need
the exact full checkout with its pinned toolchain. A standalone Clang 17
host smoke of the LLVM memset/memcpy calling convention is useful only as a
finite compiler intrinsic probe, not complete Hepta codegen qualification.

**Remaining P0–P7:** source-to-HIA formal refinement; general typed
provenance, lifetime and concurrency; C/C++ L2/L3; broad ABI; GPU/NPU;
independent Agent model A/B, stable CPU/RSS/p99 and physical DMA/IRQ.
\`whole_project_blockers_closed=false\`.
