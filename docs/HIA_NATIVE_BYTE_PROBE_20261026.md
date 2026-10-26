# HIA P1/P2 finite LLVM byte-trace native probe — 2026-10-26

This is an experimental, test-only, path-specialized LLVM native oracle,
not the production Hepta compiler or universal HIA Owned/Loan/Memory SSA.
It extends PR #177's finite byte trace without introducing another parser or
replacing the existing independent Resource IR checker.

## Executable finite profile

hia_native_byte_probe.compile_native_byte_trace first calls the existing
replay_byte_memory_path and the underlying boolean CFG/resource-transition
replay. The externally supplied byte action script is checked by that finite
model. The native probe lowers **observed operations** to actual LLVM IR:
calloc/free, volatile i8 load/store, conditional read guards and a live-value
rolling checksum. It checks monotonically increasing Memory effect tokens,
exact proof-claim fields, trace SHA, balanced allocation/Drop and exact
operation shape. It uses Clang -O0 and LLVM optnone; no speed claim follows.

Host support: Linux x86-64 ELF64 shared objects, bounded heap extents up to
4096 bytes per allocation, one selected finite CFG path, and synthetic byte
values, not the original Hepta-source numerical SSA. There is no general
dynamic allocator-failure model, graph-wide generated branch execution,
machine provenance proof, arbitrary FFI, GPU/DMA or physical-board semantics.

## Executed local test evidence (not full Hepta checkout)

Python 3.13.5 + real Clang 17 x86-64: **6/6 isolated protocol methods
passed, 0 skipped**. Real ELF shared objects were compiled and called:
read-zero, true/false branches, mutable loan byte write then read, and
actual calloc/free. A deliberately wrong emitted store was independently
compiled, and the native read guard aborted as expected. Out-of-range byte
actions, existing-output overwrite, forged proof field and a rehashed
out-of-order Memory effect token were rejected.

The exercised test directory included exact current HIA modules:
hia_resource_trace blob 5ad92fab5aa5cbc62fdd4830b52cc89a1cfb069e,
hia_boolean_trace blob 30d0f58bbc3b215e84dc9a773cac5420f3c2de0a,
hia_byte_trace blob 7662254c81a907e2852544b05e4a263a22a67df1.
**A minimal test substitute for Resource IR was used, NOT the complete
production resource verifier.** This result does not qualify real checked
Hepta source, even though native Clang execution itself is real.

New committed source/test Git blobs match the locally executed bytes:
- hepta/hia_native_byte_probe.py: 73af540eed6a43b49ee33b0ce17072cca576eef7
- tests/test_hia_native_byte_probe.py: 929dc6ef4f0aba71a3c0ad7f95a1642f77bd7977

## Full-checkout verification commands (not executed on this commit)

    python -m unittest tests.test_hia_native_byte_probe tests.test_hia_byte_trace tests.test_hia_boolean_trace tests.test_hia_resource_trace -v
    python -m unittest tests.test_resource_ir tests.test_llvm_owned_backend tests.test_owned_operation_witness tests.test_hia_oracle -v

## Remaining acceptance

P0 versioned source authority still partial. P1 requires a single executable
source-bound Value/Owner/Loan/Drop/Memory SSA with inter-block and error
semantics. P2 requires Owned LLVM exclusively consuming that verified Core
and actual independent Rust/LLVM differentials. P3/P4 complete real C/C++
migration, P5 fair CPU/GPU comparison, P6 true AI model A/B, P7 physical
MMIO/DMA/IRQ, service recovery and p99 all remain OPEN/PARTIAL.

whole_project_blockers_closed=false
