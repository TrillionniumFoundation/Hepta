# HIA program v3 — verified overlapping byte movement

**Status:** finite, source-independent HIA Core extension. This is **not** Rust-wide memory safety, general Provenance/Memory SSA, or full P0–P7 blocker closure. The verifier and native lowering are ordinary code, not a machine-checked refinement proof.

## Why v3 instead of weakening v2

HIA v2 'buffer.copy(dest: mutbuf, src: readbuf, len: usize)' requires distinct owner roots and lowers to LLVM memcpy. Accepting two views of the same owner under that opcode would invalidate nonoverlap guarantees. V1 and V2 remain closed and **reject** the new opcode. Only schema 'hepta.hia.program.v3' admits 'buffer.move_within'.

## Verified operation

| Field | Exact contract |
| --- | --- |
| Opcode | buffer.move_within |
| Arguments | (loan: mutbuf, destination: usize, source: usize, count: usize) |
| Results, attributes | [], {} |
| Effects | read, write, trap |
| Alias rule | Both ranges belong to the **same**, uniquely borrowed, live buffer owner |
| Semantics | memmove: copy original source bytes to destination even when regions overlap |
| Bounds | destination <= extent, source <= extent, count <= extent-destination, count <= extent-source |
| Zero count | Allowed for offsets up to extent, including the final position; no bytes accessed |
| Failure | Out-of-bounds trap **before mutation**; cleanup after trapping is not promised |
| Interpreter | Snapshot the source byte slice, then write the destination |
| Native | Explicit unsigned guards, non-inbounds GEP, LLVM memmove.p0.p0.i64 with align 1 |

A same-owner move needs one unique mutable loan; it must not fabricate two aliasing readbuf/mutbuf capabilities. A read-only loan cannot perform it. Suspended mutable parents must not be accessed until all child loans end. Ordinary returns must still end the loan and drop or transfer the owner.

Source and destination may be identical, may overlap partially or entirely, or may be disjoint. This differs from an arbitrary forward-copy loop when ranges overlap. It enables a safe primitive for future memmove-like C/C++ migration, but no automatic migration is claimed here.

## LLVM lowering boundary

All three offsets/count values are exactly usize (unsigned 64-bit). First verify each offset <= extent. Only then calculate extent - offset to avoid unsigned underflow. Verify count <= each remaining capacity before either byte pointer is formed. Lower to **memmove**, never memcpy: no noalias/nonoverlap premise is introduced. Alignment is 1. New v3 native LLVM profiles isolate existing v1/v2 syntax and evidence.

The new opcode is **not** on the zero-initialization elision whitelist: bytes remain initialized whenever this memory operation may read them. Raw pointers, foreign address assumptions, device and DMA capabilities are still unsupported by the standalone core.

## Agent-addressable standalone Core example

`examples/hia_program/overlap_move_v3.hia` is a complete, parseable
JSON-form assembly program with one C-compatible scalar export and real
owned allocation, unique borrowing, five byte stores, overlap-safe move,
read, loan.end and owner.drop. The regression re-verifies this file and
requires byte-identical canonical Core to the directly constructed test
program, so the public example cannot drift away from the checker.

## AArch64 finite target execution driver

The existing `hepta.hia_program_aarch64` driver now admits **explicit**
`mode="overlap_move"` with the same reviewed 4096-byte, one-live-owner
runtime, native compiler/linker/QEMU identity requirements and ELF parser.
It refuses missing/mismatched `move_bytes(usize,usize,usize,usize,usize)->u8`
C ABI exports before any target launch. Eight fixed scalar ABI calls exercise
both overlap directions, exact self-copy and a zero-length move, then demand
the reviewed allocator counters: allocations=8, frees=8, outstanding=0,
denials=0. It cannot silently change existing matrix/bounds modes.

Use a complete source checkout and exact pinned tool paths to execute it:

    from pathlib import Path
    from hepta.hia_program import verify_program
    from hepta.hia_program_aarch64 import run_finite_program_aarch64

    source = Path("examples/hia_program/overlap_move_v3.hia").read_text()
    verified = verify_program(source)
    result = run_finite_program_aarch64(
        verified, clang="/exact/clang20", linker="/exact/ld.lld",
        qemu_aarch64="/exact/qemu-aarch64", mode="overlap_move")
    assert result["execution"]["returncode"] == 0

`tests.test_hia_overlap_aarch64` checks exact reviewed runtime-driver
construction and wrong C ABI rejection without claiming that pinned QEMU
has actually executed in the current environment. A compiled ARM64 .o
header is **not** proof of target execution.

## Exact-checkout tests

    python -m unittest tests.test_hia_overlap_move tests.test_hia_overlap_aarch64 \
      tests.test_hia_bulk_memory tests.test_hia_program tests.test_hia_program_llvm -v

The new regression suite covers actual HIA verifier and interpreter with overlapping left/right and same-range cases, empty owners, bounds errors, type/effect/borrow negatives, old-schema rejection, LLVM output and ARM64 text profile checks, native host LLVM execution and a wrong-bound SIGABRT control.

A separate directly compiled Clang 17 Linux host LLVM memmove/guard probe matched 20/20 expected byte observations. This proves the bounded intrinsic sequence, **not** that the new full-repository HIA implementation or pinned Clang20/native toolchain suite ran on this commit.

## Remaining blockers

General source-Hepta -> HIA v3 lowering/refinement, general provenance and multi-region Memory SSA, formal LLVM backend correctness, C/C++ broad L2/L3 translation, heterogeneous/physical hardware, real Agent-model A/B, stable resource/performance/p99 and whole-language proof are all open.

whole_project_blockers_closed=false.
