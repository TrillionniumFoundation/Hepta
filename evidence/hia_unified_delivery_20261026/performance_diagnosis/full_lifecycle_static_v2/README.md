# Remaining full_lifecycle cost: static diagnosis, revision 2

This supplement describes the frozen `06266df5df19cb2b08ec3756ac750699cd987b81`
candidate. No compiler source changed and no native kernel or timing sample
was executed for this supplement. P5 remains **not qualified**. The complete
final performance run still reports `measurement_inconclusive`: eight of nine
kernel/backend groups exceed the fixed relative-MAD limit, and full_lifecycle
exceeds the per-kernel ratio threshold against both Rust baselines. Its recorded
paired ratios are 1.333230 versus generated Rust and 1.309395 versus handwritten
Rust; these noisy values are not causal measurements of individual instructions.

## Confirmed differences

| Operation | Standalone HIA | Generated and handwritten Rust |
| --- | --- | --- |
| Fill main loop | 16-byte vector stores | 16-byte vector stores |
| Fill tail | Scalar tail with a bounds branch | Additional four-byte vector epilogue, then scalar tail |
| Tail at the fixed size 4093 | 13 scalar stores | Three four-byte vector stores and one scalar store |
| Checksum | Scalar byte load and checked unsigned addition | Scalar byte load and checked unsigned addition |
| Checksum bounds | Separate index-versus-buffer-length branch on each byte | No corresponding per-byte bounds branch in retained optimized loops |
| Initial zeroing | calloc | Allocation helper, memset(size - 1), and one last-byte zero store |

The additional HIA checksum bounds branch is visible in the exact measured
HIA binary: a compare and branch to abort precede each byte load. The same
loop separately checks the add carry flag. Both Rust checksum loops retain
that overflow check, so this is not a comparison against unchecked arithmetic.
Both fill loops are vectorized; the evidence does not support saying that
HIA failed to vectorize the whole kernel or that Rust vectorized the checksum.

The optimized HIA IR keeps input `size` and the buffer's extracted `length` as
different SSA values. The buffer and success flag come from an aggregate
allocation-result PHI that also represents failed allocation. Even after the
success branch, the per-byte length guard remains. This is consistent with
the optimizer not recovering the equality needed to eliminate the guard.
That explanation is an inference from the emitted IR, not a proved sole cause.
Any future optimization would need to establish that equality while preserving
the checked semantics; no such optimization was added here.

Unlike constructor_error, both Rust full_lifecycle variants still perform
bulk zero initialization before filling bytes. The constructor diagnosis must
therefore not be generalized into a claim that only HIA zeros this buffer.
calloc and the Rust allocation-plus-memset path still differ, but this static
analysis does not isolate their costs.

## Identity and limits

The retained HIA binary and handwritten Rust binary exactly match the SHA-256
artifact identities in the final performance report. The retained generated
Rust binary does not match that final binary byte-for-byte; its source, compiler
and compilation flags match. Its static code is corroborating evidence, not a
claim to possess the exact final measured generated-Rust artifact. The HIA raw
LLVM bytes also exactly match the frozen report.

The Rust LLVM excerpts were generated solely for static inspection using the
same pinned compiler, source and safety flags. Commands and source identities
are recorded in `rust_ir_static_commands.json`. The `.excerpt.ll` files omit
module declarations and metadata and are reading excerpts, not build inputs.

No causal fraction of the remaining ratios is established. Shared-host noise,
allocator behavior, and Clang LLVM 20.1.2 versus rustc LLVM 20.1.8 have not been
isolated. The supported conclusion is a concrete remaining code-generation
difference plus unresolved performance risk, with P5 still nonpassing.

The parent `manifest.json` is unchanged. This directory has its own
`manifest.v2.json`, which binds the supplement and records the parent's digest.
