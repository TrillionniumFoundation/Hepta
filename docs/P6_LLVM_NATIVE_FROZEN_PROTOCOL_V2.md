# P6 native qualification protocol v2: longer samples, unchanged acceptance

## Reason fixed before v2 measurement

Protocol v1 was run exactly once at commit
cfa247162e535f24108b5fc7a43d9775f7844b11 and is inconclusive. Its complete
receipt and analysis are preserved by commit
a1095a6d295a80dea1550e82db89e8e2b7754f78, in
evidence/P6_LLVM_NATIVE_V1_FIRST_RUN_20261025.json and
docs/P6_LLVM_NATIVE_V1_FIRST_RUN_20261025.md.

Some samples were below the 50 ms validity minimum; the shortest was 32.542 ms.
v2 changes one experimental dimension: every kernel performs 16 times the
work per measured sample. Native calls increase from 64 to 1,024. The former
64-call input sequence repeats exactly 16 times, with the same 1,048,576
iterations per function call. This targets roughly 520 ms even for the
shortest v1 sample, while remaining far below 30 seconds per sample.

This is an explicit new protocol, not a rerun or reclassification of v1.

## Unchanged controls

- The same three Hepta kernels and generated arithmetic semantics.
- The same native Rust and LLVM optimization options.
- Seven paired groups per kernel, rotated kernel order, alternating backends.
- Eight native warmup calls per process, one fixed logical CPU.
- At least 50 ms for every sample.
- Relative median absolute deviation at most 5% per backend/kernel.
- Geometric mean of paired kernel median LLVM/Rust ratios at most 1.10.
- Every individual kernel paired median ratio at most 1.20.
- Every deterministic oracle case and every timed checksum must agree.
- All samples and failures retained, with no clipping or selective reruns.

The implementation and this protocol must be committed before v2's single
measurement run. If v2 still exceeds a noise limit, it remains inconclusive.
Changing sample duration does not guarantee acceptance, and no result here
qualifies whole-language, owned/borrowed-memory, or cross-target performance.

Run tools/qualify_llvm_native.py with a new output path after this commit.
The --describe-protocol command reports the new protocol hash without
compiling or timing native code. Historical v1 is reproducible from its
implementation commit above.
