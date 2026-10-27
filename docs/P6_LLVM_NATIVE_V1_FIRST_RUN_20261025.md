# P6 scalar32 native performance: v1 first run is inconclusive

## Outcome

The committed v1 protocol was executed exactly once. Its performance
acceptance gate did **not** pass: the result is measurement_inconclusive.
The finite correctness cases and every timed Rust/LLVM checksum agreed.
No thresholds were changed and no samples were discarded or repeated.

- Implementation committed before measurement:
  cfa247162e535f24108b5fc7a43d9775f7844b11.
- Protocol SHA-256:
  b6d02dd1423590766589945531fe7489c22347ee35737917de3215de6e1b9a6e.
- Run interval: 2026-10-25 15:38:19–15:38:23 UTC.
- Complete unchanged receipt:
  evidence/P6_LLVM_NATIVE_V1_FIRST_RUN_20261025.json.
- Receipt SHA-256:
  c9adcd2f40a3d20df7877f919d512375e624be99f20287295cc505096acd8433.

The receipt retains all 42 samples, 186 independent-oracle correctness cases
(372 native calls), source/compiler/artifact identities, compile-operation
wall times, environment details, and individual failed gates.

## Observations

| Kernel | Rust median ms | LLVM median ms | Median paired LLVM/Rust | Rust relative MAD | LLVM relative MAD |
| --- | ---: | ---: | ---: | ---: | ---: |
| signed_walk | 40.768 | 40.540 | 0.991734 | 1.410% | 0.695% |
| unsigned_walk | 59.381 | 59.683 | 0.998717 | 1.743% | 2.366% |
| branch_accumulate | 58.706 | 42.007 | 0.728245 | 9.618% | 6.720% |

The observed geometric mean ratio is 0.8968196432. This number does not confer
a performance pass: four backend/kernel distributions contain samples shorter
than the predeclared 50 ms minimum. Both branch_accumulate distributions also
exceed the fixed 5% relative-MAD maximum.

The three performance-ratio limits themselves were not exceeded. In
particular, the apparently favorable branch_accumulate ratio cannot be
promoted to an established speedup because its measurement-quality gate failed.

## Interpretation and next controlled change

CPU affinity was fixed to logical CPU 0 on an AMD EPYC 9V74 host. This is a
shared environment, not exclusive hardware. The measurements establish
insufficient sample duration and branch-kernel timing variation; they do not
identify a unique cause of that variation.

The shortest observed sample was 32.542 ms. A separately committed v2 can
increase every kernel's native call count by the same factor, preserving the
exact kernels, inputs, optimizer flags, sample count, correctness checks, and
all performance/noise thresholds. A factor of 16 gives a nominal lower sample
duration around 520 ms based on v1, without promising that future noise will
pass. v1 remains an inconclusive result regardless of any v2 outcome.

The Rust library is 3,823,896 bytes and the LLVM library 15,392 bytes in this
run. These are whole unstripped library artifacts with different runtime/link
contents, not equivalent function-text sizes or a qualified memory-usage
comparison. Build-operation wall times likewise include tool identity,
validation and temporary file I/O, not solely compiler optimization time.

No owned/borrowed memory backend, whole-language performance, arbitrary
C/C++ migration, cross-target execution or universal Rust superiority is
qualified by this experiment.
