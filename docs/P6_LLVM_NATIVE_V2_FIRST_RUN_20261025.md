# P6 scalar32 native performance: v2 remains inconclusive

## Decision

The v2 protocol was committed before timing and executed exactly once. It
resolved v1's sample-duration problem but did **not** pass the full performance
acceptance gate: branch_accumulate on the Rust reference exceeded the
unchanged 5% relative-MAD noise maximum.

No third measurement was performed. No threshold, kernel, optimization option,
sample selection, or acceptance status was changed after observing this run.
The v1 inconclusive receipt remains intact.

- Implementation/protocol commit before measurement:
  c19e88801ec75ca19ab99f9762c248f09eb78d1f.
- Protocol SHA-256:
  4e688e468819eb317043fb94db6834ec790c4da98c1956d60bc7ec357d65ed89.
- Run interval: 2026-10-25 15:40:32–15:41:05 UTC.
- Complete receipt:
  evidence/P6_LLVM_NATIVE_V2_FIRST_RUN_20261025.json.
- Receipt SHA-256:
  3f40e337434b8c11c068e43ce629b450086ccd2012cca6ed302a16ebd2394757.

## All observed kernels

| Kernel | Rust median ms | LLVM median ms | Median paired LLVM/Rust | Rust relative MAD | LLVM relative MAD |
| --- | ---: | ---: | ---: | ---: | ---: |
| signed_walk | 674.579 | 695.394 | 1.030857 | 1.502% | 4.908% |
| unsigned_walk | 1,018.592 | 990.908 | 0.963486 | 1.226% | 1.295% |
| branch_accumulate | 647.659 | 532.924 | 0.806285 | **7.513%** | 4.718% |

All 42 measured samples now exceed 50 ms. The minimum is 478.166 ms; the
maximum is 1,042.054 ms. All 186 independent-oracle cases, representing 372
native calls, agree, as do all paired timed checksums.

The observed geometric mean paired ratio is 0.9286328770. Neither the fixed
1.10 aggregate ratio nor any 1.20 individual ratio limit was exceeded.
Nevertheless, the noisy Rust reference for branch_accumulate prevents the
whole three-kernel gate from passing. The apparent aggregate advantage is
not an accepted speedup result.

## Evidence and interpretation

v2 uniformly repeats v1's exact 64-call seed sequence 16 times. The Hepta
source hash remains
3a069315a09790a282768310bf6ba60790dcb4593cd89c4dccfb5126a804577f.
All other protocol controls are preserved. The complete JSON records
identities of the source, generated Rust/LLVM, compiler, two native libraries,
two separately emitted objects, and the native timing driver's object/binary.
It also retains build-operation wall times, all raw samples and checksums,
CPU affinity, cgroup budget, host model, and load averages.

Logical CPU 0 was selected on a shared AMD EPYC 9V74 Linux host. Pinning
prevents CPU migration but does not grant exclusive CPU time or prove stable
frequency/cache behavior. The available evidence identifies timing
variability, not a unique scheduler, frequency, cache, or compiler cause.
Root-coordinated heavy tests were paused during measurement, which does not
eliminate activity outside this task's control.

The concrete remaining P6 condition is a complete three-kernel run satisfying
the already frozen measurement-quality rules in a sufficiently controlled
environment. Repeated sampling until a favorable run appears, deleting the
noisy kernel, or changing the 5% limit would not close that condition.

Implementation and finite correctness are complete for this qualifier; the
P6 performance acceptance condition remains open. No owned/borrowed-memory
backend, whole-language performance, cross-target execution, heap-allocation
cost, or universal superiority to Rust is established.
