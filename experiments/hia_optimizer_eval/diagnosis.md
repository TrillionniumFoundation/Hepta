# What the first complete measurements actually found

This diagnosis refers to the exact `hepta-seven-stage-bench-02` artifacts. It is
an explanation of a failed performance gate, not a claim that the compiler has
been fixed. The frozen workload and acceptance thresholds were not changed.

## Main cost: a checked scalar reduction

The admitted HIA source uses checked `u64` addition for its checksum. In the
measured `full_lifecycle` binary, addresses `0x12e0` through `0x12f3` implement
one byte per loop iteration: load, add, conditional branch to `abort` on carry,
increment, compare, loop. `packet_xor` has the same pattern at `0x17e0` through
`0x17f3`. The retained LLVM contains `llvm.uadd.with.overflow.i64` for these sums.

The independent release Rust and C implementations have an eight-way unrolled
checksum loop with no per-add carry branch. For example, the measured Rust
`full_lifecycle` reduction is at `0xd440` through `0xd487`; the C reduction is
at `0x18d0` through `0x1918`. **These particular reductions are unrolled scalar
code, not SIMD reductions.** The HIA fill and transform loops already contain
SIMD instructions, and their per-element buffer checks have been eliminated.
The result does not show a general interpreter, ownership or borrowing tax.

There is a real arithmetic-semantics distinction: HIA checks overflow, while
the independent release references use modular `u64` sums. Every registered
input has size at most 65,536, so the outputs are identical on the complete
benchmark domain: a sum of bytes cannot exceed 16,711,680 there. That finite
fact does not authorize deleting checks for arbitrary library callers.

## Controlled exploratory ablation

`diagnose_codegen.py` constructs a separate, valid HIA program that changes only
the two sums to explicit `wrapping_add`, compiles it through the existing
verified-Core entry, and retains the complete disassemblies and executions.
This is intentionally a **different arithmetic contract outside the finite
benchmark domain**. It is not proposed as an admitted semantics-preserving
replacement.

On the actual exploratory run, all 144 independent finite-domain checks passed
and all 28 paired driver executions returned the expected checksums. The median
paired wrapping/checked time ratios were:

| Kernel | Wrapping / checked time |
| --- | ---: |
| `full_lifecycle` | 0.623750 |
| `packet_xor` | 0.778331 |

The generated wrapping reduction becomes eight-way unrolled, matching the
identified structural difference. This supplies direct evidence that checked
reduction lowering is a substantial cost in these workloads. These exploratory
ratios are neither an independent held-out performance claim nor a universal
speedup. They do not replace the six-backend benchmark.

## Next implementation steps with explicit proof obligations

1. **Guarded reduction specialization.** Recognize a side-effect-free unsigned
   byte reduction starting from zero. Emit a fast branch when
   `n <= floor((2^64 - 1) / 255) = 72340172838076673`, and retain the original
   checked loop for the other branch. Prove the invariant
   `0 <= sum <= 255 * i`, `i <= n`, and preservation of the owner/loan state.
   On the fast branch, every prefix sum fits in `u64`; explicit wrapping
   operations therefore equal checked operations. The guard selects an
   implementation; it must not reject previously accepted inputs, alter
   allocation failure, move I/O, or skip cleanup. Nonzero initial accumulators,
   signed values, other element widths and loops with effects need distinct
   proofs or must be rejected by this optimization.
2. **Alternatively test checked unrolling.** An unroll transformation that
   preserves each original checked addition and its order can reduce loop
   control overhead without changing overflow behavior. Its gain is not
   established here, and it must retain the original trap prefix and cleanup
   semantics.
3. **Carry actual allocator freshness into alias analysis.** The current HIA
   LLVM declares allocation calls with `no-builtins` but no return `noalias`.
   The measured `packet_xor` has an extra pointer-distance alias check at
   `0x15cf`–`0x15d9`, absent from the C version. A `noalias` return attribute
   should only be added after binding it to the runtime's already required
   fresh-owned-allocation contract, including interposition assumptions. Keep
   allocator calls/effects observable; do not replace this with broad
   `readnone`, unchecked pointer assumptions or deleted allocation attempts.

The first step is the primary candidate supported by the ablation. The third
is a secondary generated-code opportunity whose speed contribution has not
been measured separately. Neither was installed in the compiler during this
experiment.

## Reproduce the diagnostic

```sh
python experiments/hia_optimizer_eval/diagnose_codegen.py \
  --baseline-dir /tmp/hepta-seven-stage-bench-02 \
  --output-dir /tmp/new-codegen-diagnostic
```

The baseline binaries and driver are checked against their recorded identities
before use. The diagnostic emits its plan before compiling the changed program,
retains all native outputs, and marks `optimization_admitted=false` and
`admissible_replacement_proved=false` in its report.

## Frozen final follow-up

The integration added allocator return `noalias` declarations while retaining
`no-builtins`/`nobuiltin` and opaque allocation effects. The final emitted LLVM
contains those declarations, but the final HIA shared library is byte-for-byte
identical to the earlier measured binary (SHA-256
`9b02e9faf8fcd4dd37328659abec332b6c00054aa50bba7133d7a87db8957b42`).
The packet pointer-distance alias check and both checked reductions remain.
Thus this declaration change is not a demonstrated machine-code or performance
improvement for these two kernels. Following freshness through the allocator
helper's aggregate returns and pointer PHIs is an investigation to perform;
the present observation does not establish where LLVM loses that information.

The frozen final benchmark still fails every noninferiority comparison. Its
report, unchanged thresholds, full source snapshot, raw samples, final
disassembly and post-run provenance are in `evidence/bench_final`. See
`results.md` for exact final ratios and the shared-host interference limitation.
