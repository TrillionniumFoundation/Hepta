# Empty-entry Core clone: complete negative observation

`execution.tar.xz` is the complete 257-file native execution directory for
source `22de2bceebaf28ea03215fc4751d095d2e26c228`, run on the shared Linux x86-64
`main` host. The archive is 1,070,036 bytes, SHA-256
`38bd1c4cf8ec88d0db36074e31677f09ba89238a5b0f7263a17f9e8c1de79522`.
`SUMMARY.json` binds the full result inside it. `source-22de2bc.bundle` contains
the two candidate/observation commits above the published `18291446` baseline.

The isolated Core candidate freshly verifies the existing narrowing/induction
proofs, complete cloned resource CFGs and equality-guarded length substitution.
It retains the full native source/proof/LLVM/compiler/assembly/library/driver
artifacts and all raw driver streams. No historical samples or failures were
removed. All three loads (1, 16, 64), all original v2 lengths/seeds, both Rust
comparators, median/p95/p99 thresholds and the original 180-comparison Rust
denominator remain present. Eight new lengths and three new seeds contribute
another 96 comparisons.

The run completed in 61.545 seconds, including 37.641 seconds for build/proofs
and 22.885 seconds for timing. The 2,070 requests contain all 43,470 samples.
All 180 correctness observations and 70 boundary-refusal observations pass.
Before/after source, tool and executable identities agree.

The candidate passed **219/276** Rust comparisons: historical regression
66/84, historical holdout 73/96 and prospective lengths 80/96. The unchanged
four-arm replay passed 147/180. Neither result establishes complete parity.
At zero length and 64 calls, the candidate measured 225 ns (linear) and 255 ns
(affine); the strong Rust arms measured 153/157 ns and 154/163 ns respectively.
The generated zero path still saves three callee-saved registers and shares the
nonempty epilogue. Moving the equality guard in Core alone therefore does not
close this fixed-cost performance gap.

This observation does not enable the candidate in production. The Core
candidate adds three evaluator steps, so exact quota-stop behavior is outside
its equivalence claim. Backend refinement, whole-language soundness and full
lifecycle net benefit are not established. Affinity was recorded but the host
was not exclusively owned.

The later `wrapper-v2` profile is separate: it keeps complete Core calls on both
branches of a thin LLVM export wrapper, inlines only the equality-guarded zero
call and keeps the generic call out of line. Its new lengths/seeds and results
must be evaluated separately; they cannot relabel this negative observation.
