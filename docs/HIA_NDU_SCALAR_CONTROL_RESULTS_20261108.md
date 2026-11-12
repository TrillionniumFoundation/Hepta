# Same-pool native NDU controls: 2026-11-08 result

All 64 registered pairs completed and chose the specified same candidate. The
native NDU selector took longer in all 64 pairs. This closes the missing
same-input mechanism measurement for the current scalar selector; it does not
close the broader NDU incremental-value or economic gate.

The measured source was the clean local source commit
`55fe9e39a3b2c5a1d17536f9f83394f37feb48e0`, based on the copied-byte Agent
lifecycle source. GitHub publication commit
`e6cb3f8bd29db14aca786c807e1231844c6ce927` has its identical independently
checked tree `da298c2a04aa27f1f56a7a3a64eef66340dbddfb`; only commit metadata
differ. This is a development measurement, not qualification of the
selected public release or transfer of observations to later commits. The
[protocol](HIA_SCALAR_CONTROLLER_CONTROLS.md) was frozen before execution.

## Complete observations

| Measure | Ordinary | Native NDU |
| --- | ---: | ---: |
| Planned selector calls | 64 | 64 |
| Completed calls | 64 | 64 |
| Complete-call wall total | 4.460608 ms | 938.923222 ms |
| Complete-call wall median | 0.0507015 ms | 11.865674 ms |
| Failed calls | 0 | 0 |

Each pair supplied exactly the same pool, allowance, objective and generation.
All 64 pairs agreed with the independent specified choice, including tie,
quality, resource and inclusive-budget cases. There were 64 actual native
calls and zero model calls. All eight scenarios used four Ordinary-first and
four NDU-first pairs. No warmup, sample, failed attempt or pair was removed.

Ordinary minus NDU wall cost had median **−11.809995 ms**, mean
**−14.60097834375 ms**, and sample standard deviation **5.656736052 ms**.
All 64 deltas were negative. These describe repeated invocations on one shared
Linux host; they are not a population estimate or independent training runs.

The outer observed execution interval was **1.423365758 s**, comprising
0.943383830 s in timed selector calls and 0.479981928 s in admission, capture,
export and offline checks. Nested timings are not added a second time. Prior
source acquisition, native compilation, final summary write, artifact upload,
authorship and monetary costs are outside that interval. Monetary and complete
lifecycle costs remain unknown.

## What this resolves

In this profile, every feasible candidate receives the same single conservative
scalar cost. Ordinary enumerates its minimum. The original native evaluator
returns the same minimum-cost frontier, and the caller applies the same
incumbent-first and lexicographic tie rule. The 64 real calls check the actual
wire relation and its overhead. They expose no additional decision information
or improved downstream artifact choice from NDU in this profile.

This is a scoped negative finding. A useful next incremental-value experiment
needs a task where independently calibrated prices or forecasts change a
relevant decision, matched strong direct-value/ordinary controls, and measured
calibration and lifecycle cost. Repeating this one-axis selector with more
samples cannot establish additional decision information. The historical
four-pair authored-task result, prior failures and unknown fees remain intact.

## Original evidence

The original archive (historical path `../review-evidence/hia-ndu-scalar-controls-20261108-23d1/original-campaign.zip`; not shipped in this tree)
is 1,283,026 bytes with SHA-256
`d9025d10bacdd5e8558625c26fce40130effc87e05fe962a2387bfd4680add6d`.
It contains the pre-execution plan, all 128 original scheduled cell records,
307 content-addressed objects including execution source and the actual native
image, original request/reply streams, test log and verification result.

The frozen plan SHA-256 is
`882a8c1e8ed96c0b409c8f4183f6b6e079bafbe76a9872666b44304f1acbc493`.
Independent offline verification (historical path `../review-evidence/hia-ndu-scalar-controls-20261108-23d1/VERIFICATION.json`; not shipped in this tree)
checked all 307 objects and 128 scheduled cells without launching new native
or provider calls. Eight evidence-integrity regression tests passed.

The executable is the exact retained original CI artifact from source
`321daf28ef230a532f0f382469a9f6fc4f4fa249`, run
[42497221815](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42497221815).
Its archive digest was independently read through GitHub and matched the local
original archive. The existing `_bridge_identity` contract matched adapter,
builder, dependency lock, build receipt and binary before and after the new
campaign. This is trusted build/process evidence, not remote or hardware
attestation. The selected public lock and all production authority stay outside
this study.
