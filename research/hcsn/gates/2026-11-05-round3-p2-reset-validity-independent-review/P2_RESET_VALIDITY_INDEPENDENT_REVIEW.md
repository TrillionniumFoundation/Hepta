# P2 reset-validity: independent pre-fit review

**Disposition:** the three numerical blockers found in the unexecuted draft have been addressed in the revised candidate. This is a source and numerical-contract review, with **zero training fits and zero heldout quality panels** run by this reviewer. It does not establish task quality, an HCSN advantage, autonomous regeneration, or closure of P2.

Reviewed files in the candidate repository are `research/hcsn/p2_reset_validity.py`, `p2_reset_validity_campaign.py`, `test_p2_reset_validity.py`, their imported gate/memory helpers, and `gates/2026-11-05-round3-p2-reset-validity-protocol.json` (revision 2). Review date: 2026-11-05 UTC. Numerical reproduction used PyTorch 2.10.0+cpu and one Torch thread.

## Numerical findings and repair

| Check | Original draft | Revised candidate |
| --- | --- | --- |
| A model-produced simultaneous write/reset, with finite FP32 memory and validity entries equal to `finfo(float32).max / 2` | The old matrix-vector products overflow before the final reset multiplication. Output, memory, and validity become nonfinite despite reset=1. | Memory, validity, and address context are erased before unsafe products; active write is zero during reset. Output and all four state tensors are finite, and memory, validity, and older context are exactly zero in the reproduced witness. |
| FP16 zero initial state | `normalize(0, eps=1e-8)` underflows the epsilon and produces NaNs. | FP16 and BF16 model execution both raise an explicit `ValueError`; supported model/state dtypes are FP32 and FP64. |
| FP32 HCSN versus algebraically mapped Put+linear at a hard threshold | Exact-real channel identities do not imply identical floating-point hard events. | The protocol, documentation, and regression retain this limitation; each trained checkpoint must report its actual mapped event equality and log-probability discrepancy. |

The threshold witness is constructive, not a trained-model error-rate estimate. With `u=-0.3779296875`, coefficients `(6, -6)`, and common bias `1.8883278369903564`, the HCSN pre-sigmoid logit is exactly 0 while the mapped logit is `-2.384185791015625e-7`; the resulting hard events are 1 and 0. In a deliberately threshold-centered 4097-point grid, 1095 constructed points differ; the largest pre-sigmoid discrepancy is `2.384185791015625e-6`. A different bias is chosen at each grid point, so this count must not be presented as a frequency for one deployed controller.

The revised reset ordering changes the straight-through surrogate gradient. It has the intended discrete forward behavior but is not claimed to have the original draft's relaxed derivative. This change is recorded in revision 2 before any fit. The rejected original protocol and source are retained rather than silently replaced in the historical record.

## Mechanism and information flow

The model receives raw token IDs through a shared embedding, positive elapsed times, and optional model state. Its forward computation does not branch on semantic WRITE, RESET, KEY, VALUE, or UNKNOWN IDs. Targets and semantic reset/write masks do not enter the controller. Both event coordinates are obtained from learned logits through a sigmoid and a 0.5 hard threshold. Semantic token recognition appears in data generation, the independent interpreter, and evaluator diagnostics, where it is appropriate.

Reset has priority over writing. On a successfully returned step with learned reset=1, the revised forward state is `(zero memory, zero validity, current observed embedding, zero older context)`. A reset step's validity score is zero; the factorized readout therefore gives UNKNOWN probability `sigmoid(6)`, approximately 0.997527, independently of the learned four-way value distribution. This is an exact conditional forward-state erasure property under the stated numerical contract. The current observed token is intentionally retained for causal continuation.

This property does not prove that the learned event occurs at the correct semantic command. A false write can create validity, continuous learned addresses can cross-talk, and a false reset can discard information. The new validity vector is an architectural intervention shared by both compared modes; improvement over the earlier memory would not by itself isolate the HCSN channel as the cause. Hard-forward erasure also does not imply zero backward credit through the straight-through computational graph.

`hard_event` has exact 0/1 forward values and identity surrogate derivative with respect to its probability argument; the sigmoid derivative remains upstream. This is a surrogate for optimization, not the mathematical derivative of a hard stopping time or a proof of free-boundary optimality.

## Campaign and comparison audit

The fixed campaign pairs seeds 613 and 719 across ordinary and HCSN modes, with the same architecture, 2276 trainable parameters, 176 persistent state floats, numeric initialization, generated training streams, optimizer, update schedule, and final-checkpoint rule. Matching parameter counts does not establish equal compute or gradients; the protocol correctly avoids that claim. Mapped Put+linear is evaluated as an additional verification using the same canonical parameters, with finite-precision event equality measured rather than assumed.

Before fitting, the runner checks an actual registration commit's protocol bytes and the current source hashes. Heldout panel construction occurs only after all four fixed fits complete. Development panels have distinct declared seeds, are logged at fixed update counts, and are not used for checkpoint selection or tuning. All errors, partial fits, and budget exhaustion are retained; no heldout substitute is run if the four fits do not finish.

The registered reset claim requires every model/seed to pass every fixed quality panel, zero UNKNOWN false accepts on both reset panels, a detected learned reset in every visible-command-to-first-query window, and a conditional erasure witness. The witness selects a model-produced event from a separately declared development stream, perturbs memory and validity while holding context fixed, and compares the returned state and scores. It is evidence for that conditional mechanism, not a quality score or a theorem over all contexts.

Two reporting qualifications remain important:

- The 180-second training budget is a soft stop. The 20-second evaluation reserve is not enforced as a kill switch or a hard total-runtime limit; revision 2 now states this explicitly.
- `event_diagnostics.write_events` counts proposed write events, including events cancelled by simultaneous reset. It should not be described as the number of effective memory updates. Reset events outside evaluator command windows likewise are not automatically mislabeled as errors.

No additional blocking source issue was found in this review after the numerical repair. This disposition is restricted to the reviewed design and execution contracts, not the campaign's yet-unmeasured scientific outcome.

## Reproduction and provenance

The portable `preflight_numeric_review.py` accepts `--root` (repository root, default current directory), optional `--module` (an archived source file), and a required fresh `--output` path. It refuses to overwrite an existing report. It constructs only hand-written numerical edge cases, not training or quality-panel data.

```bash
python preflight_numeric_review.py --root /path/to/repository --output /fresh/path/repaired.json
python preflight_numeric_review.py --root /path/to/repository --module original_reset_validity_before_review.py --output /fresh/path/original.json
```

Recorded files accompanying this review:

- `pre-repair-numeric-review.json`: actual original-draft reproduction.
- `post-repair-numeric-review.json`: actual revised-candidate reproduction with the same script.
- `original_reset_validity_before_review.py`: exact reviewed original source snapshot.
- `preflight_numeric_review.py`: portable reviewer script.

SHA256 provenance:

| Item | SHA256 |
| --- | --- |
| Original model | `393c2204a75b830f8713cd5dc968913660d036492a170305d3b01a673472d9fa` |
| Revised model | `7ebeaf9069bdd547a2e41d607345a3ce3b29c300d93acf187bdfb51ebc99a02d` |
| Campaign runner | `58e0481d630839bd851fd01366797d0514e3ed2db9c3981a34a94f5c1e106c49` |
| Revised model tests | `2cbff6ac73f6b346969d33c450df8438fffbe5a02b2d1223b3b4e12449de92e8` |
| Reviewer script | `0be225aac3b89bb580c2372eb221b53de1a245a5172183c35841ac092e3d0b4a` |

The independent role here is a separate internal reviewer, not external attestation. The implementation agent reported 13 scoped model tests passing; this note does not count those tests as independent scientific acceptance or as the full HCSN test suite.
