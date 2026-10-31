# Hepta Continuous Spiking Network — research gates (2026-10-31)

This branch is **research-only**, not a production activation. It investigates He–Xiong (2012), *Rollover Risk and Credit Risk*, Journal of Finance 67(2), equations (8), (11), (12) and Appendix (A5)/(A7), plus a **new, separate** regenerative QVI neuron.

## Integrity rules
- Never conflate the original credit model with the simplified Call/Put neuron or the newly constructed impulse-reset QVI.
- A passing numerical test is not a proof of global parameter admissibility.
- Dual Call/Put has **not** beaten the ordinary two-gate control on the existing matched-parameter synthetic decision task.
- CPU-only synthetic sequence tests do not validate text/audio/image/video encoders or hardware power efficiency.
- Production HCSN switching stays disabled until P0–P6 acceptance criteria have independent evidence.

## Current locally reproduced results
- Original HX baseline: analytic Eq. (12) threshold 67.44151539060374; independent Eq. (11) Green smooth-pasting threshold 67.44151539060366; boundary derivative residual 5.71e-13.
- Direct original Appendix A7 equity agrees with independent Green solution to approximately 1e-13 in the baseline points; finite sampled parameter tests pass. The near-degenerate z-z_hat denominator remains a guarded blocker.
- New regenerative QVI: analytic value matching, smooth fit, complementarity, and exact first-passage reset-time sampling; validated only in stated experimental domain.
- Heldout decision audit (three seeds, 420 states each): dual-minus-ordinary exact regret +0.00378 ID (exploratory CI [0.00222,0.00570]), +0.00708 OOD ([0.00359,0.01158]). Analytic gate superiority **not demonstrated**.
- Short Selective Copy / MQAR CPU tests: learned selective-write HCSN improves over its non-selective version, but GRU remains stronger. No full long-sequence certification.
- 4096-example PyTorch CPU eager feature probe: dual Call/Put p50 0.135ms and p99 0.298ms; ordinary baseline p50 0.167ms and p99 0.338ms, **not** a fused-kernel or energy comparison.

## Open blockers
P0: original (A7) all-domain and FP32 extreme cases; formal checks and hostile boundaries; regenerative resets outside stationary fixed-reset model.
P1: slope and FLOPs matching; actual independent improvement vs strong controls.
P2: MQAR, joint retrieval, long context, multiple resets *under trained policy*.
P3–P4: real heldout text/speech/vision/video encoder and multimodal alignment benchmarks.
P5: real CPU/GPU fusion, target hardware power, throughput, peak RSS and p99 end-to-end.
P6: medium-size encoder and scaling quality–cost frontier.

Paper: https://www.princeton.edu/~wxiong/papers/rollover.pdf
