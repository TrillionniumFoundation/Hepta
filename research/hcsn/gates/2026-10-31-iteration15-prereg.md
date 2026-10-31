# HCSN P2 iteration 15 — learned context boundary reset protocol

Research-only stacked on PR #487. Scientific P0–P6 OPEN; production_activation=false.

## What is being tested
A causal model learns a time-varying signed log-margin and triggers true hard resets
when the current input context changes. The model is supervised by a separate
event label at training time, not given an event flag as input. It has an explicit
key/value scratchpad and is **not** an unsupervised free-boundary optimal-stopping
solution, general He–Xiong A7/QVI, or a pretrained text/image/audio/video encoder.

## Frozen local protocol (documented locally before the experiment)
- Modes: analytic continuous Call/Put/margin, ordinary sigmoid/sigmoid/margin,
  and no-reset ablation; all have identical 17 trainable parameters and optimizer.
- Seeds 11/23/37, 120 Adam updates, 48 examples per update, sequence length 42,
  4 contexts (=3 true changes), learning rate .012.
- Objective: final-key binary recall BCE plus .20 times transition BCE
  (positive-event weight 8). Ground-truth transition indicators are loss targets
  and never part of the model input.
- Independent frozen generator seeds for evaluation: ID = 192 examples with
  4 contexts and length 42; OOD = 192 examples with 6 contexts, length 84 and
  irregular dt. No test-time training.
- Report per-seed and aggregate hard/soft accuracy, hard reset count, event
  precision and recall, training times, and source SHA256.
- Exploratory *narrow-task* target (not a scientific release signoff):
  analytic ID/OOD accuracy >=.90, event precision/recall >=.95,
  3+ actual ID resets, AND positive net advantage over ordinary control
  on both ID and OOD. If analytic and ordinary tie, mechanism superiority fails.
- Unclosed matching: FLOPs, signed slopes, energy, real encoders, independent
  scientific preregistration/signatures, and scaling.

## Reproduction

    OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest research.hcsn.test_p2_learned_autonomous_content -v
    OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m research.hcsn.p2_learned_autonomous_content --steps 120 --batch 48 --length 42 --eval-n 192 --seeds 11 23 37 --output /tmp/hcsn-p2-iteration15.json

No production activation, no main merge, no scientific gate flip.
