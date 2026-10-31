# HCSN P2 iteration 19 — hard-forward/soft-backward surrogate falsification

**Status: research-only; ALL P0–P6 OPEN; DENY_ALL / NO_GO.** This is a follow-up stacked on the iteration 18 synthetic query-memory experiment; existing research code and results are preserved. It is NOT true event-time differentiation or original He–Xiong financial QVI.

## Hypothesis and intervention

Iteration18 ordinary soft/BPTT trained `analytic`/`ordinary` yielded ID query accuracy 100%, OOD hard 99.38%, but OOD soft 90.28%. Hard-forward soft-backward straight-through (`ST`) attempts to eliminate this forward mismatch, using the exact hard reset memory in the forward pass and the soft-memory path for gradients:

`m_ST = stopgrad(m_hard) + m_soft - stopgrad(m_soft)`.

This **is a surrogate gradient** (not the original claimed continuously differentiable free-boundary event gradient), and requires computing both soft and hard memory transitions during training. Thus it has additional compute cost and is not a FLOP-matched improvement claim. Baseline, ordinary and no-reset modes still use the same original 17 declared parameters; no-reset temperature remains inactive.

## Executed verification (local isolated reconstructed model subset, no GH CI)

- 11/11 focused iteration18+19 tests passed, 0 skipped; specifically 4/4 new tests: exact hard-forward equivalence for all 3 modes, finite backprop through threshold with surrogate, streaming chunk equivalence, bounded training path.
- 9 new scoped CPU FP32 task-only trainings; matched three seeds 11/23/37, 30 updates, batch 12, ID length 56, OOD length 112, 48 heldout streams per split and seed. Same input generation, loss/optimizer/updates as iteration18 except for the ST gradient/forward implementation.
- **Every evaluated ST forward logit equals hard-inference logit exactly** (max measured absolute difference zero) on both ID/OOD. This *implementation-level parity* is not a proof of training gradient correctness, event-time sensitivity, optimal stopping or OOD generalization.
- `p2_hard_forward_soft_gradient.py` SHA256: will be listed in evidence JSON and validated against Git SHA after upload. Full local exploratory raw evidence also stored in bundled artifacts; local model dependency was reconstructed, not a full exact GitHub checkout.

## Explicit negative results (mean across 3 paired seeds)

| Variant | ID hard | OOD hard | OOD event precision | OOD event recall | Mean predicted OOD events / stream | OOD no-ST soft |
|---|---:|---:|---:|---:|---:|---:|
| Analytic ST | 100.00% | **66.59%** | 29.98% | 93.75% | **15.75** | 62.77% |
| Ordinary ST | 100.00% | **66.74%** | 30.59% | 93.33% | **15.38** | 62.77% |
| No-reset ST | 75.00% | 72.22% | 4.47% (detector only) | 100.00% | 111.74 predicted, **0 applied** | 72.22% |
| Iteration18 analytic, normal soft BPTT | 100.00% | **99.38%** | 100.00% | 82.22% | **4.11** | 90.28% |

The true OOD context event count is 5 per stream. The ST-trained HCSN analytic model predicts ~15.75 crossing events; high recall with very low precision triggers excessive state erasure. The **27–33 percentage-point OOD hard accuracy regression** vs the previous normal-BPTT model means the hypothesis "hard-forward parity solves temporal stability" is **falsified on this benchmark**, despite exact forward equivalence. The conventional ST gate is almost identical: no independently demonstrated Call/Put advantage.

The task exposes explicit +/-1 contexts, has 6 keys and short synthetic token lengths; cannot claim actual multilingual text, speech, video, real MQAR or pretrained Encoder performance. No matched FLOPs, slopes, energy, full-model p99, BF16, GPU, independent preregistration or external scientific signoff. **P2 remains OPEN.**

## Reproduce

From the stacked branch with `existing` `AutonomousBoundaryMemory` and iteration18 files:

```sh
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest research.hcsn.test_p2_multiquery_noevent research.hcsn.test_p2_hard_forward_soft_gradient -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m research.hcsn.p2_hard_forward_soft_gradient --steps 30 --batch 12 --length 56 --eval-n 48 --seeds 11 23 37 --output /tmp/hcsn-iteration19-st.json
```

The source leaves `production_activation=false`, `scientific_gates_closed=false`, and identifies `surrogate_gradient=true`. **Next blocker:** suppress excessive spurious resets under longer irregular intervals while retaining BPTT signal, then validate first-hitting/event-time sensitivities independently and conduct fair matched-CPU/GPU tests. Do not make ST the default production path.
