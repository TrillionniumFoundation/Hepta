# HCSN P2 iteration 20 — causal edge/refractory negative-control follow-up

**2026-10-31 | Research only | P0–P6 OPEN | production_activation=false | DENY_ALL / NO_GO**

## Frozen upstream context

- Hepta main observed SHA: `125d11c5454835a7df1dc51915fc49901fbede5b`.
- Upstream research Draft #505 `2ce3267ca148a6568497cc20b27c09c26058b739`, stacked on #503; this experiment uses its `AutonomousBoundaryMemory`, ST rollout and multiquery generator.
- No modification to the original financial He–Xiong 2012 equations or production gate.
- **Important limitation**: local execution reconstructed the upstream model core and task generator from the read GitHub sources. It was not an exact full remote checkout and was not GitHub CI. The new uploaded source and test can be replayed against the real upstream branch.

## Experiment and intervention

The iteration19 straight-through (ST) negative result predicted 15.75 analytic and 15.38 ordinary OOD threshold events per 112-token sequence despite exactly five true context transitions. The new evaluation-only filter uses **the same trained ST weights for all conditions**:

1. `raw`: original hard policy (exact logit parity asserted, no filtering).
2. `edge`: fire only when raw margin enters its nonpositive region from a previously positive region.
3. `edge_refractory`: the edge rule plus fixed 8-token cooldown after each applied event.

Training: three paired seeds 11/23/37, 30 steps, batch 12, length 56; identical ST optimizer and query-only BCE training. Heldout ID length 56 / four segments; heldout OOD length 112 / six segments and irregular delta-times; 48 sequences per seed. `no_reset` is detector-only and applies zero erasures. No event labels are consumed during training or filtering; they are used only for offline metrics. Cooldown=8 was chosen before the local rerun but not independently preregistered and cannot qualify as confirmation.

## Measured paired OOD means (3 seeds, local CPU FP32)

| Model and policy | Hard query accuracy | Applied events / stream | False applied / stream | Applied event recall |
|---|---:|---:|---:|---:|
| Analytic raw | 66.59% | 15.750 | 11.062 | 93.75% |
| Analytic edge | 66.71% | 14.236 | 9.861 | 87.50% |
| Analytic edge+8 | 73.69% | 8.514 | 6.069 | 48.89% |
| Ordinary raw | 66.74% | 15.382 | 10.715 | 93.33% |
| Ordinary edge | 66.86% | 14.000 | 9.639 | 87.22% |
| Ordinary edge+8 | 74.04% | 8.465 | 5.965 | 50.00% |
| No-reset, all policies | 72.22% | 0 | 0 | 0% applied |

ID hard query accuracy remained 100% for analytic/ordinary and 75% for no-reset across conditions. Raw parity held exactly for every evaluated hard-forward logit and detector mask. The three analytic seed-level OOD accuracies were raw 67.94/66.20/65.62%, edge+8 74.31/73.96/72.80%.

**Interpretation: a partial recovery, not a scientific pass.** Analytic accuracy improves by ~7.10 percentage points relative to raw ST but remains below the previous normally trained OOD hard baseline (~99.38%). The cooldown eliminates some false resets while **losing nearly half of real event recall**. Ordinary remains slightly better than analytic under the same intervention. Neither analytic Call/Put gain nor learned correct event-time derivatives is shown.

## Executed checks and reproducibility

Local focused 7/7 unittest cases passed (no skips): raw upstream hard parity across all three modes; stuck-negative event de-duplication; full/chunk equality; causal prefix; per-batch isolation; cooldown never adds firings versus edge-only; fail-closed invalid inputs; same-weight training smoke.

From a checkout with upstream Draft #505 contents plus the new files:

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest research.hcsn.test_p2_event_refractory_diagnostic -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m research.hcsn.p2_event_refractory_diagnostic --steps 30 --batch 12 --length 56 --eval-n 48 --seeds 11 23 37 --output /tmp/hcsn-iteration20.json
```

Source SHA256 (`p2_event_refractory_diagnostic.py`): `92676eaf13c79a0b32666212f564d1f61546c6f1498eecc548528f4f07361d55`.

The companion raw JSON contains row-level seed/model/split/condition metrics. Reproducibility is **local scoped**, no remote CI/full checkout, no independent preregistration or sign-off. Per-seed data are exploratory rather than a statistically powered broad claim.

## Residual strict gates

- P0: Original coupled HX full parameter domain, smooth pasting/FP32 certification, dynamic regenerative QVI.
- P1: equal-parameter **and** FLOP/slope/budget causally isolated superiority. Negative HCSN-vs-ordinary evidence remains.
- P2: autonomous long-horizon Selective Copy/MQAR + event recall/precision, exact event-time sensitivity, irregular-time streaming robustness. Current cooldown fails recall.
- P3/P4: real heldout text/audio/image/video encoders, temporal alignment, missing modality/negative transfer.
- P5: full-model GPU/CPU/fused-kernel Joules/RSS/p99.
- P6: frozen-budget medium encoder, pretraining/distillation and independent quality-cost frontier.

**Recommendation:** do not promote the refractory filter to production. Next compare fully causal, gradient-bearing event *hazard* or compensated reset loss under matched compute and heldout longer irregular streams, and reject mechanisms that trade recall for apparent accuracy.
