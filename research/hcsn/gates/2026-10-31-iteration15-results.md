# HCSN P2 iteration 15 — observed learned-context reset panel (research only)

**Date:** 2026-10-31 UTC. **Source commit:** PR #492, based on Draft #487. **All P0–P6 scientific gates still OPEN; no production activation.**

## Reproducible sources and actual test runs

- Model / task script: \`research/hcsn/p2_learned_autonomous_content.py\`
- Tests: \`research/hcsn/test_p2_learned_autonomous_content.py\`
- Model source SHA256: \`5582d48f4131355c7ca51d49950097ef0ee718a085474b9860d384a961cdd8f5\`
- Model Git blob SHA1: \`ca2a2fcc80a7fef69762f9a5d700c255eb0c8147\`
- Local full raw experiment output SHA256: \`743b202609c7eab2030ef013f40fe0372001b64a1624ab18dae55cf1023ccc73\`
- Local run exit code **0**; 8/8 focused tests PASS on Python 3.13 / PyTorch 2.10 CPU. Also 18/18 tests PASS in the earlier standalone P0 exploratory bundle (not a reconstruction of the complete stacked GitHub research suite).
- Code and branch blob were verified byte-for-byte, after correcting a causal ablation confound before the final panel.

## Frozen experiment configuration

Exactly 17 active learnable parameters per model; seeds 11, 23, 37; 120 updates/seed/mode; Adam lr 0.012; batch 48; training length 42; ID test: 192 separate samples/seed, 42 steps, 3 context changes; OOD: 192 samples/seed, 84 steps, 5 context changes and irregular delta times. Supervised event BCE (+0.2 times; positive weight 8) and final-key label BCE. The context code is observable, but the event targets are **not input columns**. No independent external preregistration/sign-off.

| Model | ID hard recall | OOD hard recall | Event precision/recall | Applied hard resets ID/OOD | Mean train wall/seed |
|---|---:|---:|---:|---:|---:|
| Analytic Call/Put/margin | 100.0% | 100.0% | 100% / 100% | 3 / 5 | 7.23 s |
| Ordinary sigmoid/sigmoid/margin | **100.0%** | **100.0%** | 100% / 100% | 3 / 5 | 5.66 s |
| Same analytic features, erasure disabled | 63.89% | 63.89% | 100% / 100% detector only | **0 / 0** | 6.64 s |

All 9 training experiments completed and all hard/soft accuracy outcomes match within each model. ID and OOD paired sample seeds were identical across the three modes. The no-reset control still **predicts** boundary events (training BCE) but does not execute erasure; its event count is not evidence of a physical reset. Individual no-reset ID hard accuracies: 61.46%, 65.10%, 65.10%. OOD: 62.50%, 60.42%, 68.75%.

### Mandatory negative interpretation

- Hard state erasure has a large positive effect on *this intentionally simple synthetic context-memory task* (analytic minus no-reset +36.11 percentage points in both ID and OOD).
- **There is zero demonstrated independent Call/Put advantage:** the ordinary parameter-identical gate also reaches 100% on both ID and OOD. The preregistered narrow mechanism-superiority criterion therefore **FAILS**.
- This experiment supervises the context transition detector; it does **not** show autonomous *unsupervised* optimal stopping or a learned QVI, nor a general-purpose MQAR solution.
- Exact 3/5 learned boundary-triggered events are simulated and state is actually erased, unlike the old forced-marker study. However context flips are simple and directly observable; the benchmark is insufficient to close P2 long-horizon recall.
- No matched FLOP/signed-slope study, independent multi-institution signoffs, real encoder quality, GPU, power, or medium-size pretraining. The 100% scores have **no relevance** to P3–P6 acceptance.

## Run (repo root)

    OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest research.hcsn.test_p2_learned_autonomous_content -v
    OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m research.hcsn.p2_learned_autonomous_content --steps 120 --batch 48 --length 42 --eval-n 192 --seeds 11 23 37 --output /tmp/hcsn-p2-iteration15.json

Research-only Draft #492; strict independent evidence gate remains fail closed.
