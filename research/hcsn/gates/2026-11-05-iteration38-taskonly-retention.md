# HCSN P2 Iteration 38 — task-only learned noncommuting CTMC retains order briefly but loses memory with positive blank hazard

**Research-only / HOLD / DENY_ALL. All P0–P6 OPEN; production_activation=false.**

Repository: `TrillionniumFoundation/Hepta`. Reviewed before editing: `main` `125d11c5454835a7df1dc51915fc49901fbede5b`; original Draft #468 `00a9dc11714f35866be18cd4fece5ce3addefc4a`; stochastic renewal #481 `407201690a617629255d7f5d0968ce4c544c1b93`; two-state Markov reset #486 `1aa8eb5f0efc2661472aa5a11221c07553152a03`; prior P2 Draft #512 `c31c4cb7c7e004341141c4e44bf95421a6f8fdd4`. Other HCSN Draft branches #463/#483/#487/#492/#498/#500/#503/#505/#509/#511/#513/#526/#527 were inspected for branch status and file-path overlap. This change adds new file paths only, no rebase, no main merge, no production activation or security/signature changes.

## Narrow independently checkable finding

Iteration 37 showed noncommuting input-conditioned CTMC generators can distinguish two-write order with a single endpoint state. That result did *not* test whether this information survives long blank periods, or whether the rates can be learned exclusively from task labels. In this follow-up, six rates are optimized by exact differentiable two-state CTMC transfer via Torch, with **only final last-write binary labels**. Three seeds (11, 23, 37), 420 Adam steps each, 16 balanced train schedules using write durations 1 s and blank delays 0/0.5/1/2 s. No event times, internal states, or resets are supervised; no OOD delay used in training.

Let `a_x` and `b_x` denote input-conditioned `0→1` and `1→0` rates. The exact physical-time transition is

`p_1(t+Δ)=a_x/(a_x+b_x)+(p_1(t)-a_x/(a_x+b_x))*exp(-(a_x+b_x)Δ)`.

For *any* pair of write histories A and B followed by the same blank generator, their endpoint separation after a blank of duration `D` is precisely

`|p_B(D)-p_A(D)|=|p_B(0)-p_A(0)| exp(-(a_blank+b_blank)D)`.

In the particular architecture here, all rates have a prescribed floor `epsilon=0.04 s^-1`, so the **balanced single-state readout Bayes-optimal accuracy** obeys

`accuracy(D) ≤ 1/2 + (1/2)exp(-0.08 D)`.

This is a conditional no-go result for this constrained two-state CTMC, **not** a theorem about general HCSN, regenerative QVI, moving boundaries or learnable memory with an absorbing blank state. An exact zero-blank-hazard ablation retains its initial gap, and is tested separately. The floor is a controlled mechanistic intervention; it is *not* learned from original HX or inferred to be mandatory.

## Reproduced measurements (2026-11-05 UTC)

| Seed | Initial/final supervised NLL | Bayes accuracy, blank 0 s | 16 s | 64 s | 256 s |
|---|---|---:|---:|---:|---:|
| 11 | 0.681899 / 0.042928 | 0.990384 | 0.632261 | 0.502595 | ≈0.500000 |
| 23 | 0.673806 / 0.042942 | 0.990182 | 0.632842 | 0.502644 | ≈0.500000 |
| 37 | 0.634081 / 0.042604 | 0.991035 | 0.631895 | 0.502556 | ≈0.500000 |

These are **exact Bayes accuracies** for equal-prior labels given **one sampled final two-state observation**. They are *not* empirical hard MQAR accuracy, and are *not* accuracy for an unrestricted decoder that can read the entire event history. The task-only training loss is an analytical endpoint likelihood rather than an event-timing loss.

Independent SciPy DOP853 and `scipy.linalg.expm` checks over 60 random rate/schedule cases show max absolute errors `8.55e-15` and `2.61e-15` against the separate closed-form transfer, respectively. Sampling refinements 4/16/64 have max absolute difference `7.77e-16`. Independent continuous-time Gillespie simulator checks use 60,000 trajectories (3 model seeds × 2 opposite-last-write histories × 10,000) at unseen 16 s blank; max normal-approximation standardized discrepancy `2.66σ`, with >1 mean autonomous event per path. Seven tests passed locally. Strict generator exit status **actually measured 2**; JSON with all seven gates OPEN was identical in strict and nonstrict runs.

## Independent exact commands

From the repository root, with Python packages in `research/hcsn/requirements.txt`:

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  PYTHONPATH=research/hcsn python -m unittest discover -s research/hcsn -p test_p2_task_only_ctmc_retention.py -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  python research/hcsn/p2_task_only_ctmc_retention_evidence.py > /tmp/hcsn-iter38.json
cmp /tmp/hcsn-iter38.json research/hcsn/gates/2026-11-05-iteration38-taskonly-retention-raw.json
set +e
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  python research/hcsn/p2_task_only_ctmc_retention_evidence.py --strict > /tmp/hcsn-iter38-strict.json
code=$?
set -e
test "$code" -eq 2
cmp /tmp/hcsn-iter38.json /tmp/hcsn-iter38-strict.json
# Strict nonzero is required. Do not suppress failure with `|| true` in a gate.
```

## Important limitations / preserved negative results

- Not the He–Xiong 2012 original Eq 8/11/12/A7, independent full-domain/FP32/QVI proof, nor an actual Brownian stopping boundary. No P0 closure.
- Not the P1 same local slope/parameter/FLOP/training-budget, stronger ordinary gate or exact DP experiment. Prior P1 negative regret stays negative.
- Only synthetic two-write last-write memory and positive background hazard; not full learned self-resetting HCSN, censored multi-reset Markov laws, irregular-time long Selective Copy, MQAR or multisource/multiseed OOD. Prior negative P2 outputs preserved.
- P3–P4 pretrained real four modalities/heldout, P5 real CPU/GPU end-to-end energy/RSS/p95/p99 and P6 medium-model quality-cost remain untested here.
- Draft #468 CodeQL run `124550087193` remains a `failure` with 1 high-severity alert; inaccessible annotation details are not guessed. Draft #512 prior HEAD had no check runs at inspection. This local reference is not external independent certification.

**Gate rule:** all P0–P6 `OPEN`; production activation `false`; `--strict` must exit nonzero (2) even with passing numeric checks. Do not change signature enforcement, production gates, or merge into main.
