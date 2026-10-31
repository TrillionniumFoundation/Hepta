# HCSN iteration 20 — causal edge latch fails to close irregular-time OOD P2

**2026-10-31 · RESEARCH ONLY · all P0–P6 OPEN · DENY_ALL / NO_GO · production_activation=false.**

## Frozen upstream provenance (read before creating the child branch)

- main: `125d11c5454835a7df1dc51915fc49901fbede5b`.
- Original HCSN Draft #468 head `00a9dc11714f35866be18cd4fece5ce3addefc4a`, base `main`, Draft/open.
- Stationary renewal Draft #481 head `407201690a617629255d7f5d0968ce4c544c1b93`, base `research/hcsn-qvi-nonlocal-and-p1-controls-20261031`.
- Two-state Markov reset Draft #486 head `1aa8eb5f0efc2661472aa5a11221c07553152a03`, base `research/hcsn-stochastic-renewal-20261031-gpt6`.
- P2 succession: #487 `72df6bfde191c7a628e2bb17cc1057aa9681c0b5`; #492 `2eebea6f1001690106106a4596447150292f84b1`; #498 `c6631f7939cf0d9008026b4e5762d80e577827cd`; #500 `e3a23cfce69d94cab598dbb8fd23b9e92ce167e0`; #503 `9ee51122df8b40bf4c3aa46b5f41b8f702d9c04e`; #505 `2ce3267ca148a6568497cc20b27c09c26058b739`.
- Concurrent P0 Draft #509 is separately stacked on #468 at `9c0b7ebfd722877634f7ef74ac01d5e861dedc8e`; this patch does not alter it.
- This **additive-only** iteration is stacked directly on #505 exact head `2ce3267ca148a6568497cc20b27c09c26058b739`, not a second implementation of its ST surrogate and not a rebase of the independent #486 family.

## Testable hypothesis and mechanism

Draft #505 established the hard-forward straight-through (ST) surrogate can over-trigger resets under irregular OOD time, while matching hard-forward inference exactly. The new *edge latch* computes its event from a negative margin **only when armed**, disarms on firing, and rearms only on a later positive margin (optionally a positive hysteresis margin). The non-trainable per-trajectory boolean armed state is preserved across streaming chunks. The existing learned `AutonomousBoundaryMemory._step` parameters and its hard/soft values are unchanged; the latch reconstructs the non-reset write/decay substep using those same parameters.

This intervention is a **discrete-time debounce heuristic**, not He–Xiong QVI, not stochastic first-hit event-time differentiation, not a proof of surrogate-free training. The ST backward path still uses the original soft surrogate. It has extra hard-kernel/state work and **is not FLOP-matched** to the unlatched baseline.

## Exact local execution

Environment: Python 3.13, PyTorch 2.10.0 CPU, NumPy, threads capped to 1. **Local minimum research mirror**: upstream model `_step`, MQAR generator and #505 surrogate are behaviorally reconstructed from retrieved files, **not a byte-for-byte full upstream checkout**. All new source/test bytes themselves are verified as identical to the remote Git blobs. Do not report these tests as full GitHub CI.

```sh
cd <repo-root>
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  python -m unittest research.hcsn.test_p2_latched_event_falsification -v
# Local reconstructed subset: Ran 8 tests, OK, 0 skipped.

# Complete command to regenerate the three-seed exploratory study:
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  python -m research.hcsn.p2_latched_event_falsification \
  --steps 30 --batch 8 --length 56 --eval-n 24 --seeds 11 23 37 \
  --output /tmp/hcsn-iteration20-raw.json

# Actual execution was split into per-seed jobs after a single large
# invocation exceeded the local tool timeout. Each train_one(mode,seed,
# latch,steps=30,batch=8,length=56,eval_n=24) for all 3×3×2
# configurations completed; 18 records were combined without altering
# their recorded measurements. The committed compact evidence JSON
# retains every OOD per-seed comparison and the aggregates.

# Actual strict gate invocation (the gate is reconstructed byte-exact):
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
  python -m research.hcsn.independent_gate \
  --bundle research/hcsn/gates --strict \
  --output /tmp/hcsn-independent-iteration20.json
# Exit 2. All P0–P6 OPEN, full_closure=false,
# independent_attestation_verified=false, production_activation=false.
```

## Measured result — 3 paired seeds, 30 updates per model, 24 held-out streams/seed

OOD streams: 112 tokens with 6 contexts, irregular delta times; **five true context transitions per stream**. No event labels are included in the model's training target; training uses only query BCE. The dataset exposes context codes and is synthetic, not pretrained-encoder evidence. Same declared 17 parameters, train updates, and data for each analytic/ordinary/no-reset paired control; the `no_reset` temperature parameter has no active erasure pathway, so 17 is declared, not active. Latching adds boolean state/work.

| Variant (hard inference) | Query accuracy ↑ | Event precision ↑ | Detected events/stream | False predicted events/stream |
|---|---:|---:|---:|---:|
| Analytic level-ST | 67.4383% | 31.72% | 14.847 | 10.250 |
| Analytic latched-ST | 67.7469% | 32.18% | 13.653 | 9.333 |
| Ordinary level-ST | 67.5154% | 31.73% | 14.694 | 10.125 |
| Ordinary latched-ST | 67.7469% | 32.25% | 13.500 | 9.208 |
| No-reset control, level-ST | 72.2222% | 4.47% | 111.764 | 106.764 |
| No-reset control, latched-ST | 72.2222% | 0.00% | 1.139 | 1.139 |

**Important interpretation:** no-reset *predicted* crossings do **not** erase memory; therefore its event-precision fields are detector diagnostics, not applied-reset counts. All six modes have 18.0 OOD queries per stream (6 contexts × 3). On the easier ID streams, analytic and ordinary both achieve 100% query accuracy under both event policies; no-reset achieves 75%. This is a selective negative OOD result, not an overall quality ranking.

The latch reduces analytic OOD false event predictions by about 0.917/stream (8.94%) but also reduces event recall from 91.94% to 86.39%; query accuracy increases only 0.31 percentage points. **No Call/Put gain over ordinary gate is demonstrated; no-reset has higher OOD query accuracy in this limited task.** False resets remain more numerous than the five true transitions. This *falsifies the hypothesis that an edge latch alone closes the learned hard-event OOD failure*.

## Technical checks and source identity

- 8/8 local focused tests: hard/ST logit equality, 3-mode full/chunk streaming parity, persistently negative margin fires only once, finite surrogate gradient, prefix causality, invalid dt/release margin and short training. Zero skipped.
- For all 18 30-step runs, measured `st_hard_max_abs=0`; this is hard-forward **value** parity, not unbiased event-time gradients.
- New implementation: SHA256 `b441122b3bf8aa26e3993d1c20081f720c741746dfc88c6aa116ce00761ef418`; remote Git blob SHA-1 `f80e3178864fc9f3478f9ffec20d57662fd31b25` byte-matches local.
- New focused tests: SHA256 `6b1163fcfdfac0feffbc88984e65c55e94c71f59e05a39ff6f39054e846dc766`; remote blob `eb38da8170e8ba5ef2c0e96978cb72010c0a871a` byte-matches local.
- Base independent_gate.py remote and local Git blob `4611f0569f62bff00d932b7b7e95743dbbccbc29` exactly match; **strict exit code 2** observed locally.
- Per-seed OOD measurements: `gates/2026-10-31-iteration20-latched-ood-per-seed.json`. The JSON preserves all 18 seed/mode/policy rows; full local diagnostic JSON additionally retains ID/train times/losses.

## Outstanding scientific blockers — do not close

**P0:** Full original HX Eq8/11/12/A7 global obstacle and nonlocal QVI, low precision, independently bounded errors (see #468/#509 negative counterexamples).

**P1:** Matched local slope / trainable active parameters / FLOPs / budget with independently preregistered heldout causal gain; **prior ordinary-gate wins remain negative evidence**.

**P2:** Stronger autonomous learned first-hit/event-time training and no-input-label leakage on difficult MQAR/Selective Copy, long multi-seed OOD and genuine stochastic event-time gradients. This negative edge-latch result is **not acceptance**.

**P3–P4:** Real text/speech/vision/video pretrained weights plus independent cross-modal heldout, alignment, modality dropout, negative transfer.

**P5:** End-to-end CPU/GPU/RSS/p95/p99 and Joules, fused/quantized operators.

**P6:** Medium encoder scale-up, frozen compute and cost-quality frontier.

No independent signed scientific evidence, no full remote CI, no production activation, no main merge. Keep this PR Draft and upstream negative controls immutable.
