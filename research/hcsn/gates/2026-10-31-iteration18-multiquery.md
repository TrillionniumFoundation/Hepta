# HCSN P2 iteration 18 — task-only multi-query memory and hard/soft reset gap

**2026-10-31; research-only stacked on Hepta Draft PR #500 HEAD `e3a23cfce69d94cab598dbb8fd23b9e92ce167e0`. ALL P0–P6 scientific gates remain OPEN; no production activation, no main merge.**

## Exact scope and method

An additive P2 synthetic evaluation of the existing 17-parameter `AutonomousBoundaryMemory` from PR #492, which is reachable through the stacked #500 branch. No changes to that model or the original HX PDE/QVI. Compare `analytic`, `ordinary` and `no_reset` (the latter still includes one *inactive* temperature parameter; do not claim equal active parameter count in that ablation). Training uses only query binary cross entropy. There is **no event-label supervision**, no true-event bit in the input, and no future-query information. Context value itself remains directly visible (alternating +/-1), making this an intentionally limited task.

Every sample contains four contexts, 3 queries per context, a positive key written in the first context but forbidden from reappearing in later writes, and current-context positive and negative keys. Querying the stale key in every later context measures real erasure. Independent dictionary semantics (`exact_stream_oracle`) proves 100% attainable; identical writes without resets make exactly 1 stale-positive error per context after the first. Evaluation adds 6 contexts, doubled length and irregular positive timestamps.

- Seeds: 11, 23, 37; 30 task-only Adam updates / model / seed; batch 12; learning rate 0.012; train/ID length 56 and OOD length 112; 48 separately seeded test streams / seed / split. 17 declared learnable tensor scalars per mode; no slope/FLOP matching.
- Each ID eval has 48*4*3=576 query labels per seed; OOD 48*6*3=864 per seed. Three seeds aggregate 1,728 ID and 2,592 OOD query labels per mode. The data generator is synthetic and not a held-out pre-trained encoder.
- Local Python 3.13 / PyTorch 2.10 CPU: **7/7 new tests passed** (0 skipped) on isolated subset reconstructed from the GitHub model. 9 scoped training runs executed, one per seed/mode; unit tests verify deterministic generator, precise stale distractor, no future leakage, chunked/full recurrence equivalence, hard-event vs detector-only semantics, and finite BPTT gradients.
- Source SHA256 of iteration script: `a9a33abc3ff9f5f98506c3f2079ba4da6606ee262cfbb77b79e4a7c90c3e67cf`; full local raw JSON SHA256 `3307d2e62e05ac8cc499e5e51ce853ccc1bd29907066f6063ec977b655829590` (the full standalone bundle is available separately). No clean GitHub CI, exact full-branch checkout, GPU or watt-hour proof is claimed.

## Observed values: means across three paired random seeds

| Gate feature | Analytic | Ordinary | No reset |
|---|---:|---:|---:|
| ID soft/hard query accuracy | 100.00% / 100.00% | 100.00% / 100.00% | 75.00% / 75.00% |
| ID event precision / recall | 100.00% / 94.68% | 100.00% / 94.68% | 5.36% / 100.00% (detector only) |
| ID applied hard resets per stream | 2.840 | 2.840 | 0 |
| OOD soft query accuracy | 90.28% | 90.28% | 72.22% |
| OOD hard query accuracy | 99.38% | 99.38% | 72.22% |
| OOD event precision / recall | 100.00% / 82.22% | 100.00% / 82.22% | 4.47% / 100.00% (detector only) |
| OOD applied hard resets per stream | 4.111 | 4.111 | 0 |

**Mandatory negative interpretation:** the analytic channel gives exactly **zero measured benefit** over ordinary gates on every reported accuracy (not statistically distinguishable as a performance difference here). True reset is beneficial on this contrived stale-memory task, but that is not proof that financial Call/Put operators are beneficial. The soft training path underperforms hard execution by ~9.1 percentage points OOD; training/deployment equivalence therefore remains an open blocker. The no-reset detector is not a reset operation and its event precision must not be read as actual reset precision. This benchmark may be solved by a trivial causal context-change gate; more realistic MQAR, long distraction, non-trivial context inference and masked modalities remain open.

## Reproduction

From a branch containing `research/hcsn/p2_learned_autonomous_content.py`:

```
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest research.hcsn.test_p2_multiquery_noevent -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m research.hcsn.p2_multiquery_noevent --steps 30 --batch 12 --length 56 --eval-n 48 --seeds 11 23 37 --output /tmp/hcsn-p2-iteration18.json
```

The raw result schema includes per-seed losses, gradient maxima, query/event statistics, wall-times, source SHA and explicit `scientific_gates_closed=false`. Do not overwrite original research evidence.

## Remaining scientific blockers P0–P6

P0 original global HX coupled obstacle, low-precision and QVI; P1 equal compute/signed-slope net benefit (current evidence is negative); P2 nontrivial autonomous long-context MQAR, event-time gradients, crash/restart, and soft-hard equivalence; P3 real four-modal pretrained encoder comparisons; P4 multimodal alignment/missing-modality/generalization; P5 fused GPU/Joules/p99/RSS at full model; P6 medium-scale pretrain/distillation quality-cost frontier. No independent signed acceptance, and **DENY_ALL / NO_GO** stays active.
