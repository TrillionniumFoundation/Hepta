# HCSN P0–P6 Iteration 7 — Independent original HX equity finite differences

**Research-only, 2026-10-31. P0–P6 scientific gates remain OPEN; production_activation remains false.** This checkpoint is a bounded independent cross-check of the **original** He–Xiong 2012 equity value Eq. (11), original bond Eq. (8), free boundary Eq. (12), and Appendix A7; it is *not* a neural performance result.

## New source on the research PR branch

- \`research/hcsn/hx_equity_fd_independent.py\`: monotone log-state tridiagonal finite-difference discretization of original Eq. (11). Eq. (8) bond value is evaluated as the PDE source. The equity solver and the independent numerical smooth-pasting root do **not** call Eq. (12), A7, equity Green, or their smooth-pasting integrals.
- \`research/hcsn/test_hx_equity_fd_independent.py\`: four test methods, six bounded original-HX panels, three mesh levels (800/1600/3200), fixed six log-margins, far-field check and invalid-parameter rejection.
- \`research/hcsn/p0_equity_fd_evidence.py\`: deterministic JSON generator, exclusive-create output, source hashes, all-gates OPEN status.

GitHub git-blob SHA (checked against locally run exact source):
- solver: \`c3801c5a3f2607371b7d9d17916f49fbcb103877\`
- tests: \`37444784dd832d50101ec0c5b84182a38a3e9f95\`
- evidence script: \`60527e3327dac12e9fdf21c67cd208bbf8c11841\`
- introducing commit: \`cf10090a0acf72d00d830b2b08bf24e7ef34285b\`.

## Reproducible local experiment

From repo root:
\`\`\`bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m unittest discover -s research/hcsn -p 'test_*.py' -q
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m research.hcsn.p0_equity_fd_evidence --output /tmp/hcsn-equity-fd-iteration7.json
python -m research.hcsn.independent_gate --bundle research/hcsn --strict
\`\`\`

Locally actually executed against byte-identical files under \`/mnt/data/hcsn_round5_20261031\`: **89/89 CPU tests passed** (the local bundle also includes a separate concurrently advanced four-test first-passage density check; this local count must not be confused with a remote CI result). The evidence generator produced six parameter panels, 36 equity checkpoints, and 18 independent numerical boundary roots.

Bounded results:
- Maximum \`abs(E_FD - E_Green)/max(1,abs(E_Green))\` at fixed x points: **0.00026263308181517786**, about **0.0263%**.
- Maximum Richardson-extrapolated free-boundary relative error versus Eq. (12): **1.7908688396683914e-6**, about **0.000179%**.
- Maximum original Eq. (11) tridiagonal interior algebraic residual in the six tested panels: below **1e-7**, with finite mesh; this is *discrete* not continuous-domain proof.
- Baseline Eq. (12) boundary **67.44151539060374**; FD 3200-cell boundary **67.43977757009802**; second-order extrapolated **67.44150182699151**.
- Deterministic panel JSON SHA256: \`72730092a62167aa7e0849696cf6f969b0223b4b3f8e2b5ab8565846dd4b0a58\`.
- Independent signed scientific gate: **exit code 2**, expected failure due to absent external trust root and missing P0–P6 evidence. No production activation and no main merge.

This is **not preregistered independent replication**: the six case choices, diagnostic thresholds, and grid order were exploratory. Richardson extrapolation supplies numerical convergence evidence, **not** a rigorously certified a posteriori error interval. The original A7 expression has a removable singularity near \`xi*k=0\`, so the zero-liquidity panel uses Eq. (8)/Eq. (11)/Eq. (12)/Green and does **not** pretend to validate the direct A7 formula there.

## Still-open scientific blockers

| Gate | Open closing evidence |
| --- | --- |
| P0 | Original coupled solution global admissibility, singular/near-boundary quantitative FP32/BF16/gradient certification, time-varying/nonlocal QVI and real workloads |
| P1 | Independent matched-slope/FLOPs/train-budget positive heldout gain against ordinary gates; earlier ordinary gate still wins |
| P2 | Long autonomous multi-reset Selective Copy, MQAR and joint recall, many seeds and event-count transition BPTT |
| P3 | Genuine text/speech/vision/video pretrained encoder experiments; Transformer/Mamba/SpikingSSM fair baselines |
| P4 | Heldout cross-modal temporal/entity alignment, missing modality, retrieval and negative transfer |
| P5 | Target device fused kernels, measured joules/throughput/RSS/p95/p99 and low-precision equivalence |
| P6 | Medium encoder training, distillation, continuous pretraining and frozen quality–cost frontier |

**All P0–P6 remain OPEN and production disabled.** The numerical subgate advances P0 reproducibility only.
