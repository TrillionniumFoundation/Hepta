# HCSN P0–P6 independent acceptance checkpoint (2026-10-31)

**Not production ready. ALL gates P0–P6 OPEN.** Existing local research bundle reverified on Python 3.13 / torch 2.10 CPU: **45/45 unittest passing**. Strict evidence gate returns exit code **2** by design. These are implementation checks, not proof of scientific closure.

## Existing comparative evidence (three seeds; previous recorded runs, not rerun this checkpoint)

| Task | HCSN v2 | Ordinary v2 | GRU |
|---|---:|---:|---:|
| Selective Copy ID | 93.099% | 93.750% | 100.000% |
| MQAR ID | 69.010% | 67.839% | 71.615% |
| MQAR long irregular | 62.630% | 58.854% | 67.708% |

HCSN has no demonstrated broad superiority. P1 independent paired regret excess, dual minus ordinary: ID +0.003783 [0.002219,0.005698], OOD +0.007077 [0.003591,0.011580] (exploratory bootstrap; not preregistered).

## Evidence identity (local files SHA-256)

- GATES.json: cea61cb4022029f9f81225a1f7035779e0fbeb295c6beec912a0b6e6c0276db0
- temporal_replicates.json: ccb8eb34718b67da901e41ce1699d2b2a3f8a19f128fe6124892254c37bd14f6
- p1_audit_results.json: 810bef3f283d4fd96c7871951ddc093d9c66ff39b20343d66d24ef1f6c8c8fdf
- perf_results.json: 5f5b03bde45db260ffa511a3878ec00c286928727caada32533b7408273e618b

## Remaining hard blockers

- P0: global admissibility, FP32 extremes, coupled HX and state-dependent regenerative QVI.
- P1: independent preregistered matched-slope and matched-FLOP ablations and net OOD gain.
- P2: long joint recall, trained multiple resets, gradient/long-horizon stability.
- P3: real frozen multi-encoder baselines with equal data and compute.
- P4: heldout missing-modality, alignment, cross-modal retrieval and negative transfer.
- P5: end-to-end CPU/GPU power, fusion, RSS, sustained throughput and p99.
- P6: trained medium encoder, continued pretraining, quality-cost frontier.

Do not merge into the production neural path or claim gate closure without an independent evidence bundle and required thresholds.
