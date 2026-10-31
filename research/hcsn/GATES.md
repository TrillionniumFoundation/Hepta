# HCSN scientific gate ledger — 2026-10-31

**No P0–P6 production acceptance gate is fully closed.** The core is research-only and must not be auto-enabled.

| Phase | Evidence currently available | Unclosed acceptance |
|---|---|---|
| P0 | Original He–Xiong 2012 (8), (11), (12), direct (A5/A7), independent Green and finite differences; new separate stationary regenerative QVI; local Taylor checks | Singular/hostile all-domain, strict FP32, state-dependent reset |
| P1 | Five-mode 161-parameter synthetic study, paired independent 420-state evaluations × three seeds | Signed local slopes, compute parity, net benefit vs ordinary gate |
| P2 | Synthetic selective-copy/MQAR BPTT, ordinary and GRU controls; sampled exact renewal resets | Long joint recall, true trained multi-reset, robust MQAR, stability |
| P3 | None with real encoder checkpoints | Real text/audio/image/video and matched Transformer/Mamba/SpikingSSM |
| P4 | None | Time/entity alignment, missing modalities, cross-retrieval, negative transfer |
| P5 | CPU-only PyTorch eager feature throughput/p50/p99; no power measurements | GPU/CPU fused end-to-end throughput, power, RAM, p99 |
| P6 | None | Medium encoder training and frozen quality–cost frontier |

## Actual measured values (local research only)

- Original HX baseline Eq12 boundary 67.44151539060374, independent quadrature root 67.44151539060366, smooth-fit derivative 5.71e-13. Direct Appendix A7 agrees with independent Green across baseline inputs.
- P1 dual vs ordinary exact regret on independent heldout: ID +0.00378 [0.00222,0.00570], OOD +0.00708 [0.00359,0.01158] (exploratory hierarchical bootstrap; positive = worse for HCSN). Call-only has 55.7% nearly zero feature Jacobians.
- P2 3-seed 140-step training, HCSN-v2/ordinary-v2 both 1270 parameters, GRU 1321: Selective Copy 24/48-irregular accuracy 93.1%/96.6% vs GRU 100%/99.7%; MQAR 69.0%/62.6% vs GRU 71.6%/67.7%.
- P5 CPU eager feature-only at batch 4096, one thread: dual p50/p99 0.135/0.298 ms; ordinary 0.167/0.338 ms. Not end-to-end and not GPU or energy evidence.
- 40 tests pass in the full local research bundle (including prior study modules). Branch's portable reference tests are a smaller subset.

## Run portable mathematical tests

```sh
python -m pip install -r research/hcsn/requirements.txt
python -m unittest discover -s research/hcsn -p 'test_*.py' -v
```

No passing test authorizes production activation. Reference: https://www.princeton.edu/~wxiong/papers/rollover.pdf
