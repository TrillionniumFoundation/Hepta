# HCSN P2 iteration 12 — two-mode Markov reset + refractory law

**SCIENTIFIC GATES P0–P6 OPEN. Research only. No production activation or merge to main.**

## Exact restricted mathematical statement

Between autonomous events, signed log margin X_t follows dX = mu dt + sigma dW, until its first passage to zero. After each event, a deterministic refractory interval rho is applied and the margin resets to either R0 or R1. The first reset mode Z1 follows pi and subsequent reset modes follow the two-state row-stochastic transition matrix P, independently of the Brownian path.

Define S_k = sum(R_{Z_j}) for j=1..k. Strong Markov and spatial homogeneity yield

    P[N(T) >= k+1] = E_Z[F(T-k*rho,x0+S_k)]

and each discounted event transform is exp(-lambda*k*rho) times the corresponding Markov-mode expectation of G at the effective horizon T-k*rho. F and G are the verified affine Brownian first-hitting operators. A dynamic-programming mode count runs in O(K^2) rather than enumerating 2^K reset sequences.

The code outputs the complete finite K count histogram plus **separate censored tail P(N>K)** and expected count/discounted event reward lower bounds. It rejects nonfinite inputs, out-of-domain inputs, unsupported zero-discount gradients, malformed Markov probabilities, and unresolved count tails when a caller supplies a tail budget.

These are **exact under restricted fixed-coefficient, path-independent two-mode reset assumptions**, not the original He–Xiong equity or endogenous QVI, not an input-conditioned adaptive neuron and not proof of superior machine learning accuracy.

## Tested locally on 2026-10-31

- 11/11 new tests, 135/135 tests when integrated with the locally reconstructed preceding research suite, CPU PyTorch 2.10, Python 3.13. Neither complete remote CI nor formal proof is asserted.
- Exhaustive independent 2^k mode sequences using separately implemented first-passage density quadrature; fixed-reset equivalence; alternating modes; mode correlations; extreme refractory; positive-drift defective first-passage; full probability normalization.
- Independent signed finite-difference vs torch autograd checks over 11 unconstrained model coordinates.
- Three exact-event-time inverse-Gaussian/Levy Monte Carlo panels of 100,000 paths each for negative/zero/positive drifts. Descriptive max |z| count 1.31019, reward 0.59267. **Exploratory only; not preregistered.**
- Actual local source SHA256: markov_reset_renewal.py f254227db2b3aa54a0c29c452116eecb1397771f4ac6283b336eb63197a51ab8; test_markov_reset_renewal.py ca47c34723a678059fe9fa82eb59441bb6bb75f38bc07d8a6decbdc60c83ad53.

## Reproduce

~~~bash
python -m pip install -r research/hcsn/requirements.txt
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m unittest research.hcsn.test_markov_reset_renewal -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m research.hcsn.p2_markov_reset_evidence --output /tmp/hcsn-markov-reset.json --paths 100000
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m unittest discover -s research/hcsn -p 'test_*.py' -q
python -m research.hcsn.independent_gate --bundle research/hcsn --strict
~~~

The last command MUST continue to fail closed pending external independent real P0–P6 attestation. The test runners do not grant scientific or production admission.

## Unclosed requirements

- P0: independent full-domain coupled He–Xiong/rolling debt/QVI and precision/robustness proof.
- P1: equal local-shape, slope, trainable-parameter, full-FLOP matched positive out-of-distribution incremental benefit; existing negative evidence retained.
- P2: autonomously learned dynamic boundary/Markov modes, sampled event-time training, actual selective copy/MQAR/long-horizon joint recall and multi-seed generalization.
- P3/P4: four pretrained real encoders and strict cross-modal holdout/negative-transfer studies.
- P5: fused CPU/GPU plus real device energy, throughput, peak RSS and p95/p99.
- P6: medium-sized encoder pretraining, distillation, frozen fair quality-cost frontier.

No edits to production authority or activation and no scientific closure claims.
