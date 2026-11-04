# HCSN Iteration 34 — joint holding-time / destination semi-Markov counterexample

**DRAFT RESEARCH ONLY. P0–P6 OPEN. DENY_ALL. `production_activation=false`.**

Parent snapshot for Draft #512: `e179de289b44210920e80ed5f376e5abbe864fee`, base `research/hcsn-hardforward-ood-falsification-20261031-gpt6` at `2ce3267ca148a6568497cc20b27c09c26058b739`. Foundation PR #468 `00a9dc11714f35866be18cd4fece5ce3addefc4a`; renewal #481 `407201690a617629255d7f5d0968ce4c544c1b93`; Markov #486 `1aa8eb5f0efc2661472aa5a11221c07553152a03` remain Draft. Other active HCSN Draft branches were inspected before publication and file paths of this iteration are new/additive.

## Negative result — matching marginal renewal data is insufficient

A semi-Markov event kernel must retain dependence between *sojourn duration* and the *mode selected at the event*. In our strictly limited synthetic two-mode exponential example, fix `pi=(1,0)`, embedded transition matrix `P=[[.5,.5],[.5,.5]]`, and compare conditional rate matrices:

- Fast-to-zero: `lambda_A=[[4,0.25],[0.7,0.07]]` 1/second.
- Fast-to-one: `lambda_B=[[0.25,4],[0.07,0.7]]` 1/second.

The two models have **identical embedded P, identical marginal holding-time CDF in each initial mode, identical full first-event CDF, and 100% eventual probability of each finite-ranked event**. However the jointly coupled waiting-time/destination kernel differs: `K_ij(s)=P_ij*lambda_ij/(lambda_ij+s)`. The event-rank Laplace transform is `pi K(s)^n 1`. The null factorization `K_ij(s)=P_ij*sum_k P_ik*lambda_ik/(lambda_ik+s)` destroys their distinct duration/destination dependence.

| Probability by physical time 1 second | Fast-to-zero | Fast-to-one | Difference |
|---|---:|---:|---:|
| at least one event | 0.6014417890 | 0.6014417890 | 0.0000000000 |
| at least two events | 0.2878026018 | 0.1625719182 | **0.1252306835** |
| at least three events | 0.1224018448 | 0.0278676076 | **0.0945342372** |

**Implication:** In a P2 Markov-reset upgrade, a state-only next-mode transition plus a marginal wait-time model cannot be assumed sufficient without a conditional independence test. This is an explicit *semi-Markov negative control*, **not** a Brownian first-passage result, a He–Xiong QVI validation, a neural prediction win, or a claim that all state-dependent hazard models fail.

## Independently executable evidence and limitations

- Candidate Laplace evaluator cross-checked against full `2^(n+1)` scalar path enumeration over 2 scenarios, `n=1..6`, 5 Laplace rates, joint and deliberately factorized controls. Maximum absolute difference: `2.78e-16`.
- Finite-horizon event counts independently evaluated by enumerating transient phase-type generators and SciPy `expm`; the second event was also checked by an unrelated scalar flux convolution (`quad`). Maximum absolute difference: `6.94e-16`.
- Separate NumPy conditional-exponential Monte Carlo with seeds 11, 23, 37 and 50,000 paths per scenario/seed: **300,000 paths**; ranks 1–3, horizons 1 and 4 seconds, 36 raw integer-count records; maximum standardized discrepancy: **2.657 standard errors**. Shared samples across ranks/horizons are *not* independent panels.
- Exact physical-event scheduler tested under observation partition 1 vs 96, plus atomic event-budget failure, invalid physical time and malformed probabilities/rates.
- Combined local unittest suite for this candidate and prior Iterations 30–33: **46/46 passed** (`combined_tests.log` SHA256 `1a3662b84bba3d72fad3f53491212c097c7086e00ccd68443af8cd1c51012381`). Not equivalent to remote CI or independently attested science.
- The actual original #468 `independent_gate.py` (`SHA256 da04c2135c63d04a32c997421730c2f97565e5b5bf582e0341d3347590bb1a13`) was run with no externally attested trust root, strict mode, and an untrusted empty bundle: **exit code 2**, all seven `P0..P6=OPEN`, `full_closure=false`, `independent_attestation_verified=false`, `production_activation=false`. `strict_gate.json` SHA256 `7b895f6758982fc19030c9c39d72707b6e179e7d9c695c2fa93f86fc04c53203`.
- #468 HEAD still has failing CodeQL check `124550087193`, without exposed alerts in the present connector. Do not invent an annotation or declare it fixed. #512 new HEAD requires an independent remote-CI reread.

### Exact reproduction (checkout #512 after this commit)

```bash
export PYTHONPATH=. OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
python -m unittest -v \
  research.hcsn.test_p2_joint_sojourn_markov \
  research.hcsn.test_p2_markov_defective_firsthit \
  research.hcsn.test_p2_defective_first_hit_clock \
  research.hcsn.test_p2_first_hit_renewal_falsification \
  research.hcsn.test_p2_physical_hazard_clock
python -m research.hcsn.p2_joint_sojourn_evidence \
  --samples 50000 --output /tmp/hcsn-iteration34-reproduced.json
base64 -d research/hcsn/gates/2026-11-04-iteration34-joint-sojourn-raw.json.gz.b64 \
  | gzip -dc > /tmp/hcsn-iteration34-committed-raw.json
sha256sum /tmp/hcsn-iteration34-committed-raw.json
# Expected SHA256: 3b6fe8bd5bfd08a6f7e61ee06ab6247e88373b62fc739ceffb9fd6b86289cfc4
# Replay strict gate from Foundation Draft #468 isolated source (do not assume it is on #512's ancestry):
# python -m research.hcsn.independent_gate --bundle /tmp/hcsn-iter34-untrusted-empty --strict --output /tmp/hcsn-iter34-strict.json
# Expected exit code 2 without independent external trust; never turn it into a pass.
```

### SHA256 of executed source and committed raw JSON

- `p2_joint_sojourn_markov.py`: `13528dc94dd476cfd774a1734353d913c4333e220b4908e42a915d3281c03e2d`
- `test_p2_joint_sojourn_markov.py`: `9eb5ba107236a3918c4a571b6eab1cf2993cb5b14593f888d8c3bbe2c75da5ae`
- `p2_joint_sojourn_evidence.py`: `6ce911170442a2acadb61a5a3a0a425d4ecc108925d0b23318cc8a2185469006`
- Decoded raw JSON: `3b6fe8bd5bfd08a6f7e61ee06ab6247e88373b62fc739ceffb9fd6b86289cfc4`

**Unclosed obligations:** P0 full-domain original HX Eq8/11/12/A7, low precision and independent QVI; P1 genuinely matched signed slope, parameters, FLOP and training budget with negative controls; P2 learned input-driven causal boundary, real Brownian hidden-hit timing, autonomous multi-reset and OOD Selective Copy/MQAR; P3/P4 pretrained text/audio/image/video and separate multimodal heldout; P5 real CPU/GPU RSS/joules/p95/p99; P6 medium-model quality–cost frontier. An external, separately administered scientific trust root remains absent. Preserve all historic negative results and Draft/HOLD status. No main merge, signing relaxation, production activation or Library deletion.
