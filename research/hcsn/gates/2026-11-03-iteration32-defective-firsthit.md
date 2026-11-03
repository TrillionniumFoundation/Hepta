# HCSN iteration 32 — defective Brownian first-hit renewal and no-event mass

**Research-only; P0–P6 all OPEN; DENY_ALL; production_activation=false.**
Target: stacked [Draft #512](https://github.com/TrillionniumFoundation/Hepta/pull/512),
observed parent HEAD `90e824923e68318b0602fa28abcf70cc0e20bd9e`.
Foundational branches: #468 (`00a9dc11714f35866be18cd4fece5ce3addefc4a`),
#481 (`407201690a617629255d7f5d0968ce4c544c1b93`),
#486 (`1aa8eb5f0efc2661472aa5a11221c07553152a03`).

## Mathematical change and falsifiable limitation

Iteration31 showed that a constant Poisson intensity, even calibrated to the
driftless Brownian first-event CDF at 1s, fails other horizons and higher resets.
This iteration covers *Brownian first passage with drift* and **defective**
first-hit probability when drift points *away* from the barrier.

Let `X(t)=mu*t + sigma*W(t)`, starting at distance `a>0` below a fixed barrier.
For negative drift, `q=P(first_hit<infinity)=exp(2*mu*a/sigma**2)<1`.
The missing probability `1-q` means a genuine sample path may never fire.
For fixed `a=0.4`, `sigma=0.4`, `mu=-0.12`, **q=0.5488116360940264**,
so **45.11883639059735%** of paths never fire, even over unlimited time.

For iid reset cycles with the same Brownian parameters and a fixed physical
refractory `r`, the n-th event time has the exact *defective* CDF:

`P(N(T)>=n)=F_{n*a,mu,sigma}(T-(n-1)*r)`,

where `F` is the single Brownian first-hit CDF (defined as zero at nonpositive
time). In particular `P(ever reach event n)=q**n`, so with the frozen negative
drift, the **third event ever occurs on only 16.52988882215865% of paths**.
Any positive constant Poisson hazard from #512 has eventual hit probability
1 and therefore fails this test.

The candidate event clock samples one `E~Exp(1)` at each actual regeneration,
maps `u=1-exp(-E)` through the proper defective CDF, and emits no future
event if `u>=q`; it honors refractory in *seconds*, not tokens. Unlike a
token-sampled Bernoulli rate, it gives identical event times on the same
underlying seeded latent draws under coarse or fine observation partitions.

**Strict scope:** This is an iid, constant-distance, constant-coefficient
Brownian first-hit renewal benchmark; negative drift is a useful failure
mode but is not a learned input-driven barrier, genuine He–Xiong Eq8/11/12/A7,
nonlocal QVI, or realized pathwise Brownian crossing oracle. Matching the
first-hit distribution does not recover an unknown realized Brownian path.

## Independent checks performed locally

- 60 analytical grid cases: drift `(-0.4,-0.12,0,0.12)`,
  hit ranks `1,2,3`, times `(0.25,0.5,1,4,16)`s, refractory `0.1`s.
- Independent reflection-principle normal-CDF reference maximum absolute
  disagreement: `2.2204460492503131e-16`.
- Independent numerical flux integral (`scipy.integrate.quad`) maximum
  absolute disagreement: `1.8204188156900614e-14`.
- 81 heldout independent NumPy Wald / normal-square Monte Carlo comparisons,
  40,000 draws per experiment for seeds 11, 23, 37; maximum |z|:
  `2.8397913`.
- All 12 same-seed refinement cases agree **exactly** across one 16s interval
  versus 64 quarter-second intervals (same latent event draws); this tests
  scheduler refinement, not physical Brownian path reconstruction.
- 28/28 local tests pass: 8 new, 20 previously retained #30/#31 tests.
- Exact `independent_gate.py` from #468 (Git blob
  `4611f0569f62bff00d932b7b7e95743dbbccbc29`) executed with no
  independently managed external trust root; **exit 2**. P0–P6 OPEN,
  `full_closure=false`, `production_activation=false`. We did not fabricate
  evaluator/observer signatures or preregistration.

### Frozen illustration at 16 seconds with refractory r=0.1s

| Drift mu | First-event probability | Third-event probability |
|---|---:|---:|
| -0.40 | 0.135334 | 0.002478 |
| -0.12 | 0.528463 | 0.136375 |
| 0 | 0.802587 | 0.450410 |
| +0.12 | 0.962923 | 0.825022 |

There is no pretrained encoder, Selective Copy/MQAR train/eval gain, high-fidelity
QVI guarantee, matched slope/FLOP P1 gain, measured CPU/GPU joules, or
medium-scale frontier in these results. Historical P1 ordinary-gate wins
and #512 OOD negative results are preserved.

## Strict reproduction (from the #512 branch after this additive commit)

```bash
export PYTHONPATH=. OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
python -m unittest \
  research.hcsn.test_p2_defective_first_hit_clock \
  research.hcsn.test_p2_first_hit_renewal_falsification \
  research.hcsn.test_p2_physical_hazard_clock -v
python -m research.hcsn.p2_defective_first_hit_evidence \
  --output /tmp/hcsn-iteration32-defective-firsthit.json
python -m research.hcsn.independent_gate \
  --bundle /tmp/hcsn-iteration32-untrusted-empty \
  --strict --output /tmp/hcsn-iteration32-strict.json
# strict gate must exit 2 without genuine external trust root and attestations.
```

New source SHA256:
- `p2_defective_first_hit_clock.py`: `7bc198014ce882fcf0906d1f8261892d71e52af192ec6c7d6d4b8e4a278e9f1a`
- `test_p2_defective_first_hit_clock.py`: `e09305847733a8ada869cb5a72e5c057479f0f8a5ae53f153f0002a840f67270`
- `p2_defective_first_hit_evidence.py`: `96765c8015e7a60a64eb3d85b23de5a78180f86b706dab9ab8c1da79c32f279f`
- `gates/2026-11-03-iteration32-defective-firsthit-raw.json`: `1e0c9af1d60776f6597098962e0e8628acdfc4421520df35bac942faaa7999fa`

Neither a local pass nor a successful Git object push is a remote CI pass or
science-stage acceptance. Keep this PR **Draft**; no main merge, no trust-root
changes, no signature bypass, no production activation.
