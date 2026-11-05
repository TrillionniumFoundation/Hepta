# HCSN P1 — exact vectorized Bellman policy audit, negative exploratory result

**2026-10-31 | RESEARCH-ONLY | P0–P6 OPEN | production_activation=false**

## Provenance and non-overlap

- Repository: `TrillionniumFoundation/Hepta`; initial main SHA `125d11c5454835a7df1dc51915fc49901fbede5b`.
- Branched from PR #468 HEAD `00a9dc11714f35866be18cd4fece5ce3addefc4a` into independent `research/hcsn-p1-vectorized-bellman-fairness-20261031-gpt6`; no edits to #509 (P0) or #481/#486/#492–#505 (P2), production, gate signatures or release policy.
- New policy evaluator explicitly enumerates both possible future public binary observations, then runs a binary64 Bellman recursion *backwards*; neural inference sees only each candidate public state, in float32. It is a CPU synthetic Bayesian READ-task reference, **not original HX Eq. 8/11/12**, a multimodal encoder, or a production kernel.
- Frozen training seeds `(11,23,37)`, 512 rows each, 90 Adam updates each; six 161-parameter heads (`call_only`, `put_only`, `margin_only`, `dual_call_put`, `ordinary_two_gate`, `c1_hermite_null`). Each seed's variants use identical training samples and initialization. Independent 420-state ID and 420-state OOD holdouts. Hierarchical paired seed/state bootstrap 1000 draws, exploratory only.

## Actual scoped local execution — NOT GitHub CI / complete checkout

Python 3.13.5, PyTorch 2.10 CPU, NumPy/SciPy, one CPU thread. The three **existing** dependencies `boundary_content_bridge.py`, `train_study.py` and `p1_hermite_control.py` were locally reconstructed with their exact relevant function bodies; this was **not** a byte-identical checkout of the existing remote modules. All four **new** remote files were compared byte-for-byte to their locally executed Git blobs. Full audit completed using these locally reconstructed dependencies. Re-run in an exact remote checkout remains necessary.

| Head | ID exact policy regret | OOD exact policy regret |
|---|---:|---:|
| ordinary_two_gate | 0.002136 | 0.003048 |
| dual_call_put | 0.006281 | 0.010091 |
| c1_hermite_null | 0.006281 | 0.010091 |
| call_only | 0.035149 | 0.041723 |
| put_only | 0.008401 | 0.011878 |
| margin_only | 0.011915 | 0.020863 |

**Paired dual minus ordinary** (positive means analytic candidate worse): ID `+0.004145` exploratory 95% CI `[+0.002433,+0.006449]`; OOD `+0.007043` CI `[+0.002478,+0.013335]`. Each seed's mean difference was positive on both distributions. **Paired dual minus C1 Hermite: exactly 0** on the evaluated seed/state policies, not a theorem of global equality.

On 512 independent heldout public inputs, Hermite-vs-analytic maximum absolute feature difference `5.96e-8`, maximum absolute *signed* full-input Jacobian difference `5.96e-7`; no all-domain Jacobian certification. Recorded CPU batch-forward nanoseconds per sample are merely descriptive measurements (GPU power, training FLOPs and end-to-end system costs unmeasured).

Synthetic smoke and independent recursion checks: **7/7 local tests passed**, no skips, in the reconstructed research subset. Full experimental evidence JSON SHA256 `f414be5a1022248be8fc88a1e19563f6d55a0df83968b6a7d2cc8996b15c2336` was generated locally; this report records its summaries and digest, not a claim that the JSON has been committed remotely.

## Exact reproduction on this Draft branch

From repository root with `research/hcsn/requirements.txt` installed:

```sh
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  python -m unittest research.hcsn.test_p1_exact_policy_eval research.hcsn.test_p1_paired_policy_audit -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  python -m research.hcsn.p1_paired_policy_audit --output /tmp/hcsn_p1_paired_new.json
python -m research.hcsn.independent_gate --bundle research/hcsn --strict
# Must continue to exit 2 without externally reviewed P0–P6 science.
```

New source/test Git blob SHA1 (locally executed and connector-read-back matched):

- `p1_exact_policy_eval.py`: `2a7efde8cf0a7f0d981dd55f26c39a7a07fb563e`
- `p1_paired_policy_audit.py`: `59537fd4a47e4071a1c10749fe0b4915dbe1b230`
- `test_p1_exact_policy_eval.py`: `2986a30da9306967522b1782db71b13ff0edb04c`
- `test_p1_paired_policy_audit.py`: `3e5ef5d72206bfcb9f98827e41746270e1282132`

**Strict non-acceptance:** Three seeds and a small synthetic task do not establish broad efficacy; slope match is empirical, kernel backward FLOPs are not equalized, future-window causal benefits are not preregistered, and independent Evaluator/Observer attestation is missing. Ordinary gates beat analytic dual on this particular toy task. P1 remains OPEN. P0 and P2–P6 are unchanged and OPEN; neither merging to main nor production activation is justified.
