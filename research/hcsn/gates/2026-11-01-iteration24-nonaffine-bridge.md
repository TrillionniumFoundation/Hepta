# HCSN P2 iteration 24 — endpoint-only affine bridge risk fails on a deterministic intra-gap tent boundary

2026-11-01. **All P0–P6 OPEN, production_activation=false, research-only, no main merge.**

## Provenance and overlap

- `main`: `125d11c5454835a7df1dc51915fc49901fbede5b`.
- Draft #468: `00a9dc11714f35866be18cd4fece5ce3addefc4a` / base main.
- Draft #481: `407201690a617629255d7f5d0968ce4c544c1b93` / base research/hcsn-qvi-nonlocal-and-p1-controls-20261031.
- Draft #486: `1aa8eb5f0efc2661472aa5a11221c07553152a03` / base research/hcsn-stochastic-renewal-20261031-gpt6.
- Draft #512 parent at inspection: `bed4bfcd3f5ce75dd51d501c8ec2e202ba877521`; base research/hcsn-hardforward-ood-falsification-20261031-gpt6, base SHA `2ce3267ca148a6568497cc20b27c09c26058b739`.
- Other HCSN research PRs #463, #483, #487, #492, #498, #500, #503, #505, #509, #511, #513, #526, #527 were checked for changed paths. The five iteration24 filenames were absent; no other research path was overwritten.

## Mathematical witness

Let `X_t` be Brownian motion conditioned on `X_0=a>0`, `X_T=b>0`. The sample gap contains a deterministic **non-affine tent barrier** starting/ending at zero with height `H` at `T/2`. The affine endpoint-only bridge formula is `p_flat=exp(-2ab/(sigma^2*T))`, independent of `H`.

A rigorous **lower bound** on the tent crossing event follows from continuity and the midpoint Gaussian bridge: `P(hit tent | endpoints) >= Phi((H-(a+b)/2)/(sigma*sqrt(T)/2))`. The two affine halves are conditionally independent given the midpoint; their exact survival probabilities can therefore be integrated over the Gaussian midpoint law. A separate midpoint+two-bridge Bernoulli Monte Carlo independently checks the integral, without discretization of the Brownian paths.

Frozen `a=b=0.4`, `T=1s`, `sigma=0.4/sqrt(s)`. With `H=0.6`, `p_flat=0.1353352832366127`, midpoint lower bound `0.8413447460685429`, tent hitting integral `0.942094699798187`, MC `0.942175` from `120000` seeded paths, empirical SE `0.0006738030707298685`. Thus blindly reusing the affine-only endpoint formula underestimates the crossing probability by ~`0.8067594166` absolute probability here. This is **not** an independent unconditional or online learnt-neuron performance result.

## Executed commands and evidence

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m unittest research.hcsn.test_p2_nonaffine_bridge_enclosure -v
OPENBLAS_NUM_THREADS=1 python -m research.hcsn.p2_nonaffine_bridge_evidence --output research/hcsn/gates/2026-11-01-iteration24-nonaffine-bridge.json
```

- Local Python/NumPy/SciPy minimal reconstruction; **6/6 PASS**, zero skipped. This does not certify full remote checkout or GitHub CI.
- Raw JSON records four tent heights `0,0.2,0.4,0.6`, independent bridge MC with `120000` paths for each, frozen seed `20261101`, error estimates, and explicit `scientific_gate=OPEN`, `production_activation=false`.
- FP64 quadrature returns an **estimated**, not rigorously enclosing, numerical error. The Gaussian midpoint lower bound itself is mathematical and independent of numerical integration.
- Source SHA256: `p2_nonaffine_bridge_enclosure.py` `a04546c55381c02583ff58a8732042fe2e0d7809679efa048beee5b40b836221`.
- Test SHA256: `test_p2_nonaffine_bridge_enclosure.py` `444d8ad58cc083288ba36f61a98deb0f6a3e761c2ad57b606e42c8014e13906b`.
- Evidence generator SHA256: `p2_nonaffine_bridge_evidence.py` `36917810f07fdd5f30b03ec267a14ecdcaf610dc7e9e4889815b89fdc466a8e2`.
- JSON SHA256: `253235a98c3cd692fab5c2431f1b4f1976dc32cfb31493aaa50f1ae28fe51378`.

## Scope and unclosed blockers

This is a predetermined deterministic tent barrier, not a learned online input-dependent boundary. The conditional posterior uses the future endpoint; it **must not** be used for causal decisions before the endpoint arrives. No repeated endogenous reset, gradient, long MQAR heldout or pretrained encoder proof follows. Prior P1/P2 negative controls remain. P0–P6 remain OPEN without independent external signed evidence; strict gate must continue exiting nonzero. No CI or GPU/energy claim.

## Post-push independent local replay and immutable blob check

- Extracted the pre-existing `independent_gate.py` from the earlier self-contained local HCSN research archive, verified its Git blob `4611f0569f62bff00d932b7b7e95743dbbccbc29` exactly matches the pinned GitHub version, and actually ran:
  `python -m research.hcsn.independent_gate --bundle research/hcsn --strict`.
  **Exit code 2**; all seven phases report `status=OPEN`, `full_closure=false`, `production_activation=false`; missing external trust root.
- Remote blob SHA-1s matched the locally run source (Git `hash-object`) exactly: kernel `518eab4f4578f9ca0eb1d6f5d86a9d9da4a7146f`, tests `aa0bc1645bdbc209ada6ec6f8de9a4e44940360f`, evidence generator `e3daee5e8cb55f775682e7f0acd0964974f23160`, raw JSON `f44cfc5deba4e20fb33979f6798a8a5e2f4c0a8b`.
- This was run on the **local minimal replay**, not a full byte-identical GitHub checkout. GitHub latest-head combined status and PR-triggered workflow queries both returned empty lists; **no remote CI pass is claimed**.
- Related #500 already studies independently verified two-stage moving barriers; this patch adds a distinct *endpoint-conditioned* non-affine bound witness to the #512 hidden-event clock line, and does not overwrite #500 or claim to supersede it.
