# Iteration 25 — off-centre deterministic tent barrier: independent P2 negative witness

**Research only; all P0–P6 OPEN.** No learned neural barrier, autonomous spike, full HX/QVI domain certification, independent signing, merged main, or production activation. This note records an additional *necessary* P2 interval-risk condition, not an accepted scientific gate.

## Repository provenance and overlapping research

Checked GitHub metadata before edits (2026-11-01):

- Protected `main`: `125d11c5454835a7df1dc51915fc49901fbede5b`.
- Original #468: `00a9dc11714f35866be18cd4fece5ce3addefc4a`, base `main`, OPEN Draft.
- Fixed regeneration #481: `407201690a617629255d7f5d0968ce4c544c1b93`, base `research/hcsn-qvi-nonlocal-and-p1-controls-20261031` (base SHA `819e33f691e9a3a255a74a6088789512e65ba951`), OPEN Draft; parent subsequently advanced.
- Two-state independent Markov #486: `1aa8eb5f0efc2661472aa5a11221c07553152a03`, base `research/hcsn-stochastic-renewal-20261031-gpt6`, OPEN Draft.
- Existing P2 edge/refractory #512: `8e3806cfb9a1aa4b62292ac02b5e7eca3498b66a`, base `research/hcsn-hardforward-ood-falsification-20261031-gpt6`, OPEN Draft.
- Parallel P2 #511 and P1 #513 retain their original research branches; we did not modify them. Existing #512 contained a midpoint-tent reference only. Every new path was checked to be absent at the pinned prepatch HEAD.

## Independent analytic statement

Condition a constant-diffusion Brownian path on observed positive margins `X_0=a`, `X_T=b`, and a **predetermined** triangular boundary of height `h` at a non-central time `c*T`. The apex margin `M=X_(cT)` is normal with mean `mu=(1-c)*a+c*b`, variance `v=sigma^2*T*c*(1-c)`. The two bridge halves are conditionally independent given `M`. For `M>h`, survival is

`(1-exp(-lambda_L*(M-h)))*(1-exp(-lambda_R*(M-h)))`, with
`lambda_L=2*a/(sigma^2*T*c)` and `lambda_R=2*b/(sigma^2*T*(1-c))`.

The **independent** arbitrary-precision reference evaluates `S=I(0)-I(lambda_L)-I(lambda_R)+I(lambda_L+lambda_R)`, where `I(lambda)=exp(-lambda*(mu-h)+lambda^2*v/2)*Phi((mu-h-lambda*v)/sqrt(v))`. A distinct SciPy Gaussian quadrature and an exact-in-time conditional half-bridge Monte Carlo check this formula. The independent integral returns an *estimated* error and omitted normal tail, **not** an outward-rounded certified enclosure.

## Counterexample: same observed endpoints and apex height, different apex time

`a=0.2, b=0.8, T=1 s, sigma=0.4, h=0.45`; only `c` changes:

| `c` | MP80 retrospective hidden-crossing probability |
|---:|---:|
| 0.10 | 0.9839219837997083 |
| 0.25 | 0.8817630213879804 |
| 0.50 | 0.7110570035323712 |
| 0.75 | 0.5626767892129148 |
| 0.90 | 0.47148047940323456 |

With identical endpoints, horizon and height, changing only the intra-gap apex time changes the probability by **51.2441504 percentage points** between `c=0.1` and `c=0.9`. The earlier central-apex shortcut would misstate the off-centre risk. Neither endpoint nor a fixed-median-midpoint-only input determines this moving-boundary risk without the intra-interval boundary trajectory.

Five MP80 comparisons to independent SciPy quadrature have maximum absolute FP64 difference `2.220446049250313e-16`. Fifteen fixed-seed simulations of `120000` conditional paths each (1,800,000 total) have maximum descriptive absolute `z=1.9676308584543132`. These are exploratory finite-domain checks; not preregistered, not independent evaluator sign-off, and not a neural model result.

## Actual local commands and outcomes

From the minimal research tree reconstructed from verified GitHub files (Python 3.13.5; NumPy 2.3.5; SciPy 1.17.0; mpmath 1.3.0; CPU-only PyTorch 2.10.0), ran:

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
python -m unittest discover -s research/hcsn -p 'test_p2_offcenter_tent_reference.py' -v
# Ran 9 tests: OK (0 skipped)

OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
python -m research.hcsn.p2_offcenter_tent_evidence \
  --output research/hcsn/gates/2026-11-01-iteration25-offcenter-tent.json
# Generated original JSON when path did not yet exist; refuses overwrite.

python -m research.hcsn.independent_gate --bundle research/hcsn --strict
# exit 2; P0,P1,P2,P3,P4,P5,P6 all OPEN; production_activation=false.
```

To reproduce **after checkout**, generate the JSON to a fresh empty path such as `/tmp/hcsn-iteration25-offcenter-new.json`; compare it to the committed evidence. This strict gate run used the original `independent_gate.py` pinned Git Blob `4611f0569f62bff00d932b7b7e95743dbbccbc29`, but **did not** use a byte-identical full-remote checkout. No GitHub CI or four-modal pretrained weights/heldout data, GPU measurements, hardware energy, or external signed trust root were available in this execution.

Pinned local-tested Git Blobs:

- `p2_offcenter_tent_reference.py`: `0362de472bdf8d5e88b0722b32bbcaf6db81bfe9`
- `test_p2_offcenter_tent_reference.py`: `0bda16065922c5ab4da89b6fc180d1d2f55def2f`
- `p2_offcenter_tent_evidence.py`: `ed33eaf8aab12030667653a9eed4b09f807fbf63`
- `2026-11-01-iteration25-offcenter-tent.json`: `47f448fd439d3413ffb122ea2418100461135467`

Source file SHA256: `412b81098b3d8c31f3e16cfb489bca7b18c4ad5aaf353ffb503affd8ddedc24a`; test SHA256: `b9669e2485b0a0b3f704dae8e5d45ae5b66ddaecc9ce9eadb19a43059ba79783`; JSON SHA256: `6d2a6af78721b53c072317b323c4888bd49c06a69c622ff7f9197a796af0548e`.

## Fail-closed status

- P0 original He–Xiong Eq8/11/12/A7, global low-precision and QVI: **OPEN**.
- P1 parameter/slope/FLOP/training-matched independent utility: **OPEN**, prior negative results retained.
- P2 dynamically learned **causal** boundary, actual repeated reset time, selective copy/MQAR and multi-seed OOD: **OPEN**; this retrospective deterministic triangular path is not a causal model.
- P3/P4 real text/speech/image/video pretrained Encoder and independent heldout fusion: **OPEN**.
- P5 real CPU/GPU energy/RSS/p95/p99, fused kernels: **OPEN**.
- P6 medium pretrained encoder and frozen-budget quality–cost frontier: **OPEN**.

**DENY_ALL / NO_GO** until actual independently attested scientific evidence; preserve Draft, never merge into main or weaken the signed activation gate.
