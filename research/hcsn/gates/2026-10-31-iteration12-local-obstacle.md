# HCSN P0 — Iteration 12: local limited-liability counterexample to smooth-fit-only HX admission

**2026-10-31 | RESEARCH ONLY | P0–P6 OPEN | production_activation=false**

This is a **new negative finding**, not a new general neural spiking operator or a scientific acceptance. At the start of this iteration, Draft PR [#468](https://github.com/TrillionniumFoundation/Hepta/pull/468) had exact branch HEAD `819e33f691e9a3a255a74a6088789512e65ba951` (main base `125d11c5454835a7df1dc51915fc49901fbede5b`). All existing P1 and P2 negative evidence is retained.

## Source derivation: *original financial* He–Xiong, not HCSN invention

Paper: [He and Xiong (2012), *Rollover Risk and Credit Risk*, *Journal of Finance*](https://www.princeton.edu/~wxiong/papers/rollover.pdf), printed pp. 400–401, Eqs. (8), (11), (12), plus its Appendix.

For `x=log(V/V_B)` and fixed smooth-pasting candidate `V_B`, the original equity Eq. (11) becomes

```
0 = (sigma²/2)*E_xx + (r-delta-sigma²/2)*E_x - r*E + f(x)
f(x) = delta*V_B*exp(x) - (1-tax)*coupon_total
       + original_bond_eq8(x,m,V_B) - face_total/m
```

At the proposed default boundary, original bond Eq. (8) gives `d(V_B,m)=alpha*V_B/m`. If the continuation solution is C² to the boundary and satisfies `E(0)=E_x(0)=0`, then **necessarily**

```
E_xx(0+) = -2*[delta*V_B - (1-tax)*coupon_total
                 + alpha*V_B/m - face_total/m] / sigma².
```

If the square bracket is *strictly positive*, `E_xx(0+)<0` and `E(x)<0` for sufficiently small positive `x`. Limited liability requires `E(x)>=0`, therefore this **smooth-fit-only candidate is invalid as a globally admissible equity stopping boundary**. Negative boundary cashflow **does not imply** global admissibility. Our binary64 sign margin is an exploratory diagnostic, **not an outward-rounded proof of parameter-domain certification**.

## Explicit counterexample with recovery BELOW face

All ten parameters are within `HXParams` current exploratory bounds:

```
r=.10, delta=.075, sigma=.20, alpha=.40, tax=.27,
xi=4., k=.20, maturity=3.,
coupon_total=5., face_total=100.
```

- Smooth-fit Eq. (12) root `V_B=197.52085498628088`; independent Green smooth-fit root agrees.
- At `V_B`, liquidation recovery / face = `0.7900834199451237`, so the counterexample **does not depend on recovery above face**; `r>delta` also holds.
- Boundary net equity cashflow `f(0+)=+4.16684478880852`; implied `E_xx(0+)=-208.342239440426`.
- Independently evaluated original Eq. (11) Green equity: `E(V_B*exp(.005))=-0.0024507427`, `E(V_B*exp(.02))=-0.0321351878`, `E(V_B*exp(.05))=-0.1200538084`. These are **negative**, not small rounding noise.
- A separate finite-difference solver of the original Eq. (11), using bond Eq. (8) instead of Green/A7, agrees in sign on 800/1600/3200-cell meshes; the negative minimum stabilizes near `-0.141`. Its maximum algebraic residual stays below `3e-10` in this example.
- Same `xi*k` with `xi=8,k=.1` leaves these financial Eq. (8)/(12) quantities invariant, a separate metamorphic check.

These numerical results **do not refute the paper in its calibrated range**. They expose a hole in extending a smooth-fit formula over an enlarged parameter domain and treating it as a globally verified obstacle/free-boundary operator.

## Independent 50-digit integral check (new numerical subgate)

A separate `mpmath` reference (`hx_local_obstacle_mp_reference.py`) evaluates first-passage `F/G` at **50 decimal digits** and integrates their weighted densities on a geometrically subdivided semi-infinite domain. It reconstructs the smooth-fit boundary without calling `hx_integrals`, the binary64 `closed_boundary`, Green equity or the finite-difference solver:

```
V_B  = 197.52085498628085915289694345014521938607425062626
f_B  =   4.1668447888085123235201965521135873720988022138047
E_xx = -208.34223944042561617600982760567936860494011069023
```

This rules out the observed contradiction being merely a binary64 cancellation artifact. It is a **pointwise numerical** cross-check, **not** an outward-rounded interval theorem or a proof that all parameters are safe/unsafe. Three additional high-precision reference tests passed.

## Full no-drop fixed-seed numerical panel

`p0_local_obstacle_evidence.py` records **all 256** attempts from `random.Random(20261031)`, including exceptions and a numerical status per case. These *exploratory*, nonpreregistered fixed ranges are embedded in the script.

| Outcome | Cases |
|---|---:|
| Rejected by positive boundary net cashflow / negative curvature | 76 |
| No local sign obstruction (NOT acceptance) | 180 |
| Numerically unresolved / indeterminate | 0 |
| Rejections with liquidation recovery **below** face (subset of 76) | 12 |

These counts are not estimates of population failure rates. No global optimal stopping proof, interval arithmetic, or neural quality advantage is claimed. The full 256-record JSON was generated locally, SHA256 `4f89d1a9d655201f9b821d676ce1390d7720124ff817851d031c2ab5f10e3c7b`; it can be byte-recreated with the exact committed script and dependencies. The file is in the local research reproduction archive; this commit adds the reproducer and a concise ledger, **not** a claimed remote copy of that large JSON.

## Executed on a reconstructed local research suite (NOT remote CI)

Python 3.13.5, NumPy 2.3.5, SciPy 1.17.0 and CPU PyTorch 2.10.0:

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
 python -m unittest -v research.hcsn.test_hx_local_obstacle_sign
# 6/6 PASS for the binary64 sign/FD tests

OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \\
 python -m unittest -v research.hcsn.test_hx_local_obstacle_mp_reference
# 3/3 PASS for separate 50-digit first-passage quadrature

OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
 python -m unittest discover -s research/hcsn -p 'test_*.py' -q
# 101/101 PASS in the locally reconstructed subset, NOT complete remote checkout/CI

OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
 python -m research.hcsn.p0_local_obstacle_evidence --output /tmp/hcsn-p0-iteration12.json
# create-only; 256 complete case records; refuses overwrite

python -m research.hcsn.independent_gate --bundle research/hcsn --strict
# EXIT 2, correct fail-closed; external trust root/complete science absent
```

Source/test/reproducer Git blob SHA-1s read back from the research branch after delivery must match these **locally executed** bytes:

| File | Git blob SHA-1 |
|---|---|
| `hx_local_obstacle_sign.py` | `307eac9285090fa22b0630a10f46f2d64d5d6cce` |
| `test_hx_local_obstacle_sign.py` | `e123eff3917e4dcc113b6e4f2e785bfdd7b91d23` |
| `p0_local_obstacle_evidence.py` | `0ef295f7906d020112b9159f48b3ff326ec2105b` |
| `hx_local_obstacle_mp_reference.py` | `f131082e2844f16ddc0c8b0cee9126417caae604` |
| `test_hx_local_obstacle_mp_reference.py` | `b10a8d3626930314e87fa941de6d24af07b83878` |
| Unmodified original `hx_original.py` | `880ce9caea309d74569e5574df8f4d30aa0060f7` |
| Unmodified independent `hx_equity_fd_independent.py` | `c3801c5a3f2607371b7d9d17916f49fbcb103877` |

## Admission policy and follow-ups

**P0 OPEN:** a local necessary condition catches some invalid roots; other roots need a truly **global** coupled bond/equity obstacle QVI, all-domain error bounds, and low-precision/gradient safety. Preserve original negative evidence. No path from `NO_LOCAL_SIGN_OBSTRUCTION_ONLY` to admission is allowed.

**P1 OPEN:** analytic Call/Put mechanism still lacks matched-FLOP causal OOD gain over ordinary shape-matched gates. **P2 OPEN:** the separate stationary multi-reset reference in Draft #481 is not learned autonomous long-horizon memory. **P3 OPEN:** real frozen four-modal text/audio/vision/video Encoder controls absent. **P4 OPEN:** real cross-modal alignment/missing modality/negative transfer absent. **P5 OPEN:** real GPU fusion, device Joules, full-model latency/RSS/4096-Cell measurements absent. **P6 OPEN:** medium-Encoder pretraining and independently validated quality-cost frontier absent.

**Do not merge to `main`, change production wiring, set any scientific gate PASS, or turn on production activation.**
