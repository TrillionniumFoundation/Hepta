# HCSN P0: exact binary32 tax preimage and boundary sensitivities (2026-10-31)

**RESEARCH ONLY — P0–P6 OPEN; DENY_ALL; production_activation=false; no main merge.**

## Frozen provenance and scope

- TrillionniumFoundation/Hepta main at inspection: `125d11c5454835a7df1dc51915fc49901fbede5b`.
- Parent Draft #509 starting HEAD: `9c0b7ebfd722877634f7ef74ac01d5e861dedc8e`, stacked on Draft #468 at `00a9dc11714f35866be18cd4fece5ce3addefc4a`.
- This child branch adds two research Python files and this evidence report only; no changes to production, signature authority, release gates, P1/P2 branches, or CI.
- For fixed other physical parameters, original He–Xiong Eq12 numerator is **affine in tax**. The code computes the two exact rational midpoints between adjacent positive IEEE-754 binary32 values that bound the set of real tax inputs rounding to the same word. It evaluates the original Eq11 necessary local-obstacle cash flow at those ends, and computes analytic Eq12 partial derivatives for tax, liquidation recovery, coupon total, and face total.
- F/G first-passage Laplace integrals are sourced from the separate 35–90 digit mpmath CDF quadrature in `hx_local_obstacle_mp_reference.py`, not the FP64 closed-boundary method. Thus the gradient test against the FP64 Laplace Eq12 is a second numerical implementation, not a formal proof.

## Actual local observations

Python 3.13.5 CPU, SciPy 1.17, mpmath 1.3, NumPy 2.3, OPENBLAS/OMP one thread. Reconstructed local Eq12 + MP reference subset; **not a complete remote Git checkout**.

`python -m unittest research.hcsn.test_p0_tax_cell_sensitivity -v`: **8/8 PASS**, 0 skips, approximately 2.8 s. Includes: same-word opposing-sign counterexample; exact rational rounding midpoints; uniformly positive/negative scoped local sign diagnostics; zero-liquidity degeneracy; 4 analytic partial derivatives over two parameter settings; independent high-precision finite-difference tax derivative; rejection of bad input/precision.

| Parameter fixture | Local necessary-screen result | q_B range across tax-only FP32 preimage |
| --- | --- | --- |
| HX default | no local sign obstruction, **not admitted** | [-24.530960769, -24.530960407] |
| xi=k=0 | no local sign obstruction, **not admitted** | [-26.014690490, -26.014690129] |
| r=.10, delta=.075, sigma=.20, alpha=.40, xi=4, k=.20, m=3, C=5, P=100, tax=.27 | local invalidity across this tax-only cell (numerical) | [+4.166844763, +4.166844793] |
| Same but P=20 and tax=.39990773048821087 | **ambiguous sign** across tax-only cell | [-1.87632948e-8, +1.11818681e-8] |

The last fixture's `tax=.3999077379072307` has the same binary32 word `0x3eccc0b5` but opposite local cash-flow sign. Among 8 central-FD comparisons against an independently implemented FP64 original Eq12, largest absolute gradient discrepancy was approximately **3.19e-9** (zero-liquidity recovery derivative); these are not full-domain bounds.

Git blob SHA-1 of newly executed source and test, independently read back from GitHub:
- `p0_tax_cell_sensitivity.py`: `9f642e30043600487ba5c7b00cd0c9a747830433` (SHA256 `a2e8eeb4fb8f76b8222e687d19d002143a2363ef7fa08edcc9301b85f4517983`)
- `test_p0_tax_cell_sensitivity.py`: `232051decc6102e49d0ff1bd8a9e9250250c7d3c` (SHA256 `5939ae0bc13cb2214bcd048e0cc13adc46d2517bc5be7306a9a718b9e2370604`)

## Reviewer commands at exact child HEAD

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest research.hcsn.test_p0_tax_cell_sensitivity -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest research.hcsn.test_hx_uniform_failclosed -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest discover -s research/hcsn -p 'test_*.py' -q
python -m research.hcsn.independent_gate --bundle research/hcsn --strict
```

**Strict scientific gate must remain exit 2 without external reviewed signed evidence.** No whole-repo CI, remotely executed test suite, proof of directed-rounding quadrature error, or third-party scientific signoff is claimed.

## Explicit outstanding P0 blockers

1. This is **tax-axis only**: all other parameters are fixed decimal inputs, not their joint FP32 quantization preimages.
2. mpmath quadrature is not a verified outward-rounded interval enclosure; q_B signs far from zero are diagnostics, not globally certified bounds. No BF16 guarantee.
3. A locally non-positive q_B is only a **necessary-condition screen**: no global positive-equity obstacle, coupled original HX Eq11/A7 solution across all admissible parameters, or regenerative QVI proof.
4. P1 matched causal advantage, P2 autonomously learned long-memory resets, P3/P4 real four-modal encoders, P5 fused CPU/GPU energy/full-latency, and P6 quality-cost frontier remain independent OPEN gates.

Do not merge to main, enable production, or label these tests scientific PASS.
