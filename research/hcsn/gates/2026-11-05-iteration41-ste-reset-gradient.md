# HCSN P2 Iteration 41: exact hard reset vs surrogate gradient

**Draft research only. P0–P6 OPEN; `production_activation=false`.** This is an *isolated* algebraic counterexample to the sigmoid STE plus reset-before-read pattern of `p2_reset_validity.py` in Draft #512, source blob `91191126ce18281db0a6cfd7d819261fda1fa19a`, observed HEAD `50f3dc86853d13e906ffb04f11351fa207d0be3e`. It is **not** a replay of trained checkpoints or an original He–Xiong/QVI verification. Existing review already acknowledges surrogate/true derivative mismatch; this adds a quantified adverse-step witness, not an assertion that all STE training is invalid.

Let `p=sigmoid(w)`, hard reset `r=1[p>=0.5]`, prior memory `M`, output `y=(1-r)M` and task loss `L=(y-t)^2`. For every `w>0`, the exact hard forward gives `y=0` and `dL/dw=0`, independent of old memory. But the STE `r_ST=r+p-stopgrad(p)` yields `dL_ST/dw=-2(y-t)M p(1-p)`, which varies with the *erased* memory. An independent `math` formula agrees with PyTorch autograd on signed values. Central finite differences of the true hard loss (`delta=1e-4`) remain exactly zero.

With `w=.2, M=8, t=1`, the actual hard loss is **1** and the surrogate gradient is **+3.960265163389759**. A single SGD update at LR `.1` produces `w'=-.19602651633897594`, switches the hard gate off and raises loss to **49**. Opposite old histories `+8/-8` give opposite surrogate gradients but the same forward output. The `M=0` control has zero gradient. This shows a *possible* non-descent step, not a statistical frequency estimate or a claim of universal optimization failure.

**Actual scoped verification:** 8/8 local unit tests passed (Python 3.13.5, PyTorch 2.10.0+cpu); deterministic raw JSON was emitted; independent `--strict` returned **2** and produced byte-identical JSON. No external independent attestation was obtained. The four trained #512 reset-validity models separately remain at 0/864 exact sequences, predicting UNKNOWN on every one of 9888 registered queries, per their independent review. That separate failed experiment is not a result of this toy counterexample.

From repository root, reproduce (all sources remain Draft only):

```bash
PYTHONPATH=research/hcsn python -m unittest discover -s research/hcsn -p test_p2_ste_reset_gradient_counterexample.py -v
PYTHONPATH=research/hcsn python research/hcsn/p2_ste_reset_gradient_counterexample.py > /tmp/hcsn41.json
cmp /tmp/hcsn41.json research/hcsn/gates/2026-11-05-iteration41-raw.json
set +e
PYTHONPATH=research/hcsn python research/hcsn/p2_ste_reset_gradient_counterexample.py --strict >/tmp/hcsn41-strict.json
code=$?
set -e
test "$code" -eq 2
cmp /tmp/hcsn41.json /tmp/hcsn41-strict.json
(cd research/hcsn && sha256sum -c gates/2026-11-05-iteration41-SHA256SUMS.txt)
```

**Scope:** no full HCSN acceptance, no original HX equations or QVI proof, no FLOP-matched P1 gain, no Selective Copy/MQAR OOD, no pretrained four-modality heldout, no GPU energy/p95/p99 or medium-model Pareto evidence. Do not disable reset, discard UNKNOWN rejection, merge main, or change signatures. Keep existing negative controls and strict OPEN gates.
