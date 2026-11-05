# P1: Put plus a linear payoff path, exact capacity control and source-exact replay

Research evidence recorded 2026-11-05 UTC. **P1 remains OPEN; production activation is false.**
This is a synthetic Bayesian READ-task experiment using the simplified stopping
kernel. It does not qualify original He--Xiong equity, a multimodal encoder,
hardware energy, or an end-to-end HCSN model.

## What this experiment resolves

The requested Put + linear control was missing from the earlier six-head audit.
It reveals a specific algebraic restriction of the implemented simplified kernel:

\[
C-P=u-1,\qquad u=v/k.
\]

In the stopping region, `C=0` and `P=1-u`. In the continuation region,
`C=u-1+option/k` and `P=option/k`. Consequently the identity holds in both
regions, including their common boundary. It also respects the upstream
definition of `v`, including its positive-input clamp.

Thus `[C,P]` and `[P,L]`, with `L=u-1`, are invertible linear coordinates for
the same features. For the existing learned input projection the exact
real-arithmetic weight transformation is

\[
W_{P,\mathrm{new}}=W_C+W_P,\qquad W_{L,\mathrm{new}}=W_C.
\]

The inverse is `W_C=W_L,new`, `W_P=W_P,new-W_L,new`; the bias and remaining
weights stay the same. This proves equal representational capacity for this
particular head architecture. The extra Call feature cannot be interpreted as
new information beyond Put and the normalized linear payoff path. Numerical
implementation errors are measured below rather than assumed away.

**Scope of “linear”:** this path is affine in normalized value `u=v/k`.
Here `v=2 min(p,1-p)` with the old clamp, and `k=1+0.5 cost`; it is not affine
in all four raw public inputs. Substituting raw `p` or unnormalized `v` changes
the control. This identity is not asserted for original coupled HX equity.

## Source identity and protocol

- Repository: `TrillionniumFoundation/Hepta`, existing Draft PR #513.
- Exact checked-out base: `9985a91dbf7233c973301b2fddaf8f1778cf9331`.
- All pre-existing tracked source and test files remained byte-identical to this
  base. New code is identified by the SHA256 manifest and the subsequent commit.
  No dependency function was reconstructed or replaced with a shadow module.
- Python 3.12.14, PyTorch 2.10.0+cpu, one PyTorch CPU thread; OpenBLAS/MKL/OMP
  each restricted to one thread. Dependency versions are in the execution manifest.
- Paired seeds `(11,23,37)`, 512 training rows per seed, 90 Adam updates per
  independently trained head, learning rate 0.008, the unchanged Bayes READ
  advantage target and training data generation.
- Legacy 420-state ID and 420-state OOD holdouts are replayed with their original
  seeds and hashes. These previously exposed sets are not a new prospective test.
- Nine heads are trained separately for each seed. A tenth head is derived by
  mapping the already trained dual head; it is not counted as a training run.
- Exact finite-horizon policy evaluation averages all potential observation
  paths under their probabilities. The deployed policy receives only public
  causal state, never the unrealized future observation path.
- Every model has 161 trainable parameters, using 644 bytes in FP32. Fixed
  feature storage is also disclosed rather than hidden by this parameter count.

The three Put + linear variants separate different questions:

| Variant | Initialization/training | What it checks |
|---|---|---|
| Same parameter seed | Same numeric initial learned weights as dual, standard Adam | A new feature parameterization under the same training budget |
| Function-matched initialization | Map the initial dual head, then standard Adam in the new coordinates | Removes initial-function difference; optimizer-coordinate effects remain |
| Mapped after training | Map the trained dual weights, no further optimization | Exact function-class equivalence up to measured floating point error |

Adam is not invariant under this non-orthogonal reparameterization. The first
two independently trained variants therefore need not learn identical policies.
Their differences do not establish an increase in representational capacity.

## Actual results

Lower exact policy regret is better. All entries average the same three seeds
and the same heldout public states.

| Head/control | ID regret | OOD regret |
|---|---:|---:|
| Ordinary two gates | 0.002136105 | 0.003048298 |
| Call only | 0.035149037 | 0.041722648 |
| Put only | 0.008401213 | 0.011878095 |
| Margin only | 0.011914709 | 0.020862749 |
| Dual Call/Put | 0.006281313 | 0.010090813 |
| C1 Hermite shape control | 0.006281313 | 0.010090813 |
| Ordinary gate with a matched tangent at one anchor | 0.008666202 | 0.012590453 |
| Put + linear, same parameter seed | 0.006777882 | 0.010545410 |
| Put + linear, function-matched initialization | 0.006695122 | 0.009443633 |
| Put + linear, mapped after training | 0.006281313 | 0.010090813 |

The old six-head audit was independently rerun on this complete, exact
checkout. Its regrets, paired confidence intervals, and Hermite feature/
Jacobian differences reproduce the earlier report's numeric results. The
earlier caveat about reconstructed local dependency modules is addressed for
this replay; the original record is preserved unchanged.

The ordinary two-gate model remains substantially better than the dual model
on this particular synthetic task. Dual minus ordinary is `+0.004145208` ID
and `+0.007042515` OOD. The exploratory paired bootstrap intervals are
`[+0.002432726,+0.006448567]` and `[+0.002478281,+0.013334796]`, respectively.
Positive differences mean the candidate has higher regret.

The independently trained Put + linear variants do not establish a stable
advantage over dual:

| Candidate minus dual | ID mean difference | Exploratory 95% interval | OOD mean difference | Exploratory 95% interval |
|---|---:|---|---:|---|
| Same parameter seed | +0.000496569 | [-0.000986162,+0.001979882] | +0.000454597 | [-0.001524866,+0.003120218] |
| Function-matched initialization | +0.000413809 | [-0.000524537,+0.001227448] | -0.000647181 | [-0.002118050,+0.000867166] |
| Mapped after training | 0 | [0,0] | 0 | [0,0] |

The mapped-after-training policy has exactly the same evaluated per-state
regrets across all `3 × 420 × 2` seed/state/distribution combinations. These
regrets integrate the internally enumerated decision paths; equal regret alone
does not prove that every internal floating point decision is identical. This
is a numeric observation on these states; the real-arithmetic function-class
claim follows from the independent algebra above. No claim of bitwise equality
on every possible floating point input is made.

The raw JSON retains all 25,200 per-state regret values across the ten controls,
per-seed means, paired differences, training records, and data/source hashes.
The confidence intervals use only three training seeds, reuse exploratory
holdouts, and do not replace a prospective, independently evaluated experiment.

## Signed slope and fixed-capacity checks

The 512-point heldout feature check reconstructs `[C,P]` from `[P,L]` and
compares each channel's full **signed** Jacobian with respect to all four
inputs. Tests additionally check finite differences, both belief-reflection
sides, both stopping regions, and points at/near the stopping boundary.

| Check | FP32 maximum absolute difference | FP64 maximum absolute difference |
|---|---:|---:|
| Reconstructed feature values | 5.9605e-8 | 1.1102e-16 |
| Reconstructed signed feature Jacobian | 8.9407e-8 | 1.1102e-16 |
| Trained head logits after weight mapping, worst seed | 2.6822e-7 | 4.4409e-16 |
| Trained head signed input Jacobian, worst seed | 1.4305e-6 | 2.6645e-15 |

No decisions changed on those 512 diagnostic points for any of the three
mapped trained heads. The FP64 head check converts trained FP32 weights to
FP64 first and then performs the coordinate mapping in FP64.

| Model class | Trainable parameters | Parameter bytes | Fixed buffer bytes |
|---|---:|---:|---:|
| Dual, Put + linear, Call/Put/margin only, ordinary gates | 161 | 644 | 0 |
| Tangent-matched ordinary control | 161 | 644 | 64 |
| C1 Hermite control | 161 | 644 | 52,844 |

The tangent control matches signed derivatives only at its declared anchor
`(0.30,0.82,0.06,3)`: maximum signed-Jacobian mismatch `1.1921e-7`.
The maximum mismatch on the heldout inputs is `7.5393`, so this is explicitly
not global slope matching. Its poor task result cannot by itself isolate
the value of free-boundary curvature.

## Executed verification and reproduction

**21/21 combined P1 tests passed, zero failures and zero skips**, including
seven new tests of the identity, inverse mapping, signed gradients, independent
finite differences, RNG/source preservation, exact policy evaluation, and the
full audit path. The test log is retained. The unmodified independent scientific
gate returned **exit 2**, with all legacy P0–P6 stages OPEN and no production
activation. Its missing external trust root is not treated as the only
remaining scientific requirement.

From the repository root:

```sh
export OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
python -m unittest research.hcsn.test_p1_exact_policy_eval research.hcsn.test_p1_paired_policy_audit research.hcsn.test_p1_tangent_control research.hcsn.test_p1_hermite_control research.hcsn.test_study research.hcsn.test_p1_put_linear_control -v
python -m research.hcsn.p1_paired_policy_audit --output /tmp/hcsn-p1-legacy-replay-new.json
python -m research.hcsn.p1_put_linear_control --output /tmp/hcsn-p1-put-linear-new.json
python -m research.hcsn.independent_gate --bundle research/hcsn --strict
# The last command is expected to return 2 until independent scientific evidence exists.
```

Artifacts in this directory:

- `2026-11-05-p1-exact-checkout-legacy-replay.json`: complete legacy audit replay.
- `2026-11-05-p1-put-linear-control.json`: ten-control results and per-state data.
- `2026-11-05-p1-controls-tests.log`: the executed 21-test receipt.
- `2026-11-05-p1-execution-manifest.json`: commands, source identities, versions,
  artifact digests, and the actual strict-gate exit code/output.

## Remaining P1 requirements

The feature/control omission and the source-exact replay gap are addressed.
An independent positive mechanism benefit is not established: the existing
ordinary baseline wins this task, the Put + linear control has the same
function class as the implemented dual kernel, and the remaining training
differences include parameterization/optimizer effects. Actual backward FLOPs,
global slope controls against non-equivalent gates, real temporal and multimodal
quality, future independent test sets, and quality-matched system costs still
require evidence. All results remain research-only on the existing Draft PR.
