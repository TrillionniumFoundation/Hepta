# HCSN P2 Iteration 37: noncommuting CTMC restores endpoint order information

Parent Draft #512 expected HEAD `5a6ee4d8d00f8ec933543bd9f8d79c0a3edce9c5`; research-only, additive, HOLD/DENY_ALL.

## Independent mathematical construction
Two inputs use distinct generators (row-vector convention):

`Q0 = [[-r,r],[0,0]]` and `Q1 = [[0,0],[r,-r]]`, `r=2`.
They do not commute: `[Q0,Q1]=[[r*r,-r*r],[r*r,-r*r]]`.
For balanced two-write schedules A=0 then 1 (label 0), B=1 then 0 (label 1), identical 1-second durations, state initially 0, and q=exp(-r):

`P(state1|A)=(1-q)*q=0.11701964434787852`
`P(state1|B)=1-q=0.8646647167633873`
`Difference=(1-q)^2=0.7476450724155088`
`Bayes accuracy on balanced single final-state readout=.5+.5*difference=0.8738225362077544`.

Scalar shared-generator null retains 0 endpoint difference; changing to noncommuting generators therefore repairs the *specific* iteration36 permutation invariance in this minimal model. However this is not evidence of learned long-memory/selective-copy/MQAR performance.

## Actually evaluated in an independent JS V8 numerical reference
28 assertions passed, including separate RK4 ODE integration (maximum absolute error 2.4424906541753444e-15), exact analytic formulas, 4/16/64 split clock consistency (max 3.3306690738754696e-16), nine pre-specified rate/duration heldout analytic cases, fail-closed invalid inputs and independent Monte Carlo counts across 3 seeds (20,000 per schedule per seed; max z=1.2405218630700632). This is *not* a GitHub Actions CI run, independent external controller, Python HCSN suite, GPU or model training.

## Reproduce with a Node-compatible JS runtime
```bash
node research/hcsn/p2_noncommuting_order_reference.mjs > /tmp/hcsn-iter37.json
cmp /tmp/hcsn-iter37.json research/hcsn/gates/2026-11-04-iteration37-noncommuting-raw.json
node research/hcsn/p2_noncommuting_order_reference.mjs --strict >/tmp/hcsn-iter37-strict.json
# strict command MUST return exit 2; never use success of its numerical assertions to close any P0-P6 gate.
```
The Node CLI commands are reproduction instructions; execution verified in this turn was the JS reference algorithm in V8, not a Node/OS process (unavailable in this execution environment).

## Gate conclusion
P0-P6 OPEN; independent external full-domain HX/QVI, fair FLOP/parameter/slope controls, task-driven long Selective Copy/MQAR, real four-modality heldout, CPU/GPU energy/RSS/p95/p99 and medium-model frontier all missing. Prior P1/P2 negative results retained. No main merge, signatures, trust roots, or production activation changed.
