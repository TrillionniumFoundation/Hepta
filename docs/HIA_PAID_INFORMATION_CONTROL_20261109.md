# Paid information before macro selection

## Delivered boundary

`experiments/hia_ndu_feedback_20261106/paid_probe.py` adds a bounded information
action before a terminal macro choice. Earlier feedback-cache experiments
observe a request and signal at no explicit acquisition price. Here a `read`
is a selectable, positive-cost action. It reduces the original remaining
budget, reveals one current signal, and changes a later decision through its
posterior. An unused probe is never a realized future observation.

The implementation is a finite research controller, with two possible latent
regimes and at most two one-use probes. Likelihoods are supplied and signals are
assumed conditionally independent given the fixed regime. Terminal numbers are
declared utilities after declared terminal costs. They are not measured task
quality, provider invoices, or actual artifact adoption. All advice remains
`DENY_ALL`; existing production proof, adoption and accounting gates are intact.

## State, costs and controls

The immutable state contains only the consumed probe/signal history and the
remaining observation budget. The posterior is recomputed from that history.
The sum of consumed probe costs and remaining budget must equal the original
budget. Repeated probes, impossible observations and unpaid histories are
refused. A terminal `abstain` represents keeping the incumbent; it can have a
positive terminal value and is always available.

For belief `p`, budget `b`, unused probe `i`, and terminal actions `a`, the
full-depth controller implements

\[
V(p,b)=\max\left\{\max_a\mathbb E_p[U(a,Z)],\quad
\max_{i:c_i\le b}\left(-c_i+\sum_y P(y\mid p,i)V(p_{i,y},b-c_i)\right)\right\}.
\]

The actual arithmetic is Q32 with ties-to-even rounding at each backup.
Utilities and resource counters use distinct fields. Probe cost is charged
once in utility and once as consumption of its resource constraint; those are
not summed as two monetary charges.

Four controls use the same public model and original budget: no observation,
one-step VOI, full-depth direct arithmetic, and a separately encoded exhaustive
enumeration of complete contingent policy trees. The last control is an exact
finite oracle with the same information, not a clairvoyant policy. It does not
call the planner, its posterior helper, its transition helper or its backend;
it shares only input admission and the declared model.

An optional original `NativeValueBackend` performs each NDU backup before the
node selects its action. The backend verifies its original build receipt,
sealed executable, raw request/response identity and numeric relation. The
planner qualifies native evidence only from that exact supported class with
retained request/evaluation digests. Ordinary callbacks remain reference-only.
Native-required calls fail on absent evidence; they do not fall back to Python.

## Frozen mechanism witnesses

These are source-authored witnesses, not a held-out empirical task cohort.

| Witness | Strong finite control | Reason |
| --- | --- | --- |
| Perfect information, fee 1, terminal correct/wrong utilities +20/-20 | Read, value 19; then select according to the observed signal | The paid observation changes the later choice. |
| Same information, fee 21 | Keep incumbent, value 0 | Information has insufficient value after its price. |
| Uninformative signal, fee 1 | Keep incumbent, value 0 | A paid read does not change the belief. |
| Two independent 70%-accurate signals, fee 1 each; incumbent value 60; alternative payoffs +100/-100 | Full-depth reads, value approximately 63.2; one-step VOI keeps incumbent at 60 | Information can have value that requires more than one continuation. |

The fourth witness has approximately 3.2 units of value over the myopic policy.
The strong same-objective full-depth control and complete policy oracle obtain
the same value. This is evidence for nonmyopic information acquisition, **not
an incremental benefit unique to NDU**. With identical forecasts, objective,
rounding, feasible actions and tie rule, the affine native utility kernel and
the ordinary arithmetic kernel yield the same Bellman values by backward
induction. More repetitions of these supplied models cannot remove that fact.

## Verification and reproduction

Nine focused test methods cover hand-computable information value, posterior
dependent choices, price/budget stopping, two-step acquisition, 45 combinations
checked against exhaustive policy enumeration, causal state shape, native
qualification, failed-search cost retention and exact model admission.
`test_native.py` adds an actual original-backend integration method for all four
witnesses and both perfect-signal continuations. The research workflow retains
its existing source, build, no-skip and original-native gates and includes the
new reference and native tests. Local reference success is never substituted
for that native CI result.

From a clean checkout, write evidence outside the source directory:

```sh
python -B -m unittest tests.test_hia_ndu_paid_probe -v
python -B tools/qualify_hia_paid_information.py \
  --mode reference --expected-head FULL_EXECUTION_COMMIT \
  --output /absolute/new-paid-information-evidence
```

Native mode additionally requires `--binary` and `--manifest` for the original
value adapter. The runner writes its declared protocol before decisions,
retains complete case traces and failure state, checks unchanged source, and
measures an outer wall/parent-CPU/child-CPU interval including native startup
and close. It excludes prior acquisition/builds, authorship, final persistence
and upload. Those costs and monetary charges remain unknown, not zero.

## P5 acceptance

P5 remains HOLD. The new interface makes information acquisition an action with
an explicit price, and provides a strong finite reference for a later macro
task. It has no learned likelihoods, independent Agent tasks, original provider
fees, measured downstream value or positive increment over the strongest
same-objective control. A real comparison must freeze calibration on separate
training tasks, give every controller identical access and total allowances,
retain failures and fallback/use outcomes, and account for observation,
planning, calibration, candidate residency, execution and complete provider
costs. Changing the objective or granting hidden future information to one arm
does not establish that comparison.
