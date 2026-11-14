# HIA full-cost arithmetic owner

The selected `full_cost.hepta` image implements the finite arithmetic in the
ordinary `assess_full_cost` caller. It sums every declared one-time cost and
every execution, controller and failed-attempt cost, finds each arm's maximum
RSS and p99 observation, chooses the cheapest control, and produces the exact
signed saving, parts-per-million ratio and six ordered reason flags.

The ordinary immutable JSON parser, field and digest checks, registered trial
matching, report construction and foreign object transport remain hosted.
Observation provenance, semantic equivalence and deployment authority do not
follow from arithmetic. All existing report fields and their meaning are
retained, including `authority="DENY_ALL"` and
`production_activation_allowed=false`.

## Selection and construction

```sh
python -B tools/build_hia_full_cost.py \
  --compiler /qualified/B3.image.bin --cold-report /qualified/cold.json \
  --output /new/private/full-cost
export HEPTA_HIA_FULL_COST_MANIFEST=/new/private/full-cost/manifest.json
python -B tools/qualify_hia_full_cost_callers.py \
  --cold-report /qualified/cold.json --evidence /new/private/cost-callers
```

The builder requires the complete current source identity in a successful cold
report. Its separate `--development` mode permits component experiments with an
explicit compiler, and reports that narrower scope. It does not relabel a
previous-source compiler as a current cold qualification.

An absent selector preserves the original API. A present empty selector is
refused. An invalid selected manifest, changed packaged source, failed native
transport or malformed native result has no reference-arithmetic fallback.
The ordinary caller captures one selected image for the whole comparison.

## Exact numerical and refusal behavior

The original limits remain eight through 128 registered trials, eleven named
one-time costs, four strategies, and a complete per-arm total at most
100,000,000,000,000,000 nanoseconds. RSS retains its 2^48-byte ceiling. Every
original numeric and identity check runs in its original order before native
facts are used. The total-limit refusal still precedes the same arm's
unknown-cost ledger check and the next arm's admission.

A native arm accumulator saturates only after exceeding the original complete
arm limit. Such an arm is rejected at the original location; a saturated total
is never used to construct a verdict. This avoids machine-word overflow even
when every individually valid supplied cost is near its maximum. All admitted
totals and every maximum are exact.

Control selection uses `(total, name)` ordering, including ties:
`baseline`, `dp`, then `fixed`. The HIA program computes

```text
saving = best_control_total - ndu_total
saving_ppm = floor(saving * 1,000,000 / best_control_total)
```

The intermediate product can exceed 64 bits. Two unsigned 64-bit limbs retain
it, and a bounded 128-step division preserves every bit. For a negative saving,
a nonzero remainder rounds the magnitude up before restoring the sign. This
preserves Python's floor division, including ratios whose final magnitude also
exceeds 64 bits. No float conversion or new ratio ceiling is used.

The relative threshold uses the exact integer ratio: for nonnegative saving,
`floor(saving * 1,000,000 / best) < minimum_gain_ppm` is equivalent to the original
cross-product comparison because the threshold is an integer and `best > 0`.
Negative saving always fails the positive minimum-gain threshold. The reason
order remains unaccounted costs, different observers, absolute gain, relative
gain, memory and p99.

## Source and caller verification

The frozen `full_cost_0daf86d.py.txt` input under `tests/fixtures/` contains the original full-cost module
from the published baseline. It is an independent test input, not an alternate
production implementation. Its exact SHA-256 is pinned by the component tests.
The tests compare complete original verdicts and refusal messages, then execute
the HIA source in the independent Core VM before constructing a native image.
Actual native results compare full output buffers with those VM observations.
Transport refusals leave output unchanged, and adjacent output/workspace
canaries protect the ABI checks.

`tests/test_hia_full_cost_native.py` covers the original 128-trial and total
boundaries, simultaneous invalid conditions and their refusal order, signed
ratios beyond 64 bits, negative rounding, control ties, all six reasons, random
exact integer cases, source regeneration and selection failure without fallback.

`tools/qualify_hia_full_cost_callers.py` runs all methods in six complete original
modules: full-cost comparisons, paired holdout, bounded research wire, evidence
JSON, real four-arm ELF process observations, and native paired replay. It
forbids both retained Python arithmetic bodies, counts actual native calls, and
requires identical planned, started and finished test identities with no skips,
errors, expected failures or unexpected successes. Compiler/source/manifest
bytes and the complete original modules are bound in its result. These controls
qualify this arithmetic component; the retained JSON, service, process and
persistence implementations require their own replacement and acceptance.
