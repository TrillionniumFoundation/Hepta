# Compiler-plan paired observations and cost scope

The current actual compiler workload already compares canonical code with two
explicit compact-immediate plans. Its median alone does not describe paired
changes, observed slow samples, or the preparation cost that must be recovered.
`tools/analyze_hia_selfhost_machine_plans.py` adds a read-only analysis over the
original native campaign. It launches no native program or model and never
turns a finite timing observation into a release/performance acceptance.

## Frozen measurement for this follow-up

Use the unchanged `qualify_hia_selfhost_machine_plans.py` with seven repetitions
on source based on `2e2afc1ad725db85cb8cf7eba69f657cae7c4464`. The actual checkout
commit, tree, source inventory, Python identity, machine plans, ELF images,
native requests and all output buffers are recorded by that original tool.
No candidate is selected from these observations and no ISA feature is added.

The three arms remain `canonical`, `compact_immediates`, and
`compact_swapped_scratch`. Each compiles the same complete checked-in compiler
and byte-hash example seven times, in the original rotated and alternating
order. Retain all 42 measured compilations, 18 invalid-source observations,
six capacity observations and 15 executions of the produced example. A failed
campaign remains an original failed campaign; no replacement sample is allowed.
The analyzer's accounting rules are committed before the measurement.

This is a CPU native compiler experiment, not a GPU workload. The available
local qualification runtime is appropriate for the small fixed campaign.
Concurrent load and shared-host scheduling are not controlled; the result makes
no isolated-host or population inference claim.

## What the analysis adds

- Reconstruct every pair by original round and arm. Report each timing and each
  canonical-minus-candidate difference, their mean and median, and the number
  of positive differences. A difference of unpaired medians is not substituted.
- Retain minimum, median, maximum and nearest-rank empirical p95. With seven
  observations, that p95 is the maximum; it is not a service tail estimate or a
  population confidence bound. No outlier or failed control is removed.
- Reconcile measured arrays against each original scheduled call, the original
  child stdout, request, receipt, image and complete source/output bytes.
- Report each arm's original emission plus rederive/link/recheck wall and CPU
  intervals. Keep common registration separate and preserve the campaign's
  enclosing wall and CPU interval without adding nested phases again.
- Compute a conditional point break-even only if the median paired saving is
  positive: `ceil(max(0, candidate_prepare - canonical_prepare) / saving)`.
  It covers only the observed preparation difference and repeated identical
  workload assumption. If no positive saving is observed, this value is null.

Source/dependency acquisition, Agent or human engineering, provider fees,
final inventory/upload, deployment, future use and recovery are not measured.
Their values remain unknown. Therefore `full_lifecycle_break_even_calls` is
always null, `full_lifecycle_cost_known` is false, and broad P4 remains HOLD.
The canonical compiler is the strongest baseline measured by this plan-only
comparison; an independent strong compiler/application baseline is still absent.
Identical finite compiled output and buffer ABI do not prove general compiler
refinement or all-input resource semantics.

## Reproduction

From the clean committed source, write original evidence outside the checkout:

```sh
python -B tools/qualify_hia_selfhost_machine_plans.py run \
  --output /absolute/new-original-campaign --repetitions 7
python -B tools/qualify_hia_selfhost_machine_plans.py verify \
  --output /absolute/new-original-campaign
sha256sum /absolute/new-original-campaign/SEALED.json
python -B tools/analyze_hia_selfhost_machine_plans.py \
  --campaign /absolute/new-original-campaign \
  --expected-sealed-sha256 EXACT_ORIGINAL_INVENTORY_SHA256 \
  --output /absolute/new-paired-analysis.json
```

The analysis output must stay outside the sealed original directory. The
inventory and every original file are checked before a saving is calculated.
This establishes retained-byte consistency, not independent execution or
billing provenance. Synthetic accounting tests in
`tests/test_hia_selfhost_paired_cost.py` reject missing pairs, reordered
observations, changed timing summaries, different input/output identities,
missing costs and incomplete control inventories; they are not timing data.

## P5: keep the strongest-control comparison

The separate paid-information candidate in
[PR #829](https://github.com/TrillionniumFoundation/Hepta/pull/829), exact source
`e3ae8b615f2a173d99efe16d08f884f4617f321b`, has original-native integration in
[run 42591644213](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42591644213).
Its two-step authored witness reaches approximately 63.2 declared utility units
against myopic 60. The complete same-objective ordinary controller and the
independently enumerated full policy tree attain exactly the same optimum.
That result establishes priced nonmyopic information acquisition, not an NDU
increment. Its original four finite witnesses are not an independent Agent
cohort, learned calibration, provider bill or economic-value result.

The next P5 comparison must use separately calibrated uncertain forecasts,
actual observation that changes downstream actions, independent task outcomes,
matched same-Agent information and budget, and retain all failures and fallback
use. None of the compiler timings or repeated finite supplied-model backups
substitutes for those missing observations. P5 stays HOLD.
