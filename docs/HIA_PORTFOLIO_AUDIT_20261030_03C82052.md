# Independent audit: registered portfolio result at 03c82052

The registered execution passed. The registered economic acceptance failed. The
saved artifacts support this negative result; this review found no cost-sum,
native-parity or candidate-selection error that explains it away. The experiment
also failed to establish its intended competitive choice regime, so it cannot
establish the value of a learned predictor or adaptive choice among profitable
alternatives.

This report inspects existing evidence. It does not rerun, extend or replace the
registered experiment, change its horizon, or treat a later protocol as its success.

## Identity and inspected evidence

- Registered source: `03c8205271dc5e8f9c5cad806e46056bffe2bc02`.
- [Actions run 41059492139](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41059492139), job `124075353180`.
- [Original artifact 12978382875](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41059492139/artifacts/12978382875).
- Uploaded ZIP SHA-256: `96a386d6fb883a7c214223260bfc88b4155f7d155edc52e99851c801383aabd6`.
- Original native source: `4b6391e116949af0c7e59776baead67271856bdb`, Rust 1.95.0.
- Host: x86_64 Azure Linux, Python 3.12.15; report start `2026-10-30T13:00:54.058284+00:00`.

The independent calculations are saved in
`evidence/hia_portfolio_audit_20261030_03c82052/independent-audit.json`.
They bind the original result, source copies, protocol, native build manifest,
small oracle, every episode and the stored decision/native-response data.

All 16 audit checks passed. In particular:

- Every archived source copy matches its registered source binding, and the local
  runtime inspected for this audit matches those copies.
- All five warm and original-build-inclusive totals recompute exactly.
- The outer native build receipt matches its original identity and builder hashes;
  the before/after native source admissions agree.
- The stored independent 625-combination small oracle agrees with the DP on plans,
  Q32 values and frontier. This is a small finite-model control, not a language proof.
- Every stored complete plan's activation/run sums, per-event Q32 debit and model
  resource constraints recompute independently.
- All 120 execution observations report matching independent checksums, matching
  expected artifact hashes, sealed snapshots, verified loaded mappings and exit 0.
- All 24 original native NDU responses agree with the exact control's values,
  frontier and advisory choice.
- Every arm's final evidence write is included in its own outer elapsed time.

These are checks of actual saved evidence and arithmetic. They do not independently
attest the CI hardware, toolchain's semantic correctness or native memory safety.

## Measured result

The protocol used two groups, five arms, twelve regions per episode and 4,093
kernel calls per region. The sum of lengths was 187,584, corresponding to
767,781,312 logical element visits per episode. All ten episodes completed and
all arms selected `base` for every region.

| Arm | Two actual episodes | With common preparation/controller | With original NDU build |
| --- | ---: | ---: | ---: |
| Fixed base | 1.579854659 s | 11.525890119 s | 11.525890119 s |
| Fixed best plan | 1.584252541 s | 11.530288001 s | 11.530288001 s |
| Lightweight greedy/single | 1.615901151 s | 11.561936611 s | 11.561936611 s |
| Exact Q32 DP | 1.638929717 s | 11.584965177 s | 11.584965177 s |
| Original native NDU | 1.751733964 s | 11.700444938 s | 39.715816139 s |

Observed common preparation is 9.946035460 s, charged once to each standalone arm.
The native identity/controller admission adds 0.002675514 s to native NDU.
The original empty-target build's outer cost is 28.015371201 s; its inner recorded
cost is 27.948726915 s. The 0.066644286 s difference is retained instead of silently
omitting outer startup/manifest scope. The reconstructed experiment wall time,
excluding the separately measured native build, is 18.119383006 s.

Within the already-built-NDU scope, native NDU costs 0.115479761 s more than exact
DP, about 0.997%. Including the original bridge build, it costs 28.130850962 s more,
or about 3.428 times the exact-DP measured standalone total. These are descriptive
two-group observations, not significance estimates or universal speed ratios.

The cold scope means an absent Cargo target and the original measured build. It
does not mean a fully cold machine: toolchain acquisition, dependency-cache prior
history, human work, persistent storage and final aggregate writing remain outside
known lifetime costs. The common calibration charge is deliberately identical for
all arms; it is not a claim that a minimal fixed-base deployment needs to calibrate
all alternatives. Removing that common charge would not make the observed native
delta positive.

## Why no alternative was chosen

The calibrated complete-horizon economics are:

| Artifact | Activation/proof/build | Twelve-region runtime | Complete cost | Net saving versus base |
| --- | ---: | ---: | ---: | ---: |
| Base | 0.352664434 s | 0.370340037 s | 0.723004471 s | 0 |
| Guard small | 0.729021969 s | 0.365051193 s | 1.094073162 s | -0.371068691 s |
| Guard wide | 2.681892009 s | 0.334335309 s | 3.016227318 s | -2.293222847 s |
| Narrow wide | 3.139168635 s | 0.461158982 s | 3.600327617 s | -2.877323146 s |

Guard wide saves 36.004728 ms of modeled runtime but requires 2,329.227575 ms of
additional activation. Narrow wide is slower over the registered mixed horizon
even before charging its additional build/proof cost.

There is an even stronger independent diagnostic. At the first decision, completing
the entire baseline costs 723.004471 ms, while the cheapest nonbaseline artifact's
activation alone costs 729.021969 ms. Every possible plan using a nonbaseline
artifact must pay at least that activation and then nonnegative runtime. Baseline
therefore wins without needing a complex search. This lower-bound dominance holds
in **all 120 actual decision states**, including the same per-event Q32 arithmetic.
The smallest margin is 6.017498 ms. Once baseline is paid for, the largest remaining
baseline cost observed in the decision model is 520.596321 ms, still below the
cheapest alternative activation.

The workload has a further disclosed design limitation: guard-small's maximum is
256, but the smallest formal region is 257. Its fast length guard can apply to
zero of twelve formal regions. The calibration probe includes length 127, but
that probe is not a heldout deployment region. Wide and narrow-wide have length
guards covering nine of twelve regions; three use the general fallback. The small
guard's slight measured runtime difference cannot establish a useful fast-path
advantage on this heldout horizon.

Accordingly, `competition.established=false` and
`actual_nonbaseline_artifacts=[]` are meaningful failures of the preregistered
competition gate. The implementation did not manufacture a profitable candidate,
remove acquisition cost, or enlarge the horizon after seeing this result.

## Separate search, prediction and native evaluation

The mechanism does exercise bounded state search: the first twelve-region DP
generates 420 labels, peaks at 16 states and excludes combinations for capacity
and rejected verification status. It represents a much larger raw Cartesian set.
That machinery works on this recorded model, but its final choice is also implied
by the simple activation lower bound above. This run cannot demonstrate a practical
selection advantage from the additional search machinery.

There is no trained predictor in this profile. Every dynamic arm uses the same
calibration model and its own latest completed latency ratio, clamped to [1/4,4].
Because every arm executes only base, the heldout trajectory provides no actual
observations of choosing or switching among the alternative artifacts. There is
no basis for a learned forecasting, generalization or exploration claim.

The native arm first performs the exact Hepta search and then supplies its best
feasible paths to the original Rust NDU evaluator. It cannot obtain a better
optimum of that same finite additive model than the exact oracle that produced
its input. Its useful result here is numerical/selection parity, not a higher
quality optimization choice.

Across 24 decisions, recorded decision-stage time is 235.997639 ms for native NDU
and 103.071405 ms for exact DP, a difference of 132.926234 ms. This includes problem
construction, exact search, wire/bridge work, one-shot process handling and parity
checks; it is not an isolated benchmark of Rust arithmetic. Differences in actual
proof/build time and runtime reduce the final warm delta to 115.479761 ms. Those
components should not be attributed to a superior or inferior choice when all
arms execute the same baseline.

## Acceptance still unmet and the next independent study

This result supports: the particular registered attempt did not meet its economic
acceptance and did not demonstrate competitive candidate selection. It does not
support: NDU can never help another workload, every future learned model is useless,
Rust has been surpassed, whole programs are globally optimized, or NDU establishes
resource safety. The proof/admission path remains separate from NDU advice.

A future study requires a new ID and prior registration, retaining this result:

1. Choose a realistic deployment trace and reuse lifetime from an external workload
   requirement before examining its prospective outcome. Do not choose a repetition
   count merely to cross this experiment's measured break-even point.
2. Include guard-covered and fallback work matching that trace, and genuine tradeoffs
   in execution time, retained code and scratch use. Treat absence of profitable
   competition as a reported outcome again, not an exclusion criterion.
3. Distinguish candidate-generation/proof savings, prediction quality and search
   quality with separate ablations. A new learned predictor needs equal information
   and lightweight prediction controls; the present recursive evaluator is not it.
4. Keep an exact small-model oracle, honest bounded-search refusal, original native
   source identity, complete failed-attempt costs, and both prepared and build-inclusive
   deployment scopes. Do not exempt only NDU or only its controls from preparation.
5. Preserve finite-model versus whole-program, descriptive versus statistical, and
   admission versus performance boundaries in both code and claims.

No such follow-up has been run or counted as success by this audit.
