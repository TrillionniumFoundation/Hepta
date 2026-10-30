# Exact finite-graph compression before native NDU

## Problem and implemented change

`finite_plan_request` previously materialized every path through its bounded
compiler graph. The native bridge admits at most 128 candidates including
literal abstention, so a graph with more than 127 paths failed even when almost
all paths were strictly inferior. The existing `light_bundle` control already
uses additive dynamic programming, but chooses by total integer nanoseconds
with an explicit tie-breaking policy. It is a control, not an exact replacement
for native Q32 evaluation and its unresolved value ties.

`hepta.hia_planning.compact_finite_plan_request` now reuses the original intake
validation and wire encoder and selects `search="dynamic-frontier"`. It solves
the same disclosed graph with memoized resource/utility labels, then sends real
retained paths to the unchanged Rust NDU executable. Default enumeration remains
available for exhaustive comparison.

`exact_finite_plan` is the equal-objective lightweight control: it reuses the
same validated graph, exact Q32 label search and unresolved-tie/abstention
semantics, while avoiding native event encoding and transport. Its Python
advice explicitly says `native_evaluation=false`. This control distinguishes
native NDU overhead from a difference in mathematical objectives.

This profile supports the existing limits: 8 states, 32 transitions, 4 future
batches, a common terminal value, unit discounts, zero path risk, and one
additive total-cost ceiling. It is not an arbitrary recursive-utility solver.
The bridge's resource quantity is a feasibility ceiling; the profile's only
Pareto utility dimension is `utility.net`. General multi-axis utility or
non-unit discount profiles require a different compression proof.

## Preservation argument

For a path, let `C` be total integer nanoseconds and let `D` be the sum of the
positive debits actually encoded for its events:

```
D = sum(floor((setup_ns + decision_ns) * 2^32 / 1_000_000)
        + floor(execution_ns * 2^32 / 1_000_000))
```

The current wire profile has unit discount, so native backward recursion gives
the exact integer value `terminal_q32 - D`. Converting total nanoseconds once
does not give the same value in general. At a shared `(state, batch)` boundary,
a suffix `(C1,D1)` strictly dominates `(C2,D2)` only if `C1 <= C2` and `D1 < D2`.
Every common prefix preserves that strict utility improvement and budget
feasibility. A cheaper suffix with equal debit does **not** erase the other
suffix: when both fit, native NDU must preserve their tie.

All costs are nonnegative. A suffix already over the whole remaining budget
cannot become feasible after any prefix. For integral nanoseconds, the resource
encoding `floor(C * 2^32 / 1000)` is strictly increasing, so the integer test
`C <= remaining_budget_ns` is exactly the bridge's resource-ceiling test.

The root keeps every best budget-feasible complete path for each first action.
A lower-value path in that group cannot enter the global winning frontier,
because a higher-value feasible path in the same group is present. Keeping all
ties in every group therefore preserves the complete globally winning native
frontier, its unique recommendation or unresolved disposition, and its
comparison with literal abstention. Path identifiers and event encodings are
unchanged for every retained path.

These claims are conditional on the declared graph and cost inputs. They do not
show that forecasts predict future hardware performance, that the graph is a
sufficient representation of a whole program, or that a source verification
digest authenticates a proof.

### Numerical domain and request-level refusal boundary

The preservation claim concerns feasible candidates in the current validated
finite-graph profile. It does **not** assert that every uncompressed wire request
has the same request-level acceptance or rejection as its compressed request.
The `complete_native_winning_frontier_preserved` field has this candidate-level
scope. A successful response from an otherwise valid full request and its
compressed counterpart must have identical winning IDs and dispositions; when
the full request fails decoding or numeric-profile admission, it has no native
winning frontier to compare.

This distinction is observable at admitted graph-input limits. An individual
cost may be at most `10^12` ns, but an uncompressed path can sum several such
costs. A 23-path native probe reached `5,000,000,000,004` ns and a resource field
of `21,474,836,480,017,179,869`, exceeding signed i64. The full request failed
native decoding; compression first excluded over-budget paths and its valid
request succeeded. A separate probe stayed within i64 but reached
`1,200,000,000,003` ns with zero completion value; the full bridge rejected
projected utility. Compression again excluded the over-budget paths and native
evaluation succeeded. No equivalent whole-request refusal is claimed for these
cases, and omitted invalid paths do not receive fabricated native receipts.

The retained paths have a stronger, automatically enforced numerical bound.
Both public entries use the same original validator:

- `0 <= completion_value_ns <= 10^12`;
- `0 <= remaining_budget_ns <= 10^12`;
- retained total cost does not exceed that budget;
- every phase cost is nonnegative, and every discount is exactly one.

Consequently the largest retained resource Q32 value is
`4,294,967,296,000,000,000`, below signed i64's
`9,223,372,036,854,775,807`. The terminal value and total per-event debit are each
at most `4,294,967,296,000,000`, exactly the bridge's utility limit. Every backward
value is the terminal minus a nonnegative suffix debit, so it stays between
the inclusive lower and upper limits without projection. Per-event flooring
can reduce a debit; it cannot violate this bound. Thus a valid retained winning
path cannot be accepted by `exact_finite_plan` while requiring projection in the
native compressed request under this profile.

The post-freeze read-only audit exercised seven native endpoint cases: maximum
terminal with zero cost, zero terminal with cost exactly equal to the maximum
budget, equal maximum terminal/cost, four large cost phases, nonintegral Q32
phase conversion at the same total bound, an unaffordable later decision, and
all delivery paths exceeding a small budget. All native projection counts were
zero and all exact-Q32 recommendations, complete frontiers and dispositions
matched. Budget or terminal input `10^12 + 1` was rejected by both public
entries. Frozen production sources were not changed during this audit.

Any later widening of the public bounds, changing utility units or discounts,
or adding signed costs must restore this proof or add shared numeric admission
before both controllers. Boundary regression requirements are to retain the
seven endpoint agreements and both expected full-request refusal differences;
tests must not require request-level equality for unencodable or projected full
requests. These read-only review probes supplement the frozen nine-test run;
they are not silently relabeled as additional committed test cases.

## Refusals, ties and stopping

- Unknown, rejected and timed-out states/transitions never become feasible.
  The search retains exact complete-path counts by verification-status set.
  Omitted invalid paths do not receive fabricated native rejection receipts;
  `native_rejected_list_preserved` is explicitly false.
- Every optimal tied path needed by a first-action group must fit the 127-path
  native wire allowance. If it does not, the search rejects the whole request.
  It does not replace a large tie by two samples or choose an arbitrary ID.
- `stop` is an executable plan that delivers all remaining batches on the
  current code. Its costs and terminal value remain present. `abstain` has
  literal zero effect, cost and utility; they are distinct alternatives.
- Search counters and complete multiplicities are bound into support evidence.
  The output says `search_complete=true` and `enumeration_complete=false`.
  Label-work and frontier limits fail without emitting a partial plan.
- At execution the existing caller still checks source and checker identity,
  re-proves and compiles an actual transition, checks the resulting source and
  artifact receipt, loads sealed bytes, and enforces the observed episode
  budget. Cost forecasts do not waive those boundaries.

## Discriminating regression cases

`tests/test_hia_planning.py` includes exhaustive differential checks of 80 fixed
random graphs, independent rational backward recursion, all verification
statuses, budget boundaries, explicit abstention and complete equal-value
frontiers. Twenty-four additional graph pairs are evaluated by the original
native binary when `HEPTA_NDU_IDENTITY` is supplied. Both native responses must
have identical complete winning IDs, advisory ID and disposition.

One two-nanosecond witness distinguishes the native profile from total-cost
ordering. Stopping with one 2 ns execution encodes a debit of 8589 Q32 units.
A transition with 1 ns setup followed by 1 ns execution encodes 8588. The native
utility strictly prefers the transition despite equal total nanoseconds; the
ordinary nanosecond control's separate tie policy may prefer stopping.

A five-state, four-batch graph covers 656 complete paths and is compressed below
the native capacity. Eight further 656-path graphs, including changing costs,
budgets and verification states, are independently expanded and their complete
best-path sets for every first action agree with the DP. The same graph with all-zero costs has an oversized tied
frontier and is deliberately rejected. The latter is a retained limit, not a
successful unique optimum.

## Cost and execution evidence

The controller qualification entry point is:

```sh
python tools/qualify_hia_ndu_compression.py \
  --identity /path/to/original-native-build-identity.json \
  --transport oneshot --output /new/evidence/directory --repetitions 9
```

Its model costs are explicit fixtures, not newly measured program runtimes.
It compares the existing nanosecond DP, exhaustive native requests and
compressed native requests on identical inputs. Construction, actual native
request/response, the arm's evidence encoding/write, process admission and
shutdown are accounted. The unchanged executable's original measured cold
build cost is separately included in each native standalone-strategy total.

The 2026-10-30 one-shot run in
`artifacts/hia-ndu-compression-oneshot-20261030/RESULT.json` retained 4 of 31 paths;
8 complete native differential cases agreed. Nine fixed repetitions yielded:

| Control | Median measured pipeline | Standalone total for nine repetitions |
| --- | ---: | ---: |
| Existing nanosecond DP | 0.632 ms | 5.320 ms |
| Native exhaustive | 5.671 ms | 24.5959 s |
| Native compressed | 2.906 ms | 24.5722 s |

The native totals include the original manifest's 24.5417 s cold build, which
was not rerun for this unchanged Rust executable. These descriptive controller
measurements do not establish an advantage over the lightweight DP or a whole
program performance gain.

After the explicit equal-Q32 control was added, the separate, retained
four-control run in
`artifacts/hia-ndu-compression-four-controls-20261030/RESULT.json` used nine
predeclared repetitions. Median measured pipeline costs were 0.725 ms for the
historical nanosecond DP, 1.210 ms for exact-Q32 DP, 8.251 ms for native exhaustive
requests and 4.098 ms for native compressed requests. All eight native
differential cases also agreed with the exact-Q32 control's complete frontier,
unique recommendation and disposition. The original measurement remains
archived; these samples are not pooled into a claimed confidence interval.

The attempted persistent transport was rejected because this managed sandbox
denied the existing `/proc/<native-child>/exe` identity check. The failed attempt
and unchanged-check boundary are retained in
`artifacts/hia-ndu-compression-20261030/FAILURE.json`. The successful run explicitly
selected the supported one-shot transport; it did not weaken the stream check.

For full actual compiler/workload accounting, the existing
`tools.qualify_hia_ndu_graph.qualify` accepts all six original controls plus the
optional `ndu-compact` and `q32-dp` arms through `protocol["arms"]`. Both native arms share the
same measured candidate bank and workload protocol and have separately charged
native admissions, calibration, requests and, for streaming, shutdown. Each
standalone strategy includes its original native build allocation. Actual
proof/build/load/run/measurement and each arm's evidence writes retain the
existing ledger.

### Actual eight-arm compiler pilot

`artifacts/hia-ndu-eight-arm-20261030/` preserves the real native libraries,
driver, per-stage ledgers, complete receipts, protocol and a 136-file frozen
source closure. The one-group shared-host pilot used 19 calls, a 5-element
initial probe and future batches of 5, 19 and 47 elements. All eight episodes
completed, all independent output checks passed and every observed budget
passed. The fixed-small and fixed-wide controls performed two actual
re-proposal, proof, compilation and native-installation transitions. Both native
NDU controls, the exact-Q32 DP and the best-fixed-plan control stopped optimizing
and delivered every remaining batch on the baseline. Thus stopping was a real
delivery choice, not unearned terminal reward or a hidden failed run.

| Strategy | Observed episode wall time | Complete standalone cost within the registered scope |
| --- | ---: | ---: |
| Best fixed plan | 0.513049 s | 2.564834 s |
| Historical nanosecond DP | 0.507032 s | 2.560208 s |
| Exact-Q32 DP | 0.505286 s | 2.560145 s |
| Native exhaustive | 0.626027 s | 27.239987 s |
| Native compressed | 0.472808 s | 27.080783 s |

Each native standalone total includes the original, separately identified
24.541662 s build. Shared calibration/proof/driver costs are charged once per
standalone strategy; per-arm compilation, actual decisions, workload execution
and evidence writes remain in that arm's ledger. The native binary was reused,
not rebuilt or silently assigned zero build cost. Installation/dependency-cache
acquisition and the final aggregate report write remain declared exclusions.

The preceding seven-arm pilot is also retained in
`artifacts/hia-ndu-seven-arm-20261030/`; there compressed native had a *higher*
observed episode cost than exhaustive native. These single-group samples on a
shared host do not establish a performance ranking or statistical superiority.
The current end-to-end evidence does not show a net benefit over the equal-Q32
lightweight control. A smaller serialized candidate set and a passing native
equivalence check are the supported improvements.

Reproduce the frozen eight-arm result with a writable new output directory:

```sh
python artifacts/hia-ndu-eight-arm-20261030/REPRODUCE.py \
  --identity /path/to/original-native-build-identity.json \
  --clang /path/to/clang --output /new/eight-arm-evidence
```

The frozen closure is checked before import; the protocol is loaded from its
preserved file. It restores the exact baseline `kernels.hepta` from commit
`a32ad51250b905bb4729168f4d8f9328880b44db`, Git blob
`a03cfe5f090138546cce3d3d86a4577f13cae999`, which was missing from the initially
restored local worktree. The same source identity is retained with both pilot
archives. Execution-source drift is rejected by the original measurement
boundary rather than excused by unchanged performance results.
