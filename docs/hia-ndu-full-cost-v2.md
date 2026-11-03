# NDU full-cost finite profile v2

This profile makes **not invoking NDU** an executable option. It is opt-in and
does not change `hia_ndu_stateful.py` v1, its contract, or its negative results.
The implementation is `hepta/hia_ndu_cost.py`; its native qualification entry
point is `tools/qualify_hia_ndu_cost.py`.

## Scope and authority

The registered profile has one always available baseline, one or two optional
native artifacts, and one to four remaining batches. Costs are bounded,
nonnegative integer nanoseconds. The model is deterministic and contains no
learned prediction or omniscient future information. Its optimality statement
concerns only these declared costs and this finite action set.

The model, Rust NDU, returned digests, and measured evidence remain advisory:
`authority=DENY_ALL`, `safety_certificate=false`. A digest binds bytes and inputs;
it does not authenticate a proof. The caller must independently admit executable
artifacts. The qualification checks HIA Core with its verifier and checks all
native artifacts against finite behavior, allocation failure, and lifecycle
observations. These probes do not prove all-input safety of C++, Rust, the ELF
loader, LLVM, or machine code.

## State and costs

A state is `(batch, ready artifacts, native session resident, remaining budget)`.
Artifacts have bound source, verification and support digests, a verification
status, validity for each modeled batch, resident bytes, preparation cost, proof
revalidation cost, retirement cost, holding cost, and per-batch execution cost.
The resident quota is checked before admitting a set. Retirement occurs before
new preparation. An invalidated artifact is removed even when NDU is skipped;
it cannot silently become usable again when a later validity bit becomes true.

The two actions at each boundary are:

* `skip`: keep only currently valid resident artifacts and execute the best
  admitted implementation; do not create a native session or send a request.
* `invoke(target)`: pay for search, original Rust NDU evaluation, transport and
  response validation, plus session startup if necessary; retire obsolete
  artifacts, independently revalidate newly prepared artifacts, load them, and
  execute the best admitted implementation.

Every boundary pays its gate cost. Every resident artifact pays its holding
cost. Native session closure is charged once at the terminal boundary. Sunk
costs are retained for accountability but are not subtracted from an already
reduced remaining budget a second time. Zero-cost fields are explicit; no field
is optional. In the native qualification the unchanged Rust protocol has no
internal timer, so evaluation, transport and response checking are a single
measured round-trip field. Their other fields are zero because they are included
in that field, not because the work is free.

For state `s`, action `a`, remaining budget `B`, and transition `T`, the finite
recurrence is:

`V(s,B) = min_a { cost(s,a) + V(T(s,a), B-cost(s,a)) }`.

An action is omitted if its status, validity, resident quota or budget is
infeasible. The terminal value is the remaining session-close cost. The
implementation retains one least-cost continuation for every distinct first
action. Within this scalar, zero-risk, zero-uncertainty profile, continuations
with the same first action and a greater total cost cannot improve the native
result. This is a complete first-action frontier; it is not a complete
enumeration of every future schedule.

### Exact elimination of the budget cache dimension

The current implementation memoizes `(batch, ready artifacts, session resident)`.
It computes the least total continuation cost, then checks that complete cost
against the caller's remaining budget. This is exactly the budgeted recurrence
above in this profile: budget is an upper bound on the same nonnegative scalar
quantity being minimized. If the least-cost continuation does not fit, no more
expensive continuation can fit. If it fits, every prefix fits because no edge
or terminal cost is negative. The finite horizon, validity, resident quota,
invalidation, preparation, proof, holding, retirement and session-close costs
remain in the state transitions.

`formal/HiaNduBudgetErasure.lean` states this as equality between recursively
budgeted search and a final budget filter on the unconstrained minimum of a
finite decision tree. The model theorem does not prove Python refinement,
measured wall time, native NDU, or a stochastic/multiobjective generalization.
With at most two artifacts and four batches, there are at most 32 distinct
continuation keys instead of a separate key for each reachable remaining
budget. First-action tie order stays skip-first and then lexical resident set.

The native request builder uses the same request-local continuation cache as
the preliminary exact decision. For an already-committed first skip, it selects
the continuation with the session already resident and adds the modeled
current call once. Later skip/invoke states use the same cache. This replaces
repeated complete planning and repeated detachment of the same internal model;
it introduces no cross-request result cache. Native plan outputs are copied so
two returned plans do not share mutable tail action dictionaries.

Independent tests enumerate every schedule for the existing 96 deterministic
randomized small models, and additionally check every first-action minimum for
128 independently seeded models both before invocation and after the current
call is committed. They include initial residency, invalidation, rejected
artifacts, zero-cost ties, exact budget boundaries and session cleanup. These
checks corroborate the Python implementation; they do not replace its missing
refinement proof.

The registered implementation comparison is separate from native economics:

```bash
python3 tools/qualify_hia_ndu_budget_erasure.py \
  --output /absolute/new-model-comparison-directory
```

`benchmarks/hia_ndu_cost/BUDGET_ERASURE_PROTOCOL.json` pins the historical
`931c96fcc7fb698226b809862c233a345dcca4ec` implementation and its file digest,
128 declared models, independent seed 49979687, and eleven alternating paired
sweeps. Before timing, it compares every full witness with the historical
implementation, every first-action minimum with independent exhaustive
schedules, and every native request byte with the historical builder. It
retains every timing sample and reports median, p95 and complete observed
sum. The measured operations include their public model validation and request
encoding. The experiment does not run native NDU, an application or a complete
lifecycle; faster Python planning cannot by itself establish any of those wins.

## A cheap no-invocation bound

The gate first prices the all-skip delivery plan. It then computes an optimistic
lower bound for any invoking plan: for every remaining batch use the fastest
currently modeled valid implementation, ignore preparation, proof, retirement,
holding and the resident quota, and add the unavoidable gate, invocation,
startup and shutdown costs. All omitted costs are nonnegative.

If even this optimistic invocation cannot beat feasible all-skip delivery, the
controller returns skip without constructing `NduSession`. It also skips or
refuses when the optimistic cost cannot fit the remaining budget. If the bound
does not settle the question, exact finite search may still choose skip now.
Only an invoking first action proceeds to actual request construction and
native process startup. Wall-time guards run before construction, after
construction, and after startup. A native protocol rejection retains the
currently admitted incumbent; it never authorizes a rejected candidate.

These cost estimates are forecasts. They are not guaranteed upper bounds on
physical execution time, and the mechanism is not a hard real-time scheduler.

## Committed costs and native abstention

The original Rust wire protocol requires literal abstention to have exactly zero
incremental effect and cost. By the time its request is evaluated, the current
call is already committed. The unavoidable call and session-close costs are
therefore reserved before constructing the advisory request and subtracted from
every candidate's native incremental resource/utility quantity. They remain in
the full plan total and actual wall-time ledger. A first-step skip on a request
that was already sent is charged for that call; it cannot invent a free
alternative. The public gate decides whether to send a request before this
commitment.

The native request contains genuine recursive-utility events and is processed
by the original `codex-hepta-ndu` Rust algorithms. The controller projects only
a unanimous first resident set and dispatch from the native Pareto frontier.
Abstention or conflicting first actions returns no new admission.

The stream bridge is pinned to source
`c4a1bbed3a39beba43a6abf1a18b6f75c5725c21`. It is distinct from the older
`d3c2d760...` candidate-ranking bridge and the `4b6391e...` finite one-shot
profile. Their schemas and identities must not be substituted.

## Native qualification

```bash
python3 tools/qualify_hia_ndu_cost.py \
  --output /absolute/new-evidence-directory \
  --clang /absolute/clang \
  --rustc /absolute/rustc \
  --bridge /absolute/hepta-hia-ndu-bridge \
  --identity /absolute/identity.json \
  --bridge-built-this-campaign
```

Use the final flag only when the supplied bridge's source build belongs to the
same campaign. Build it with `tools/build_hia_recursive_ndu_bridge.py`, the exact
source pin, and the tracked lockfile. An output directory must be new: a failed
or negative campaign is never replaced. The runtime requires Linux sealed
memfds and coherent process identifiers under `/proc`; a mismatched namespace
is rejected, without disabling executable identity checking.

The runner builds real C, C++, Rust and HIA shared objects, including the strong
Rust release profile (optimization level 3, fat LTO, one codegen unit, aborting
panic). It records compiler flags and the remaining cross-language differences.
All artifacts use the same observable allocator wrapper. The new native driver
can actually `dlclose`, records remaining loader mappings, and can reload and
execute a retired artifact. Compiled bytes are sealed before loading. Native
refusal and recovery are also exercised on the original Rust process.

All policies use the same frozen training observations, the current request,
the current external validity/epoch, and the number of remaining batches. The
predictive rule is current-request persistence. Evaluation seeds, future size
order and future invalidation events are not passed to a policy. The fixed
control selects the best resident bank over all registered training sizes and
the known four-batch horizon before evaluation episodes are disclosed. The
exact DP and one-batch lightweight control use their own measured control costs;
they are not charged fictitious native costs.

Every arm performs real preparation, proof-receipt revalidation, loading,
retirement, reuse, delivery and cleanup. Each episode retains raw driver traffic
and actual component wall times. Native episodes additionally retain requests,
responses, raw Rust envelopes and sealed-session identity evidence. Total
service wall time includes interpreter/host work and unclassified overhead;
component accounting never subtracts unmeasured work. The report separately
charges the complete shared build/training/proof/calibration campaign and the
native source build, without silently assuming an amortization horizon.

The registered default profile uses 1,024 kernel calls per batch at lengths 64,
4,096 and 65,536. It has three four-batch episode shapes and three repetitions,
with rotating policy order. Invalidation/recovery changes the caller's admission
epoch and performs actual retirement and re-admission of identical artifact
bytes. It does not claim a real library ABI upgrade. A preserved developmental
256-call campaign exercised only skip; the expanded coalesced-load profile
exists to exercise the invocation branch as well. Both results must be retained.

## What acceptance can establish

The useful result is a working full-cost invoke/skip and residency mechanism,
plus honest measurements. With the same deterministic scalar information, an
exact DP already supplies an upper bound on decision quality. Ranking the same
compressed frontier through NDU cannot improve that optimum. Any claimed NDU
benefit must therefore pay for the complete added machinery and improve a real
cost or extend the model in a separately evaluated way. The runner reports
per-scenario comparisons even when all are negative. Three exploratory
repetitions do not establish general net benefit or a statistical superiority
claim.
