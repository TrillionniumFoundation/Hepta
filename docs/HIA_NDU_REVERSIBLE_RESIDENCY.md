# Stateful NDU v3: eviction and paid reacquisition

## What changes

The v1/v2 stateful preparation model retained every prepared candidate until
the end of the horizon. Under a one-candidate memory quota this excluded a
schedule that uses one specialization early, releases it, and uses another
later. `hepta.hia.ndu.stateful-preparation.v3` adds that schedule space through
the existing finite graph protocol and original Rust NDU evaluator. It does
not introduce another NDU implementation.

V3 requires the v2 `future_decision_cost_ns` field and a nonnegative integer
`eviction_ns` for every candidate. V1/v2 reject this new field and retain their
existing semantics. V3 is limited to two candidates and one to four batches.
Its complete graph has at most four resident states and twelve transitions,
checked before graph construction. The original native limits of eight states,
32 transitions and 127 non-abstention candidates are unchanged.

A transition from resident set A to B pays preparation for B minus A and
eviction for A minus B. Retained candidates pay neither transition cost.
Reacquiring an earlier evicted candidate pays preparation again. Each batch
also pays the execution latency of its selected available candidate and the
holding costs of every retained candidate. Stopping ends future decisions but
continues to pay resident holding costs and delivery costs. Active decisions
after the first, including a later stop decision, retain the v2 decision charge.

The model releases old candidates before preparing new ones. Its memory bound
is the larger endpoint residency, not their union. This is an advisory model
of that order. The native loader, outstanding borrows, asynchronous users and
actual unload completion must independently establish that release is safe;
the model never grants permission to unload executable mappings.

## Reference and control semantics

The independent subset enumerator and independent resource DP were extended
to allow reversible resident-set moves. Neither calls the production graph
builder or pruning code. Both charge the same eviction, repeated preparation,
holding and decision costs, including the wire's separate Q32 truncation of
transition-plus-decision and execution-plus-holding phases.

For every admitted v3 model, each legal schedule is a sequence of verified,
memory-feasible resident sets. A change between two successive sets has a
complete graph edge; an unchanged set has hold/stop representation. Conversely,
every admitted graph path yields such a resident sequence. Since batch index
strictly advances, reversible edges do not produce infinite executions. This
is the finite model correspondence being tested, not a mechanized proof about
the production compiler or arbitrary dynamic residency.

The strong fixed control may select any feasible constant resident set at
batch zero. It pays the same initial preparation and eviction costs and needs
no future controller invocation. The greedy control has the same information
but chooses one step at a time. Exact DP has the same complete cost estimates
as NDU. Therefore NDU must match its best finite-model value; exceeding that
exact optimum is not a valid acceptance condition. Any advantage over exact
DP must come from measured total computation/service cost under an appropriately
registered workload, not a better value for this identical deterministic model.

One declared control illustrates the new opportunity. Two specializations each
occupy 64 bytes under a 64-byte quota. Over four batches the baseline takes
100 ms per batch. The early specialization takes `[1,1,100,100]` ms and costs
150 ms to prepare; the late one takes `[100,100,1,1]` ms and costs 100 ms to
prepare. Eviction costs 5 ms and future active decisions cost 1 ms. The best
reversible continuation is early, early, late, late: 262 ms including repeated
decisions and the release. The strongest constant configuration costs 302 ms;
the myopic control remains at the 400 ms baseline. Independent exact DP also
returns 262 ms. These numbers are declared model inputs/results, not measured
application durations or an empirical NDU speedup.

## Invocation and actual observation accounting

The existing invoke/skip bound remains conservative for v3 by giving every
individually memory-feasible verified candidate free preparation, free eviction,
zero holding cost and free future decisions. It then selects the cheapest
delivery alternative independently at each batch. This relaxation is no more
expensive than any legal schedule. Incumbent holding cannot be included as an
unavoidable lower-bound charge in v3 because it can now be released. The skip
alternative still pays the incumbent's full holding cost. The gate's own
runtime cost must be measured by its caller.

`observe_residency` accepts a caller-observed transition in v3. It preserves
the actual supplied cost, decreases the remaining budget, records any overrun,
increments the generation, retains released/acquired identities, and refuses
replayed observation digests. It does not advance the batch or authenticate
the observation. A new graph based on that state recharges later reacquisition;
historical preparation cost cannot become fresh optimization credit. Existing
refusal observations remain available and preserve failed-attempt costs.

## Verification and reproduction

The new source-owned `RESIDENCY_PROTOCOL.json` registers six declared cases:
alternating reacquisition, delayed payback, expensive eviction, release of an
unused incumbent, rejected target, and insufficient budget. The qualification
runner preserves all six historical v2 cases and their two original native
search arms. It adds six v3 native calls using the existing exact frontier.
Uncompressed enumeration of the complete reversible graph may exceed 127
paths; that whole request still refuses instead of returning a partial optimum.

```sh
python -m unittest tests.test_hia_ndu_stateful tests.test_hia_ndu_residency -v
python tools/qualify_hia_ndu_costed.py \
  --bridge /absolute/path/to/original-stream-bridge \
  --identity /absolute/path/to/identity.json \
  --expected-source EXACT_CLEAN_COMMITTED_SHA \
  --output /new/output/directory
```

The unit suite includes 80 independent generated models over lengths one to
four, both resident quotas, existing incumbents, unavailable candidates,
nonzero and zero decision costs, resource budgets and nonintegral-millisecond
Q32 rounding. It compares all winning schedules and values among enumeration,
independent DP and the production frontier. Historical v1/v2 request contents
remain unchanged on their twelve existing fixtures.

Real native qualification requires source commit
`c4a1bbed3a39beba43a6abf1a18b6f75c5725c21` and its bound executable identity.
The runner records actual native calls, transport/build identity, per-operation
wall time and independent-control results. Without `--expected-source`, the
result is explicitly development evidence. Even a passing exact-source replay
does not establish positive full-lifecycle NDU economics, measured application
speedup, physical residency behavior or loader eviction safety. Those claims
remain false in the result schema.

## Native-economics artifact identity

The separately executed owned-buffer economics protocol is now v3. It retains
the same cohort and acceptance thresholds, while binding library loads to the
recorded path, size and SHA-256. Preparation estimates include this check,
the actual dlopen exchange and initial mapping observation. The complete
campaign rechecks every built library, driver and recorded compiler/tool
binary before preserving an acceptance result. Missing or changed identities
withdraw acceptance even when compiler source is unchanged. The final check's
actual wall cost is charged once to shared campaign work; it is not free
service work. Original v2 observations and their negative results remain
historical records, not requalified v3 observations.

These checks use the existing trusted-host contract. They do not seal shared
libraries or rule out a hostile transient path change between observations.
Five identity-boundary controls use real temporary file changes without
executing those fixture files; only a separate native campaign supplies actual
machine-code or performance evidence.
