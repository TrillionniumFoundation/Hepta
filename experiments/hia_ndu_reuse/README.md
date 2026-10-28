# Exact advisory decision reuse

This extension addresses repeated compiler-controller queries over an unchanged
snapshot. `NduDecisionCache` retains only the immutable bytes of a successful
advisory native response. Its key contains the entire canonical request and the
admitted native/build, transport implementation and cache implementation identity.
Generation, objective, snapshot, budget, candidate proof/support and event changes
therefore require a new native evaluation. Every hit rereads the identity receipt,
checks executable and implementation bytes, validates response schema and exact
bindings, and returns a detached object. LRU entry and byte limits bound retained
request/response payloads; Python allocator overhead is reported outside that byte
bound. Concurrent requests share one owner and close discards all retained bytes.
Hosts without the required no-follow regular-file descriptor support refuse this
cache profile explicitly; the current native execution qualification is Linux.

The existing finite compiler graph can opt in with `--decision-cache-entries`.
`choose_native_graph_plan` is its common decision consumer. Reuse never authorizes
execution and never replaces `run_episode`'s fresh proposal, resource/function
proof, native build or artifact checks before a transition. The original default
remains uncached. A cached response is explicitly reported as reused, not as a new
native invocation or a fresh proof. Request identity does not itself prove that
upstream `verified` inputs are true.

## Registered new experiment

`PROTOCOL_20261028.json` freezes two controller trace workloads before their timing
run. One repeats exactly eight snapshots; the other changes generation on every
query, so reuse must provide no hits. Each trace group begins with empty caches.
Strong fixed-plan, complete DP and exhaustive controls receive equivalent reuse
opportunities and the same complete input model. They are not required to build
NDU wire requests. Uncached and cached native NDU are separate arms.

The input model is an exact, previously frozen measured compiler bank. Its old
costs are advisory input data, not current-machine timings or publication proofs.
New controller timings are holdout observations and never modify the registered
model, workload, cache capacity, thresholds or order. Every sample and failure is
retained. All per-arm construction, cache checks, actual native invocations,
selection, evidence serialization and close costs are charged to that arm.
Common preparation is charged once per standalone strategy; the recorded native
empty-target build is charged separately to each native strategy's cold result.

This study measures controller overhead, including the cost of exact reuse. It
does not execute a new HIA application workload, publish code, establish better
optimizer decisions or demonstrate general NDU value. A reduction relative to
uncached NDU is reported separately from comparison with the strong controls.
The historical 48-episode and finite-graph negative experiments remain unchanged.

```sh
python tools/qualify_hia_ndu_reuse.py \
  --identity /absolute/path/to/finite-build/identity.json \
  --output /absolute/path/to/new-evidence-directory
```

The native tests in `tests/test_hia_ndu_cache.py` require
`HEPTA_FINITE_NDU_IDENTITY` and `HEPTA_FINITE_NDU_BRIDGE`. Tests using the explicit
`CountingBridge` double check cache boundaries only; they are never represented
as native or performance evidence.
