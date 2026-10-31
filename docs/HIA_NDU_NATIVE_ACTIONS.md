# Native NDU advice and a common first action

`tools/qualify_hia_native_ndu.py` measures the existing four native implementations
of the owned-byte fill/checksum workload and runs fixed, independent exact DP,
light greedy and actual Rust NDU policies. Each policy sees frozen training
observations, the current request size, the remaining horizon and work already
spent. It cannot see later request sizes, seeds or timings. The native workload,
loader, allocator probes and NDU process actually execute; supplied costs remain
estimates for this finite workload rather than certified future performance.

## A whole-path tie can still have a determined next action

The native evaluator retains a Pareto set. It may correctly return
`advisory_candidate_id: null` when several complete paths are tied. The previous
caller treated every such response as a reason to keep the incumbent. That lost
an available preparation action when every retained path began with the same
prepared set. Comparing only the largest native path value to exact DP did not
detect the mistake: the best value was present, but the caller executed another
first action.

The `native_first_action` caller policy now inspects every returned Pareto path
against the request's admitted model actions:

1. An explicit abstention or conflicting first prepared sets keep the incumbent.
2. If all paths start from the current prepared set and agree on the next one,
   the caller can perform that common preparation step.
3. Replanning pauses until the current request size changes only if every
   retained path has that same prepared set for its entire remaining schedule.
   A later preparation in any retained path prevents that pause.

The policy preserves the full Pareto set, the original native advisory and
`DENY_ALL`. It does not select a fictitious unique native path. Model
`verified` inputs are external assertions; they are not proofs of native code
safety and confer no deployment authority. This helper is in the qualification
consumer, not a replacement for the production translation validator or native
publication protocol.

The independent audit now records the actual chosen prepared set and all exact
DP optimal first sets. For a unanimous native action it requires first-step
agreement as well as equality of the maximum path value. Conflicting Pareto
actions remain explicit abstentions; no hidden preference or arbitrary scalar
weight resolves them.

## Measurements and lifecycle costs

The existing protocol retains all attempts and samples. Per-policy service
totals include driver startup, baseline and variant loading, policy calls,
transport and response validation, native work, resource probes and shutdown.
An independent DP audit runs for every policy; its measured time is reported
separately and excluded equally from service-only comparisons. Shared native
bank compilation, validation, training and the actually rejected translation
are disclosed once for the campaign, without inventing a deployment lifetime
over which to amortize them. Reusing an existing NDU binary does not constitute
a new compiler build measurement.

The forecast repeats the current size across the remaining horizon. Future
controller costs in that inherited finite model remain zero, although actual
controller cost is charged in the service total. Therefore a model optimum does
not imply economic benefit. The protocol requires NDU's observed service total
to beat each control in each episode before passing its service benefit gate;
whole-lifecycle benefit, global optimality and whole-language safety remain
unestablished. A negative result is retained.

```sh
python -m unittest tests.test_hia_native_ndu -v
python tools/qualify_hia_native_ndu.py \
  --clang /path/to/clang --rustc /path/to/rustc \
  --bridge /path/to/hepta-hia-ndu-bridge \
  --identity /path/to/identity.json \
  --build-profile optimized-release-v1 \
  --expected-source EXACT_CLEAN_HEPTA_COMMIT \
  --output /new/evidence/directory
```

The stream bridge has its own source identity and protocol; it cannot be
substituted for the scalar candidate-ranking bridge used by the background
optimizer. The default build profile remains `instrumented-checked-v1` for
historical reproduction. `optimized-release-v1` names the separate stronger
release configuration and retains its exact build commands. Exact clean-source
qualification withdraws acceptance if any relevant source changes during a run.
