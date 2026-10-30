# Native guarded+narrowed candidates with matched NDU controls

The prepared artifact owner now accepts an explicit
`prepare_guarded_narrowed(base_token, proposal)` operation. It uses the existing
guarded-reduction and modular-narrowing verifiers, binds their actual
intermediate/final Core, builds the candidate, and issues an internal prepared
proof only after the normal policy, compiler, sealed-image and byte-budget
checks. The immutable baseline remains the proof ancestor. Existing base and
guarded entry points retain their behavior.

The narrowing proof producer now includes its canonical `policy_sha256`, as the
existing prepared-proof consumer already requires. The consumer was not made
permissive. The session's implementation identity also includes the complete
chain checker, so changing its code invalidates existing admissions.

This route retains the existing scalar checksum ABI, fresh-child execution,
bounded entries/metadata/images/leases, cancellation ownership and uncertain
release accounting. It does not add persistent owner/loan hot replacement or
receipt import. Both checked stages preserve their existing finite proof scope;
the native backend and host remain trusted.

## Actual native regression entry

```sh
HEPTA_RUN_ARTIFACT_SESSION=1 python -m unittest \
  tests.test_hia_artifact_narrowing tests.test_hia_artifact_session \
  tests.test_hia_narrowing -v
```

The new controls cover a real guarded+narrowed native build, guard-boundary and
fallback execution without repeated proof solving, a wrong baseline, malformed
or weakened guard input, second-stage receipt mutation, checker drift,
cancellation after the real build, live-lease cleanup and entry-budget refusal.
They require the actual Linux compiler and pinned solver. A skipped invocation
is not native qualification.

## Separately frozen experiment

`PROTOCOL_20261030.json` registers the two existing `byte_sum` and `packet_xor`
workloads with three real candidates: baseline, guarded, guarded+narrowed.
The collector extracts the actual native `.text` into separate inspection
outputs, checks that the admitted source image was unchanged, and records its
hash. Functional acceptance requires distinct guarded+narrowed native text for
both modules. Distinct bytes alone are not a performance advantage.

All four controllers receive the same interleaved calibration bank, actual
prepared-artifact reuse and one shared candidate-build credit. Fixed commits
the complete finite stationary suffix allocation once. A separate
feedback-greedy controller starts with each module's cheapest already admitted
image, then spends its shared credit only on the largest positive saving for
the current epoch, including complete setup cost. It updates estimates from
its own completed observations and deliberately does not inspect suffix costs.
DP recomputes the finite remaining-trace allocation after each completed
observation. The original native NDU
framework evaluates the same supplied allocations. Its recorded choices are
audited against the exact same-model DP after policy execution, without adding
that audit to the controller's live decision cost. Four cyclic arm orders put
every policy in each execution position once.

The separate feedback-greedy arm and fourth Latin group were added before any
performance-study samples were collected. The earlier native preflight only
checked correctness and actual code bytes. This prospective revision does not
change the workload, guard, call count, resource budget or sample-exclusion
policy. The observed net-cost gate now requires NDU to beat all three controls.

Each episode pays its real preparation, proof/build/sealing, identity checks,
native delivery, evidence and cleanup. The common source/driver/calibration
cost is charged once per standalone strategy; NDU additionally pays the actual
recorded empty-target bridge build in the build-inclusive table. A builder
checkpoint may differ from the experiment commit only when its original
identity and identical builder bytes are retained. It is not relabelled as an
experiment-source build or a fully cold-machine measurement.

After all policies, fresh independent sessions execute complete baseline,
guarded and guarded+narrowed controls for each module. Their timings cannot
feed the policies. Their actual costs remain in the study total and are
reported separately from deployment cost. No failed, refused or slow sample is
removed. Earlier negative experiments retain their identities and scores.

```sh
python tools/qualify_hia_ndu_narrowed_candidates.py \
  --output /absolute/external/new-run \
  --identity /absolute/native-build/identity.json \
  --build-envelope /absolute/native-build/BUILD_ENVELOPE.json \
  --clang /absolute/clang --objcopy /absolute/objcopy
```

The runner requires a clean committed checkout and the original pinned native
NDU bridge. It records its own source/tool identities before observations and
checks them afterward. Native outcomes, original stream frames, per-stage
costs and resource-release states remain in the external run directory.

Correctness, an observed finite cost difference and algorithmic superiority
are separate conclusions. If NDU matches the complete DP plan, a noisy wall
difference does not establish a superior planning algorithm. These two kernels
and the available nonexclusive host do not establish application-wide Rust,
C or C++ superiority, universal optimality or physical-dot qualification.
Authority remains `DENY_ALL`; `safety_certificate=false`.
