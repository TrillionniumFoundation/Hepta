# Native dynamic cache experiment

This is a separate native Rust workload and controller experiment. It does
**not** compile these matrix kernels through HIA, and cannot establish an HIA
language speedup, all-input ownership theorem, or global program optimality.
The previous HIA full-cost result at source `3707b871ecbe563233ee9a3b69299fc627408936`
remains 0/3 native net-win scenarios and is not replaced by this cohort.

The workload performs actual matrix transposition and matrix-vector products.
Each transpose owns a real `Vec<u32>`; preparation allocates and computes,
retirement drops it, and a monotonic data-epoch change invalidates it. The
driver meters the actual vector capacities against a cache quota, refuses
stale/unavailable preparations or dispatches, and checks every output against
an independent algebraic oracle for the registered generated matrix family.
This is finite behavioral evidence for that family, not a proof for arbitrary
matrices. The crate forbids unsafe code; Rust, its dependencies, compiler and
operating system remain trusted components.

`PROTOCOL.json` is the prospective contract. There are 24 holdout cohorts,
three repetitions and six arms, yielding 432 episodes and 10,368 workload
executions. An arm sees at most twelve already-announced queue requests and
their data-epoch changes. Actual holdout execution times are never forecasts.
Training uses different dimensions and seeds. All prediction errors survive
in the evidence; no later fit changes completed decisions.

The controls are direct execution, exhaustive training-selected fixed cache,
future-aware lightweight static-set search, optimized native exact DP, a
four-state beam, and the identical beam plus the unchanged NDU APIs pinned at
`8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d`. The last pair isolates the added
NDU evaluation. All arms deliberately use the same sealed binary. A separate
NDU-free build is not measured; the shared actual build is charged to every
conservative standalone allocation. These overlapping alternative allocations
must never be summed as actual machine cost.

The finite model accounts for current committed invocation cost, estimated
future solver/transport cost on residency changes, startup, close,
preparation, retirement, execution, epochs and capacity. A cheap optimistic
gate may skip planner startup entirely. Optional preparation is withheld when
the observed budget has elapsed. Forecast feasibility never guarantees a
physical deadline. The caller independently replays every supplied witness;
NDU keeps `DENY_ALL`, cannot send workload commands, and grants no execution
authority. Source hashes bind identities, not program safety proofs.

After online execution, a separately charged exact-DP audit evaluates each
actual model with precisely that model's cost estimates. A reported gap is
selected complete-witness model cost minus its same-information exact
minimum. It is neither observed application regret nor a whole-program bound.
The audit never feeds the online decisions. Every native exact minimum is
independently checked by a Python bottom-up traversal of all legal resident
states and transitions; its wall time is retained and charged. The hot-path
linear replay proves only the supplied witness's feasibility and arithmetic.
Its `search_complete` flag is the pinned implementation's assertion, not an
independent optimality proof. Empty or incorrect native exact frontiers cannot
pass the separate full-state minimum audit on a feasible model.

## Commands

Use the exact frozen tool paths, CPU affinity, source commit, build manifest
and registration recorded for a campaign. The following interfaces are
implemented; placeholders must be replaced by those recorded values.

```sh
python tools/build_hia_ndu_dynamic_bridge.py \
  --upstream UPSTREAM_CHECKOUT --output NEW_BUILD_DIRECTORY --cargo CARGO
python tools/qualify_hia_ndu_dynamic.py freeze \
  --source-commit COMMIT --binary BINARY --manifest BUILD_RECEIPT \
  --output NEW_REGISTRATION_JSON
python tools/qualify_hia_ndu_dynamic.py run \
  --registration REGISTRATION_JSON --binary BINARY --manifest BUILD_RECEIPT \
  --output NEW_RUN_DIRECTORY
```

Set `RUSTC` to the frozen direct compiler invocation and retain its version,
binary identity and complete build command streams. The builder uses a fresh
target directory, a committed lockfile and unchanged original upstream source
bytes. Keep failed preparations and partial campaign outputs. The enclosing
driver must retain startup/serialization/output costs beyond the internal
timers; full allocations need that explicit outer-wall correction. Training,
build, correctness, exact-gap auditing and final reporting are separately
reported from per-episode service. Historical acquisition, engineering,
maintenance and long-term retention remain unknown.

The machine-readable request/response interface and resource witness are an
integration boundary for future HIA work. They are not current integration
through HIA's verified compiler bridge. That would require a new registered
qualification with actual HIA-compiled kernels and its independent admission
receipts.
