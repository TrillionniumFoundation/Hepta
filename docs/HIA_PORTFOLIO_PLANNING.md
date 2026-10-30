# Shared-acquisition portfolio planning and prospective NDU comparison

This addition addresses a specific missing optimization state: using one
independently verified artifact in several regions should pay its acquisition
once, while keeping its retained bytes charged until the end of the episode.
The original finite graph and its historical negative experiments are retained.

## Executable model

`hepta/hia_portfolio.py` accepts an immutable objective and calibration snapshot,
one to sixteen artifacts, and one to thirty-two regions. Each region selects
one artifact. The state includes every already-acquired artifact, the next
region, its first action, remaining time, and two separate model capacities:
retained executable file bytes and peak declared scratch bytes. The model
does not equate either byte quantity to physical RSS.

The objective is the fixed completion value less one-time activation costs and
per-region running costs, with the same per-event Q32 conversion used by the
original Rust NDU protocol. Time in nanoseconds and Q32 debit are separate
labels. A label with lower debit and no higher time dominates one with the same
paid set and first action. Equal utility is not silently broken by an artifact
name, path length, lower cost, or presumed preference.

The dynamic program retains every best feasible complete path per first
artifact. Tied-prefix multiplicities are exact while stored witnesses are
bounded. If required winning witnesses exceed 127, or a search work/state bound
is exhausted, the function rejects and publishes no partial optimum. A separate
Cartesian oracle independently scores small complete choice products.

The native adapter sends those actual retained paths to the existing Rust
`evaluate_recursive_utility` and `evaluate_candidates_with_policy` APIs. Its
semantics are still `DENY_ALL`, with no safety certificate. Upstream source and
verification digests bind context; they do not authenticate evidence or replace
the compiler verifier. This is deterministic compiler search. It is not a
learned FBSDE or a claim that native NDU can beat exact DP on the same additive
model.

## Registered actual-workload experiment

The new protocol is `benchmarks/hia_portfolio_holdout/PROTOCOL.json`.
`tools/qualify_hia_portfolio_holdout.py` requires an exact committed registration
before any formal calibration. It checks the current compiler Python sources,
collector, original proof/build/execute helpers, kernel fixture, protocol and
tests byte-for-byte against that commit, then preserves the execution sources.

The five arms are fixed baseline, fixed best complete calibrated plan, a cheap
amortized-greedy plus best-single-artifact control, exact Q32 DP, and original
native NDU. Twelve regions share a real HIA baseline and three independently
verified guarded/narrowed variants. An actually rejected unguarded body remains
visible. Every first use in an arm is freshly proposed, independently verified,
compiled and bound to its exact native artifact. Later regions reuse those
same bytes. The existing sealed-image driver performs the workload and its
independent checksum checks. Changed source, invalid proof, image drift,
capacity excess, timeout, abstention, and native-versus-DP value disagreement
remain failed observations.

Dynamic controls observe only their own completed runs. They use the same
registered bounded integer timing-ratio update. The strong fixed arm commits
the exact calibrated plan before executing its first region. The artifact set
and ratios are explicit state, including the actual retained size of artifacts
that have already been rebuilt.

The experiment reports whether at least two distinct complete-horizon
nonbaseline alternatives are modeled as profitable after one shared activation,
and whether at least two nonbaseline artifacts were actually executed. Failure
of this competition gate is an informative negative result, not permission to
increase the serving horizon or remove setup cost after observing it.

## Costs and interpretation

Common preparation, source handling, independent proof/calibration, driver build
and oracle work are charged once to **each** standalone strategy. Per-arm
planning, native admission/transport, new artifact builds, loader/workload and
evidence writes are charged to that arm. Every failed attempt remains charged.
The exact historical original empty-target native build outer receipt is
charged only to native NDU. If it is missing, complete cold-start cost is null,
not zero; already-built marginal observations remain separately available.

Toolchain and dependency acquisition, human work, persistent evidence storage,
process startup before the collector and the final aggregate report write stay
explicitly unknown or excluded. A complete-lifetime net-gain claim is therefore
false. Two groups support descriptive measurements, not statistical superiority
or cross-task generalization. Hardware resource safety, unrestricted program
optimality and learned-policy advantage are not implied by a passing test or
correct native receipt.

## Reproduction

Pure mechanism and accounting checks require only Python:

```sh
python -m unittest discover -s tests -p 'test_hia_portfolio*.py' -v
```

After publishing the complete prospective registration, use the existing finite
native profile at `hepta-private-ci@4b6391e116949af0c7e59776baead67271856bdb`,
Rust 1.95.0, the repository's actual pinned SMT solver and native compiler:

```sh
python tools/qualify_hia_portfolio_holdout.py \
  --registration-commit FULL_REGISTERED_COMMIT \
  --identity /path/to/finite-build/identity.json \
  --clang /path/to/clang \
  --native-build-envelope /path/to/original-outer-build.json \
  --output /path/to/new-portfolio-attempt
```

The output directory must be new. Omitting the outer-build envelope retains a
warm execution study with unknown complete cold cost. The runner does not
replace the original source/profile with Python scoring or a different native
binary merely because the requested build is unavailable.
