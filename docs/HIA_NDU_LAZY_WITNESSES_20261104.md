# Lazy witnesses for the finite NDU cost model

## Mechanism

The full-cost v2 planner formerly allocated a complete nested action receipt for
every search edge. Most edges were discarded after their continuation costs
were compared. Native request construction then deep-copied each surviving
witness to remove shared mutable tail actions.

The planner now searches with scalar costs and immutable step descriptors.
Delivery costs are cached by batch and resident target; transfer costs are
cached by the old and new resident sets. A target must first be entirely
available in the current batch. Therefore `target - live(ready)` equals
`target - ready`, so transfer costs do not hide invalidation or reacquisition.
All costs are nonnegative and the original root budget comparisons remain.
The same ordered choices, skip-first/lexical ties and search counters are kept.

Only surviving complete witnesses are materialized through the original
`_action` routine. Each witness occurrence receives fresh nested dictionaries
and lists, so native request construction no longer needs an additional deep
copy. The caches exist only inside one detached, validated model request.
They never cache a proof, a native reply, an authority or another generation.

This is an implementation optimization of the existing finite model. It does
not enlarge the two-artifact/four-batch scope or add a whole-language theorem.

## Verification and fixed comparison

The exact prior `hepta/hia_ndu_cost.py` from
`f2b76f5741c83822be2e12cf5a50b50a8d27b96a` is retained with SHA-256
`e5ba69bcb9ac9fa78c6cd216e76e9abaa3bd850df1a8c8add7ce160bdfae0142`.
The independent exhaustive schedule enumerator is unchanged.

`LAZY_WITNESS_PROTOCOL.json` freezes 256 declared models, horizons one to four,
one or two artifacts, eleven alternating paired sweeps and no sample exclusion.
Every complete witness, tie, search counter, native request, support digest and
plan byte sequence must equal the frozen implementation. Both the uncommitted
and already-committed first-action frontiers must match independent enumeration.

The native phase sends 32 model requests from each frontend through the real
`8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d` Rust stream, explicitly selected
as `zero-abstain-v1`. It checks identical native responses/advice and retains
all request/response envelopes and actual preparation, roundtrip, projection,
startup and cleanup costs. Model nanosecond values are declared arithmetic
inputs; they are not physical deadlines for these conformance calls.

The protocol measures frontend and transport cost. It does not measure
application execution, fresh bridge acquisition/build, human work, energy or
long-term residency. Native-call counts are reported separately. Neither a
faster frontend nor 64 successful native calls establishes full-lifecycle
NDU benefit.

## Why the separate full-cost study remains necessary

For the current scalar completion-minus-cost profile, the native path first
uses the same exact finite DP to construct a first-action frontier and then
asks NDU to rank that frontier. It cannot improve the correctly solved model
optimum. It adds native validation, serialization and transport work; measured
runtime noise must not be interpreted as a new source of planning quality.

The existing `qualify_hia_ndu_cost.py` remains the four-arm native workload
qualification: strong fixed, exact DP, lightweight and native NDU receive the
same frozen observations, and their actual preparation, proof, residency,
invalidation, future decisions, native startup/cleanup and service work are
charged. Its original acceptance thresholds and failed evidence are unchanged.
An integrated source-composition run supplies the outside process/build
envelopes. This increment does not assert that those economic gates passed.

## Reproduction

Use a clean committed source and distinct evidence directories:

> Removed source/mixed-campaign reproduction command; its harness is not
> delivered. No historical result is promoted to current qualification.

Keep both positive and negative timing samples. Source drift, missing native
identity, altered registrations and incomplete native comparisons fail.
