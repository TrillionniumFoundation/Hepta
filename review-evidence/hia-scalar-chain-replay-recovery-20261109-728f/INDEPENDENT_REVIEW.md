# Independent review follow-up

The first recovered head `ff5b975a53bedc65283e0053ac2bbfe4edd85b7c` passed its
complete scalar v2 CI step in
[exact-source run 42627352955](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42627352955/job/129194441760)
at 2026-11-09 13:42:15–13:43:05 UTC. That step ran the twelve focused methods,
a new clean-source full four-width native qualification and strict v2 replay.
This is new CI evidence, separate from the earlier interrupted local run.

A second agent independently reviewed the reader and identified four remaining
internal-consistency relationships. They are independent of authentication of
the original operator and can be checked from the retained original bytes:

1. Plan evidence must contain the exact retained plan and pure preservation
   checks, and both object hashes and frame maps must match the original builds.
2. Encoding evidence must bind the rederived final-image digest and every stable
   native-build field to the planned original build. Temporary command paths are
   the only excluded values, since rederivation used another temporary directory.
3. Evaluate, adopt and rollback request arguments must match their original
   receipts, with unique mutation request keys and the actual operation order.
4. The complete profile inventory must be exactly compiler, target, backend,
   artifact, validation, lowering and plan; two equally incomplete inventories
   cannot qualify each other.

This follow-up adds those read-only comparisons and four regression methods,
bringing the focused two-module gate to sixteen methods. Proof-dependency tests
isolate reference reads after the original hash validation so that they exercise
the new relationship checks instead of merely rediscovering a digest mismatch.
Journal regressions change both intent and response arguments, and the order
case retains correctly paired and renumbered events.

The follow-up does not reemit or relink original code, start a native owner, or
strengthen any mathematical or execution-authority claim. The original
no-emission/no-linkage/no-native-execution regression remains in the gate.
The new head must pass its own complete scalar gate and source CI; the first
recovered head's success is preserved but does not qualify later changes.
