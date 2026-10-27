# Independent concurrent resource protocol IR

`hepta concurrent-ir file.hepta` exports `hepta.concurrent-ir.v1` and runs a
separate verifier. `python -m hepta.concurrent_ir graph.json` checks a retained
graph without importing the parser, frontend checker, or a native backend.
Its JSON reader rejects duplicate fields, nonfinite constants and inputs above
16 MiB. Unknown operations, fields, types, capabilities and CFG edges reject.

## Verified obligations

The accepted profile has `Buffer<u8>`, `Task<u64>`, local `TaskGroup` owners,
and worker-borrowed `Cancellation` / `Sender<u64>` capabilities. Creation,
ownership transfer, worker submission, borrowing, cancellation, selection,
budget attachment and joining are explicit operations. A worker submission
consumes its input on both successful and refused admission. The submitted
worker must have the complete required ownership/capability signature, and
its own graph is independently checked.

Every reachable normal return discharges all owned buffers and pending task
or group joins. Cancellation only signals; it does not consume the join
obligation. Ordinary function calls transfer explicit owned inputs and outputs.
Group handles and sender/cancellation capabilities cannot escape through a
function result or ordinary value slot. A use after a transfer/join fails.

Each incoming CFG edge must agree on the exact live-owner set. This includes
loop backedges and early returns. Scalar predicates are nondeterministic in
this abstraction, so both sides of a branch are checked. Short-circuit Boolean
operators retain conditional execution of their right operand; their resource
operations are not scanned eagerly. Unreachable graph blocks cannot conceal
unchecked instructions.

The runtime retains each admitted worker's native join handle inside the group.
The IR verifies the static group obligation rather than pretending to know
which runtime admissions succeed or how many workers are live at an arbitrary
point. Native select/pool counters and races have a separate qualification.

## Explicit boundary

This is a normal-exit lifecycle protocol, not a concurrency soundness proof.
It does not establish scheduler fairness, termination, deadlock freedom,
runtime race freedom, scalar result correctness, input-byte/global memory
bounds, or source/IR/native refinement. In particular, a syntactically joined
program may block forever waiting for an uncooperative worker.

Owned ADTs, partial aggregate moves, generic bodies, stored references, raw
pointers and FFI are rejected by this concurrent profile. The independent
sequential resource IR covers richer ownership semantics. Acceptance by one
profile is not reported as acceptance by the other; the two abstractions have
not been proven to compose into a complete memory model. Native Rust checks
remain mandatory for an executable Rust-backed program.

The graph carries source/project hashes supplied by its producer. Standalone
replay reports `source_binding_verified=false`. The native qualifier separately
compares those hashes with the actual source and native build, retains the
serialized graph, and compares its full independently recomputed verification.
Hash binding is not a theorem that the lowering is correct.

## Qualification

```sh
python tools/validate_concurrent_ir.py --output artifacts/concurrent-qualified.json
python -m unittest discover -s tests -p test_concurrent_ir.py -v
```

Seven source programs execute three times each: bounded pipeline, local
admission budgets, cancellation, worker failure, two-group select, shared
reservations and a compact lifecycle program. Fifteen graph mutations cover
missing cleanup/join, a forged worker/capability, duplicate join, use after
join, hidden unreachable operations, bad CFG edges and inflated proof claims.
Independent source-order counterexamples and their fixes are retained in the
integration audit archive.
