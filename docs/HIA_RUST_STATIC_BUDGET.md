# Independent Rust structural resource bounds

`hia_core_shadow::analyze_static_budget` and the CLI flag
`--owned-static-budget` add an independent analysis to the existing Rust
checker. `hepta.hia_rust_crosscheck.crosscheck_rust_static_budget` compares that
analysis with the existing Python `analyze_static_budget` over the same
immutable canonical Core.

The result is an opt-in development corroboration. Python remains the
production admission authority. Neither the new Rust report nor a successful
comparison grants native execution, publication, or production promotion.

## Reviewed profile

The profile is `acyclic-byte-owner-v1-v8-u64-bounds`. The Rust entry first runs
the existing complete owned verifier; resource flow, loan origins, types,
effects, all declarations, and every CFG edge remain checked. It then audits
all types and instructions against an explicit byte-only inventory, including
uncalled private helpers. Primitive v1 through v8 are admitted when their
operations belong to that inventory.

Both the direct call graph and each function's CFG must be acyclic. Iterative
topological passes reject a cycle instead of assuming a recursion or loop
bound. Recursive `chain` types are refused anywhere in the module, even if
the only chain operation is an ordinary `owner.drop`: destroying an input
chain can perform an input-dependent number of VM events and frees. A future
instruction or schema cannot inherit the profile without an operational audit.

The Python adapter can normalize a supported nominal input through the existing
canonical verifier. The Rust analysis receives only the resulting primitive
bytes. The outer result retains both the original input identity and the
canonical Core identity. This process does not widen nominal public-entry or
C ABI eligibility.

## Three conservative bounds

The report contains one row for every function, in source inventory order:

| Field | Meaning | Exclusions |
| --- | --- | --- |
| `max_vm_ticks` | Function-entry events, instruction events, terminator events, and recursively composed callee events | Native instructions, CPU time, wall time, WCET |
| `max_allocator_interactions` | Potential `buffer.new`, `buffer.try_new`, and byte-owner `owner.drop` interactions, plus callees | Host allocations, allocator implementation work, RSS, requested payload bytes |
| `max_call_depth` | Root-inclusive synchronous VM frames | Native stack bytes, async task stacks, general recursion |

A zero-length allocation/drop or failed optional allocation can perform fewer
actual allocator interactions than its syntactic bound. A trap may stop before
later instructions or ordinary cleanup. The report does not infer destructor
completion from a trap or from host container destruction.

For a block, local tick cost is its instruction count plus one terminator.
Each call occurrence adds the complete callee tick and allocator bounds;
calling one helper twice pays twice. Function entry adds one more tick.
Sequential calls use the maximum nested frame depth, not a sum of frame depths.
At a branch, each metric independently takes the maximum of successor bounds.
The maxima for different metrics need not occur on one feasible execution.
Even a syntactically reachable branch selected by a constant false condition
retains its cost, since this analysis does not solve path feasibility.

Accordingly, `per_metric_conservative_upper_bounds=true` and
`exact_feasible_path_maxima_proved=false` are distinct fields. The analyzer
does not claim an achievable worst-case trace or a globally optimal program.
Bulk byte operations count their existing single VM event even when they
copy or fill many bytes; this is particularly not a constant-time claim.
Returned-loan processing in v8 uses the existing call/return events and does
not introduce an extra synchronous frame.

All Rust bound arithmetic uses checked `u64` addition. A finite call DAG whose
expansion exceeds `u64::MAX` rejects with `E_HIA_BUDGET_OVERFLOW`; it never
wraps, clamps, or emits a small bound. Python's arbitrary-precision analyzer
can still report such a bound. That larger domain is outside this Rust
comparison profile, so a crosscheck refuses it rather than changing Python's
existing contract.

## Actual producer and consumer

```sh
cargo build --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
rust/hia-core-shadow/target/debug/hia-core-shadow --owned-static-budget < program.hia.json
```

The producer emits `hepta.hia.rust-static-budget.v1`, binding the canonical
program digest, original primitive schema, complete function inventory, all
three metrics, exact profile, and explicit claims.

The Python API accepts optional `max_allocator_interactions`, `max_vm_ticks`,
and `max_call_depth`. It re-runs the existing Python verifier and analyzer
and enforces those policies before invoking Rust. It then uses the existing
checksum-pinned, sealed executable and bounded process-lifecycle transport.
It compares the entire Rust report using canonical JSON equality, including
field inventories and exact numeric types. Missing/extra functions, changed
source identity, lower or unexplained higher bounds, bool-as-int metrics,
unsupported profiles, and promoted claims refuse. An imported report alone
is not an input to this API.

```python
from hepta.hia_rust_crosscheck import crosscheck_rust_static_budget

report = crosscheck_rust_static_budget(
    core,
    executable,
    executable_sha256=trusted_executable_sha256,
    max_vm_ticks=10_000,
    max_allocator_interactions=100,
    max_call_depth=16,
)
```

The trusted executable pin, Python verifier and normalizer, both analysis
implementations, Rust verifier, runtime semantics used for validation, and
host process environment remain assumptions. Agreement between independent
implementations is additional evidence, not a machine-checked soundness or
source-to-Core-to-native refinement theorem.

## Repeatable acceptance

```sh
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_static_budget -v
```

The Rust tests independently check exact small bound calculations, actual VM
traces, separate branch maxima, repeated call charges, early traps, hidden
cycle/chain refusal, invalid resource graphs and finite arithmetic overflow.
The Python tests build the actual Rust executable and use the sealed runner
for v1-v8 bounds, multi-result returned loans, every versioned bulk memory
operation, actual dual-VM observations, original nominal identity, complete
large inventories, policy refusals and modified-report negative controls.
The reply-mutation controls qualify only the consumer's refusal behavior;
they are not substitutes for the actual producer runs.

Missing Cargo or a skipped native test is not a passing qualification. This
increment does not close general Rust authority, arbitrary ownership/ADT,
async cancellation, crash cleanup, chain bounds, native refinement, RSS/WCET,
or whole-language safety work.
