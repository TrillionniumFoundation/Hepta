# Explicit call-depth policy for bound Rust execution v2

The production Python VM accepts a configurable root-inclusive call-depth
budget. The independent Rust Machine previously used a fixed limit of 32 in
every execution mode. Bound v1 correctly compared both VMs at that fixed
limit, but could not qualify a caller selecting a smaller depth.

Bound v2 makes that smaller policy explicit. The existing Machine gains one
`max_call_depth` field; its frame, loan, return and chain lifecycle code is
unchanged. The check still occurs before entering the next frame or charging
its call-entry tick. The root occupies one frame. For an otherwise unbounded
function that only calls itself, a limit of `N` admits `N` frames and stops
after `2 * N` ticks (one entry and one call instruction per admitted frame).

## Separate wire contract

```sh
hia-core-shadow --owned-run-bound-v2 FUNCTION JSON_ARGS JSON_POLICY < canonical-core.json
```

Every policy key is mandatory, including the explicit null failure policy:

```json
{"max_steps":100000,"max_heap_bytes":1048576,"allocation_fail_at":null,"max_call_depth":4}
```

| Field | Accepted values |
| --- | --- |
| `max_call_depth` | Exact integer, 1 through 32, root inclusive |
| `max_steps` | Exact integer, 1 through 1,000,000 |
| `max_heap_bytes` | Exact integer, 0 through 16 MiB of logical payload/node bytes |
| `allocation_fail_at` | Null, or exact integer 1 through `u64::MAX` |

The policy text has a 1024-byte cap before decoding. It uses the same bounded,
duplicate-safe JSON decoder as the existing Core/argument paths. Missing or
extra keys, booleans in integer fields, strings, floats/exponents, negative or
out-of-range values, duplicate keys and trailing JSON reject. The existing
8192-scalar/128-KiB argument limits and whole-module validation remain in force.
No positional/default policy is accepted for this new command.

The response is `hepta.hia.rust-bound-execution.v2`; its exact request is
`hepta.hia.rust-execution-request.v2`. The request binds the canonical Core,
function, typed scalar arguments, mode and all four policy fields. The
reported/requested depth comes from the actual Machine policy. The wrapped
execution still uses the existing `hepta.hia.rust-byte-owner-execution.v1`
schema and program-derived v3/v4/v5 resource profiles. Changing the envelope
version does not introduce a new Core grammar or resource capability.

`--owned-run`, `--scalar-run`, `--owned-run-bound`, and the public
`crosscheck_rust_execution` API keep their fixed depth of 32 and existing
report versions. A v2 result cannot stand in for a v1 result, even when both
selected depth 32 and produced identical values and ledgers.

## Fresh dual execution

```python
from hepta.hia_rust_crosscheck import crosscheck_rust_execution_v2

report = crosscheck_rust_execution_v2(
    core, "probe", arguments, executable,
    executable_sha256=expected_executable_sha256,
    max_call_depth=4,
    max_steps=100_000,
    max_heap_bytes=1024 * 1024,
    allocation_fail_at=None,
)
```

The required keyword `max_call_depth` distinguishes the new API. It uses the
same original-input verification, scalar public-entry checks, pinned transport,
Python interpreter and complete outcome/ledger comparison as bound v1. All
policy fields must equal the actual invocation, even if a changed request has
a recomputed hash and happens to produce the same outcome. Bool/int
substitutions and one-field result/ledger/claim changes reject. The API accepts
no imported successful receipt. Neither its report nor a hash confers
production admission or deployment authority.

## Qualification

```sh
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_bound_depth tests.test_hia_rust_execution_crosscheck -v
python tools/qualify_hia_rust_bound_depth.py --expected-head COMMIT --output-directory /tmp/hia-bound-depth
```

The output directory must be new and outside the frozen source checkout. The
collector requires the exact clean commit, preserves the real Cargo build and
executable identity, inventories actual tracked files before/after, rejects
skips/failures and records the fixed test denominator. Each positive row
includes the exact request, both full VM reports and stdout/stderr from the
actual pinned subprocess. Refusals retain original raw Core, policy/argument
text and process results; invalid Core is sent independently to both verifiers.
Legacy comparisons retain actual v1 and unwrapped output for all eight schemas.

The corpus checks all 32 depth values at scalar recursion boundaries, selected
depths with recursive returned loans and owned/borrowed chains, normal return,
call stops retaining live owners/loans/nodes, every step cut of a returned-chain
cleanup, heap stops and injected allocation failure. Hidden invalid functions
must reject even at depth one or before an early allocation/step stop. Fake
replay fixtures are refusal controls, never positive execution evidence.

Python remains production authority. This finite policy qualification does not
cover the production Python API's wider limits (256 frames, 10,000,000 steps,
1 GiB payload), native stack bytes, process RSS, asynchronous cancellation,
public resource-return ABI, complete refinement or whole-language soundness.
The scope remains one Machine and the existing finite primitive resource
profiles; P2 authority-switch qualification remains open.

The separate [bound v3 budget contract](HIA_RUST_BOUND_BUDGET_V3.md) extends
those three numeric ceilings using explicit language call frames. It does not
upgrade the v2 request, report, API limits or authority described here.
