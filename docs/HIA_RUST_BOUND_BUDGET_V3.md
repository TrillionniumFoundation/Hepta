# Bound Rust v3: evaluator budgets on explicit call frames

The production Python evaluator accepts up to 256 root-inclusive frames,
10,000,000 operation ticks and 1 GiB of live logical payload/node bytes.
Bound Rust v1/v2 accepts only 32 frames, 1,000,000 ticks and 16 MiB. The v2
crosscheck therefore intentionally narrows Python's policy; it cannot evaluate
every policy accepted by that production API.

Bound v3 removes those three numeric ceiling differences for the existing
finite primitive execution profiles. It retains the independent verifier and
the existing single Rust `Machine`/`ByteMemory`. Language calls now use explicit
frames with a saved operation position, environment, formal-loan scope and
return-origin bindings. A call suspends its caller; a successful return rebinds
the returned loan, leaves the callee's formal scope, and writes results to the
original caller continuation. The underlying resource ledger is shared.

Call entry checks the root-inclusive depth before its entry tick. Ownership
transfer still precedes entering the callee. Trap and budget stops drop no
language resources and do not fabricate cleanup: the stopped memory ledger is
reported with the same tick convention. Chains still charge one tick per
destroyed node. Legacy scalar, owned, bound v1 and bound v2 execution also use
this one explicit-frame Machine, preserving their original policy limits and
report contracts.

## Separate invocation contract

```sh
hia-core-shadow --owned-run-bound-v3 FUNCTION JSON_ARGS JSON_POLICY < canonical-core.json
```

All four policy fields are mandatory on the wire:

```json
{"max_steps":1000000,"max_heap_bytes":16777216,"allocation_fail_at":null,"max_call_depth":256}
```

| Field | v3 accepted policy |
| --- | --- |
| `max_call_depth` | Exact integer 1 through 256, root inclusive |
| `max_steps` | Exact integer 1 through 10,000,000 |
| `max_heap_bytes` | Exact integer 0 through 1,073,741,824 logical bytes |
| `allocation_fail_at` | Null, or exact integer 1 through `u64::MAX` |

The bounded, duplicate-safe JSON decoder retains the 1024-byte policy limit.
Missing/unknown fields, booleans or floats in integer positions, exponent
spellings, duplicates, trailing JSON and out-of-range values reject. Arguments
retain the 8192-value/128-KiB scalar boundary. Independent whole-module checking
still occurs before execution; a short budget or allocation injection cannot
hide an invalid unused helper. Original nominal signatures and explicit export
restrictions continue to control the public entrypoint after normalization.

The envelope is `hepta.hia.rust-bound-execution.v3` and its request is
`hepta.hia.rust-execution-request.v3`. They bind the original canonical Core,
entry, typed arguments and all four actual policies. The complete underlying
execution report is still `hepta.hia.rust-byte-owner-execution.v1` with its
program-derived resource profile. A v3 envelope never substitutes for v1/v2.

```python
from hepta.hia_rust_crosscheck import crosscheck_rust_execution_v3

observed = crosscheck_rust_execution_v3(
    core, "probe", arguments, executable,
    executable_sha256=expected_executable_sha256,
    max_call_depth=256,
    max_steps=1_000_000,
    max_heap_bytes=16 * 1024 * 1024,
)
```

These defaults match the production Python evaluator's three default budgets.
The API freshly executes both existing VMs and compares the exact request,
outcome, ticks, every resource-ledger field, capability profile and unproved
claims. It accepts no imported successful receipt. Its Rust-process timeout
defaults to 30 seconds and can be selected in `(0, 120]`; it is not a total
verification or Python-execution timeout. v1/v2 retain their existing 15-second
timeout ceiling.

## Execution evidence and explicit limits

```sh
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_budget_v3 tests.test_hia_rust_bound_depth tests.test_hia_rust_execution_crosscheck -v
python tools/qualify_hia_rust_budget_v3.py --expected-head COMMIT --output-directory /tmp/new-bound-v3-report
```

The frozen-source collector refuses a changed test denominator, skips, failed
methods, source drift, tool drift and executable drift. It retains actual build
output, exact requests, both full execution reports and pinned-process output;
deliberately replayed bytes occur only in refusal tests. Existing v1/v2 cases
and the Rust crate regressions are separate, overlapping checks.

The new corpus executes all 256 depth policies at unbounded-recursion and
finite-return boundaries, including deep returned mutable loans and owned and
borrowed chains. It checks actual deep trap/step stops, a loop stopped after
10,000,000 allowed ticks, allocation and release of 16 MiB plus one byte, and
denial before host allocation when a request exceeds the 1 GiB policy. The
small-host-stack Rust test executes every language depth on a thread explicitly
configured with 512 KiB of stack. That finite observation does not establish
native stack usage on every platform.

An accepted 1 GiB policy is distinct from an observed successful 1 GiB
allocation; this corpus does not claim the latter. Logical bytes exclude frame,
map and allocator overhead and are not RSS. Host allocation failure, general
memory/provenance, arbitrary recursive ADTs, escaping/foreign lifetimes,
asynchronous cancellation and complete cleanup remain outside this contract.

Python accepts arbitrarily large positive allocation-failure indices; the
Rust transport retains its explicit `u64` bound. Scalar argument transport and
primitive Core normalization also retain their independent limits. The three
budget ceilings therefore do not establish complete production API parity.
The separate [v4 API contract](HIA_RUST_BOUND_API_V4.md) adds ordered tuple inputs
and exact hexadecimal failure indices beyond `u64` within its 1024-byte policy;
it does not change this v3 contract or its refusal cases.
Python remains production authority. All production-admission, whole-language
soundness, backend-refinement and full-P2-closure claims remain false.
