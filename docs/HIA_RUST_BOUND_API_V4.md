# Bound Rust v4: exact finite API-domain extension

## Current combined baseline

This convergence joins catalog `192d2cbba7e49bde3b03af73685ecf96f6fb1b05`
and P0-P7 `953fa62dee5aa563551d57b1374ab95b6d548b45` over their common
ancestor `2cc9fb3b92a7306d2f5aae316c99e8364be700f9`. Both historical
lineages remain in Git. See `HIA_RUST_INTEGRATION_REVIEW_20261030.md` for
the scoped implementation review and exact-lock execution evidence. Historical
results never qualify the combined source automatically.

## Integration lineage

This integration ports the reviewed v4 work from PR #394, exact source
`95a67fb487da981e1941ec0d44c7f4305a22e6d6`, onto the round8 base from
PR #395, `2cc9fb3b92a7306d2f5aae316c99e8364be700f9`. Qualification must
bind the resulting integration commit; neither branch's historical results
qualify the new source. The existing Core registry and production verifier
are retained.

## Scope

The production Python evaluator accepts exact `list` or `tuple` arguments and
any positive Python integer for `allocation_fail_at`. The existing v1/v2/v3
crosschecks deliberately accept only lists and failure indices through
`u64::MAX`. Their documented refusal tests and report contracts remain intact.

V4 adds a separate invocation envelope for two finite differences: ordered
tuple inputs and exact failure-index values beyond `u64`. It uses the existing
Rust checker, explicit-frame `Machine` and `ByteMemory`; there is no additional
evaluator, opcode, Core schema or production admission path.

## API and canonical invocation

```python
from hepta.hia_rust_crosscheck import crosscheck_rust_execution_v4

observed = crosscheck_rust_execution_v4(
    core, "entry", (3,), executable,
    executable_sha256=expected_sha256,
    allocation_fail_at=(1 << 128) + 1,
)
```

The API accepts only exact built-in `list` and `tuple` containers. Both represent
the same ordered argument sequence and normalize to the same JSON array; their
request digests are identical when the values and policies agree. This preserves
the production evaluator's ordered scalar invocation. That evaluator now
freezes one immutable tuple before arity and type validation, so concurrent
caller-list mutation cannot change the executed invocation. Subclasses,
generators, fabricated resource descriptors, and inexact scalar values are
rejected. Original nominal/public-entry eligibility is still enforced before
execution; flattening a nominal type cannot authorize a new public entry.

The CLI is:

```sh
hia-core-shadow --owned-run-bound-v4 FUNCTION JSON_ARGS JSON_POLICY < canonical-core.json
```

The policy has exactly four required fields. The three numeric budget ceilings
and defaults are those of v3: up to 256 root-inclusive frames, 10,000,000 allowed
ticks and 1 GiB of logical payload/node bytes; defaults are 256, 1,000,000 and
16 MiB. The subprocess timeout remains `(0, 120]` seconds, default 30; it does
not bound the Python verifier or evaluator's complete execution time.

```json
{"allocation_fail_at":"0x100000000000000000000000000000001","max_call_depth":256,"max_heap_bytes":16777216,"max_steps":1000000}
```

`allocation_fail_at` is null or the string `0x` followed by a canonical positive
lowercase hexadecimal integer. The first digit is nonzero. Empty, zero,
leading-zero, uppercase, signed, whitespace, separator and nonhex spellings
reject. JSON numbers, booleans, arrays and objects in that field reject. The
other three fields keep exact integer types. Duplicate decoded keys, exponent
spellings in integer fields, unknown/missing fields and trailing JSON reject.

The complete policy has a **1024-byte** limit. Python calculates the exact
remaining digit budget from the other three policy fields, compares it with
the input integer's `bit_length`, and refuses an oversized value before
constructing its hexadecimal string or opening the executable. It never
converts that integer to decimal or changes Python's process-wide integer
conversion limit. Rust independently bounds raw policy bytes before decoding.
This still excludes sufficiently large positive Python integers; it is not
unbounded transport or complete production API parity.

## Exact allocation semantics and report types

Internally the failure index is either an exact `u64` word or the complete
canonical hexadecimal representation of an integer greater than `u64::MAX`.
The latter variant preserves every digit. Comparing it with the `u64`
allocation counter is exact integer inequality, not conversion to `None`,
clamping, wrapping, floating-point rounding or projection onto a tick budget.
The actual finite Machine permits at most 10,000,000 ticks, and each operation
can attempt at most one allocation, so the counter cannot overflow `u64` in
this admitted profile. A zero-size owner still consumes no allocation attempt;
object-size and heap checks keep their existing order.

The v4 request schema is `hepta.hia.rust-execution-request.v4`, and the envelope
is `hepta.hia.rust-bound-execution.v4`. The full canonical hex value is bound in
the request digest and repeated in the execution report. Changing two large
indices that produce the same execution therefore changes the bound request;
rehashing an altered producer report cannot satisfy the original invocation.

The v4 execution report is `hepta.hia.rust-byte-owner-execution.v2`, with the
hexadecimal/null field type made explicit. v1/v2/v3 envelopes continue to carry
`hepta.hia.rust-byte-owner-execution.v1` and numeric/null indices. Their old
list-only/u64 admission contracts, budget limits, report fields, tick counts
and resource ledgers are not upgraded by the new entrypoint.

## Executable qualification

```sh
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_api_v4 -v

```

The finite corpus executes list/tuple equivalence through primitive v1–v8,
indices whose low word would otherwise alias allocation attempt 1, exact
1024-byte policies, owner/chain/returned-loan paths, allocation refusal and
every selected stopped prefix. Raw native refusals cover malformed hex,
duplicate/ambiguous policy JSON and an invalid unused helper hidden behind a
small budget. Consumer controls reject rehashed changed policy and cross-version
replays. Legacy v1/v2/v3 results are actually compared on the same Machine.

The integration must execute all eight selected methods with zero failures,
errors or skips and bind its reports to the actual source and executable.
The tests retain native process outputs, exact requests and complete dual
reports in their class observations. Refused oversized policies are negative
controls, not accepted executions or extra successful tasks.

The scalar boundary still limits arguments to 8192 values and 128 KiB. Python
owns nominal normalization and production admission. General memory/provenance,
arbitrary recursive ADTs, escaping or foreign lifetimes, general public ABI,
asynchronous cancellation, complete error cleanup, process RSS bounds,
production Rust authority and full refinement remain unqualified. Optimization
policy remains `no_change`; P2 is still OPEN.
