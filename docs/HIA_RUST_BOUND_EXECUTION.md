# Bound Rust execution crosschecks

The existing Rust shadow can independently admit and execute primitive Core,
but its legacy execution report identifies the program and entry without the
actual argument vector. A result from another invocation can have identical
return values, ticks and resource counters, particularly when an argument is
unused. Static `crosscheck_rust_shadow` does not compare execution behavior.

This increment adds an opt-in invocation envelope and a reusable dual-execution
consumer. Both use the existing Python verifier/interpreter and Rust
checker/Machine. It does not introduce another Core grammar, interpreter,
source lowerer or native backend. Python remains the production authority.

## Invocation contract

The additional Rust command accepts the same parameters and policy as
`--owned-run`:

```sh
hia-core-shadow --owned-run-bound FUNCTION JSON_ARGS MAX_STEPS MAX_HEAP_BYTES FAIL_AT_OR_none < canonical-core.json
```

The existing `--owned-run`, scalar-run and static-shadow reports retain their
schemas and contents. The new command wraps the actual owned execution report
in `hepta.hia.rust-bound-execution.v1` with an exact request and SHA-256 of its
canonical JSON representation. Request schema
`hepta.hia.rust-execution-request.v1` includes:

- The canonical Core SHA-256, public function name and exact scalar arguments.
- Mode `owned`, the step and live-byte budgets, allocation-failure position
  or null, and the root-inclusive call-frame limit of 32.

The envelope is produced only after whole-module independent verification and
the actual Machine invocation. An invalid hidden helper cannot acquire an
envelope by requesting one step or an immediate allocation failure. Successful
return, a specified semantic trap and an evaluator budget stop are separate
results. The envelope contains the complete existing report for each result.

`hepta.hia_rust_crosscheck.crosscheck_rust_execution` accepts the program,
function, argument list and an independently supplied executable SHA-256. It
reverifies the original input, keeps its public-entry restrictions through
normalization, validates the bounded scalar and policy contract, and executes
the exact copied binary bytes using the existing bounded subprocess transport.
It also executes the same immutable Core through the Python VM. Admission of
the new result requires exact agreement on:

- The current request, even if a substituted request has a correctly
  recomputed digest and would produce the same result.
- Return values or the precise trap/budget reason, operation ticks and every
  resource-ledger field, including stopped live owners and loans.
- The program-derived v3, v4 or v5 execution profile and the exact boolean
  capability and unproved-claim fields.

Missing or extra fields, changed policies, bool/int substitutions, floating
numbers, duplicate JSON keys, unsupported envelopes, stderr, failed process
exit and oversized output reject. There is no legacy-report fallback. The
static runner keeps its 32 KiB output limit; the bound invocation transport
allows at most 512 KiB per output stream because it includes the arguments.
Arguments retain the existing 8192-value and 128 KiB wire bounds. VM policy is
limited to one million ticks and 16 MiB live payload/node bytes. The subprocess
timeout applies to the Rust process, not a total compiler/verification budget.

Example using a Cargo-built executable whose digest the caller has checked:

```python
from hepta.hia_rust_crosscheck import crosscheck_rust_execution

observation = crosscheck_rust_execution(
    core, "probe", [2, 37], executable,
    executable_sha256=expected_executable_sha256,
    max_steps=100_000, max_heap_bytes=1024 * 1024,
)
```

The result retains the request, original-input/Core/executable identities and
both complete reports. Original nominal inputs can share normalized Core;
their original input identities remain separate. This comparison does not
prove source-to-Core translation correctness.

## Validation and remaining obligations

The regressions run the actual Rust producer through the exact-byte wrapper for
v1–v8 scalar boundaries, mutable returned loans, recursion, multiple aliased
shared returns, chain roots/storage collisions, all bulk operations, normal
cleanup, allocation refusal and step/heap/call stops. Selected returned-loan
programs are compared at every executed step boundary. Legacy report equality
is checked against the real binary, and nominal scalar erasure cannot create
a new public entry. Deliberately fake replay fixtures test request/result
substitution, missing/downgraded capabilities and fabricated stopped cleanup.

```sh
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_execution_crosscheck tests.test_hia_rust_crosscheck tests.test_hia_rust_crosscheck_cli -v
```

A digest is a binding, not a signature or proof that a hostile producer ran the
program. The selected executable and host remain trusted. This development
API accepts no imported success receipt and grants no production or deployment
authority. Finite comparison does not prove whole-language soundness, arbitrary
lifetimes, general cancellation/concurrency, native/LLVM refinement, physical
device behavior or process RSS. P2 production-authority qualification and the
complete P7 correspondence obligations remain open.

The separate [bound v2 depth policy](HIA_RUST_BOUND_DEPTH_V2.md) can explicitly
select 1–32 root-inclusive frames. It does not change the fixed-depth v1
command, API or report contract described here.
