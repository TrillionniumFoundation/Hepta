# Explicit Rust admission for raw byte-DAG Core

`--byte-dag-admit-run` is a separate, opt-in Rust interpreter route. It accepts
raw primitive Core bytes, independently checks the entire module, enforces a
finite static policy, and runs the admitted snapshot through the existing v4
Machine. Python semantic verification, nominal normalization and evaluation
are not prerequisites for this route.

The Rust checker is the admission authority **for this one interpreter mode**.
Default Hepta, source/nominal and LLVM/native admission retain their existing
Python authority. Existing shadow/crosscheck receipts keep their old schemas
and false production/native authority claims. The new route has a distinct
profile and an explicit scoped authority claim; it does not relabel a shadow
comparison as a whole-language authority switch.

## Entry points and immutable admission

The Rust library entry point is:

```rust
admit_and_run_byte_dag(
    raw_core, function, scalar_arguments, static_policy_bytes, v4_policy_bytes,
)
```

The corresponding CLI command is:

```sh
hia-core-shadow --byte-dag-admit-run identity '[7]' \
  '{"max_allocator_interactions":0,"max_vm_ticks":2,"max_call_depth":1}' \
  '{"max_steps":2,"max_heap_bytes":0,"max_call_depth":1,"allocation_fail_at":null}' \
  < primitive-core.json
```

A private `AdmittedByteDag` owns the canonical Core snapshot, original raw
input digest, complete static report and static policy. Its only constructor
uses the existing duplicate-safe bounded Rust decoder and independently
rechecks ownership, loans, types, SSA, effects and CFG before calculating
bounds. No public constructor, deserializer or imported report can create
that admission object. Every definition is examined, including unused private
helpers and operations behind an early trap or runtime stop.

Execution takes that same owned canonical snapshot. The existing v4 executor
still rechecks it and applies its whole-module execution whitelist and exact
public scalar entry/argument/result boundary. This increment introduces no
unchecked Machine path, second evaluator or separate ownership rules.

## Finite scope and two independent policies

| Boundary | Accepted scope |
| --- | --- |
| Input | Raw primitive `hepta.hia.program.v1` through `v8` JSON, at most 8 MiB; bounded structure, exact integers and unique decoded keys |
| Resources | Byte owners and read/mutable loans; internal owning calls and v8 parameter-bound returned loans |
| Control flow | Closed acyclic CFGs and an acyclic direct call graph throughout the module |
| Operations | The explicit byte-only whitelist in `static_budget.rs`, followed by the existing Machine whitelist |
| External entry | Existing exported scalar function with exact scalar arguments and results |
| Static policy | All three fields required; each an exact unsigned u64 integer; JSON at most 1024 bytes |
| Runtime policy | Unchanged v4: 1–10,000,000 ticks, 0–1 GiB logical byte payload, 1–256 root-inclusive frames, exact positive hexadecimal allocation-failure index or null |
| Python transport | Immutable raw `bytes`; bounded scalar argument list/tuple; actual pinned and sealed Linux executable; bounded single-line response |

The static policy fields are `max_allocator_interactions`, `max_vm_ticks` and
`max_call_depth`. Every function's independently calculated bound must fit
every selected limit. A small exported identity function cannot hide an
over-budget private helper. A bound above u64, a recursive call/CFG, chain
type or opcode, unknown feature, malformed ownership graph or nominal schema
refuses admission. Cycles are refused even when a runtime limit would stop
them, or one particular input would not traverse them.

The metrics retain the conservative semantics documented in
[the static-bound contract](HIA_RUST_STATIC_BUDGET.md). Sequential calls add
their costs; alternative branches use separate per-metric maxima. These are
structural upper bounds, not proved feasible-path maxima. One bulk byte
instruction consumes one VM event while its host work depends on its extent.

The runtime policy is independent of the static policy. It may intentionally
provide fewer ticks or frames than the structural upper bound. The resulting
`budget_exceeded` observation preserves the actual stopped resource ledger.
Heap exhaustion and allocation failure also retain the existing v4 behavior.
Admission does not promise a successful return, automatic unwinding, or cleanup
that the program never executed. Logical payload limits do not bound total
process RSS, compiler work, wall time, native stack bytes or hardware latency.

## Actual-process Python transport without Python semantic admission

```python
from pathlib import Path
from hepta.hia_rust_byte_dag import execute_rust_byte_dag

observation = execute_rust_byte_dag(
    Path("primitive-core.json").read_bytes(), "identity", [7],
    "/absolute/path/to/hia-core-shadow",
    executable_sha256="<trusted exact lowercase SHA-256>",
    static_policy={
        "max_allocator_interactions": 0,
        "max_vm_ticks": 2,
        "max_call_depth": 1,
    },
    max_steps=2, max_heap_bytes=0, max_call_depth=1,
)
run = observation["rust_report"]["runtime"]["execution"]
```

`hepta.hia_rust_byte_dag` imports neither `hia_program` nor its normalizer,
static analyzer, evaluator, source bridge or LLVM emitter. A shared generic
JSON preflight bounds syntax before tree allocation. JSON serialization is
used only to calculate the canonical representation digest; it does not
perform semantic lowering. The original bytes are sent unchanged to Rust.
Invalid semantic Core is refused by the actual Rust process.

The transport reuses the existing exact-file digest check, sealed executable
image and bounded process-group lifetime. Caller argument and static-policy
containers are copied before invocation. A successful response must cover the
complete function inventory, preserve exact claim types and fit the selected
policies. The response is limited to 8 MiB and 1,048,576 JSON value nodes;
oversized/malformed output is refused. The timeout governs the Rust process,
not total Python preparation or a general compiler-time budget.

## Request identity and observation contract

The producer emits `hepta.hia.rust-byte-dag-run.v1`, profile `raw-byte-dag-v1`,
and status `admitted_and_observed`. The selected VM outcome is inside
`runtime.execution`: `returned`, `trapped` or `budget_exceeded`.

Its `hepta.hia.rust-byte-dag-request.v1` request binds:

- the SHA-256 of the original raw input bytes;
- the canonical primitive Core SHA-256;
- the profile, selected function and exact ordered scalar arguments;
- every static-policy field;
- every exact v4 runtime-policy field, including all wide failure-index digits.

`request_sha256` hashes that complete canonical request. Whitespace, escaped
identifier spellings or integer negative zero can share the same canonical
Core digest while retaining a different raw snapshot/request identity.
The nested `hepta.hia.rust-bound-execution.v4` envelope independently binds the
actual Machine invocation. Neither binding imports an old producer receipt.

The top-level scoped claim is
`rust_interpreter_admission_authority_for_this_profile=true`.
`python_verifier_required_for_this_mode=false` states this mode's dependency.
`default_production_admission_changed`, `native_execution_authorized`,
`whole_language_soundness_proved` and `native_backend_refinement_proved`
remain false. The nested historical static and runtime reports retain their
original claim meanings; they do not themselves become authority tokens.

Request comparison rejects stale/replayed or rehashed cross-source,
cross-argument, cross-policy and cross-protocol replies, missing inventory,
inexact counters and promoted claims. These checks do not authenticate a
hostile executable selected by its own caller-supplied hash, or prove an
arbitrarily self-consistent forged computation after replacing trusted
transport. The binary and its loader/libraries/kernel remain trusted. Full
execution/bound correspondence is compared to Python in differential tests;
that oracle is deliberately separate from the new execution route.

## Reproduction and qualification boundary

```sh
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_byte_dag tests.test_hia_rust_static_budget -v
python -m unittest tests.test_hia_rust_api_v4 tests.test_hia_rust_execution_crosscheck -v
```

The Rust integration tests invoke the actual CLI with a PATH containing no
Python, check all primitive versions, exact-limit/one-below boundaries, hidden
over-budget functions, raw snapshot binding, early stops and invalid profiles.
The Python tests use a clean child with all semantic Python modules blocked
from import, and also disable verifier/analyzer/VM calls in a live invocation.
The actual Rust entry still admits valid raw Core and rejects invalid ownership.

Differential cases compare every v4 outcome, scalar value, trap/stop code,
tick and resource-ledger field, along with every function's static bounds.
They include alternatives, sequential calls, multiple results, returned loans,
bulk operations, zero/failing allocations, wide failure indices, exact scalar
boundaries and partial resource ledgers. Tampering controls alter captured
responses solely to test refusal; they never supply positive qualification
evidence. Current integrated-head results belong to the normal final gate,
not to historical shadow receipts or this contract document.

The remaining broader P2 boundary is concrete: source and nominal lowering
remain Python-owned; this raw API has no source-origin/refinement certificate;
LLVM/native publication still consumes the existing Python-verified object;
the explicit profile excludes cycles, chains and foreign code; and no
whole-language, backend-refinement or hardware qualification follows. Raw
primitive admission cannot inherit a source/nominal public ABI claim merely
because some external tool flattened that source into scalar Core.
