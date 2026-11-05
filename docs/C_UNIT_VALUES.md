# Internal Unit values in the independent C backend

This bounded P11/P01 increment is stacked only on #704, exact parent
`360367b4222f11484d9992a7735d6205e0b1ddc3`. It extends existing Copy-value lowering
to internal `Unit` objects. No other research branch is composed.

## Contract

C's `void` is not an object type. A compiler-private one-byte struct represents
an internal Unit object; every produced value is initialized to its canonical
zero member. This does not promise zero-size storage, Rust layout compatibility,
a public ABI, a memory-size bound or a performance improvement.

- Calls returning Unit, `assert`, `print_i64` and `store` produce a usable Unit
  expression after their existing effects finish exactly once. The observable
  effects and any assertion failure are not erased when the value is ignored.
- Unit locals can be copied, moved, assigned when mutable, and returned. All
  Unit-returning functions still use C `void`; an explicit return expression is
  evaluated before returning. No source-level Unit literal is added.
- Nonempty Unit arrays, nested arrays, read/mut slices, record fields, concrete
  generic fields, source-enum payloads and builtin `Result<Unit,E>`,
  `Result<T,Unit>` and `Result<Unit,Unit>` use the existing ordered construction
  and snapshot rules. Unit indexing still evaluates its index and checks bounds.
- Named match payloads remain immutable arm-local values. `_` discards the value,
  not the effects of constructing it. Source-module identities are preserved.
- Only `hepta/c_backend.py` changes production logic. Frontend typing, effect,
  mutability, Copy, ownership, exhaustiveness and C ABI rules are unchanged.

## Foreign and unsupported boundaries

Unit function returns remain `void`, and raw Unit pointees remain `void`, including
already admitted opaque C pointer signatures. Raw Unit `load`/`store` now fail
with a structured subset diagnostic before C compilation, rather than relying
on invalid void-object compiler diagnostics. Opaque pointer transport is still
available; no dereference, lifetime, provenance or foreign safety guarantee is
added. The tests include actual C calls to an exported Unit-returning function
and an opaque-pointer identity function.

The frontend still rejects direct Unit parameters in all modes and Unit fields
in repr(C) records. Unit-bearing internal aggregates are not admitted at C
boundaries. Zero-length arrays, empty records, i128/u128, generic functions,
resource/control payloads and unsupported runtime types remain unsupported.
Recursive layouts remain refused; no recursive program is emitted, compiled or
executed in this increment. Inherited cycle tests check only pre-layout refusal.

P11/P01 remain PARTIAL. This is not general monomorphization, complete backend
equivalence, a lifecycle proof or release qualification.

## Reproduction

```sh
python tools/validate_c_unit_values.py
python tools/validate_c_results.py
python tools/qualify_c_unit_oracle.py
python -m hepta run examples/c_unit_values.hepta --backend c
```

The strict gate freezes **288 unique methods**: 19 new methods followed by all
269 inherited Result-gate identities in their original order. It requires equal
planned/started/finished/passed lists, no skipped/expected-failure/unexpected-pass
methods and stable hashes of all bound inputs. Historical refusal method names
are preserved; their newly supported Unit fixtures are replaced with unsupported
i128/u128 payloads or arrays, with other assertions unchanged.

Twelve new direct success-consumer methods run actual C O0/O3 with nonrecovering
UBSan. The CLI example is also executed. Four failing source cases each require
SIGABRT and no later output at O0/O3; native opaque-pointer/void-return ABI probes
run at both optimization levels. The independent repository-relative oracle
checks side effects, copies, Unit payloads and four bounds failures against
Python-derived expectations, requiring real native executions and recording
source/compiler/generated-code/executable identities and process outcomes.

Set `HEPTA_ENUM_REQUIRE_RUST=1` and provide pinned Rust 1.90.0 with `RUSTC` to
require native Rust comparisons in success, trap and independent-oracle cases.
Missing required Rust fails closed. The exact-head read-only workflow requires
C and Rust on Linux x86-64/ARM64 with Python 3.11/3.13. Local C success and Rust
source emission do not replace unexecuted native Rust/ARM or hosted evidence.

Against unchanged #704 production, the new suite records Unit layout refusals,
void-object native compilation failures and missing structured opaque-pointer
refusal. That negative evidence is retained separately; baseline failures are
not counted as final passes.
