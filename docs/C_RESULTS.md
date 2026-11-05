# Builtin Copy Result in the independent C backend

This bounded P11/P01 increment is stacked only on the concrete generic-record
work in #703, exact parent `c224a48932d97cc95d0869eaf3465d284406764b`.
It makes the frontend's reserved `Result<T, E>` available in C lowering when
both concrete arguments are already supported Copy types. It does not compose
C-header import, runtime-resource or other independent research branches.

## Contract

- `Result::Ok(value)` and `Result::Err(error)` accept complete explicit arguments
  or the exact expected type. The two alternatives retain their frontend arity,
  payload types and exhaustive-match requirements.
- Each full `Result<T, E>` uses the existing concrete enum specialization cache
  and a compiler-private tagged struct/union layout. Different argument lists
  have distinct types. This representation is not a public ABI or a promise
  about Rust's physical representation.
- Payloads include the supported integer, float and bool scalars, fixed arrays,
  source records/enums, concrete generic records/enums, finite nested Results
  and already admitted raw pointers. Result can itself occur inside those
  containers, both as success and error payloads.
- Constructor arguments are evaluated exactly once and copied before later
  operations can mutate their source. Match evaluates one scrutinee snapshot
  and copies its selected payload into an immutable arm-local binding. Ignoring
  a payload with `_` does not suppress the constructor's effects.
- Copy assignment, returns, read/mut parameters, borrowed slices, early returns,
  continuing arms and module aliases use the same rules as source enums.
  Result's reserved identity is shared across modules, while nominal payload
  identities remain distinct.
- Every concrete layout is checked, including an unconstructed alternative or
  a type in an uncalled function. There is no speculative builtin layout when
  Result is absent. The builtin is private to lowering and does not modify the
  source AST. A regression compares its complete definition with the checker.

Only `hepta/c_backend.py` changes production logic. The frontend's typing,
exhaustiveness, effects, ownership, resource and C ABI checks are unchanged.
No exception effect, `?` syntax, implicit propagation or allocation is added.

## Refusals and limits

The subsequent [Unit value increment](C_UNIT_VALUES.md) enables Unit payloads
and nonempty Unit arrays. Zero-length arrays, i128/u128 and unsupported runtime
types remain refused by C lowering, including nested or unused alternatives. Resource/control payloads remain forbidden by frontend Copy
bounds. Generic functions, recursive layouts, unions and other unsupported
language features are not enabled. This increment does not execute recursive
programs; inherited cycle regressions only check pre-layout rejection.

Result in an exported C function, extern C signature, repr(C) field or foreign
raw-pointer signature remains rejected. Internal raw pointers retain existing
explicit unsafe requirements and offer no additional lifetime, provenance or
aliasing guarantee. Conservative overlapping-borrow rejection remains in force.
There is no claim of general monomorphization, complete backend equivalence,
whole-language soundness, performance or release qualification. P11/P01 remain
PARTIAL.

## Reproduction

Run from this exact source with real GCC and Python:

```sh
python tools/validate_c_results.py
python tools/validate_c_generic_structs.py
python tools/qualify_c_result_oracle.py
python -m hepta run examples/c_results.hepta --backend c
```

The strict inventory is **269 unique methods**, all **251 inherited identities**
in their original order plus 18 new Result methods. Five inherited refusal
fixtures now use unsupported `Result<..., Unit>` instead of supported numeric
Results; method identities and all other assertions are retained. The runner
requires planned, started, finished and passed identities to match, no skips,
xfails or xpasses, and all bound source/test/example/oracle inputs to remain
unchanged.

Twelve new direct native consumer methods run C O0/O3 with nonrecovering UBSan
and require exit 0 and empty stdout/stderr; the CLI method separately runs the
checked-in example through the actual public command. Direct consumers also
emit Rust source, which is not native Rust validation. Other methods compare
the builtin definition and test frontend/backend/foreign-boundary refusals.

The separately authored repository-relative oracle uses Python-derived expected
stdout across seven fixtures and 178 observations per optimization, including
72 seeded finite calls, both alternatives, nested containers, state changes,
snapshots and scalar boundaries. It requires fourteen real C O0/O3 executions
with nonrecovering UBSan, exact stdout, exit 0 and empty stderr. Evidence binds
source, generated code, compiler identity, flags, executable and process
outcomes. A wrong-output control rejects a successful process. The oracle
shares the frontend; it is not an independent language interpreter.

Set `HEPTA_ENUM_REQUIRE_RUST=1` and provide pinned Rust 1.90.0 via `RUSTC` to
require actual Rust O0/O3 comparisons in the direct native tests and oracle.
Missing required Rust fails closed. The exact-head workflow requires this on
Linux x86-64/ARM64 with Python 3.11/3.13, using read-only repository permissions.
Local C evidence, Rust emission and queued workflows cannot stand in for
unexecuted native Rust/ARM or current-head hosted qualification.

The final new tests against unchanged #703 production yield 12 error methods,
three failed methods and three passes. The failed borrow/module/CLI methods
encounter the parent's Result refusal; the error set includes absent builtin
schema lookup and native consumers rejected before C emission. Initial fixture
import/cast/diagnostic mistakes were corrected before final gates; unsuccessful
development runs are retained and are not counted as passes.
