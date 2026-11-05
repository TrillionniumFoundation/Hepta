# Concrete Copy-generic records in the independent C backend

This bounded P11/P01 increment is stacked only on PR #702, exact parent
`9d7da36b167c83d3f466260d09239f2f3521ae11`. It extends source-language records
alongside the existing generic-enum specialization. No other research branch
is composed. P11 and P01 remain PARTIAL.

## Supported contract

A record such as `struct Box<T>{value:T}` can be instantiated through an explicit
constructor (`Box::<i32>{value:7}`) or an expected complete type
(`let b:Box<i32>=Box{value:7}`). Functions themselves remain non-generic.

- Each complete nominal type has a distinct cached C layout. Different arguments
  and different declarations remain distinct, including multiple/reordered type
  parameters and same-spelled declarations from separate source modules.
- Type substitution covers every field, including nested records, enums, fixed
  arrays and existing raw pointer types. Finite nesting such as `Box<Box<i32>>`
  works. Structs can contain generic enums and enums can contain generic structs.
- Every concrete field must be supported, including fields in declarations used
  by an uncalled function. Checked but unused generic templates do not acquire
  invented type arguments or layouts. Non-generic records retain eager checking.
- Constructor expressions are evaluated exactly once in **source field order**,
  which can differ from declaration order. Each value is copied before evaluating
  the next field. Existing assignment, parameter and return value-copy behavior
  is retained, including nested arrays and records.
- Read/mut parameters and slices keep the existing conservative borrowing rules.
  Copying before a mutation preserves the original value. Raw pointer values
  retain the existing explicit unsafe and lifetime limitations.
- Specialized records use a separate compiler-private name family, distinct
  from array helpers, enum types and non-generic source-record names.

Only `hepta/c_backend.py` production logic changes. It reuses the frontend's
existing type substitution and complete checked types. No frontend ownership,
effect, mutability, module lookup or C ABI admission rule changes.

## Retained boundaries

Generic functions, builtin Result, Unit fields, zero-length or Unit-element
arrays, unsupported runtime/resource types, resource payloads, recursively
defined C layouts and generic-record C ABI remain unsupported. Generic repr(C)
declarations and foreign uses continue to fail frontend C ABI checks.

A declaration dependency cycle returning to a generic struct or enum is rejected
before concrete specialization, including cycles through raw pointer fields.
This deliberately does not provide forward recursive C layouts. The regression
only checks this rejection before layout generation; no recursive program is
emitted, compiled or executed. Finite nesting on acyclic templates is supported.

There is no general monomorphization pass, trait/lifetime system, new allocator
or runtime, foreign layout guarantee, complete backend equivalence, performance
claim or release qualification. Compiler-private layout includes no stability
promise for field offsets, padding, size, serialization or ABI.

Four inherited negative fixtures now use a concrete unsupported Unit field or a
still-unsupported generic function instead of a newly supported generic record.
All inherited method IDs, ordering and other assertions are preserved. Earlier
enum documents retain their original, narrower qualification results.

## Reproduction

From the repository root, with Python 3.11+ and native GCC:

```
python -m hepta run examples/generic_structs.hepta --backend c
python tools/validate_c_generic_structs.py
python tools/qualify_c_generic_struct_oracle.py
python tools/validate_c_generic_enums.py
```

The strict combined runner freezes 251 unique methods: 19 new struct methods and
all 232 inherited enum/backend/parser/checker/language methods, in the same
inherited order. Planned/started/finished/passed identities must match exactly,
with zero skips, expected failures or unexpected successes. Compiler, test,
example, runner, inventory and oracle inputs must remain byte-identical during
each run. This targeted gate is not the full project release gate.

Thirteen direct new native consumers execute C at O0/O3 with nonrecovering UBSan;
a fourteenth runs the example through the public CLI. The direct helper emits
both C and Rust source, but Rust emission is not native Rust validation.

The separately authored oracle covers 96 deterministic seeded records, nested
record/enum/array combinations, all six source field permutations, snapshots,
mutable/read slices and concrete type permutations. Seven fixtures run at
O0/O3, fourteen native C executions per Python version. Python-computed expected
stdout and Hepta assertions are both checked. Evidence records input, source,
compiler, generated-code and executable hashes and exact process results.
This oracle shares the frontend and is not an independent language interpreter.

Set `HEPTA_ENUM_REQUIRE_RUST=1` and `RUSTC` to the pinned Rust 1.90.0 executable
to require actual Rust O0/O3 comparisons. The read-only exact-head workflow
requires native C and Rust on Linux x86-64/ARM64 and Python 3.11/3.13. Missing
tools, queued jobs and previous PR results do not qualify the new head.

## Local evidence and limits

The combined 251/251 gate and inherited 232/232 gate pass with zero skips on
Python 3.12.14 and 3.13.5 using native GCC 14.2.0 on Linux x86-64. Native Rust and
ARM have not run locally. Required-Rust mode must fail closed without Rust.
Finite native execution and UBSan are not a whole-language soundness proof or
qualification of arbitrary unsafe inputs.

Against unchanged #702 production, the final 19 new methods yield twelve
lowering-error methods, four failing methods (seven assertions including four
check-only cycle subcases), and three passes. Module/CLI/borrowing failures
reflect the parent's blanket generic-struct refusal. These retained baseline
failures establish the missing capability; they are not final passes.

An initial new fixture accidentally shadowed a local binding; it was corrected
before the final gate. An inherited fieldless-enum negative still expected
all generic structs to fail; it now uses an unsupported concrete Unit field.
These earlier unsuccessful runs are retained and are not reported as passes.
No merge, release, deployment or activation is part of this draft.
