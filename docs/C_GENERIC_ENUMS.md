# Concrete Copy-generic source enums in the independent C backend

This bounded P11/P01 increment is stacked only on PR #701, exact parent
`4622792c5925984c1e4174492b0c9b0bd214391f`. It extends source-language enums,
not C-header imports, generic functions, or a foreign enum representation.
P11 and P01 remain PARTIAL.

A later bounded extension specializes concrete Copy-generic records; see
[C_GENERIC_STRUCTS.md](C_GENERIC_STRUCTS.md). The original scope and results
below describe this earlier increment, not a new full gate.

## Contract

An enum such as `enum Maybe<T> { None, Some(T) }` can be instantiated at checked
concrete types through an explicit constructor (`Maybe::<i32>::Some(7)`) or an
expected type (`let x:Maybe<i32>=Maybe::Some(7)`). Functions themselves remain
non-generic. The frontend still checks every declaration before C emission.

- Each complete nominal type, including every type argument, has a distinct
  cached C layout. `Maybe<i32>` and `Maybe<bool>` cannot alias the same layout.
- Type parameters substitute throughout payload types, including fixed arrays,
  raw pointers, other generic enum applications, and finite nesting of the same
  template, for example `Maybe<Maybe<i32>>`.
- Concrete payloads retain the existing supported Copy subset: scalars,
  positive fixed arrays, non-generic records, enums and existing raw pointers.
  Several parameters, reordered parameters and repeated instances are supported.
- Every variant's concrete payload layout is checked, not only the constructed
  variant. Unsupported payload types reject even if only a fieldless variant
  would be used. Unused non-generic enums retain eager validation.
- A checked but unused generic template does not invent a concrete type argument
  or a runtime layout. Its eventual concrete instantiations must all be supported.
- Constructor arguments retain exactly-once, left-to-right materialization.
  Matching copies its scrutinee once, and selected arm bindings copy the concrete
  payload types. Mutating the original cannot modify the saved values.
- Value parameters, returns, assignments, arrays, records, read/mut parameters,
  slices and module aliases retain the previous frontend and backend contracts.

The representation remains a compiler-private tagged struct with selected union
members. No layout, padding, tag, size, serialization or foreign ABI stability is
promised. Raw pointer values have the existing unsafe/lifetime limitations.

The production change is confined to `hepta/c_backend.py`. It reuses the
frontend's existing type substitution. No frontend admission, ownership, effect,
mutability, exhaustiveness, module lookup or C ABI rule is weakened.

## Retained boundaries

Generic functions and structs, builtin Result, Unit payloads, zero-length or
Unit-element arrays, unsupported runtime/resource types, resource payloads,
recursive C layouts and enum C ABI remain unsupported. A declaration dependency
cycle reachable back to a generic enum is rejected before concrete layout
specialization, including cycles through raw pointer fields. This avoids
expanding generic layout cycles without trying to implement forward recursive C
types. Finite nested type arguments on an acyclic template remain supported.
The associated regression only checks rejection; it never emits, compiles or
executes a recursive program.

This does not provide a general monomorphization pass, generic lifetime/trait
system, new allocation/runtime, foreign safety proof, or full backend equivalence.
Two inherited refusal fixtures replace their now-supported generic enum with a
still-unsupported generic struct. Their method IDs and all other assertions are
preserved. No unrelated research branches are composed.

## Reproduction

From the repository root, with Python 3.11 or newer and native GCC:

```
python -m hepta run examples/generic_enums.hepta --backend c
python tools/validate_c_generic_enums.py
python tools/qualify_c_generic_enum_oracle.py
python tools/validate_c_payload_enums.py
```

The strict combined runner freezes 232 unique methods: 17 new generic-enum
methods and the 215 inherited payload/fieldless/backend/parser/checker/language
methods. Exact planned/started/finished/passed identities must match, with no
skips, expected failures or unexpected successes. Compiler, tests, example,
runner, inventory and oracle hashes must remain unchanged during each run.
This is a targeted gate, not the full project release gate.

Eleven direct new native consumers compile and execute at O0/O3 with
nonrecovering UBSan. A twelfth runs the actual public CLI example. Tests cover
multiple concrete types, nested specialization, arrays/records/enums/pointers,
constructor and binding snapshots, read/mut slices and returns, source modules,
unused templates, and retained frontend/C ABI/borrowing/type refusals.

Set `HEPTA_ENUM_REQUIRE_RUST=1` and `RUSTC` to the actual pinned Rust 1.90.0
binary to require native Rust comparisons as well. The exact-head read-only
workflow requires native C and Rust on Linux x86-64/ARM64 with Python 3.11/3.13.
Missing tools, queued jobs and previous PR results do not qualify this head.

## Evidence limits

Native Rust and ARM have not run locally. The local environment has actual GCC
14.2.0 on x86-64; Rust source emission is not native Rust validation. Finite
native execution and UBSan cannot establish whole-language soundness, arbitrary
unsafe correctness, performance superiority, a public ABI or release readiness.
No merge, release or deployment is part of this draft.

Local qualification passes the combined 232/232 gate and inherited 215/215 gate
on both Python 3.12.14 and 3.13.5, with zero skips. An independently authored
oracle executes five fixtures at O0/O3: 120 seeded transitions across i16/u32/i64
plus nested-specialization and snapshot/slice cases, ten native C executions
per Python version. It records source, tool, generated-code and executable hashes,
and fails closed when requested native Rust is unavailable.

Against unchanged #701 production, the final 17 new methods produce ten
lowering-error methods, four failing methods (six assertions including three
check-only layout-cycle subcases), and three passes. The module/CLI/borrowing
failures reflect the parent's blanket generic-enum refusal. These retained
negative results establish the missing capability; they are not final passes.
Independent review found no must-fix production defect and separately executed
the 49 enum-only tests and the ten-run oracle before the frozen complete gate.
