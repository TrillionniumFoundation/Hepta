# Bound generic types across source modules

## Reproduced false refusal

On the physical function/type/local union #662 at commit
`40542c9a5f1ca710ce3c125b1b9e2504a6137a8e`, this imported library rejects if the
entry happens to declare an unrelated private `struct Secret { value: i32 }`:

```hepta
pub fn answer<Secret>(value: Secret) -> Secret effects {} {
    return value;
}
```

The entry calls `lib::answer::<i32>(42)`, but the checker reports
`E_GENERIC_PARAMETER` in the library. Renaming only the entry type, or only the
library parameter, makes real GCC O0/O3 executables with UBSan return 42. The
same false refusal affects generic structs/enums and Copy/Owned declarations.
The earlier #660 source reproduces it too. Both predecessor drafts explicitly
left this restriction open; their green results did not repair it.

The generic name binds a type within one declaration. It must not accidentally
refer to an unrelated entry nominal type after flattening. This is a language
correctness issue, not a security-isolation boundary.

## Bounded repair

The module loader gives a bound generic parameter a deterministic internal name
only when its spelling would collide with a flattened nominal type outside its
source module. Fresh names occupy the compiler-reserved module namespace and
avoid all existing flattened type/function names and that declaration's type
parameters. Noncolliding generic parameters retain their original spellings.

The existing AST Type traversal applies the declaration's parameter map to
bound Type nodes, including nested types and explicit generic arguments. The
loader also updates `type_params` and function `type_bounds` keys together;
Copy/Owned bound values are unchanged. It does not globally replace strings.
Nominal constructor and enum-pattern names, term bindings, fields, aliases,
function symbols, lifetimes and explicit return origins remain independent.

The checker and backends are unchanged. Simply weakening the checker's shadow
rule would leave its nominal/capability/field/lifetime consumers ambiguous.
Distinct internal bound names preserve their existing invariant instead.

## Deliberate compatibility limits

- Source-local nominal names remain excluded. Root same-source shadowing still
  rejects. Imported same-source shadowing has an existing inconsistent case:
  an imported nominal and same-spelled generic parameter can pass after the
  nominal is mangled, but adding a same-spelled entry nominal can make it
  reject. This repair preserves that behavior rather than silently imposing a
  new same-module naming rule.
- Duplicate/reserved parameter lists, invalid bounds and generic C boundary
  declarations remain unchanged for their existing refusal and source-name
  diagnostics. Generic C declarations are not newly supported.
- The normal generic arity, ownership/capability, borrowing and unused-parameter
  checks remain. Newly reachable diagnostics may contain internal parameter
  spellings, while source spans remain original. Newly accepted flattened
  interfaces and inspection data likewise expose internal bound names. Source
  declaration names, public import names and C ABI symbols are not renamed.
- The earlier function/type visibility guards and local-term isolation remain
  active. A generic name does not grant a nominal constructor, field, stored
  lifetime, or capability from an unrelated same-spelled type.
- No loader budget, package identity algorithm, other shadowing restriction,
  recursive execution path or Part03 relocation is changed.

## Explicit inherited test reconciliation

Two inherited methods asserted the former cross-module generic refusal or its
unmodified bound spelling. Their original failures on this candidate are
retained separately. The methods now require the repaired acceptance and
consistent type/bound identities. A complementary root same-source fixture
still requires exactly `E_GENERIC_PARAMETER` and the original source spelling.
The union method separately checks term-binding identity and the Copy bound.
No inherited method is removed, skipped or weakened to accept either result.

## Verification boundaries

The new suite exercises function/record/enum parameters, nested types and
explicit imports, fresh identities and original spans, public CLI behavior,
and negative capability/field/bound controls. Finite native controls execute
real GCC O0/O3 with UBSan. A separate native Rust comparison runs only after
its C/frontend prerequisites and requires the actual pinned compiler.

`python tools/test_module_generic_parameter_scope.py` includes all 407
inherited union methods plus 20 new methods: **427 unique methods**. It requires the actual physical
checkout, GCC, pinned Rust, exact unique planned/executed identities and no
failures, errors, skips, xfails or xpasses. Its workflow checks the exact PR
head on Linux x86-64 and AArch64 and retains original source/tool/log evidence.
Missing local Rust is not a passing native gate. Results for #662 or other
component drafts are not evidence for this changed source.

These finite checks do not prove whole-language soundness, complete module
isolation, arbitrary object layout, recursive/worker lifecycle behavior,
foreign implementations or production readiness. Draft publication is not a
merge, release or deployment.
