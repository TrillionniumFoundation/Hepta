# Source-module nominal type scope

## Reproduced fallback

On unchanged source `f2b76f5741c83822be2e12cf5a50b50a8d27b96a`, an imported
`lib.hepta` can construct a type it neither declares nor imports:

```hepta
pub fn answer() -> i32 effects {} {
    let value: Secret = Secret { value: 42 };
    return value.value;
}
```

If the entry module happens to declare private `struct Secret { value: i32 }`,
this library passes the frontend. Actual GCC O0 and O3 executables, both with
undefined-behavior sanitization, return 42. Renaming or removing only the entry
type restores `E_UNKNOWN_TYPE`. Making the entry declaration public does not
supply the missing import. Parameter and return annotations, an enum parameter,
and a nested generic argument have the same fallback. Python 3.12, Python 3.13,
and public CLI observations agree for the exercised cases.

This contradicts the explicit module contract: file identity owns a namespace,
and an imported type must be named through its import alias. It is a language
correctness issue, not a security boundary against source-file access.

## Narrow repair

The loader records the assembled nominal type names. An unqualified type name
that is absent from its source module but would otherwise bind an assembled
type now rejects with `E_MODULE_SCOPE`. Existing type-node traversal also
applies this check inside type arguments, annotations and struct constructors.
The error identifies the referencing source file; type annotations retain the
loader's existing file-level span precision.

Same-module types and explicitly qualified public imports are unchanged.
Generic parameters keep their existing declaration scope. Builtin types and
constructors, truly unknown type diagnostics, imported private-type rejection,
and deterministic module naming remain unchanged for valid source programs.

This change does not compose the separate function-reference repair in #658.
It does not alter checker or backend logic, public ABI names, layouts, loader
budgets, or package identity algorithms. Existing cross-module local/function
and generic-parameter name collision restrictions remain. It does not claim
complete module isolation, whole-language soundness, arbitrary object-layout
qualification or correctness of foreign implementations. No recursive or
worker-execution qualification is asserted.

## Verification

The regression module has 18 methods and includes invalid unqualified references and valid
same-module, alias, generic, enum and builtin controls. Positive native cases
execute actual GCC at O0/O3 with UBSan. A separate parity case requires actual
Rust after its C and frontend controls. Public CLI refusals reject before
native compilation.

`python tools/test_module_unqualified_type_scope.py` is a strict native gate.
It requires the real pinned Rust compiler, GCC, the exact unique method
inventory and execution order, and zero failures, errors, skips, expected
failures or unexpected successes. A missing compiler is a failed prerequisite,
not a passing gate. The complete hosted inventory has 149 methods. The workflow checks the exact
pull-request head on Linux x86-64 and AArch64 and retains original logs plus
source/tool identities.

These finite regression observations do not establish production readiness or
extend the language's documented safety and foreign-code assumptions.
