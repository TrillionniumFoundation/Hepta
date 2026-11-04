# C local bindings and explicit ABI symbols

The independent C backend keeps every `extern "C"` and `export "C"`
function's declared symbol. A different source binding must not hide that
symbol merely because the backend prefixes its local variables with `h_`.

For example, this valid checked program previously failed native C compilation:

```hepta
export "C" fn h_value() -> i32 effects {} { return 42; }
fn main() -> i32 effects {} {
    let value: i32 = 1;
    return h_value();
}
```

Both the function and the generated local were named `h_value`. GCC reported
that the called object was not a function. The expected native exit status is
42. The same problem affected parameters, loop and match binders, returned
borrow places, owned/generic locals and exported self-recursion.

## Narrow mapping

The emitter collects explicit C function symbols for the complete checked
program. A source binding `name` retains the ordinary generated spelling
`h_name` unless that spelling equals one of those symbols. In that case its
generated local spelling is `__hepta_cb_local_name`. Parameter declarations,
named places, let bindings, match payloads and loop binders use the same rule.

The two output families have disjoint prefixes and are injective within each
family. Source C boundary symbols beginning with `__` are already rejected by
the checker. The fallback prefix is also distinct from generated function,
generic, temporary, argument and returned-view prefixes.

Struct fields remain `h_name` in their separate member namespace. Header
declarations, C symbols, public layouts, source shadowing rules, borrowing,
effects and function linkage are unchanged. Collision-free debugger variable
spellings, including the existing debug fixture, remain unchanged. A local
that actually collided intentionally has a different generated debug name.

This does not incorporate the separate private-function linkage repair #605,
module header-guard repair #647, other pending C backend extensions or Part03.

## Reproduction and tests

Base: #564 `f2b76f5741c83822be2e12cf5a50b50a8d27b96a`.
With the new test file and unchanged production code, 17 test methods produce
30 failing assertions/subcases and one explicit unavailable-Rust skip locally.
Subcases are not counted as independent methods. The original failure log is
retained separately from the repaired observations.

```sh
python -B -m unittest tests.test_c_local_symbol_names -v
RUSTC=/path/to/pinned/rustc python -B tools/test_c_local_symbol_names.py
```

The new suite compiles and executes real GCC binaries at O0 and O3 with UBSan,
tests the public CLI, and links separately compiled objects to actual C11 and
C++17 clients. It covers extern/export names, all binding positions, shared
and mutable returned places, slices, generic/owned values, two simultaneous
collision families and recursive exports. Rejected source shadowing and
reserved boundary names remain negative controls. A separate real Rust 1.90
executable must match the C output; it is explicitly skipped when unavailable
in a local run and mandatory in the strict hosted gate.

The exact-head Linux x86-64/AArch64 workflow requires all 255 unique new and
adjacent controls, with identical planned/executed inventories and no skips,
expected failures or unexpected successes. It retains source/compiler
identities and original test logs. Hosted results are pending when published.

Finite native tests do not prove whole-language semantics, all foreign
contracts, all platforms or production qualification. No ABI widening, merge
or deployment is part of this repair.
