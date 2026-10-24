# HSIR transitive raw-pointer boundary inventory

This metadata repair is stacked on PR #9 at
`e0acefc51dcd884c182683f78435cef696309e12`.

## Scope and failure

HSIR already records a `raw_pointer_signature` obligation for direct raw-pointer
parameters and returns. It previously inspected only explicit type arguments,
so a nominal struct or enum hiding a raw pointer could produce an empty
boundary inventory. Seven nested nominal cases and a return-only case exposed
the omission before this repair.

The in-repository consumers of `external_obligations` are the HSIR export and
its tests. This field does not decide frontend/native acceptance. Copying a raw
pointer is not itself an unsafe dereference; this is an audit metadata
completeness defect, **not a demonstrated memory-safety or borrow-check bypass**.

## Change

The inventory iteratively traverses the signature's explicit type arguments
and the fields of declared structs and enum variants. A visited declaration-name
set prevents repeated nominal expansion; type arguments are still inspected
for every instantiation, including when the nominal name was already visited.
This retains existing generic support without adding language semantics or
monomorphization. The frontend remains responsible for accepting declarations,
including its existing generic-parameter and recursive-layout restrictions.

Tests cover nested structs, enums, arrays, existing generic wrappers, repeated
generic names with differing arguments, recursive pointer layouts, return-only
boundaries, and raw-free controls. A synthetic raw-free nominal cycle exercises
the traversal directly; it does not make an illegal by-value cycle acceptable
to the language. Repeated fresh parses produce identical inventories and hashes.

All native validation, translation-correctness, whole-language soundness, and
foreign-contract proof flags remain false. Existing metadata schema and reason
names are unchanged; hashes naturally change when the corrected inventory adds
an obligation. No checker/backend/CFG/SSA behavior is changed. PR #8's HMIR work
is separate and has no overlapping changed files.

Uninstantiated generic function parameters remain symbolic; this inventory does
not predict every future specialization or infer pointee lifetimes, validity,
ownership, or aliasing from a raw pointer. An empty inventory is not a safety
certificate.

## Local verification

- Focused HSIR suite: 12 passed.
- Complete native unit/integration suite: 435 passed, zero skips, 33.229s.
- Toolchain: Python 3.12.14, real pinned Rust 1.90.0, GCC 14.2, Clang 19.1.7.
- `git diff --check`: passed.

Remote CI, full 13-gate release qualification, and cross-target/physical hardware
qualification were not performed for this change.
