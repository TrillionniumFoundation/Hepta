# C ABI complete-layout type graph

The checker accepts finite, representable C ABI records independently of the
order in which it encounters them. For example, these declarations have a finite
layout and may cross the supported C boundary by value:

```hepta
repr(C) struct Parent { child: raw const Child, value: i32 }
repr(C) struct Child { parent: Parent, marker: i32 }
export "C" fn echo(value: Parent) -> Parent effects {} { return value; }
```

Previously, checking `Parent` incorrectly reported `E_C_ABI`: traversal remembered
`Parent` across its pointer to `Child`, then treated `Child.parent` as an unbroken
recursive value. The last edge alone cannot determine whether a cycle is legal.

The predicate now validates every reachable ABI shape with an explicit work list,
expanding each nominal record once per invocation. A separate graph records C
complete-definition dependencies. Pointers remove that dependency; arrays restore
it for their elements. Thus a pointer to an array of an incomplete record is not
mistaken for a plain pointer to that record. Cycles in the complete-definition
graph are rejected, including invalid components reached only through pointers.

This does not loosen the supported scalar, `Unit`, array-position, nonempty or
nongeneric-record rules. Raw pointers still require supported pointee shapes.
The independent language value-layout check remains unchanged. No persistent
cache is shared between calls or mutated checker environments.

## Regression gate

Run `python -m unittest tests.test_c_abi_type_graph -v` for the focused controls.
The tests include declaration-order permutations, pointer/array nesting,
unsupported fields after recursive edges, a diamond graph and a 1,200-record
predicate chain. The chain exercises this predicate, not the entire compiler's
depth limits. The diamond bounds nominal lookups without a timing threshold.

Real GCC and G++ independently check hand-written declarators, compile generated
headers, and link C/C++ callers against Rust objects that pass both records by
value and verify pointer identity and scalar fields. These native controls skip
locally if their actual compilers are unavailable; a frontend-only check is not
native ABI qualification.

The dedicated workflow runs the exact 207-test focused and adjacent inventory on
x86-64 and ARM64 with pinned Rust 1.90.0 and real GCC/G++. The runner rejects
missing tools, skipped tests, expected failures and incomplete or duplicate test
execution. Its logs bind the source commit/tree and compiler identities. These
finite controls do not establish general ABI correctness or raw-memory safety.

The independent C backend's recursive-record lowering is separate work. This
change touches only the front-end ABI predicate, not that backend, source
relocation or the Part03 application evidence pipeline.
