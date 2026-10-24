# Class-local scalar aliases in the AST C++ bridge

This draft is a child of frozen #22,
`ef20771b817c8b303efd3252e739868d7ecad1c9`. It changes only the original public
`bridge_cpp` AST importer. The declarative `bridge_cpp_contracts` route, shared
C scalar `_typ`, class lifetime/call synchronization and publication code are
unchanged. #23's subprocess descendant cleanup is a separate source repair and
is not silently imported or claimed qualified here.

## Reproduced conversion defect

A legal included header defines `using BridgeValue = long long;`. A class then
uses `using uint32_t = BridgeValue;` and exposes a public zero-argument method
returning `4294967297LL`. Its constructor and nonthrowing destructor satisfy the
existing pilot's lifetime restrictions.

Clang's method signature retains the class-local spelling `uint32_t`. The old
bridge mapped that spelling to Hepta `u32`, then reused bare `uint32_t` in the
wrapper's **global** scope. After `<cstdint>`, this is the ordinary unsigned
32-bit type, not the class's signed 64-bit alias. The generated C++ still
compiles because the assignment performs an implicit integer conversion.

Compile-only `std::is_same_v` assertions established the original member return
as `long long` and the wrapper output slot as `std::uint32_t*`. A separate native
oracle used each function's actual, matching declaration: the original object
returned 4294967297, while the generated wrapper returned 1 through its uint32
slot. Conversion to unsigned32 is defined modulo 2^32. No mismatched ABI call or
undefined signed arithmetic was executed.

This is a **method-to-wrapper conversion/contract defect**, not evidence that
the wrapper's C ABI disagreed with the generated Hepta declaration: those two
both used u32. A conflicting *global* signed typedef named uint32_t is not the
same reproducer; the generated `<cstdint>` include already rejects that case.
An independent compile-only example similarly established a class-local
`uint64_t = unsigned char` method exposed through global uint64 wrapper slots.

## Narrow fail-closed policy

Before walking public methods, collect class-local `TypedefDecl`/`TypeAliasDecl`
that shadow the four previously supported spellings: int32_t, uint32_t, int64_t
and uint64_t. Include private aliases, since a public method can legally use a
private alias. Reject `E_CPP_ALIAS_SCOPE` if any such spelling is actually used
as a public method return or parameter type. This covers return-only and
parameter-only cases and does not depend on parameter metadata to infer returns.

Unused local aliases remain allowed. Ordinary unshadowed `<cstdint>` and builtin
scalar signatures remain supported. This deliberately also rejects a used local
alias whose actual underlying type happens to equal the global type; proving and
rendering arbitrary scoped aliases is not added here. No general typedef,
namespace, nested-type or C++ canonical-type lowering is claimed.

## Evidence boundaries

Five new regression tests against the exact base produced eight failing
assertions, zero errors; all eight negative subcases were previously accepted.
They cover using/typedef, included definitions, private aliases, return-only,
parameter-only and all four spellings. The normal cstdint/unused-alias positive
remains accepted. After repair the complete focused C++ suite passed 25 tests,
including the separate explicit-contract tests. Exact full-suite and independent
review results accompany the draft publication.

The original header/class AST, wrapper, static assertions and defined native
oracle are retained in the local engineering evidence. No broad C++ correctness,
foreign memory/race safety, general ABI proof or release qualification follows.
No remote CI queried, no merge/deployment and no new toolchain expenditure.
