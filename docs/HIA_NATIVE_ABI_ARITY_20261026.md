# HIA P2 native ABI corpus arity gate — 2026-10-26

## Exact increment
Stack on the reviewed HIA v6 PR #219 native differential plus sibling PR #217
source-bound static-budget numeric replay (true two-parent integration in
PR #220). This is a narrow safety guard on the existing differential
oracle, **not a new parser, compiler, verifier or ABI backend**.

## Missing validation
The existing finite corpus bound required homogeneous i32/u32 scalars and
at most 16 arguments, but the child worker uses Python ctypes to set
`argtypes = [word] * len(args)`. A vector of **incorrect arity** could be
passed to a foreign C function if a caller-provided oracle also accepted
that vector. It is not valid to treat such undefined foreign-call behavior
as evidence of native compiler correctness.

## Change
- For independently verified executable HIA v1–v6 source/Core, derive
  **the exact parameter count for each exported function** from the
  canonical already-checked HIA function inventory, not from supplied test
  vectors. Enforce one-to-one export and corpus arity equality **before**
  invoking the foreign child.
- The older scalar Hepta source qualifier also binds each corpus vector
  to its already-verified scalar SSA parameter inventory.
- Wrong arity, missing exports, duplicate names, Boolean-as-int arity,
  float arity and counts outside 0..16 reject deterministically.
- The raw `compare_oracle_with_native` utility lacks authenticated Core
  parameter counts; its new explicit `core_corpus_argument_arity_checked:
  false` claim is NOT upgraded. Only the two source/Core-qualified
  wrappers may set this field true.
- For malformed/unhashable return-word input types, reject with the
  structured HIA differential error rather than uncaught TypeError.

## Negative controls
`tests/test_hia_v6_differential.py` adds a real HIA Owner Core zero-argument
C export and submits 1-, 2-, and Boolean-argument false vectors while
monitoring that `_observe_native` is NEVER invoked; also checks forged,
duplicate and type-confused ABI arity inventories.

A direct Python snippet containing the exact new pure admission helper can
be independently exercised without Clang. Complete code/test execution on
a checked out Hepta tree remains the acceptance test:

    python -m unittest tests.test_hia_v6_differential \
       tests.test_hia_native_differential -v

## Claim boundaries
This checks the *caller corpus* against known Core signatures. An ELF
symbol alone does not cryptographically prove a callee's C type signature;
a foreign library that lies about its ABI remains a trust boundary.
Matching finite scalar return values does not prove side effects,
allocator cleanup, all HIA machine semantics, cross-architecture ABI,
arbitrary C/C++ migration or whole-language soundness.

`whole_project_blockers_closed=false`.
