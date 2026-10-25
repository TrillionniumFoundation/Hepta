# P3/P4: checked scalar truthiness in strict C/C++ migration

Source base is PR #98 `f637901935b6b5c78afebcab229dac90dda1c2cb` (itself integrated on PR #97).
The implementation reuses `hepta.c_migrate._expr` as the single
expression-authority for C11 and C++20 source migration.

## Semantics

Existing PR #98 short-circuit `&&`/`||` and logical `!` lowering now accepts
operands that are already checked pure 32/64-bit C/C++ integer expressions.
The new `_predicate` adapter translates a nonzero scalar into a Hepta
`bool` using the exact `(value != 0)` semantics, then invokes the
existing scalar and logical lowerer for comparisons, negation and short-circuit
nodes. C++ Clang `IntegralToBoolean` AST wrappers are accepted only when
their inner integer expression passes this same fail-closed check.

The change applies to `if`, `while`, bounded `for`/`do` conditions,
and scalar ternary conditions. It does *not* silently convert a C/C++ integer
Boolean result into an arithmetic return value, and it never accepts pointer
truthiness, user-defined C++ conversions, overloaded operators, unreviewed
implicit casts, assignments, calls or increment side effects.

C/C++ arithmetic is compared only for originally defined inputs. In the
admitted scalar subset, signed overflow, division by zero, and the signed
minimum/-1 pair remain outside defined-source equivalence; Hepta may abort
when a checked runtime operation encounters them.

## Acceptance boundary

`tests/test_logical_predicate_migration.py` requires real C and C++ originals,
Clang AST translation, the Hepta frontend, and the independent Hepta/C
native backend. Positive cases cover zero/nonzero integers, nested
short-circuit conditions, negation, ternary and a bounded loop; negative
cases reject pointer or side-effecting predicates with no published source.

An independent local Clang-AST mirror of the predicate normalization ran
with actual GCC14/Clang17-compiled C and C++ original functions:
504/504 finite observations matched and two side-effecting shapes rejected.
See local receipt `hepta_p3_p4_logical_predicate_local_evidence_20261025.json`.
These are *not* Hepta compiler/binary test results. They do not establish
general source-to-target equivalence, production safety, C++ ABI compatibility
or closure of P0–P7/P01–P12 blockers.

`whole_project_blockers_closed=false`.
