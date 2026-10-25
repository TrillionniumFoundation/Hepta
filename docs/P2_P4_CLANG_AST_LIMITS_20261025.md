# P2/P4: bounded Clang AST intake for strict source migration

The strict Clang-AST C and C++ migration paths use a single bounded
`_load_bounded_clang_ast` decoder in `hepta.c_migrate`.

Clang is a real external parser, but its JSON transcript is still untrusted:
AST input is constrained to 32 MiB of UTF-8, no more than 250,000 traversed
JSON values and a depth no greater than 128. Invalid, too-deep, nonfinite,
wrong-root and unsupported JSON shape inputs reject with explicit migration
errors, not uncaught recursion or an implicit frontend-only success.

These limits can intentionally reject legitimate gigantic C/C++ translation
units; wider project support needs a separately qualified capture profile.
The project-aware C migrator remains a distinct entrypoint and is not
claimed to be protected by this strict scalar intake increment.

Real Clang C11/C++20 AST cases and malformed/oversized controls are exercised
in `tests.test_c_migrate_ast_limits`. This strengthens input robustness, not
C/C++ functional equivalence, broad migration or memory-model soundness.
