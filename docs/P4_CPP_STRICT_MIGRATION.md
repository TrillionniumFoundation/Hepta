# P4: Strict C++ L1 source migration using existing C lowering

This additive prototype is stacked on PR #43, preserving the PR #14
`hepta.c_migrate._function` rules as the only C-style scalar
expression/statement lowering authority. It does NOT copy PR #36's
second C-to-Hepta lowerer or claim general C++20 grammar support.

Strict source profile: standalone `.cc`/`.cpp`/`.cxx` files, no
preprocessing, top-level distinct `noexcept int(int...)` functions,
only the C lowering's return/if/scalar expression subset. Clang++20
must accept the entire translation unit with warning errors; unsupported
top-level declarations, defaults, attrs, templates, pointers, classes,
exceptions or overloaded symbols reject all output. The generated
Hepta uses `export "C"` and does NOT preserve original C++ mangling.

Execution: the bounded real differential test compares a Clang++-compiled
original through its explicit C wrapper with the same generated Hepta
through its independent C11 backend on finite C++-defined integer inputs.

The frontend-checked result remains L1 with `native_validation=not_run`,
`cpp_abi_preserved=false`, and
`behavioral_equivalence_proved=false`, even if a separate test happens
to execute successfully. L0 C++ native interop already lives in PR #14
and includes selected stdlib/Boost calls; it is not source migration.
L2 requires checked dynamic memory rules and measured costs.
L3 would require actual complete static memory-safety evidence.
All broad C++ class/RAII/virtual/template/STL migration is still OPEN.

The no-preprocessing boundary is deliberately conservative: after C++
line-ending normalization and backslash-newline splicing, any `#` or `%:`
directive introducer or `_Pragma` operator rejects
(including occurrences inside comments or literals). Clang AST macro
expansion provenance also rejects, including builtin macros such as
`__LINE__` and `__COUNTER__` without source directives. This is not a
preprocessor lexer or a reproducible multi-file build-graph implementation.
