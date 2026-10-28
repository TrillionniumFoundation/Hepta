# C migration entry semantics and captured source invocation

This change selectively integrates the migration fixes from PR #330 and #331
onto the 817713b HIA baseline. It does not replace newer runtime, workflow or
C++ composed-resource implementations with the older parallel branch.

* A function type containing an ABI attribute is refused even when Clang puts
  no separate `Attr` child on its declaration. Actual x86-64 `ms_abi` callers
  demonstrate the original ABI; both strict scalar and project migration refuse
  publication. Attribute-looking comment text remains harmless.
* A pointer parameter must have an unambiguous direct declarator ending at its
  name. Array spelling, including entry-effecting VLA bounds, and macro-ambiguous
  locations reject with `E_C_PARAMETER_DECLARATOR`. Record-view signatures apply
  the same guard before replacing the original pointer type with scalar state.
* Captured preprocessing, dependency discovery and AST extraction replay the
  exact original source operand in its original working directory. This keeps
  `__FILE__`, `__BASE_FILE__` and source-symlink quoted includes consistent.
  Response-file operands remain rejected.
* Optimization, PIC and `-pedantic-errors` driver flags remain ordered semantic
  inputs. C and C++ original-native, HIA interpreter and standalone HIA native
  comparisons exercise their macro and feature-query branches.

## Executed evidence

The focused Clang 20 / Rust 1.90 run executed 75 tests: 73 passed and two array
project tests failed because their captured `-Werror=vla` flag was outside the
existing build-command profile. Those failures are retained in
`hia-migration-next-validation/guards-attempt1.log`. The test databases now use
the supported `-Werror`; the separate original-native VLA examples still execute
with `-Werror=vla` and a source diagnostic pragma at both `-O0` and `-O2`.
All five array/declarator tests then passed with no skips in
`guards-vla-attempt2.log`. This correction reaches the intended semantic guard
without broadening the accepted compiler-flag profile.

The adjacent `guards-summary.json` records file hashes and both attempts. These
are focused local results, not a claim that the combined six-stage HIA branch or
a new target ABI has passed full qualification.
