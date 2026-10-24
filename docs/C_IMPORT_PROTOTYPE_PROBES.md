# Native C prototype presence and compatibility gate

This repair is stacked on PR #7, commit
`ba3758025a9e267885ed482f86cca778dbce09d0`.

## Reproduced defect

The subset parser recognizes include-guard syntax but does not evaluate the
compiler's predefined macros or the guards of preincluded system headers.
Its native probe previously measured primitive types and record layouts without
checking that every parsed function actually existed with the parsed prototype.

Three negative cases were accepted before this change:

1. A declaration inside `#ifndef __STDC__` was emitted as an imported function,
   although GCC excluded the declaration.
2. The same excluded declaration named `main` could appear satisfied by the
   probe's own function if validation were placed after that function.
3. A declaration of `int remove(int)` inside the stdio include guard was parsed
   while the real compiler saw stdio's `int remove(const char *)` instead.
   Merely checking symbol existence would not catch this ABI mismatch.

No incorrectly typed foreign calls were executed while demonstrating failures.

## Minimal change

Before introducing its own `main`, the native probe now emits a static type
compatibility assertion for every parsed function's address and original
prototype. Missing symbols and incompatible prototypes therefore fail the
native compilation before any generated binding can be returned.

This uses GCC-compatible `__typeof__` and `__builtin_types_compatible_p`, consistent
with the existing GCC-native probe contract. It is not MSVC support, a complete
preprocessor/parser, cross-target ABI qualification, or proof of foreign safety.
Empty headers, layout-only headers, struct-valued functions, pointer returns,
and unnamed parameters retain positive coverage.

## Release-gate distinction

The complete unit/integration suite is only one of the 13 release checks.
The remaining checks are five executable examples (parser, ownership, tasks,
results, locked package), bounded concurrency, ABI matrix, native/performance,
representative performance, Lean formal core, AArch64 execution, and agent
fixture qualification. Passing unit tests does not close the other gates.

A separate local ABI matrix run against the frozen PR #7 compiler sources passed
on x86_64 Linux using GCC 14.2 and Rust 1.90.0: 36 aggregate shapes, 12 scalar
types, and 12 pointer shapes; each of three executions (`-O0`, `-O2`, and `-O2`
with layout observation) passed 181 foreign calls. This is a finite host-only
run, not evidence for other targets or the entire release pipeline.

## Verification for this repair

- Three regression negatives failed before the change and passed afterward.
- Focused importer suite: 13 passed.
- Complete local native unit/integration suite: 431 passed, zero skips, 33.711s,
  using Python 3.12.14, real pinned Rust 1.90.0, GCC 14.2 and Clang 19.1.7.
- Independent review: no blocking findings; new five-test suite plus the prior
  108-case pointer/typedef static compatibility matrix passed.
- `git diff --check`: passed.

The assertion establishes visible declaration compatibility, not that a linked
foreign implementation exists or is correct. Remote CI was not inspected;
full release and production safety criteria remain open.
