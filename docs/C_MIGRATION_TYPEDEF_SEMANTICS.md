# Resolve supported typedefs from Clang, not names

This repair is stacked on PR #12, commit
`f47508f5700c7595ff167c6c7ddf5458bc445a41`.

## Defined-input semantic defect

A project header may legally declare `typedef signed int uint32_t;` without
including the standard typedef of that name. The strict scalar migrator used
the identifier's spelling to choose `u32`, even though Clang reports the actual
underlying type as `int`. A function testing `x < 0` therefore changed behavior.

A regression compiles and executes two separate complete C programs: the
original input and the actual Hepta C-backend output. Each caller sees its own
real function prototype. For `probe(-1)`, the original returns 1 and the broken
migration returned 0. Conversion of -1 to unsigned in the broken program is
well-defined; no incompatible function-pointer or foreign-ABI call is used.
After repair both programs return 1.

The baseline also rejected a valid 64-bit return-only alias chain because it
mistook `int32_t` for `i32`, and incorrectly accepted aliases to unsupported
`short` and `const int` types. These regressions were captured before repair.

## Narrow repair

Keep the existing four supported stdint-style alias names; do not add arbitrary
user-defined type support. Resolve those aliases from `TypedefDecl` nodes in the
exact Clang translation unit, including headers. Use `desugaredQualType` when
present, otherwise the declaration's direct `qualType`. The result must be one
of the existing supported unqualified builtin integer types, with the existing
target data-model checks. Missing, qualified, pointer and other unsupported
types fail closed rather than reverting to name-based width or signedness.

Function type strings retain alias spellings even when parameter/expression
nodes carry desugared types. Using the same resolution for all `_typ` calls
therefore covers return-only aliases as well as parameters and comparisons.
The original C alias names do not imply standard widths; the actual underlying
C types determine the output types.

PR #4's separate main-file top-level declaration restrictions do not cover this
included-header case. This change does not merge or replace that work. No IR or
calling-convention lowering is changed, and no general C equivalence proof is
claimed.

The helper is also used by the independent C++ bridge. Canonical resolution is
explicitly scoped to the C migration context; that bridge's existing path is
unchanged and is not claimed repaired here. An initial full-suite run caught
three bridge regressions from changing the shared helper globally. The scoped
repair restored all six existing bridge tests before rerunning the full suite.

## Local validation

- Four new tests captured five failing assertions before repair, including the
  defined-input native result mismatch; all four now pass.
- Focused C migration suite: 14 passed. C++ bridge regression suite: 6 passed.
- Final full suite: 442 passed, zero skips, in 35.497 seconds using Python
  3.12.14, Clang 19.1.7, GCC 14.2 and the pinned Rust 1.90.0 on x86_64 Linux.
- `git diff --check` passed. No remote CI was queried; no release-wide or
  cross-target qualification is claimed for this source change.
- Independent review found no blocking issue: 48 additional supported
  alias/builtin/direct-or-chain cases checked parameter and return-only types;
  20 unsupported alias cases rejected without output; 12 missing or unresolved
  canonical-map cases failed closed. The four new tests also passed independently.
