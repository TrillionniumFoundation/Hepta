# Fail closed on unlowered C calling conventions

This repair is stacked on PR #10, commit
`d40f9b75ee6bbf4ce2d9634b3f28da6231f6cd80`.

## Reproduced ABI defect

Clang can store a function's calling convention in `type.qualType` without an
attribute child. For example, the Clang 19 AST for an `ms_abi` function contains
`int (int) __attribute__((ms_abi))`, but its children are just a parameter and
compound body. The migrator previously checked only attribute children and
silently emitted the default `export "C"` convention.

On the recorded x86_64 Linux host, an independent compile-only comparison of an
identity function found that the original `ms_abi` C function reads `%ecx`, while
the actual generated Hepta C-backend function reads `%edi`. These are different
argument registers. No calls across the mismatched ABI were executed.

Four actual Clang regression inputs (`ms_abi`, `vectorcall`, `preserve_most`, and
`preserve_all`) were incorrectly accepted before the repair, each with a distinct
output path. The input also contains an ordinary function, checking that a
rejected convention prevents publication of any partial conversion.

## Minimal repair

Before parsing the return type, require a plain function type shape with one
unadorned parenthesized parameter list. Type-level ABI attributes and other
unlowered decorations fail with `E_C_ATTRIBUTE`, independent of attribute-child
representation and without a fixed convention-name blacklist. Existing checks
for storage, inline/implicit declarations, variadics, parameter types and
attribute children remain intact. Plain scalar and `(void)` definitions retain
positive coverage.

This rejects unsupported conventions rather than implementing ABI adapters.
No new calling-convention, cross-platform or translation-equivalence guarantee
is claimed. PR #4's top-level declaration/atomic-output work and PR #8/#11's IR
work are separate and not replaced by this change.

## Local validation

- Baseline regression: all four convention inputs were accepted (the intended
  rejection assertions failed); after the repair all are rejected without output.
- Focused migration suite: 10 tests passed; full suite: 438 tests passed, no skips,
  using Python 3.12.14, Clang 19.1.7 and the pinned Rust 1.90.0 on x86_64 Linux.
- Independent review: 12 additional convention/placement/prototype-inheritance
  cases rejected without output; 10 ordinary integer signatures still accepted.
- `git diff --check` passed. No remote CI was consulted. PR #10's separate
  13-component evidence remains intact and was not rerun or claimed for this head.

These tests establish a conservative rejection boundary, not support for the
rejected calling conventions or proof of arbitrary C translation equivalence.
