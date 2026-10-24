# C import typedef ABI regression repair

This bounded fix is stacked on the canonical pilot commit
`b38a9f73ad28f44a44c11666ac2f9a006106f842` (PR #1). It does not replace
the C migration work in PR #4/#5 or the C++ bridge/CFG work in PR #3.

## Defects and changes

- C struct tags and ordinary typedef names occupy separate namespaces.
  `typedef int Token; struct Token { double x; }; Token inspect(Token);`
  previously emitted a struct-valued ABI instead of `int(int)`.
  Only actual struct typedefs now resolve as bare struct type names; explicit
  `struct Tag` references continue to resolve through the tag table.
- Typedef expansion discarded top-level `const`. For example,
  `typedef const int Value; int inspect(Value *);` became a mutable pointer.
  Qualified declaration resolution now retains top-level const until the next
  pointer layer consumes it. This also preserves const pointer typedefs and
  chained aliases without moving the qualifier to the wrong pointer layer.

The public parser declaration return shape remains unchanged. This is not a
complete C parser, ownership inference, foreign-memory safety proof, or general
C/C++ translation correctness claim.

## Regression evidence

Before the fix, the focused tests exposed six failing subcases: two declaration
orders of the tag/typedef collision, three scalar const alias forms, and one
const pointer alias. The generated original ABI was **not invoked**. GCC first
checked the real C signature with `__builtin_types_compatible_p`.

After the fix, the regression suite checks:

- both declaration orders, explicit struct tag references, and distinct struct
  typedef aliases;
- eight scalar/pointer/const/chained alias combinations;
- generated C prototypes against the original declarations in the same GCC
  translation unit;
- an actual scalar typedef binding linked to the original C function through
  the independent Hepta C backend, with sanitization enabled.

An independent review additionally checked 108 qualified pointer/alias
combinations with GCC syntax/type compatibility and found no blocking defect.

## Local verification (2026-10-24)

- Python 3.12.14; GCC 14.2.0; Debian Clang/Clang++ 19.1.7.
- Real Rust 1.90.0, commit `1159e78c4747b02ef996e55082b704c09b970588`;
  host compiler and standard library installed using the repository's official
  SHA-256-locked bootstrap. No alternate Rust version was substituted.
- `python -m unittest discover -s tests -p 'test_c_import*.py' -v`:
  **8 passed**.
- `python -m unittest discover -s tests -v`: **426 passed, zero skips**,
  33.351 seconds, after installing the missing local native tools.
- `git diff --check`: passed.

Earlier environment-only attempts failed the 13 Clang/Clang++ setup assertions
and skipped 23 tests whose availability checks use the documented sibling
`toolchains/rust-1.90.0` path. Those are superseded by the complete run above;
no tests or mandatory assertions were weakened to obtain the pass.

Remote CI was not queried. The 13-gate release runner, cross-target/physical
hardware qualification, and all P01–P12 production closure criteria remain
separate and are **not claimed completed** by this host test run.
