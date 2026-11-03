# Experimental plain-char boundary prototype

This is an isolated design experiment, not a compiler feature. No CLI or default
C/Rust lowering is changed. The existing imported `strlen` compilation failure
is retained as a baseline regression. Do not use a receipt to authorize lowering
or claim that this prototype authenticates a native library.

Run from the repository root:

```sh
python -m unittest experiments.c_char_boundary.test_prototype -v
```

## Profile and trust boundary

`Prepared(entry, cc=..., char_mode=...)` creates a live, temporary preparation
session. It re-loads the project, reads the actual original header, makes a
private copy, re-runs the native importer with a fixed char mode, and compares the
fresh declarations and facts with the imported module. A stored sidecar supplies
identity checks, not authority to reinterpret types. Before and after compilation,
source, project, compiler and private-input identities are rechecked. The AST and
checker result are reconstructed rather than trusting retained mutable objects.
The Python API is not a security boundary against arbitrary code executing in the
same process or hostile replacement of its private internals.

Compilation includes the original header in the final generated translation unit
and asserts native prototypes, typedefs, character representation, alignment and
signedness. TU-local typed adapters call the original C symbols. There are no asm
aliases, incompatible-function casts, suppressed pointer-type diagnostics, or
changes to unrelated i8/u8 APIs. Native fixture implementations use the same
semantic flags; LTO and strict-aliasing executions are available.

The experiment accepts one imported header containing plain-char scalar or
single-level plain-char pointer boundaries. It preserves pointee const. Other
argument/result scalars are allowed only in the existing primitive subset.
Records, arrays, char**, pointer typedefs, volatile/atomic boundaries, variadics,
function pointers, header constants and non-char-only APIs stay outside this
profile. It is qualified only for native Linux GCC on x86_64/AArch64. Only the
local x86_64 execution has happened so far. Char-mode switches are explicit;
arbitrary late compiler/link flags and search-environment overrides are refused.

Dependency paths and hashes are observations after compilation, not an atomic
snapshot of the sysroot/toolchain or proof of unchanged transitive headers.
Same-TU assertions check the declarations actually seen by compilation. They do
not authenticate a precompiled library's implementation, flags, or behavior.
Pointer validity, lifetime, bounds, termination and access permissions, as well
as declared foreign effects, remain the caller's/native implementation's
obligations. No expanded ABI portability claim is made.

## Current evidence

The 29 named cases in `docs/design/C_CHAR_BOUNDARY_CASES.json` map one-to-one to
`test_<id>` methods. A 30th test requires actual Rust and covers libc strlen plus
signed/unsigned scalar extrema against the same GCC-built helper. On the local
GCC 14.2 x86_64 machine, all 29 named tests pass and the Rust test skips because
rustc is unavailable. This is not a completed dual-architecture or Rust result.

Positive tests run real binaries (including O0/O3, UBSan, LTO, strict aliasing,
stdout capture and nm checks). Negative tests check rejection, not success after
suppressing diagnostics. Prototype/typedef/representation and probe-to-final
include drift cases deliberately fault-inject the final C translation unit. The
include-drift fixture has a fixed test-only include path; it changes only a
controlled temporary dependency after a successful compile, not system files or
the prototype's accepted compiler-flag API. These controls establish that the
final assertions are effective, not that this experiment supports arbitrary
include environments or malicious C headers.

See `docs/design/C_CHAR_BOUNDARY_PLAN.md` for the independently reviewed design.
The plan's case file intentionally remains a plan; this README describes the
actual narrower execution evidence without rewriting historical assertions.
