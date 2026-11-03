# Independent C backend: saturating float-to-integer casts

The frontend and Rust backend already admit numeric casts. The independent
C backend now also lowers `f32` and `f64` into `i8/u8/i16/u16/i32/u32/i64/u64`
and `isize/usize`, removing a concrete backend coverage gap for numeric input
conversion. This does not enable integer-to-float or cross-width float casts.

## Semantics and bounds

The behavior follows the [Rust Reference float-as-int rules](https://doc.rust-lang.org/reference/expressions/operator-expr.html#r-expr.as.numeric.float-as-int):
finite values truncate toward zero, NaNs become zero, and out-of-range values
including infinities saturate to the destination limits. Negative unsigned
inputs become zero. The cast operand is evaluated once in the existing ordered
expression lowering, including when it appears under short-circuit operators.

Each helper checks NaN and exact binary powers of two before the C cast. It
does not compare against a floating conversion of `INT64_MAX` or `UINT64_MAX`,
which would round to an out-of-range value. The remaining cast has a finite,
representable truncated result. Signed and unsigned bounds are handled
separately; integer cast/wrapping behavior is unchanged.

The generated source statically requires radix two, binary32/binary64 precision
and exponent ranges, 4/8-byte float/double storage, and the existing 64-bit
pointer data model. This is not qualification of exotic floating formats,
non-default trapping environments, or compiler options such as fast-math.
No floating exception/trap policy is added. Signaling NaNs are tested under the
host's ordinary non-trapping environment; their payload preservation is not a
language claim.

## Reproduction

Run `python -m unittest tests.test_c_float_casts tests.test_c_backend -v`.

The new native corpus has 642 exact floating bit patterns across both widths,
including zero signs, subnormals, positive and negative quiet/signaling NaNs,
infinities, immediate bit neighbours of integer saturation boundaries, and
512 seeded random patterns. Each is converted to all ten integer types under
GCC at both O0 and O3: 12,840 checked outputs. Both undefined-behavior and explicit
float-cast-overflow sanitizers are enabled. Expected results use Python's exact
integer bounds and truncation independently of the C helper implementation.
A second control confirms effectful operands execute once and preserve short
circuiting.

A real Rust reference runner applies ordinary Rust casts to exactly the same
bit-pattern corpus and checks the same oracle. The existing native-host workflow
runs both modules on Linux x86-64 and AArch64 GCC hosts with its already-pinned
Rust 1.90.0. It requires all 15 tests without skips and retains compiler identity
and test logs. Other host profiles are unchanged.

Local development validation on Linux x86-64 / GCC 14.2.0 passed 14 tests;
the separate real-Rust reference test was skipped because rustc was absent.
Remote results must be read for the exact published source before claiming
Rust differential or AArch64 qualification. Existing C-backend test helpers
also make their Rust comparison conditional locally. No performance advantage,
whole-language refinement, full P0–P7 closure, or production authority is claimed.
