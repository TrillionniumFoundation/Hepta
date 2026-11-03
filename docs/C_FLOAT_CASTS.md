# Independent C backend: numeric float casts

The frontend and Rust backend already admit numeric casts. The independent
C backend now also lowers `f32` and `f64` into `i8/u8/i16/u16/i32/u32/i64/u64`
and `isize/usize`, removing a concrete backend coverage gap for numeric input
conversion. The extension below also admits integer-to-float and cross-width
float conversion.

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

Run `python -m unittest tests.test_c_float_casts tests.test_c_float_conversions tests.test_c_backend -v`.

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
runs these modules on Linux x86-64 and AArch64 GCC hosts with its already-pinned
Rust 1.90.0. It requires all 21 tests without skips and retains compiler identity
and test logs. Other host profiles are unchanged.

Local development validation on Linux x86-64 / GCC 14.2.0 passed 14 tests;
the separate real-Rust reference test was skipped because rustc was absent.
Remote results must be read for the exact published source before claiming
Rust differential or AArch64 qualification. Existing C-backend test helpers
also make their Rust comparison conditional locally. No performance advantage,
whole-language refinement, full P0–P7 closure, or production authority is claimed.

## Integer-to-float and float-width extension

All ten integer types can now convert to either floating type, and `f32`/`f64`
can convert in either direction: 22 newly supported pairs. Same-type casts stay
unchanged. This follows the [Rust numeric cast semantics](https://doc.rust-lang.org/reference/expressions/operator-expr.html#numeric-cast):
nearest rounding with ties to even; widening preserves each finite value;
narrowing overflow produces signed infinity; zero signs are retained. NaNs
remain NaNs; payload preservation and floating exception flags are not promised.

The helpers use **integer arithmetic only**, not a native floating cast or an
intermediate `double`. Integer magnitude is formed without signed overflow,
including the most negative signed value. Floating inputs are copied with
`memcpy` into their integer representations, then decoded into an exact signed
significand times a power of two. One quotient/remainder rounding step constructs
the destination bits, including subnormal/normal and finite/infinite boundaries.
This avoids double rounding. NaNs become signed quiet NaNs without performing
floating arithmetic on the signaling input. `memcpy` also avoids aliasing UB.

The new helpers refuse compilation unless IEC 60559 is advertised, integer and
floating word order are defined and equal, binary32/binary64 parameters and
subnormals are present, and fast-math is absent. These are qualified object-
representation assumptions, not a claim about every C11 implementation. Actual
GCC Linux x86-64 and AArch64 execution is required by the hosted gate.

Because conversion arithmetic is integer-only, it does not rely on the process
rounding mode or flush-to-zero setting. Native controls run the same corpus at
O0 and O3 under all four `fesetround` modes, and on x86-64 additionally enable
SSE flush-to-zero and denormals-are-zero. These controls check conversion itself,
not the floating arithmetic that may have produced its operand. Other foreign
ABI behavior, exotic layouts, non-default trapping environments, arithmetic
semantics, and floating exception flags remain outside this extension.

The new corpus has 10,148 input records and 17,972 expected conversions. It
includes exhaustive i8/u8 values, wider signed/unsigned boundaries, integer
precision transitions and adversarial double-rounding midpoints, seeded random values, exact binary32 midpoints and
their binary64 neighbours (including zero/subnormal/overflow), both zero signs,
infinities, and quiet/signaling NaNs. Expected destination bits come from a
separate Python exact-rational oracle; NaN results are checked by classification.
Known tie/overflow/zero oracle constants are checked independently. A Rust
runner applies ordinary casts to the same corpus at its default environment.
Effectful operands and short-circuiting are checked, and fast-math/unknown
representation compilation must reject.

Local development uses GCC 14.2.0 on Linux x86-64. Its sixteen combinations of
optimization, rounding and SSE flush modes check 287,552 conversion results.
Rust is unavailable locally, so neither the real Rust reference nor AArch64
is claimed until the exact-head hosted job runs. No performance improvement,
general backend refinement, or production qualification is inferred.
