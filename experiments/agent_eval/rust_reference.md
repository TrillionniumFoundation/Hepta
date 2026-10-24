# Rust evaluation profile

Rust 1.90, edition 2021, standard library only, optimized native static library, overflow checks enabled, panic=abort. The frozen evaluate function is unsafe extern C; pointer access may use *input.add(i) and *output.add(i). Arithmetic that is specified to wrap must use wrapping_add/wrapping_sub/wrapping_mul or an equivalent explicit construction. Do not alter the frozen signature or add external packages. Return one replacement body including braces.
