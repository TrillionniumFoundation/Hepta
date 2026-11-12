# Original stb_divide v0.93 before its upstream overflow fix

`stb_divide.h` is the complete unchanged file at upstream commit
`dcb1116f1351bc8edad059d9ca432e8f322ba922`. Its subsequent direct child
`c38ec91d229cbe56167f8af865c05b3d92db705f` fixes integer-overflow defects.
The established v0.94 fixture remains in `../stb_divide/` with its original
provenance. Both license alternatives remain embedded in this historical header.

The new maintenance qualification explicitly selects the truncating-C macro
configuration. It migrates all six active functions through the existing C
project frontend and HIA Core/VM/direct-LLVM paths. In this configuration,
`stb_div_floor` and `stb_mod_eucl` have changed active bodies. Other macro
configurations and the disabled built-in test harness are not counted as active
translated declarations.

This old implementation has real signed-overflow cases. They are retained as
UBSan failures and checked-HIA traps, separately from the common defined-input
matrix. Correct successor observations do not make old undefined behavior a
cross-version equivalence success. The fixture is historical input, not a
recommended unchecked implementation.
