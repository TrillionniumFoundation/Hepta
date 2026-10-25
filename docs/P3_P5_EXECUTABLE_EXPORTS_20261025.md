# P3/P5: exported native functions must point into executable bytes

Stacked on exact PR #82 head `2f1e290641057c815bbf102cceda5b58d6e547e5`.

## Reproduced acceptance defect

After format/extent checks and exported-name verification, a global
function symbol could still name a non-executable data section, or hold
an out-of-range section-relative value. Same-length edits to five actual
Clang objects preserved accepted file-format and symbol metadata; the
old `_defined_exports` counted functions despite the missing executable
binding. Local prototype accepted all five original functions and rejected
ten forged section/entry-point mutations (3 real local unit tests passed).

## Narrow native proof boundary

ELF64: require global STT_FUNC in a nonempty executable PROGBITS section,
with the symbol value/size inside that section's extent.
COFF: require a function symbol mapped to a nonempty section carrying both
IMAGE_SCN_CNT_CODE and IMAGE_SCN_MEM_EXECUTE, with in-section value.
Mach-O: require external N_SECT symbol whose n_value lies inside a regular
instruction section marked pure/some instructions.

Such native object evidence is stronger than merely finding a symbol name
but still cannot prove machine code's functional behavior, C ABI calling
convention beyond tested scopes, source/LLVM lowering soundness, or
that underlying compilers are trusted. The test recompiles fresh LLVM IR
for all five targets; P0–P7/P01–P12 production blockers remain open.

Reproduce: `python -m unittest tests.test_llvm_ssa_executable_exports -v`.
