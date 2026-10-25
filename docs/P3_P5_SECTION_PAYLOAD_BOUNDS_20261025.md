# P3/P5: bounded object section payloads, relocations and symbols

Base: PR #75 `6535326dbd84e9936716c8a8597d0e882299772d`,
which already contains PR #72's structural object-header checks.

## Reproduced defect

An object may have complete ELF/COFF/Mach-O headers while referencing section
contents located **outside the object file**. The old `_qualified_header`
accepted all five such tampered, originally Clang-generated target objects:
ELF x86_64 / AArch64, COFF Windows x64, and Mach-O macOS x86_64 / arm64.
COFF relocation and Mach-O symbol-table offsets also went unchecked.

## Narrow fix

Without changing target selection or native LLVM codegen, validate actual
ELF section-file extents (allow SHT_NOBITS); COFF raw section, relocation and
line table extents; Mach-O LC_SEGMENT_64 section/file extents, relocation
and LC_SYMTAB bounds (allow known zero-fill types). Reject unknown formats.
Keep existing magic/CPU/MH_OBJECT and full section/load-command checks.

## Execution and limitations

Local standalone Python 3.13 + actual Clang object samples: five valid
objects accepted; out-of-file forged section offsets rejected across all
five targets; additional malformed COFF relocation and Mach-O symbol records
also rejected (4 unittest tests passed against local prototype).
Committable native Hepta test in `tests/test_llvm_ssa_section_payloads.py`
recompiles fresh Clang IR objects on the validating host.

This is **format-boundedness evidence**, NOT source-to-object refinement,
external C/C++ ABI qualification, linker success, device execution, program
memory safety or proof of object semantics. Whole-project blockers remain open.
