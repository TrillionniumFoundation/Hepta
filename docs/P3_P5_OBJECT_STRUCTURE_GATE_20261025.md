# P3/P5 — native object structural acceptance beyond a magic header

The previous `_qualified_header` would accept a short, fabricated ELF/COFF or
32-byte Mach-O header when its machine tag matched. This is not an adequate
cross-object acceptance criterion.

`hepta.llvm_ssa_target._qualified_header` now requires relocatable ELF64
(`ET_REL`, full section-header table), zero-optional-header COFF with bounded
section/symbol table extents, or Mach-O 64 `MH_OBJECT` with bounded and
well-formed load-command entries. Wrong endian, architecture, executable
file type, truncated/missing tables and forged header-only objects reject.

The local independent Clang 17 probe in
`/mnt/data/hepta_strict_object_header_probe_20261025.json` (local execution
artifact, not a committed qualification for this HEAD) generated five real
cross-target objects and rejected 25 malformed variants. The integrated
`tests.test_llvm_ssa_target` suite now checks real Clang output plus corrupt
ELF/COFF/Mach-O shapes.

**Scope limits:** Structure acceptance does not verify code section integrity,
all relocations, symbol bindings, target ABI, linkage, physical hardware,
function behavior, or general LLVM backend refinement. The strict LLVM
source-profile gate is a separate P5 input check. Neither closes the full P3
or P5 production blocker.
