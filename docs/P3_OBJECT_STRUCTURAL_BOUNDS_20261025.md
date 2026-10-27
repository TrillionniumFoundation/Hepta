# P3/P5: reject forged cross-target object metadata

Previously `_qualified_header` accepted a matching ELF machine/magic even
if section tables were truncated; a 20-byte COFF prefix declaring one
section also passed its original predicate; and a Mach-O magic/CPU/MH_OBJECT
header could omit all commands. Object-format headers alone must not be
misrepresented as evidence of a valid compiled artifact.

The strict object subset now bounds ELF64 ET_REL section tables and sizes,
COFF header/section count/optional header/symbol-table ranges, and Mach-O
MH_OBJECT command count, command-byte bounds and command alignment. Reject
truncated, inconsistent, wrong-target and unsupported object shapes.

Actual on-host Clang 17 LLVM IR cross-object probe: five genuine objects
accepted (Linux x86_64/ARM64 ELF, Windows x64 COFF, macOS x86_64/arm64
Mach-O); 25 deliberately truncated or forged objects rejected. The raw
host probe is a standalone toolchain/format test, not a Hepta compiler
end-to-end run.

Reproduce: `python -m unittest tests.test_llvm_ssa_object_layout -v`.
These static checks do not prove successful linking, machine behavior,
C/C++ runtime ABI, trusted compiler correctness, pointer/ownership safety,
formal backend refinement, or production platform qualification.
`whole_project_blockers_closed=false`.
