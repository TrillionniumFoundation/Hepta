# P3/P5: native cross-object structure qualification

The previous five-target LLVM SSA object gate checked only magic bytes and
the target machine/header type. An object whose payload offsets pointed beyond
EOF could be treated as a valid cross-object qualification receipt.

`hepta.object_structure` now independently bounds: ELF64 section tables
and file-backed section payloads; COFF section tables, raw data, relocation,
line-number and symbol table extents; and Mach-O 64-bit load commands, segment
sections, relocations and symbol/string tables. Zero-fill sections are treated
as runtime storage, not expected file bytes. All objects must be relocatable
objects of the requested CPU; no foreign program is executed.

`compile_ssa_target_object` now requires both proper LLVM scalar source
confinement and bounded native object structure before no-overwrite publish.
`tools/probe_native_object_formats.py` uses the identical payload gate and
cannot report a malformed foreign object as passed.

Real Clang 17 independent local validation verified 5 target formats and
rejected forged offsets and relocations on all formats. The new unit test
repeats corrupt-section checks with direct SSA-generated objects. Those
tests, native target-specific linking, platform ABI and execution are
distinct claims; a valid object structure does not prove an exported function
or satisfy general C++ ABI requirements.

No P0–P7 production phase is declared closed solely by these bounded gates.
