# P3/P5: Mach-O target object profile for LLVM SSA (2026-10-25)

Extends the exact supported target object whitelist from three to five:
`x86_64-unknown-linux-gnu` (ELF64 EM_X86_64),
`aarch64-unknown-linux-gnu` (ELF64 EM_AARCH64),
`x86_64-pc-windows-msvc` (COFF AMD64),
`x86_64-apple-darwin` (Mach-O 64 x86_64 CPU), and
`aarch64-apple-darwin` (Mach-O 64 ARM64 CPU).

`hepta.llvm_ssa_target._qualified_header` rejects the wrong byte order,
truncated object, wrong CPU type and non-MH_OBJECT file type for Mach-O.
Existing leaf symlink/no-replace safety remains unchanged.

An independent local Clang 17 probe successfully emitted the Mach-O targets
using `clang -target TARGET -x ir -O3 -c fixture.ll -o out.o`.
Observed Mach-O magic bytes were `cf fa ed fe`, CPU values 0x01000007
and 0x0100000c, and filetype 1 (MH_OBJECT). This local compiler probe is
not the integrated Hepta SSA runtime qualification: the corresponding
native source/LLVM object suite must run against its exact source HEAD.

**Production P3 remains open**: cross-object headers do not establish
runtime ABI, Clang/libc++/Apple linker compatibility, bidirectional calls,
physical hardware, exception unwinding, or macOS execution.

Reproduce: `python -m unittest tests.test_llvm_ssa_target -v`.

## Independently reproducible host toolchain probe

Run `python tools/probe_native_object_formats.py --output /tmp/probe.json`
on a host with an LLVM-capable Clang. The tool runs five real object
compilations, records the source fixture and compiler hashes, preserves
compiler stderr and output hashes, checks exact object headers, and
returns a nonzero exit status when any target fails. It never runs
cross-target code and cannot qualify the Hepta compiler backend.
The local five-target Clang 17 receipt is retained in
`evidence/target_object_format_probe_20261025.json` as limited host evidence.
Object binary hashes are host/Clang-version dependent, not release promises.
