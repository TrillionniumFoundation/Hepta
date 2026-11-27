# Experimental HIA Core x86-64 INVLPG lowering

This isolated stacked draft extends the actual primitive HIA Core verifier,
opcode catalog, and direct x86-64 native emitter with an explicit
`hepta.hia.program.kernel-tlb.v1` schema. The new
`x86.tlb.invlpg(address:u64)` operation requires a `privilege` function
effect. Existing Core v1–v8 schemas and the separate experimental MFENCE
schema refuse the operation and the privilege effect.

The encoder uses a named `Code.invlpg` machine instruction method, never
inline caller-provided machine bytes. Independent GNU as/objcopy checks cover
16 registers times five displacements (80 combinations) including RBP/R13
zero-offset, extended registers and RSP/R12 SIB forms. Native Core object
bytes are compared across separate verified compiles; a malicious NOP
replacement must be detected. The Python Core interpreter explicitly rejects
privileged instruction execution. Never execute generated INVLPG on a normal
Linux host process; it requires an actual CPL0 test guest.

**HOLD**: The privilege effect is a checked *declaration*, not a live CPL0
authority token or proof of page-table ownership or CR3 provenance. This
experimental direct Python-authored Core backend is not the pinned HIA
`.hepta` selfhost_elf compiler and has not executed INVLPG in QEMU. The
firmware, IPI, SMP shootdown, genuine atomic updates, memory ordering
requirements, exception/IRET and full Linux driver/ABI implementation remain
open. Neither Hepta main nor the locked HeptaKernel compiler is changed.
