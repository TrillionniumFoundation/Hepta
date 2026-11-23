# Isolated HIA Core INVLPG CPL0 hardware experiment (Draft / HOLD)

This test compiles the *verified typed HIA Core* `x86.tlb.invlpg(u64)`
program through `emit_program_machine` and links its original ELF64 object
into a throwaway 32-bit Multiboot envelope. The original HIA machine text is preserved except for independently
enumerated `R_X86_64_PLT32` linker relocations (checked internal wrapper call
and unreachable abort failure sink). Every other source-derived instruction
byte is compared against the linked ELF64 and QEMU-facing ELF32 wrapper.

The visible **NON-HIA fixture**
`tests/fixtures/hia_kernel_invlpg_qemu_boot.S` supplies the Multiboot entry,
x86-64 mode transition, GDT/IDT, CR0/CR3/CR4/MSR setup, PDE mutation,
exception observation and debug-exit device. These remain implementation
blockers in the HIA language/compiler and are never credited as HIA-native.

## Hardware oracle

On independent PC and Q35 QEMU TCG guest configurations:

1. Warm a supervisor 2 MiB translation at VA 4 MiB.
2. Clear Present on the physical PDE, `mfence`, then *call the linked HIA
   function* with this exact virtual address.
3. Require CPU #PF on a read from that same address, with CR2 exactly 4 MiB,
   saved RIP exactly the read instruction, and P/W/U error bits all clear.
4. Replace the native encoder's INVLPG with a malicious NOP (same verified
   source); it **must not** produce the requested #PF and must exit through
   the normal-read negative-control path. Also invoke the genuine HIA function
   on an unrelated VA, but classify the P/N outcome as **diagnostic only**:
   x86 permits INVLPG to invalidate more TLB entries than one requested VA,
   and QEMU TCG may over-invalidate. Address selectivity is not claimed.
5. Restore the PDE, invalidate its translation again through the genuine HIA
   function, then demand successful read rather than treating any fault as
   proof of success.

The QEMU debug-exit codes are 33/#PF/P, 35/no-fault/N, and 65/restored/R.
Unexpected exceptions, timeouts, missing tools, wrong results, wrong emitted
text, and QEMU TCG that does not discriminate INVLPG from NOP all fail the
experiment. Results are bound to the exact GitHub run's source commit and
HIA canonical-program/object/text hashes.

## Scope and non-claims

This is a test of the experimental Python-authored direct **Core** backend,
**not** the pinned freestanding `.hepta` `selfhost_elf` compiler and not a
freestanding HIA kernel. `privilege` is presently a verifier-checked
declaration, **not** a trusted or unforgeable CPL0 capability. Real CR3
provenance, linearizable page-table ownership, IPI, SMP TLB completion,
device DMA, atomic ordering, protected error return, IRET and Linux ABI
remain open. Neither Hepta `main` nor HeptaKernel's pinned toolchain or
`compatibility/coverage.json` is changed. No physical page release is
authorized by the experiment.

The exact negative-control output is as important as the positive run:
passing only the CPL0 call or accepting any generic #PF does not validate
the TLB invalidation effect. Keep this experiment as a stacked draft until
independent hardware and verifier qualification are complete.
