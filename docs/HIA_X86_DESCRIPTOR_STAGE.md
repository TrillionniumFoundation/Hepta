# Isolated x86-64 LIDT/LTR descriptor-loading stage

This experiment is **not** an HIA language or native self-hosted privilege backend.
It is stacked on the staged privileged encoder/atomic PTE QEMU work, without
changing upstream Hepta \`main\` or the locked HeptaKernel toolchain.

## Implemented machine encodings

\`KernelDescriptorCode(PrivilegedCode)\` adds direct x86-64 \`LIDT m16&64\`
and \`LTR r/m16\` register-form encodings. These are true x86 machine bytes:
the production path never invokes an assembler or embeds a precompiled blob.
The typed caller supplies the GPR address of a 10-byte GDTR-style IDT pointer
for LIDT; the CPU itself validates IDT and LTR targets. The encoder does not
prove the IDT/TSS descriptor is valid, the memory owner is unique, CPL0, or
interrupt/preemption quiescence.

\`tests/test_hia_x86_kernel_descriptor.py\` uses independent GNU as, objcopy,
and objdump to compare all 16 base-register classes, 11 signed displacement
boundaries, and all 16 LTR register operands (192 complete encodings).
Malformed or nonscalar operands must refuse before emitting any byte.
Existing ordinary HIA \`Code\`, \`PrivilegedCode\`, and the official Core v8
opcode/effect catalog remain unchanged.

## Hardware oracle

\`tests/x86_privileged_qemu/run_hardware.py\` binds the generated exact LIDT
bytes \`41 0f 01 1a\` and RET \`c3\` to the final linked PC/Q35 Multiboot
guest. The non-HIA setup provides the IDT pointer in R10; the generated
LIDT changes the hardware IDTR. Independent \`SIDT\` captures and compares
the actual hardware IDTR limit and base immediately after the call.
The real #PF/#UD/#DB observations from the already frozen PTE-revoke stage
must continue to work. A separately generated RET-only malicious descriptor
loader must be detected by the same SIDT observer and exit via the failure
path. No successful case may treat a skipped load as evidence of LIDT.

\`LTR\` presently has an exact ISA byte oracle only: **hardware execution
NOT_RUN**. The QEMU harness still contains non-HIA assembly for Multiboot
entry, page tables, GDT, fault entry, SIDT, IRETQ, port I/O, and related
observation. HIA Core \`privilege\` and \`atomic\` effects, verified descriptor
ownership, selfhost_elf lowering, SMP, Linux ABI, drivers and all 17 full
acceptance gates remain **HOLD**. The fixed 422 syscall rows are unchanged.

Do not merge this staged code into upstream main or change HeptaKernel's
toolchain lock on the basis of a byte oracle or isolated QEMU success.
