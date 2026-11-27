# LTR CPL0 execution in the isolated x86 descriptor stage

This is an **unpromoted upstream x86-64 machine-encoder experiment**, not a
HIA Core opcode, verifier-authorized privilege effect, or selfhost_elf native
lowering. It makes the previously NOT_RUN LTR instruction execute in a
single-CPU QEMU CPL0 guest on PC and Q35.

The test-only NON-HIA bridge builds a 104-byte 64-bit TSS in guest RAM and
installs an available, present 16-byte TSS descriptor at GDT selector 0x18.
The exact bytes emitted by `KernelDescriptorCode.ltr("rax")` are 0F 00 D8,
followed by RET. The staged instruction is linked and checked byte-for-byte
in both ELF64 and Multiboot ELF32 containers; GNU assembly never supplies the
LTR instruction under test. The independent guest observer uses STR to read
back selector 0x18 and inspects the hardware-updated descriptor busy bit
(type 0xB rather than the original type 0x9).

The negative control emits RET only at the LTR stage. The full guest otherwise
uses the identical TSS setup and observer; it must terminate through the
pre-existing explicit failure marker F/255 rather than silently pass. All
previous staged LIDT, page-revocation, #PF/#UD, CR4 and race controls remain.

These are QEMU CPL0 results only after exact-head CI reports PASS, not proof
of validated descriptor provenance, CPU ownership, safe RSP0/IST use, nested
TSS execution, SMP safety, or Linux scheduling. The privileged test bridge
remains assembly. The complete HIA kernel profile, effect verifier,
selfhost native privileged emission and whole Linux acceptance stay HOLD.
