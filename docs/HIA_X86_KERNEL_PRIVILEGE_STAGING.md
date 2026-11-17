# Kernel privilege instruction encoding: isolated staging slice

This branch introduces three genuine x86-64 instruction-encoding methods on
the existing direct machine-code backend's Code object:

- read_cr3(dst) encodes MOV r64, CR3 (0F 20 /3)
- write_cr3(src) encodes MOV CR3, r64 (0F 22 /3)
- invlpg(base, disp) encodes INVLPG m8 (0F 01 /7) with an explicit
  64-bit base and checked signed disp32; RSP/R12 require the SIB byte

Every accepted register is a full-width x86-64 GPR, including R8–R15;
unrecognized registers and out-of-range displacements reject without
emitting a partial instruction. The new test suite checks exact independent
instruction vectors, all 16 register classes, invalid-operand atomic refusal,
and actual GNU objdump decoding. It **never executes** these instructions
in a host user process.

## Scope and upstream integration required

This is a **machine encoder slice**, not a new HIA Core opcode and not
the native self-hosted selfhost_elf compiler. There is deliberately no
HIA assembly syntax exposing these methods yet. The current pinned
selfhost_elf binary and the HeptaKernel toolchain lock are **unchanged**.
This patch is isolated on its own branch and must not be advertised as HIA
kernel-privilege support or merged downstream as if it completed that gate.

Before integration, the upstream HIA language and verifier need an explicit
kernel authority/profile for each privileged operation. The verifier must
track permission to read/write CR3, frame and interrupt-context constraints,
page-table ownership, TLB invalidation/ordering, a CPU-locality or shootdown
protocol, and effect order across calls. The self-hosted machine encoder,
its source-identity contract, and independent reference semantics must then
implement those admitted operations. A direct Python Code call is **not**
a substitute for this path.

The next hardware oracle is a QEMU-only CPL0 fixture: check CR3 readback
against the CPU, demonstrate a controlled CR3 change and matching TLB
behavior with an independent fault witness, and reject unauthorized,
misordered or stale mappings. QEMU pass does not establish SMP shootdown
correctness. IRETQ, LIDT, LTR, interrupt entry, MMIO, atomics and all
other Linux acceptance requirements remain open.

The test runner is:

    python -B -m unittest tests.test_hia_x86_kernel_privilege_staging -v

No privileged instructions are executed by this runner.
