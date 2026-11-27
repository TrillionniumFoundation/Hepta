# Kernel privilege instruction encoding: isolated staging slice

This branch introduces three genuine x86-64 instruction-encoding methods in a separate
`KernelCode(Code)` subclass, leaving the original HIA `Code` class completely
unchanged (including its frozen native source AST and independent fixtures):

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
correctness. HIA source-level IRETQ, LIDT, LTR and interrupt entry, MMIO, atomics and all
other Linux acceptance requirements remain open.

CI readback: original `hepta/hia_machine_x64.py` retains its exact upstream
main Git blob. The pinned support-contract *source closure* is extended by the
new `hepta/hia_machine_x64_kernel.py` SHA-256 entry; the strict equality check
against generated `support_contract(root)` remains enforced on every build.
The isolated helper is not a mutation to ordinary Code, and existing
source-retention and native-caller gates
must pass on this candidate. An earlier candidate that modified the original
Code class failed all three frozen AST-retention gates; this revision repairs
the root cause rather than weakening those tests.

The test runner is:

    python -B -m unittest tests.test_hia_x86_kernel_privilege_staging -v

No privileged instructions are executed by this runner.

## Extended encoding-only interrupt/bootstrap slice (staged)

The isolated KernelCode helper now additionally emits LIDT m80 (0F 01 /3),
LTR r/m16 (0F 00 /3), and IRETQ (48 CF), with all 16 integer-register
address or selector forms where applicable. LIDT uses a signed disp32 and an
explicit SIB for RSP/R12. Invalid operands and displacements reject before
emitting bytes, including on an existing nonempty code buffer. Independent
GNU objdump checks and hard-coded expected bytes are in
tests/test_hia_x86_kernel_interrupt_staging.py. The LTR selector consumes the
low 16 bits even where GNU objdump prints the containing GPR as %eax/%r15d.

These are instruction encodings only. In particular, LIDT has no proof that
its operand points to an owned ten-byte IDTR; LTR has no TSS lifetime or busy-bit
proof; IRETQ has no stack-frame construction, canonicality, segment, or
interrupt-effect proof. All require CPL0 integration and HIA native self-hosted
compiler, source-language, and effect-verifier support before boot.S can be
replaced. No instruction is run in host userspace.

Run both isolated test modules with:

    python -B -m unittest tests.test_hia_x86_kernel_privilege_staging tests.test_hia_x86_kernel_interrupt_staging -v

The full cold replay has a fixed 180-second deadline and may fail independently
of the byte-level staging suite; never count a timed-out core job as green.

## Direct encoder atomics/fences slice (additional isolated staging)

The separate KernelCode helper now encodes LOCK CMPXCHG m64,r64,
LOCK XADD m64,r64, MFENCE, LFENCE and SFENCE. LOCK forms use
REX.W/REX.R/REX.B, mandatory ModRM and RSP/R12 SIB with disp32,
covering all integer-register combinations. Invalid operands reject
without partial emission. CMPXCHG uses RAX for the expected value,
sets ZF and returns old memory in RAX on mismatch. XADD returns the old
memory word in its source GPR.

Independent tests check literal machine bytes, GNU objdump decoding,
512 register/method combinations and malformed-input refusal. On
Linux x86-64 they execute only the *nonprivileged* LOCK instructions
in user space, using a W^X RW-to-RX text transition: one stale-expected
CAS negative control and four concurrent threads recording 1000
atomic XADD increments. The host never executes CRx, INVLPG, LIDT,
LTR, or IRETQ.

This remains Python encoder staging, NOT the locked HIA selfhost_elf
compiler, a HIA-source opcode, an effect-verifier extension, verified
SMP linearizability, or MMIO/device ordering. Full kernel integration
requires owned/valid memory lifetime, access/alias/alignment proofs,
cacheability, CPU locality, interrupt and preemption control,
cross-CPU memory ordering and IPI/TLB shootdown. User-space execution
does not replace QEMU kernel-mode hardware acceptance.

Run python -B -m unittest tests.test_hia_x86_kernel_atomic_staging -v

## Explicit CR0/CR2/CR4 and port-I/O byte staging

The isolated Python machine encoder now also offers read/write CR0 and CR4,
read-only CR2, and IN/OUT in 8-, 16- and 32-bit widths. Ports are either
a literal imm8 (0..255) or DX (low 16 bits, selected by the caller); AL/AX/EAX
is implicit. Unknown widths, ports, and registers cannot append partial
instruction bytes. CR2 writes and all unreviewed CR registers are intentionally
excluded. The fixed encoder remains independent of the ordinary HIA Code class.

The independent oracle checks 18 literal encodings with GNU objdump, all
16 GPRs for each permitted CR instruction, the allowed I/O width/port matrix,
and malicious operands against an already nonempty code buffer. These byte
tests do NOT execute any port I/O, write CR0/CR4, or run a kernel in QEMU.
No HIA Core v8 opcode, authority/effect verifier, selfhost_elf emitter,
CPU-feature/mode proof, interrupt-safe sequencing, I/O permission bitmap or
device-resource lifecycle has been implemented by this staged addition.

Run:

    python3 -B -m unittest tests.test_hia_x86_kernel_control_io_staging -v

## Isolated GDTR load encoding (LGDT m80)

The experimental KernelCode.lgdt(base, disp32) adds x86-64 0F 01 /2
using a ten-byte GDTR memory operand. Independent GNU objdump vectors
check RAX/RSP/R12/R13; the existing module checks all 16 GPR bases,
signed displacement bounds, and refusal without partial emission.
Ordinary Code and HIA Core opcode admission still reject x86.lgdt.

This is instruction encoding only, not a source-level HIA opcode,
verifier effect, selfhost_elf backend capability or CPL0 execution test.
GDTR memory ownership, selector lifetimes, canonical bases and interrupt-safe
replacement need separate proofs and QEMU tests. The non-HIA HeptaKernel
boot bridge remains mandatory. All 17 Linux acceptance gates and 422
x86-64 syscall obligations remain HOLD.

## Static TLB/IRQ effect admission experiment (not native HIA)

The separate `experiments/hia_kernel_tlb_effects_staging.py` prototype now
rejects a narrow set of unsafe *planned* single-CPU 4KiB PTE transitions
before any machine-code generation. It requires an exact CPL0/single-CPU,
PCID-off/global-page-off profile; a caller-declared, aligned owned CR3 root;
canonical aligned virtual pages; IRQ masking before a page-table write;
matching complete old-value snapshots; and an address-matched INVLPG before
interrupts can be re-enabled. It refuses duplicate/unbalanced operations,
an unmatched invalidation, cross-address flushes, unknown privilege operations,
unexpected fields, forged integer types and multiple CPUs. A static summary
reports checked effect counts. Independent adversarial tests exercise the
allowed plans and all refusal families. The separate workflow runs them.

**This does not authenticate the CPU state, owner, old PTE or actual runtime
observations.** IRQ masking does not exclude NMI, DMA, a racing host or another
CPU, and even the declared single-CPU environment is not verified. In
particular, this module neither parses HIA Core v8 source nor adds any Core
opcode, integrates the selfhost_elf compiler, creates code, performs a
runtime CAS, loads CR3, invalidates a CPU TLB, or establishes memory safety.
It is a static effect-ordering testbed with explicit assumptions, **not**
a privileged HIA kernel backend, separate interpreter, or a Linux acceptance
closure. The next required step remains translating the reviewed authority
and ordering checks into the actual HIA verifier and locked selfhost native
compiler, with QEMU negative controls and independent machine-code provenance.

## Same-page plan dataflow (isolated staging refinement)

Within one admitted sequence, a second 4 KiB PTE write to the same virtual
page must take the **previous candidate** as its entire expected and observed
old word. Even after a matching INVLPG and balanced IRQ mask interval, an
older expected value is rejected. Tests exercise valid chains, interleaved
pages, stale replay and attempts to relabel a stale observation. This checks
only *internal planned dataflow*; it does not authenticate CPU readback,
hardware-updated Accessed/Dirty bits, page-table ownership, NMI/reentrant
interrupt behavior, or another CPU. A legitimate hardware A/D change between
writes needs a separately modeled observation transition rather than bypassing
the equality guard. No privileged HIA source operation or backend is added.

## Staged SYSCALL/SYSRETQ, SMAP AC and HLT encodings (dependent draft)

The isolated `KernelCode` byte encoder now emits x86-64 `SYSCALL` (`0f05`),
**64-bit** `SYSRETQ` (`48 0f07`, including the mandatory REX.W),
`STAC` (`0f01cb`), `CLAC` (`0f01ca`) and `HLT` (`f4`).
Literal expected bytes, full instruction boundaries and GNU objdump
disassembly are independently tested. A non-partial-emission test checks
invalid call shapes; ordinary `Code` and Core v8 opcode admission remain
unchanged, and the kernel helper's SHA-256 is bound to the existing source
closure manifest. **No privileged bytes are executed on the host.**

This is **not** HIA grammar, authority/effect checking, the native
selfhost_elf backend or a guest syscall/interrupt implementation.
Before any kernel use, require validated IA32_EFER.SCE, STAR/LSTAR/FMASK,
kernel entry-stack and GS/MSR contracts; on return prove canonical user
RCX, sanitized R11/RFLAGS, segment selectors, user RSP, balanced SMAP AC
state, exception unwind/interrupt windows and context ownership.
`HLT` additionally requires CPL0 and a defined wakeup policy. Keep the
HeptaKernel compiler lock unchanged and all 17 Linux gates HOLD.


## Physical PTE slot identity in the static effect-order experiment

The isolated single-CPU TLB sequence checker now requires an exact nonzero,
8-byte-aligned, below-52-bit physical PTE slot address (slot_pa) on each
pte.write operation. Within one planned sequence it binds each virtual page
to one declared physical slot and each physical slot to one virtual page.
After INVLPG and interrupt re-enablement, that identity must still agree,
and a repeat write must use the prior candidate as its expected old word.
A plan may update multiple independent slots, but it cannot conceal a stale
PTE write by relabeling a physical slot as another VA. Negative tests cover
aliases, changes of slot identity, forged stale readback, missing/malformed
slot fields and repeated valid writes.

This is deliberately *not* physical slot authentication, a page-table walk,
authority proof, true hardware old-value readback, or a native HIA compiler
intrinsic. The declared slot and root remain caller-supplied; the checker
does not establish that RAM owns the slot, that interrupts/preemption/NMIs
are safe, or that one-CPU TLB effects generalize to PCID, global pages and
SMP. All staged privilege byte encoders remain isolated from HIA Core v8,
the freestanding selfhost_elf compiler, and HeptaKernel's pinned toolchain.
