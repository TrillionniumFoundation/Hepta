# Locked PTE revoke: isolated x86-64 stage (HOLD)

This draft adds **genuine x86-64 LOCK CMPXCHGQ bytes** to the existing
`PrivilegedCode` encoder, which remains deliberately distinct from ordinary
`Code`. It replaces an unprotected load/compare/store in the staged
single-CPU PTE Present-bit revoke with an aligned, locked 64-bit
compare-exchange and a required ZF success check before local INVLPG.

The entry sequence reads the current CR3, rejects a wrong root, samples the
old PTE, and then uses RAX as the expected-old value and RDX as replacement.
The *final* memory comparison and update are performed by the CPU as a
single locked read-modify-write operation. A mismatch must take the UD2
failure path rather than invalidate an unrelated virtual translation.
No byte injection into HIA Core or `selfhost_elf` is involved.

The independent GNU-as oracle tests 770 source/address/disp combinations,
including REX extension bits, RSP/R12 SIB, RBP/R13 displacement cases,
signed displacement boundaries and malformed operands. A separate unprivileged x86-64 Linux hardware oracle executes generated
LOCK CMPXCHGQ on actual RAM and checks both successful replacement/ZF=1
and deterministic stale-value refusal/ZF=0. It runs NO CRx, INVLPG or other
privileged instructions on the host. The complete guarded operation is
independently assembled and byte-compared, including three conditional
rejection branches. PC and Q35 QEMU execute its *exact
staged bytes* and independently check the real PTE and non-present #PF,
wrong-CR3, stale-old and dishonest RET-only controls. Each image/source
SHA and each unrun, timed-out or failed case remains separately recorded.

**No HIA Core `atomic` or `privilege` effect has been added.** This is
a host-side isolated *staging encoder*, not source-level HIA, not a
standalone Linux kernel and not a new verified memory model. LOCK on one
PTE does not atomically cover CR3 checks, authority assertions, physical
page ownership, CPU caches/TLBs, DMA/IOMMU, or multiple CPUs. The static
record still merely asserts exclusive single-CPU ownership and correct
identity mapping; no hardware-verifiable capability proves these facts.
The QEMU harness uses a non-HIA Multiboot, paging and IDT bridge.

Future closure requires an authenticated HIA atomic memory effect with
provenance, verifier ownership/ordering rules, official selfhost lowering,
CPU/feature checking, stable ABI, and independent SMP/interleaving/fault
oracles. It also requires shootdown and IOMMU coordination before page
recycling. Full HeptaKernel 17-gate acceptance and the Linux syscall/driver
obligations remain **HOLD**, even if all stage tests are green.
