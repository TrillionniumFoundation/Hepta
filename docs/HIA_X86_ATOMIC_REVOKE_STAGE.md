# Locked PTE revoke: isolated x86-64 stage (HOLD)

This draft adds **genuine x86-64 LOCK CMPXCHGQ bytes** to the existing
`PrivilegedCode` encoder, which remains deliberately distinct from ordinary
`Code`. It replaces an unprotected load/compare/store in the staged
single-CPU PTE Present-bit revoke with an aligned, locked 64-bit
compare-exchange and a required ZF success check before local INVLPG.

The entry sequence first reads the CPU's **actual CR4** and rejects any set
PGE (bit 7), LA57 (bit 12), or PCIDE (bit 17), before reading CR3 or
accessing the PTE. This moves three previously caller-asserted paging-mode
exclusions into runtime machine-code checks; the remaining owner/quiescence
assertions are still untrusted. The isolated PC/Q35 hardware oracle also
enables CR4.PGE in a negative-control image while leaving the PTE intact,
and requires original UD2 rejection with an unchanged PTE. The CR4 guard
does not authenticate single-CPU ownership, DMA quiescence or shootdown.

The sequence then reads the current CR3, rejects a wrong root, samples the
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
independently assembled and byte-compared, including four conditional
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

## Deterministic post-precheck CAS interleaving (isolated test bridge)

The PC/Q35 hardware oracle now includes a `postcheck_race` scenario. It
executes **exactly the same staged machine-code bytes** as `valid`. A
non-HIA, test-only #DB single-step observer sets TF and pauses at the original
LOCK CMPXCHGQ instruction address (independently matched to the GNU-as opcode
signature). Only after the live PTE was sampled and compared does the observer
write a competing PTE value `0x400023`. It saves/restores RAX and RDX, records
that the injection actually occurred, clears TF in the saved exception frame,
and returns via IRETQ. The native locked CAS must fail, branch to its original
UD2 instruction, and preserve the competing value. The independent #UD
observer checks both the unchanged competing word and the injection marker.
The original valid, stale-old, wrong-CR3 and dishonest RET-only cases remain.

This is a **deterministic single-CPU interleaving**, not SMP or DMA testing.
The #DB and #UD handlers, IDT setup, TF setup and mutation remain clearly
non-HIA test scaffolding. Neither the ordinary HIA Core instruction inventory
nor any kernel/full-acceptance gate is promoted by this evidence.
