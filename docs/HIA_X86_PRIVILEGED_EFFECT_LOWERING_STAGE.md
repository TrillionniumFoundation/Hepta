# Experimental checked PTE-revoke effect -> x86-64 bytes (HOLD)

This dependent draft integrates two previously separate stage surfaces: the
unpromoted PrivilegedCode encoder and a **single-CPU, single-owner, 4KiB PTE
Present-clear effect**. It does not extend HIA Core v8's accepted instructions
or effects, and the selfhost_elf compiler cannot yet emit this operation.

The experiment validates a typed restricted context before emitting any bytes.
It requires exactly one CPL0 CPU, interrupts masked, preemption disabled,
exclusive page-table ownership, DMA quiescence, no PCID/global/LA57, an admitted
maximum physical width, aligned CR3/PTE addresses, a canonical page VA, a
**caller-asserted identity mapping** for the PTE slot (linear VA equals physical
slot), and a slot below the low 47-bit canonical-address boundary, a
present non-global PTE, and **only** clearing that PTE's Present bit. All
context facts are **supplied by the caller**, not proved from hardware or
authenticated HIA resources.

The staged machine sequence uses the existing direct HIA x86-64 emitter to:
(1) read **actual CR3** and UD2 if it differs from the exact expected value;
(2) read **actual PTE slot bytes** and UD2 on stale expected-old mismatch;
(3) perform an aligned 64-bit Present-bit clear;
(4) INVLPG the exact virtual page and return. No host privileged execution is
performed. The byte-for-byte sequence is independently assembled with GNU as,
extracted via objcopy, decoded with objdump and compared in the test. Mismatch
or unsafe plan causes refusal, not a silent stub or a green full-Linux gate.

This **does not** establish trustworthy authority claims, an atomic
read-modify-write, root/page-table pointer identity, hardware PTE ownership,
Linux munmap, TLB shootdown, reallocation safety, exception handling,
interrupt/NMI-safe execution, or all-architecture parity. Concurrent hardware
accesses, alternate page-table aliases and DMA require a stronger model.
UD2 is a deliberate trap path in an isolated proposed CPL0 fixture, not a
safe production kernel error handler. **No QEMU execution in this stage**.

Next gates: represent this effect in the real HIA grammar and Core verifier,
replace caller-supplied context with authenticated resources and strong
preconditions, implement its exact typed selfhost_elf lowering, bind the
machine text to that source, then check the live PTE/CR3/TLB effects and
fault-path readbacks in PC/Q35 QEMU. The pinned HeptaKernel compiler remains
unchanged. All 17 full-target Linux gates and 422 syscall obligations remain
HOLD.

The PTE slot is dereferenced by a paged x86-64 CPU using a **linear address**;
a physical address is not automatically a usable pointer. This prototype's
identity-map claim is not authenticated and must be independently checked in
a guest before any attempted hardware execution. The target frame must not be
its own PTE-table or the current CR3 root frame.
