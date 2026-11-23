# QEMU hardware oracle for staged CR3/PTE revoke (HOLD)

This dependent experimental branch tests the machine bytes emitted by
`experiments/hia_x86_privileged_effect_lowering.py` (Draft PR #921) inside
an isolated PC/Q35 guest. No HIA Core v8 privilege effect or HIA native
`selfhost_elf` lowering has been added. `boot.S` is expressly **test-only
GNU assembly**; it is not a kernel implementation.

The test program installs fixed real page tables in guest RAM: CR3 =
0x180000; PTE slot = 0x183000 (low canonical identity mapped); VA 0x400000
points to physical frame 0x400000. It warms this translation, calls the
linked staged encoder output, and checks the exact PTE value. Correct revoke
must trigger a real non-present read #PF with CR2 = 0x400000, the expected
faulting RIP/error code, and unchanged 0x400062 replacement PTE. Wrong-CR3
and stale-old controls must trap at the emitted UD2 and leave the original
0x400063 PTE unchanged. An intentionally dishonest RET-only image must fail
the independent observer; it is a negative-control fixture, not a HIA source.
Both PC and Q35 run at 64 MiB, one CPU, and are isolated from the host kernel.

The build extracts the final ELF .text section and compares its embedded
effect bytes to the exact output of the source emitter before running QEMU.
The independently obtained GNU-as byte comparison in the parent draft remains
required. Tests must fail on unsupported QEMU, timeouts, missing debug-exit
markers, wrong exit codes, stale PTE mutation, wrong CPU exception, or a
mismatched linked image. Each machine and case retains its own status, stdout,
stderr, source hashes and image hashes.

The exact patch remains **HOLD** until independent CI records PASS. Even a
passing QEMU experiment proves only this single-CPU stage: callers supply
quiescence, identity mapping and table ownership as untrusted assertions.
It does not establish authenticated effect resources, SMP TLB shootdown,
memory-order guarantees, DMA/IOMMU exclusion, Linux munmap, freestanding
HIA privilege instructions, or full kernel compatibility. The original
HeptaKernel 17 gates and 422 syscall rows remain unmet.
