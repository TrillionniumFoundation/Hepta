# Isolated x86-64 privileged instruction encoder stage

This draft stage extends the **existing** `hepta.hia_machine_x64.Code` native
instruction encoder, rather than creating a foreign runtime, interpreter, or
an alternative HIA language. It adds four explicit typed entrypoints:
`read_cr3(GPR64)`, `write_cr3(GPR64)`, `invlpg(GPR64, disp32)`, and
`iretq()`. These emit x86-64 instruction encoding without assembler/LLVM in
the production emitter. No instruction payload is embedded in HIA source.

The new independent byte oracle uses GNU `as` / `objcopy` / `objdump`
**only in tests** and compares exact encoding across all sixteen GPRs
(including extended REX registers, rbp/r13 displacement exceptions, and
rsp/r12 SIB addressing) and eleven displacement boundaries. Malformed
registers, booleans, displacement overflow and noninteger inputs must fail
before emitting bytes. The oracle never executes privileged instructions on
the host.

## Unmet promotion dependencies

This does **not** yet add these operations to `hia_opcodes.py`, Core
resource/effect verification, Core VM semantics, `hia_program_native.py`
lowering, the standalone selfhost_elf compiler, or the HIA kernel entry ABI.
It must remain an isolated draft and **must not** be used as evidence of a
HIA-native Linux privileged backend. In particular:
- CR3 updates require a verified privilege, physical-root ownership,
  PCID/global-page policy, interrupt/preemption and SMP synchronization.
- INVLPG is a local invalidation, not inter-CPU shootdown, ownership
  transfer, or proof that a page-table write was atomically published.
- IRETQ consumes an architecture-defined return frame and must validate
  CPL, selectors, canonical addresses, stack state, interrupt masking,
  exception paths and ABI state before instruction emission.
- MMIO, control registers beyond CR3, device I/O, atomic instructions,
  fences, static data/linking and independent hardware qualification
  remain outstanding.

Next: integrate a typed `privilege` effect into the existing HIA verifier
with explicit CPL0 and authority context and a checked, sequenced native
lowering. Independently verify machine effects in PC/Q35 QEMU, including
negative controls, before proposing promotion. HeptaKernel retains its pinned
toolchain unchanged, its non-HIA `boot.S` bridge, and all Linux acceptance
gates HOLD.
