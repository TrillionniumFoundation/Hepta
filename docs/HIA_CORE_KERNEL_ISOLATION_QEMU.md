## Exact candidate CPL0 regression after isolating Core classes

The QEMU hardware observer originally patched `Code.invlpg`, while this
refactor moves `INVLPG` to `KernelCode` to preserve the historical frozen
Code AST. The observer now patches `KernelCode.invlpg`, ensuring the malicious
NOP control still targets the generated kernel instruction. This exact
candidate has a dedicated QEMU PC/Q35 CI job that checks verified HIA source,
independent byte identity and relocation integrity, exact CR2/#PF hardware
observation, malicious NOP refusal and mapping-restoration, and reports
over-invalidation diagnostics separately.

The hardware bridge remains NON-HIA, privilege effect is only a declaration,
and the pinned selfhost_elf compiler does not support the experimental opcode.
No Linux ABI, SMP or complete driver acceptance is claimed.
