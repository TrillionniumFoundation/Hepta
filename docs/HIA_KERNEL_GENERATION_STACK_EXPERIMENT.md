# Experimental generation-bound raw scheduler stack entry (HOLD)

`x86.irq.dispatch_gen_stack()` is a distinct native terminal operation, not a
reinterpretation of `x86.irq.dispatch_on_stack()`. It has the same single
raw export / no operands or results / single block / terminal `trap user`
contract and privilege, atomic, read, write and trap effects. Existing raw
IRQ and 0/1 stack-entry objects are preserved byte for byte.

The existing 32-byte GS descriptor, original integer-frame validation,
16 KiB scheduler stack and 512-byte canary are preserved. The new raw entry
reads the live lease, rejects odd or terminal even words, retains the exact
odd held generation in the saved/callee-preserved RBP register, and acquires
with locked exact CAS. It switches stacks only after acquisition. After the
callback, it checks live GS again before accepting the selected frame or
releasing. The exact acquired odd generation is consumed by CAS to the next
even generation only after canary, descriptor, IF and frame checks. The last
valid even word is 2^64-4; the next even word 2^64-2 is retired. The all-ones
word is never issued. The terminal IRETQ tail is unchanged. No rollback is
attempted on post-commit failures.

A new keyword and native verifier/emitter mode share the unchanged byte
segments of the original backend. A separate GNU mnemonic oracle verifies
the complete generation entry, and all 21 malformed-source/effect controls
are independently executed for the new operation, with the original controls
preserved. The isolated local candidate has 135 functions, 1900 blocks and
9970 operations within the unchanged 192/2048/10000/16000 experimental limits.
Actual native compiler rebuilt twice with empty PATH:

- source `f253e8e917fef8f8f55e7c2bd98a95a59e0c6807ab3b5800d341055c87bd366a`
- compiler `de7511c37d0828a638b31bc14dba64791184a31af8c8e58230ad2f08773f9f05`
- new entry source `e09b50875148a1e924f2620a043cb46ce95a44f5c8bfff5fa5a2c6e8430c8ab1`
- new entry ELF `5bffbc217e24f57379ef63b0a7ba468e41dd27f12611d22baf9e688e0a9cc91f`
- new entry text `fa89cf85667b84e64f97aa7822525b4c6e44f3a311c7cf130f35a2c64e713a87`

The first candidate keyword exceeded the existing 32-byte lexical limit and
was refused; the shortened word preserves that limit. Local integration
with the HeptaKernel dense per-CPU scheduler fixture passed 20/20 PC/Q35
cases, including simultaneous real IRQs on two vCPUs, exact raw lease 0->1->2
and 2->3->4, actual last valid cycle and exhaustion trap, stale release and
post-callback GS mutation with precise raw trap sites, and four independent
single-byte guard-bypass negative controls. The original assembly observer
is not credited as HIA implementation. Independent CI remains required.

This is a fixed integer CPL0 non-nested entry with a cooperative callback
ABI. GS, descriptor mapping and page ownership still require authority;
post-callback GS comparison does not enforce arbitrary metadata immutability,
NMI safety, FPU, CPL3, migration or general SMP scheduling. Both production
mains and locks, existing Core-only budgets and all historical failures remain
unchanged. Full Linux acceptance is HOLD.
