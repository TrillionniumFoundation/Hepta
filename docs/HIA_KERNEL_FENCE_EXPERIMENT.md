# Experimental HIA Core x86-64 MFENCE effect

This isolated draft extends the actual primitive Core admission and direct native
compiler, not a file-name or opaque payload adapter. An explicit
`hepta.hia.program.kernel-fence.v1` profile admits one zero-argument
`x86.fence.mfence` instruction requiring the `atomic` function effect.
Old v1–v8 schemas reject it; default v8 catalog remains unchanged.
The x86-64 direct backend selects the reviewed Code.mfence encoder;
the interpreter **refuses** to emulate hardware ordering.

An independent GNU assembler/objcopy oracle checks exact `0f ae f0`
bytes. Tests require genuine verifier admission, reject missing effect,
wrong schema/arguments/attributes/result/unknown privilege opcode, compare
deterministic Core object bytes, detect malicious codegen replacement with NOP,
and execute the original native shared-object export on isolated Linux x86-64.
The byte oracle detects a removed fence even when functional return-value
tests would not. This is not an SMP memory-model litmus test.

**HOLD**: MFENCE is not CRx, INVLPG, IPI, port I/O or an authority token.
There is no privileged resource ownership, MMIO semantics, exception/IRET,
true atomic read-modify-write, shared HIA selfhost_elf/compiler bootstrap,
or hardware-backed cross-core memory ordering proof in this change.
No Hepta main / HeptaKernel main/toolchain lock may be modified on the
strength of this experiment. Full 17 Linux gates and 422 syscall
obligations remain open. This draft intentionally uses a separate namespace
so as not to seize the concurrent proposed HIA v9 general-purpose schema.
