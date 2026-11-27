"""Restricted terminal CPL0 integer frame restore in the experimental native compiler.

The sole operand is a caller-owned 160-byte frame, with the saved GPRs in
r15..rax order followed by RIP, CS, RFLAGS, RSP, SS. The operation abandons
the current supervisor stack. This is not general context ownership,
interrupt entry, FPU state or a production scheduler.
"""
from __future__ import annotations
import subprocess

WORD = "x86.irq.restore_kernel_frame"
EFFECTS = ("privilege", "read", "trap")
# Fixed instruction sequence from the authored native lowering. GNU as
# checks its independent mnemonic oracle during qualification; the
# compiler itself never invokes an assembler to emit this operation.
ENCODING = bytes.fromhex("4885c075020f0ba80f74020f0b4889c248c1ea2f4885d274020f0b488d909f00000048c1ea2f4885d274020f0b9c5a48f7c20002000074020f0b668cca6683fa1874020f0b668cd26683fa1074020f0b4883b8800000001874020f0b4883b8980000001074020f0b488b50784885d275020f0b48c1ea2f4885d274020f0b488b90900000004885d275020f0bf6c20f74020f0b48c1ea2f4885d274020f0b488b908800000048f7c228f5ffff74020f0bf6c20275020f0b4889c4415f415e415d415c415b415a415941585d5f5e5a595b5848cf0f0b")
ORACLE = r""".text
.macro guard condition
\condition 1f
ud2
1:
.endm
 testq %rax,%rax
 guard jnz
 testb $15,%al
 guard jz
 movq %rax,%rdx
 shrq $47,%rdx
 testq %rdx,%rdx
 guard jz
 leaq 159(%rax),%rdx
 shrq $47,%rdx
 testq %rdx,%rdx
 guard jz
 pushfq
 popq %rdx
 testq $0x200,%rdx
 guard jz
 movw %cs,%dx
 cmpw $0x18,%dx
 guard je
 movw %ss,%dx
 cmpw $0x10,%dx
 guard je
 cmpq $0x18,128(%rax)
 guard je
 cmpq $0x10,152(%rax)
 guard je
 movq 120(%rax),%rdx
 testq %rdx,%rdx
 guard jnz
 shrq $47,%rdx
 testq %rdx,%rdx
 guard jz
 movq 144(%rax),%rdx
 testq %rdx,%rdx
 guard jnz
 testb $15,%dl
 guard jz
 shrq $47,%rdx
 testq %rdx,%rdx
 guard jz
 movq 136(%rax),%rdx
 testq $-2776,%rdx
 guard jz
 testb $2,%dl
 guard jnz
 movq %rax,%rsp
 popq %r15
 popq %r14
 popq %r13
 popq %r12
 popq %r11
 popq %r10
 popq %r9
 popq %r8
 popq %rbp
 popq %rdi
 popq %rsi
 popq %rdx
 popq %rcx
 popq %rbx
 popq %rax
 iretq
 ud2
"""


def extend_source(source, replace_once):
    source = replace_once(source, "def instruction_effects(op:u64) -> u64:",
        """def instruction_effects(op:u64) -> u64:
    if op == @x86.irq.restore_kernel_frame@:
        return 26""")
    source = replace_once(source,
        "    if op >= @x86.mmio.read32@ and op <= @x86.tr.read@:",
        "    if op >= @x86.mmio.read32@ and op <= @x86.irq.restore_kernel_frame@:")
    signature = ("def mmio_instruction(s:readbuf, o:mutbuf, w:mutbuf, op:u64, n:u64, "
                 "at:u64, t:u64, v:u64, bt:u64, a:u64, b:u64) -> u64:")
    source = replace_once(source, signature, signature + """
    if op == @x86.irq.restore_kernel_frame@:
        return kernel_frame_instruction(s, o, w, n, t)""")
    # Share the already audited terminal-only parser state and final global
    # shape check from iretq_user. No new public profile.
    source += """
def kernel_frame_instruction(s:readbuf, o:mutbuf, w:mutbuf, n:u64, t:u64) -> u64:
    if get(w, 200) != 1 or n != 1 or t != 0 or get(w, 288) != 0:
        return fail(w, 65)
    if get(w, 72) != 0 or get(w, 88) != 0 or get(w, 112) != 1 or get(w, 648) != 1:
        return fail(w, 65)
    if get(w, FBASE + 24) != 1 or get(w, FBASE + 184) != 0 or get(w, FBASE + 176) != 26:
        return fail(w, 65)
    if get(w, ARGS) != 0 or variable(w, 0) != 1:
        return fail(w, 65)
    expect(s, w, 10)
    if get(w, 8) != @trap@:
        return fail(w, 65)
    if get(w, 40) != 0:
        return 0
    put(w, 200, 2)
    load_var(o, w, 0, 0, 0)
"""
    # Native instruction emitter, not host assembler or external object.
    # The explicit trap terminator emits the final UD2, as in iretq_user.
    body = ENCODING[:-2]
    for off in range(0, len(body), 8):
        chunk = body[off:off+8]
        source += f"    emit_bytes(o, w, {int.from_bytes(chunk, 'little')}, {len(chunk)})\n"
    return source + "    return 0\n"


def program(profile, *, effects=EFFECTS, typ="u64", operation=None,
            terminator="trap user", returns="", module="selfhost_elf",
            exports="f0", extra=""):
    op = operation if operation is not None else "  _ = x86.irq.restore_kernel_frame(v0)\n"
    export_line = f"exports({exports})\n" if exports is not None else ""
    return (f"hia-asm.v1 {profile} {module}\n" + export_line +
            f"fn f0(v0:{typ}) -> ({returns}) effects({','.join(effects)}) entry(b0)\n"
            f"block b0(v0:{typ})\n" + op + f"  {terminator}\nend\n" + extra).encode()


def qualify(exe, output, profile, legacy, compile_cli, text_bytes, digest):
    label = "kernel-frame"
    source = program(profile)
    obj = compile_cli(exe, source, output, label + "-1")
    assert obj == compile_cli(exe, source, output, label + "-2")
    machine = text_bytes(output, label, obj)
    asm = output / (label + "-oracle.S")
    asm.write_text(ORACLE)
    oracle = output / (label + "-oracle.o")
    subprocess.run(["as", "--64", "-o", str(oracle), str(asm)], check=True)
    assert text_bytes(output, label + "-oracle-copy", oracle.read_bytes()) == ENCODING
    assert machine.count(ENCODING) == 1
    other = "fn f1() -> () effects() entry(b0)\nblock b0()\n  ret()\nend\n"
    bad = {
        "legacy": program(legacy, effects=()),
        "legacy-effects": program(legacy),
        "wrong-module": program(profile, module="selfhost"),
        "no-export": program(profile, exports=None),
        "wrong-type": program(profile, typ="u32"),
        "missing-privilege": program(profile, effects=("read","trap")),
        "missing-read": program(profile, effects=("privilege","trap")),
        "missing-trap": program(profile, effects=("privilege","read")),
        "extra-effect": program(profile, effects=(*EFFECTS,"write")),
        "duplicate-effect": program(profile, effects=(*EFFECTS,"read")),
        "zero-operand": program(profile, operation="  _ = x86.irq.restore_kernel_frame()\n"),
        "extra-operand": program(profile, operation="  _ = x86.irq.restore_kernel_frame(v0,v0)\n"),
        "result": program(profile, operation="  v1:u64 = x86.irq.restore_kernel_frame(v0)\n"),
        "attribute": program(profile, operation='  _ = x86.irq.restore_kernel_frame(v0) {"trust_me":true}\n'),
        "ordinary-return": program(profile, terminator="ret()"),
        "wrong-trap": program(profile, terminator="trap bounds"),
        "return-value": program(profile, returns="u64"),
        "extra-function": program(profile, extra=other),
        "extra-export": program(profile, exports="f0,f1", extra=other),
        "extra-block": source.replace(b"end\n", b"block b1()\n  trap user\nend\n", 1),
        "preceding-op": program(profile, operation='  v1:u64 = const() {"value":1}\n  _ = x86.irq.restore_kernel_frame(v0)\n'),
        "following-op": program(profile, operation='  _ = x86.irq.restore_kernel_frame(v0)\n  v1:u64 = const() {"value":1}\n'),
    }
    for key, malformed in bad.items():
        compile_cli(exe, malformed, output, label + "-" + key, expected=2)
    return {"source_sha256": digest(source), "elf_sha256": digest(obj),
            "text_sha256": digest(machine), "encoding_hex": ENCODING.hex(),
            "refusals": sorted(bad)}
