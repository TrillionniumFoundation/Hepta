"""Restricted, terminal CPL0-to-CPL3 IRETQ in the native experimental compiler.

The verifier admits only one exported function, one block, one operation,
five ordered scalar parameters, no return values, and a trap-user sentinel.
The caller still owns descriptor validity, page mappings, CPU state and
lifetime of the abandoned supervisor stack. Never execute this on the host.
"""
from __future__ import annotations
import subprocess

WORD = "x86.irq.iretq_user"
EFFECTS = ("privilege", "trap")
TYPES = ("u64", "u16", "u64", "u64", "u16")
ADDRESS_GUARD = bytes.fromhex("4885c075020f0b48c1e82f4885c074020f0b")
SELECTOR_GUARD = bytes.fromhex("6683f80375020f0b83e00783f80374020f0b")
FLAGS_GUARD = bytes.fromhex("48a928f5ffff74020f0ba80275020f0b")
RETURN = bytes.fromhex("48cf0f0b")


def extend_source(source, replace_once):
    source = replace_once(source, "def instruction_effects(op:u64) -> u64:",
        """def instruction_effects(op:u64) -> u64:
    if op == @x86.irq.iretq_user@:
        return 24""")
    source = replace_once(source,
        "    if op >= @x86.mmio.read32@ and op <= @x86.idtr.store@:",
        "    if op >= @x86.mmio.read32@ and op <= @x86.irq.iretq_user@:")
    signature = ("def mmio_instruction(s:readbuf, o:mutbuf, w:mutbuf, op:u64, n:u64, "
                 "at:u64, t:u64, v:u64, bt:u64, a:u64, b:u64) -> u64:")
    source = replace_once(source, signature, signature + """
    if op == @x86.irq.iretq_user@:
        return iretq_user_instruction(s, o, w, n, t)""")
    # The already phase-reset profile word transitions from 1 to 2 only
    # after admission of this terminal operation. It is never a new public
    # profile. Check all global shape counters after parsing the entire input.
    source = replace_once(source,
        "        expect(s, w, 0)\n        if get(w, 64) == 0:",
        """        expect(s, w, 0)
        if get(w, 200) == 2:
            if get(w, 64) != 1 or get(w, 80) != 1 or get(w, 112) != 1 or get(w, 648) != 1:
                fail(w, 65)
        if get(w, 64) == 0:""")
    source = replace_once(source,
        "    code = get(w, 8)\n    if code < @allocation@ or code > @user@:",
        """    code = get(w, 8)
    if get(w, 200) == 2 and code != @user@:
        return fail(w, 67)
    if code < @allocation@ or code > @user@:""")
    return source + """
def iretq_user_instruction(s:readbuf, o:mutbuf, w:mutbuf, n:u64, t:u64) -> u64:
    # No other instruction, function, local resource or ordinary return
    # may share this special terminal export.
    if get(w, 200) != 1 or n != 5 or t != 0 or get(w, 288) != 0:
        return fail(w, 65)
    if get(w, 72) != 0 or get(w, 88) != 0 or get(w, 112) != 1 or get(w, 648) != 1:
        return fail(w, 65)
    if get(w, FBASE + 24) != 5 or get(w, FBASE + 184) != 0 or get(w, FBASE + 176) != 24:
        return fail(w, 65)
    i = 0
    while i < 5:
        a = get(w, ARGS + i * 8)
        if a != i:
            return fail(w, 65)
        expected = 1
        if i == 1 or i == 4:
            expected = 10
        if variable(w, a) != expected:
            return fail(w, 65)
        i = i + 1
    expect(s, w, 10)
    if get(w, 8) != @trap@:
        return fail(w, 65)
    if get(w, 40) != 0:
        return 0
    put(w, 200, 2)
    i = 0
    while i < 5:
        load_var(o, w, 0, i, 0)
        if i == 0 or i == 3:
            # Nonzero, lower-half 48-bit canonical RIP/RSP.
            emit_bytes(o, w, 3112727983719752, 7)
            emit_bytes(o, w, 803782984, 4)
            emit_bytes(o, w, 3112727966942536, 7)
        else:
            if i == 1 or i == 4:
                # Non-null GDT selector, RPL=3, TI=0.
                emit_bytes(o, w, 796858360668914534, 8)
                emit_bytes(o, w, 4365885104259, 6)
                emit_bytes(o, w, 185533044, 4)
            else:
                # Only CF/PF/AF/ZF/SF/IF/OF and mandatory bit 1.
                # Reject all other bits before constructing the frame.
                emit_bytes(o, w, 281474794826056, 6)
                emit_bytes(o, w, 185533044, 4)
                emit_bytes(o, w, 12159093637800, 6)
        i = i + 1
    i = 5
    while i > 0:
        i = i - 1
        load_var(o, w, 0, i, 0)
        emit(o, w, 80)
    emit_bytes(o, w, 53064, 2)
    # The original explicit trap terminator emits the UD2 sentinel.
    return 0
"""


def program(profile, *, effects=EFFECTS, types=TYPES, operation=None,
            terminator="trap user", returns="", module="selfhost_elf",
            exports="f0", extra=""):
    args = ",".join(f"v{i}:{typ}" for i, typ in enumerate(types))
    if operation is None:
        operation = "  _ = x86.irq.iretq_user(v0,v1,v2,v3,v4)\n"
    export_line = f"exports({exports})\n" if exports is not None else ""
    return (f"hia-asm.v1 {profile} {module}\n" + export_line +
            f"fn f0({args}) -> ({returns}) effects({','.join(effects)}) entry(b0)\n"
            f"block b0({args})\n" + operation + f"  {terminator}\nend\n" + extra).encode()


def qualify(exe, output, profile, legacy, compile_cli, text_bytes, digest):
    label = "iretq-user"
    subject = program(profile)
    obj = compile_cli(exe, subject, output, label + "-1")
    if obj != compile_cli(exe, subject, output, label + "-2"):
        raise AssertionError("IRETQ repeated ELF differs")
    machine = text_bytes(output, label, obj)
    asm = output / (label + "-oracle.s")
    asm.write_text(
        ".text\n testq %rax,%rax\n jnz 1f\n ud2\n1:\n"
        " shrq $47,%rax\n testq %rax,%rax\n jz 1f\n ud2\n1:\n"
        " cmpw $3,%ax\n jne 1f\n ud2\n1:\n"
        " andl $7,%eax\n cmpl $3,%eax\n je 1f\n ud2\n1:\n"
        " testq $-2776,%rax\n jz 1f\n ud2\n1:\n"
        " testb $2,%al\n jnz 1f\n ud2\n1:\n iretq\n ud2\n")
    oracle = output / (label + "-oracle.o")
    subprocess.run(["as", "--64", "-o", str(oracle), str(asm)], check=True)
    want = ADDRESS_GUARD + SELECTOR_GUARD + FLAGS_GUARD + RETURN
    if text_bytes(output, label + "-oracle-copy", oracle.read_bytes()) != want:
        raise AssertionError("independent IRETQ guard encoding differs")
    if not (machine.count(ADDRESS_GUARD) == 2 and machine.count(SELECTOR_GUARD) == 2
            and machine.count(FLAGS_GUARD) == 1 and machine.count(RETURN) == 1):
        raise AssertionError("IRETQ guard or terminal sentinel missing")
    other = ('fn f1() -> () effects() entry(b0)\n'
             'block b0()\n  ret()\nend\n')
    second_block = "block b1()\n  trap user\nend\n"
    bad = {
        "legacy": program(legacy, effects=()),
        "legacy-effects": program(legacy),
        "wrong-module": program(profile, module="selfhost"),
        "missing-exports": program(profile, exports=None),
        "missing-privilege": program(profile, effects=("trap",)),
        "missing-trap": program(profile, effects=("privilege",)),
        "extra-effect": program(profile, effects=(*EFFECTS, "read")),
        "duplicate-effect": program(profile, effects=(*EFFECTS, "privilege")),
        "too-few": program(profile, operation="  _ = x86.irq.iretq_user(v0,v1,v2,v3)\n"),
        "too-many": program(profile, operation="  _ = x86.irq.iretq_user(v0,v1,v2,v3,v4,v0)\n"),
        "result": program(profile, operation="  v5:u64 = x86.irq.iretq_user(v0,v1,v2,v3,v4)\n"),
        "permutation": program(profile, operation="  _ = x86.irq.iretq_user(v3,v1,v2,v0,v4)\n"),
        "duplicate": program(profile, operation="  _ = x86.irq.iretq_user(v0,v1,v2,v0,v4)\n"),
        "ordinary-return": program(profile, terminator="ret()"),
        "other-trap": program(profile, terminator="trap bounds"),
        "attribute": program(profile, operation='  _ = x86.irq.iretq_user(v0,v1,v2,v3,v4) {"trust_me":true}\n'),
        "return-value": program(profile, returns="u64"),
        "extra-function": program(profile, extra=other),
        "extra-export": program(profile, exports="f0,f1", extra=other),
        "extra-block": subject.replace(b"end\n", second_block.encode(), 1),
        "preceding-op": program(profile, operation='  v5:u64 = const() {"value":1}\n'
                                      '  _ = x86.irq.iretq_user(v0,v1,v2,v3,v4)\n'),
        "following-op": program(profile, operation='  _ = x86.irq.iretq_user(v0,v1,v2,v3,v4)\n'
                                      '  v5:u64 = const() {"value":1}\n'),
    }
    for i in range(5):
        types = list(TYPES)
        types[i] = "u32"
        bad["wrong-type-" + str(i)] = program(profile, types=types)
    for key, malformed in bad.items():
        compile_cli(exe, malformed, output, label + "-" + key, expected=2)
    return {"elf_sha256": digest(obj), "text_sha256": digest(machine),
            "source_sha256": digest(subject), "oracle_hex": want.hex(),
            "address_guard_hex": ADDRESS_GUARD.hex(), "selector_guard_hex": SELECTOR_GUARD.hex(),
            "flags_guard_hex": FLAGS_GUARD.hex(), "return_hex": RETURN.hex(),
            "refusals": sorted(bad)}
