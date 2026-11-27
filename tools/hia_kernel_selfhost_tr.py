"""Isolated native task-register operations and independent instruction oracles."""
from __future__ import annotations
import subprocess

WORDS = ("x86.tr.load", "x86.tr.read")
EFFECTS = ("privilege", "trap")
ENCODINGS = {
    "load": ("ltr %ax", bytes.fromhex("0f00d8")),
    "read": ("str %ax\n movzwl %ax,%eax", bytes.fromhex("660f00c80fb7c0")),
}

def extend_source(source, replace_once):
    source = replace_once(source, "def instruction_effects(op:u64) -> u64:",
        """def instruction_effects(op:u64) -> u64:
    if op == @x86.tr.load@ or op == @x86.tr.read@:
        return 24""")
    source = replace_once(source,
        "    if op >= @x86.mmio.read32@ and op <= @x86.irq.iretq_user@:",
        "    if op >= @x86.mmio.read32@ and op <= @x86.tr.read@:")
    signature = ("def mmio_instruction(s:readbuf, o:mutbuf, w:mutbuf, op:u64, n:u64, "
                 "at:u64, t:u64, v:u64, bt:u64, a:u64, b:u64) -> u64:")
    source = replace_once(source, signature, signature + """
    if op == @x86.tr.load@ or op == @x86.tr.read@:
        return tr_instruction(s, o, w, op, n, at, t, v, a)""")
    return source + """
def tr_instruction(s:readbuf, o:mutbuf, w:mutbuf, op:u64, n:u64, at:u64, t:u64, v:u64, a:u64) -> u64:
    if get(w, 200) != 1:
        return fail(w, 65)
    if op == @x86.tr.load@:
        if n != 1 or at != 10 or t != 0 or get(w, 288) != 0:
            return fail(w, 65)
    else:
        if n != 0 or t != 10 or get(w, 288) != 1:
            return fail(w, 65)
        define(w, v, t)
    expect(s, w, 10)
    if get(w, 40) != 0:
        return 0
    # LTR consumes AX and changes the real TSS descriptor busy bit.
    # STR writes AX; zero extension preserves the scalar u16 ABI.
    # Descriptor ownership, selector validity and CPU mode remain caller obligations.
    if op == @x86.tr.load@:
        load_var(o, w, 0, a, 0)
        emit_bytes(o, w, 14155791, 3)
    else:
        emit_bytes(o, w, 54244473936285542, 7)
        store_var(o, w, v, 0)
    return 0
"""

def program(action, profile, *, effects=EFFECTS, selector="u16", op=None,
            module="selfhost_elf"):
    if action == "load":
        typ, ret = selector, "v0"
        operation = "  _ = x86.tr.load(v0)\n"
    elif action == "read":
        typ, ret = "u16", "v1"
        operation = "  v1:u16 = x86.tr.read()\n"
    else:
        raise ValueError(action)
    return (f"hia-asm.v1 {profile} {module}\nexports(f0)\n"
            f"fn f0(v0:{selector}) -> ({typ}) effects({','.join(effects)}) entry(b0)\n"
            f"block b0(v0:{selector})\n" + (operation if op is None else op) +
            f"  ret({ret})\nend\n").encode()

def qualify(exe, output, profile, legacy, compile_cli, text_bytes, digest):
    reports = {}
    for action, (mnemonic, encoding) in ENCODINGS.items():
        label = "tr-" + action
        def subject(**kwargs):
            return program(action, kwargs.pop("profile", profile), **kwargs)
        source = subject()
        obj = compile_cli(exe, source, output, label + "-1")
        if obj != compile_cli(exe, source, output, label + "-2") or not obj.startswith(b"\x7fELF"):
            raise AssertionError(label + " repeated ELF differs")
        machine = text_bytes(output, label, obj)
        asm = output / (label + "-oracle.s")
        asm.write_text(".text\n " + mnemonic + "\n")
        oracle = output / (label + "-oracle.o")
        subprocess.run(["as", "--64", "-o", str(oracle), str(asm)], check=True)
        if (text_bytes(output, label + "-oracle-copy", oracle.read_bytes()) != encoding
                or machine.count(encoding) != 1):
            raise AssertionError(label + " independent encoding mismatch")
        bad = {
            "legacy": subject(profile=legacy, effects=()),
            "legacy-effect": subject(profile=legacy),
            "wrong-module": subject(module="selfhost"),
            "missing-privilege": subject(effects=("trap",)),
            "missing-trap": subject(effects=("privilege",)),
            "duplicate-effect": subject(effects=("privilege","trap","privilege")),
        }
        if action == "load":
            bad.update({
                "wrong-selector-type": subject(selector="u64"),
                "zero-operand": subject(op="  _ = x86.tr.load()\n"),
                "extra-operand": subject(op="  _ = x86.tr.load(v0,v0)\n"),
                "result": subject(op="  v1:u16 = x86.tr.load(v0)\n"),
                "attribute": subject(op='  _ = x86.tr.load(v0) {"trust_me":true}\n'),
            })
        else:
            bad.update({
                "extra-operand": subject(op="  v1:u16 = x86.tr.read(v0)\n"),
                "wrong-result": subject(op="  v1:u64 = x86.tr.read()\n").replace(b"-> (u16)", b"-> (u64)"),
                "no-result": subject(op="  _ = x86.tr.read()\n").replace(b"ret(v1)", b"ret(v0)"),
                "attribute": subject(op='  v1:u16 = x86.tr.read() {"trust_me":true}\n'),
                "redefine": subject(op="  v0:u16 = x86.tr.read()\n").replace(b"ret(v1)", b"ret(v0)"),
            })
        for key, malformed in bad.items():
            compile_cli(exe, malformed, output, label + "-" + key, expected=2)
        reports[label] = {"elf_sha256": digest(obj), "text_sha256": digest(machine),
                          "source_sha256": digest(source), "oracle_hex": encoding.hex(),
                          "refusals": sorted(bad)}
    return reports
