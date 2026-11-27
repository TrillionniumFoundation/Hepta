"""Experimental typed 10-byte IDTR memory operations in native selfhost.

Only the isolated guest executes these operations. GNU as independently
checks the encoder. Alignment and effects are checked; pointer ownership
and valid descriptor contents are still caller obligations.
"""
from __future__ import annotations
import subprocess

WORDS = ("x86.idtr.load", "x86.idtr.store")
GUARD = bytes.fromhex("f6c20f74020f0b")
SPECS = {
    "load": (("privilege", "read", "trap"), "lidt (%rdx)", bytes.fromhex("0f011a")),
    "store": (("privilege", "write", "trap"), "sidt (%rdx)", bytes.fromhex("0f010a")),
}


def extend_source(source, replace_once):
    source = replace_once(source, "def instruction_effects(op:u64) -> u64:",
        """def instruction_effects(op:u64) -> u64:
    if op == @x86.idtr.load@:
        return 26
    if op == @x86.idtr.store@:
        return 28""")
    source = replace_once(source,
        "    if op >= @x86.mmio.read32@ and op <= @x86.msr.write@:",
        "    if op >= @x86.mmio.read32@ and op <= @x86.idtr.store@:")
    signature = ("def mmio_instruction(s:readbuf, o:mutbuf, w:mutbuf, op:u64, n:u64, "
                 "at:u64, t:u64, v:u64, bt:u64, a:u64, b:u64) -> u64:")
    source = replace_once(source, signature, signature + """
    if op == @x86.idtr.load@ or op == @x86.idtr.store@:
        return idtr_instruction(s, o, w, op, n, at, t, a)""")
    return source + """
def idtr_instruction(s:readbuf, o:mutbuf, w:mutbuf, op:u64, n:u64, at:u64, t:u64, a:u64) -> u64:
    if get(w, 200) != 1 or n != 1 or at != 1 or t != 0 or get(w, 288) != 0:
        return fail(w, 65)
    expect(s, w, 10)
    if get(w, 40) != 0:
        return 0
    # A 16-byte-aligned 10-byte pseudo-descriptor cannot cross a 4KiB page.
    # Mapping, authority, hardware state, and the descriptor's contents
    # are not proven by this numeric check.
    load_var(o, w, 2, a, 0)
    emit_bytes(o, w, 3112727955358454, 7)
    if op == @x86.idtr.load@:
        emit_bytes(o, w, 1704207, 3)
    else:
        emit_bytes(o, w, 655631, 3)
    return 0
"""


def program(action, profile, *, effects=None, address="u64", op=None,
            module="selfhost_elf"):
    if action not in SPECS:
        raise ValueError(action)
    if effects is None:
        effects = SPECS[action][0]
    operation = f"  _ = x86.idtr.{action}(v0)\n"
    return (f"hia-asm.v1 {profile} {module}\nexports(f0)\n"
            f"fn f0(v0:{address}) -> ({address}) effects({','.join(effects)}) entry(b0)\n"
            f"block b0(v0:{address})\n" + (operation if op is None else op) +
            "  ret(v0)\nend\n").encode()


def qualify(exe, output, profile, legacy, compile_cli, text_bytes, digest):
    reports = {}
    for action, (effects, mnemonic, encoding) in SPECS.items():
        label = "idtr-" + action
        def subject(**kwargs):
            return program(action, kwargs.pop("profile", profile), **kwargs)
        source = subject()
        obj = compile_cli(exe, source, output, label + "-1")
        if obj != compile_cli(exe, source, output, label + "-2"):
            raise AssertionError(label + " repeated ELF differs")
        machine = text_bytes(output, label, obj)
        asm = output / (label + "-oracle.s")
        asm.write_text(".text\n testb $15,%dl\n jz 1f\n ud2\n1:\n " + mnemonic + "\n")
        oracle = output / (label + "-oracle.o")
        subprocess.run(["as", "--64", "-o", str(oracle), str(asm)], check=True)
        if (text_bytes(output, label + "-oracle-copy", oracle.read_bytes()) != GUARD + encoding
                or machine.count(GUARD + encoding) != 1):
            raise AssertionError(label + " independent encoding/guard mismatch")
        bad = {
            "legacy": subject(profile=legacy, effects=()),
            "legacy-effect": subject(profile=legacy),
            "wrong-module": subject(module="selfhost"),
            "wrong-address": subject(address="u32"),
            "duplicate-effect": subject(effects=(*effects, effects[0])),
            "zero-operand": subject(op=f"  _ = x86.idtr.{action}()\n"),
            "extra-operand": subject(op=f"  _ = x86.idtr.{action}(v0,v0)\n"),
            "result": subject(op=f"  v1:u64 = x86.idtr.{action}(v0)\n"),
            "attribute": subject(op=f'  _ = x86.idtr.{action}(v0) {{"trust_me":true}}\n'),
        }
        for effect in effects:
            bad["missing-" + effect] = subject(effects=tuple(x for x in effects if x != effect))
        for key, malformed in bad.items():
            compile_cli(exe, malformed, output, label + "-" + key, expected=2)
        reports[label] = {"elf_sha256": digest(obj), "text_sha256": digest(machine),
                          "source_sha256": digest(source), "oracle_hex": encoding.hex(),
                          "guard_hex": GUARD.hex(), "refusals": sorted(bad)}
    return reports
