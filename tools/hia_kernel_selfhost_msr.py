"""Author and qualify typed experimental x86 MSR operations in selfhost.

Only the isolated guest executes RDMSR/WRMSR. The independent assembler
is a byte oracle, not a producer of the subject.
"""
from __future__ import annotations
import subprocess

WORDS = ("x86.msr.read", "x86.msr.write")
EFFECTS = ("privilege", "trap")
ENCODINGS = {
    "read": ("rdmsr\n shlq $32,%rdx\n orq %rdx,%rax",
             bytes.fromhex("0f3248c1e2204809d0")),
    "write": ("movq %rax,%rdx\n shrq $32,%rdx\n wrmsr",
              bytes.fromhex("4889c248c1ea200f30")),
}


def extend_source(source, replace_once):
    source = replace_once(source, "def instruction_effects(op:u64) -> u64:",
        """def instruction_effects(op:u64) -> u64:
    if op == @x86.msr.read@ or op == @x86.msr.write@:
        return 24""")
    # Preserve the large instruction function's SSA budget. The adjacent
    # opcode interval is dispatched through the existing MMIO helper.
    source = replace_once(source,
        "    if op == @x86.mmio.read32@ or op == @x86.mmio.write32@:",
        "    if op >= @x86.mmio.read32@ and op <= @x86.msr.write@:")
    signature = ("def mmio_instruction(s:readbuf, o:mutbuf, w:mutbuf, op:u64, n:u64, "
                 "at:u64, t:u64, v:u64, bt:u64, a:u64, b:u64) -> u64:")
    source = replace_once(source, signature, signature + """
    if op == @x86.msr.read@ or op == @x86.msr.write@:
        return msr_instruction(s, o, w, op, n, at, t, v, bt, a, b)""")
    return source + """
def msr_instruction(s:readbuf, o:mutbuf, w:mutbuf, op:u64, n:u64, at:u64, t:u64, v:u64, bt:u64, a:u64, b:u64) -> u64:
    if get(w, 200) != 1 or at != 3:
        return fail(w, 65)
    if op == @x86.msr.read@:
        if n != 1 or t != 1 or get(w, 288) != 1:
            return fail(w, 65)
        define(w, v, t)
    else:
        if n != 2 or bt != 1 or t != 0 or get(w, 288) != 0:
            return fail(w, 65)
    expect(s, w, 10)
    if get(w, 40) != 0:
        return 0
    # ECX selects a u32 MSR; RDMSR returns EDX:EAX and WRMSR consumes it.
    # privilege/trap is not authorization of the selector.
    load_var(o, w, 1, a, 0)
    if op == @x86.msr.read@:
        emit_bytes(o, w, 36158277431823, 6)
        emit_bytes(o, w, 13633864, 3)
        store_var(o, w, v, 0)
    else:
        load_var(o, w, 0, b, 0)
        emit_bytes(o, w, 9265315125037384, 7)
        emit_bytes(o, w, 12303, 2)
    return 0
"""


def program(action, profile, *, effects=EFFECTS, index="u32", value="u64",
            op=None, module="selfhost_elf"):
    if action == "read":
        args, typ, ret = f"v0:{index}", "u64", "v1"
        operation = "  v1:u64 = x86.msr.read(v0)\n"
    elif action == "write":
        args, typ, ret = f"v0:{index},v1:{value}", index, "v0"
        operation = "  _ = x86.msr.write(v0,v1)\n"
    else:
        raise ValueError(action)
    return (f"hia-asm.v1 {profile} {module}\nexports(f0)\n"
            f"fn f0({args}) -> ({typ}) effects({','.join(effects)}) entry(b0)\n"
            f"block b0({args})\n" + (operation if op is None else op) +
            f"  ret({ret})\nend\n").encode()


def qualify(exe, output, profile, legacy, compile_cli, text_bytes, digest):
    reports = {}
    for action, (mnemonic, encoding) in ENCODINGS.items():
        label = "msr-" + action
        def subject(**kwargs):
            return program(action, kwargs.pop("profile", profile), **kwargs)
        source = subject()
        obj = compile_cli(exe, source, output, label + "-1")
        if obj != compile_cli(exe, source, output, label + "-2"):
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
            "wrong-index-type": subject(index="u64"),
            "missing-privilege": subject(effects=("trap",)),
            "missing-trap": subject(effects=("privilege",)),
            "duplicate-effect": subject(effects=("privilege","trap","privilege")),
        }
        if action == "read":
            bad.update({
                "zero-operand": subject(op="  v1:u64 = x86.msr.read()\n"),
                "extra-operand": subject(op="  v1:u64 = x86.msr.read(v0,v0)\n"),
                "wrong-result": subject(op="  v1:u32 = x86.msr.read(v0)\n").replace(b"-> (u64)", b"-> (u32)"),
                "no-result": subject(op="  _ = x86.msr.read(v0)\n").replace(b"-> (u64)", b"-> (u32)").replace(b"ret(v1)", b"ret(v0)"),
                "attribute": subject(op='  v1:u64 = x86.msr.read(v0) {"trust_me":true}\n'),
            })
        else:
            bad.update({
                "zero-operand": subject(op="  _ = x86.msr.write()\n"),
                "one-operand": subject(op="  _ = x86.msr.write(v0)\n"),
                "extra-operand": subject(op="  _ = x86.msr.write(v0,v1,v1)\n"),
                "wrong-value": subject(value="u32"),
                "result": subject(op="  v2:u64 = x86.msr.write(v0,v1)\n"),
                "attribute": subject(op='  _ = x86.msr.write(v0,v1) {"trust_me":true}\n'),
            })
        for key, malformed in bad.items():
            compile_cli(exe, malformed, output, label + "-" + key, expected=2)
        reports[label] = {"elf_sha256": digest(obj), "text_sha256": digest(machine),
                          "source_sha256": digest(source), "oracle_hex": encoding.hex(),
                          "refusals": sorted(bad)}
    return reports

