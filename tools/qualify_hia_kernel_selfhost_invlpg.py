"""Isolated authoring and native bootstrap experiment for the kernel-tlb profile.

No historical generator, source, lock, or native owner is replaced. Python
authors a candidate Core v8 compiler and seeds B0 only; all following compiler
generations and subject objects are produced by the resulting HIA machine code.
The experiment is deliberately not a CPL0 authority proof or Linux acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from tools import generate_hia_selfhost as gen
from hepta.hia_agent_assembly import render_assembly
from tools.qualify_hia_selfhost import build_seed, compile_stage

PROFILE = "hepta.hia.program.kernel-tlb.v1"
LEGACY = "hepta.hia.program.v8"
HEADER = b"hia-asm.v1 hepta.hia.program.v8 selfhost\n"
# Isolated compiler candidate only. Historical 8192 bound remains unchanged
# in the locked source. Even at 8448 the original relocation table suffices:
# 128 + 8448 + 2*1536 + 128 + 2 = 11778 <= 12000.
CANDIDATE_INSTRUCTIONS = 8448

def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError("authoring anchor not unique: " + old)
    return source.replace(old, new, 1)

def candidate_source():
    words = dict(gen.W)
    for word in (PROFILE, "privilege", "x86.tlb.invlpg"):
        if word in words:
            raise ValueError("candidate keyword already present")
        words[word] = max(words.values()) + 1
    source = gen.SOURCE
    source = replace_once(source,
        "        expect(s, w, @hepta.hia.program.v8@)",
        """        if get(w, 8) == @hepta.hia.program.kernel-tlb.v1@:
            put(w, 200, 1)
            expect(s, w, @hepta.hia.program.kernel-tlb.v1@)
        else:
            expect(s, w, @hepta.hia.program.v8@)""")
    source = replace_once(source, "        read_exports(s, w)",
        """        if get(w, 200) == 1 and get(w, 232) != 1:
            return 4294967295
        read_exports(s, w)
        if get(w, 200) == 1 and get(w, 640) != 1:
            return 4294967295""")
    source = replace_once(source,
        """        if token != @alloc@:
            if token < @read@ or token > @trap@:
                return fail(w, 65)
            flag = 2 << (token - @read@)""",
        """        if token == @privilege@:
            if get(w, 200) != 1:
                return fail(w, 65)
            flag = 16
        else:
            if token != @alloc@:
                if token < @read@ or token > @trap@:
                    return fail(w, 65)
                flag = 2 << (token - @read@)""")
    source = replace_once(source, "def instruction_effects(op:u64) -> u64:",
        """def instruction_effects(op:u64) -> u64:
    if op == @x86.tlb.invlpg@:
        return 16""")
    source = replace_once(source,
        """    if op >= @buffer.new@ and op <= @chain.head_mut@:
        owned_instruction(o, w, op, n, a, at)""",
        """    if op == @x86.tlb.invlpg@:
        if get(w, 200) != 1 or n != 1 or at != 1 or t != 0 or get(w, 288) != 0:
            return fail(w, 65)
        expect(s, w, 10)
        if get(w, 40) != 0:
            return 0
        load_var(o, w, 0, a, 0)
        # Typed one-operand x86 INVLPG, ModRM /7, base RAX.
        # This is the compiler's own instruction lowering, not source bytes.
        emit(o, w, 15)
        emit(o, w, 1)
        emit(o, w, 56)
        return 0
    if op >= @buffer.new@ and op <= @chain.head_mut@:
        owned_instruction(o, w, op, n, a, at)""")
    # 200..207 is a dedicated candidate profile word within the existing
    # per-phase 0..255 zeroed header; no existing state field is moved.
    if 128 + CANDIDATE_INSTRUCTIONS + 2*1536 + 128 + 2 > 12000:
        raise ValueError("candidate relocation capacity exceeded")
    with patch.object(gen, "SOURCE", source), patch.object(gen, "W", words), \
            patch.object(gen, "MAX_INSTRUCTIONS", CANDIDATE_INSTRUCTIONS):
        document, _ = gen.document()
    functions = document["functions"]
    blocks = [b for f in functions for b in f["blocks"]]
    ops = sum(len(b["ops"]) for b in blocks)
    if len(functions) > 128 or len(blocks) > 1536 or ops > CANDIDATE_INSTRUCTIONS:
        raise ValueError({"functions": len(functions), "blocks": len(blocks), "ops": ops})
    result = render_assembly(document).encode()
    if not result.startswith(HEADER) or len(result) > 1 << 20:
        raise ValueError("candidate source exceeds bootstrap envelope")
    return result, {"functions": len(functions), "blocks": len(blocks), "ops": ops}

def digest(data):
    return hashlib.sha256(data).hexdigest()

def program(profile=PROFILE, effect="privilege", op="  _ = x86.tlb.invlpg(v0)\n",
            typ="u64", module="selfhost_elf", exports="exports(f0)\n"):
    return (f"hia-asm.v1 {profile} {module}\n" + exports +
            f"fn f0(v0:{typ}) -> ({typ}) effects({effect}) entry(b0)\n"
            f"block b0(v0:{typ})\n" + op + "  ret(v0)\nend\n").encode()

def compile_cli(compiler, source, output, label, expected=0):
    result = subprocess.run([str(compiler)], input=source, capture_output=True,
                            env={"PATH": ""}, cwd=output, timeout=30)
    (output / (label + ".input")).write_bytes(source)
    (output / (label + ".stdout")).write_bytes(result.stdout)
    (output / (label + ".stderr")).write_bytes(result.stderr)
    (output / (label + ".json")).write_text(json.dumps({
        "compiler_sha256": digest(compiler.read_bytes()), "source_sha256": digest(source),
        "returncode": result.returncode, "output_sha256": digest(result.stdout),
        "expected_returncode": expected}, sort_keys=True) + "\n")
    if result.returncode != expected or result.stderr or (expected and result.stdout):
        raise AssertionError((label, result.returncode, expected))
    return result.stdout

def text_bytes(output, label, data):
    obj = output / (label + ".o")
    raw = output / (label + ".text")
    obj.write_bytes(data)
    subprocess.run(["objcopy", "-O", "binary", "--only-section=.text", str(obj), str(raw)], check=True)
    return raw.read_bytes()

def run(output):
    output.mkdir(parents=True, exist_ok=False)
    source, shape = candidate_source()
    (output / "candidate.hepta").write_bytes(source)
    (output / "candidate-shape.json").write_text(json.dumps(shape, sort_keys=True) + "\n")
    seed, _ = build_seed(output, source)
    b1, _ = compile_stage(output, "B1", seed, source, image_format="seed-shared")
    b2, _ = compile_stage(output, "B2", b1, source)
    b3, _ = compile_stage(output, "B3", b2, source)
    if not b1.read_bytes() == b2.read_bytes() == b3.read_bytes():
        raise AssertionError("candidate native generations disagree")
    executable_source = HEADER.replace(b"selfhost\n", b"selfhost_exec\n") + source[len(HEADER):]
    exe, _ = compile_stage(output, "compiler", b3, executable_source, output_extension="")
    exe.chmod(0o755)
    for i in (1, 2):
        rebuilt = compile_cli(exe, executable_source, output, f"self-rebuild-{i}")
        if rebuilt != exe.read_bytes():
            raise AssertionError("empty-PATH self-rebuild differs")
        exe = output / f"compiler-rebuilt-{i}"
        exe.write_bytes(rebuilt)
        exe.chmod(0o755)

    first = compile_cli(exe, program(), output, "invlpg-1")
    second = compile_cli(exe, program(), output, "invlpg-2")
    if first != second or not first.startswith(b"\x7fELF"):
        raise AssertionError("native ELF repeat failed")
    machine = text_bytes(output, "invlpg", first)
    asm = output / "oracle.s"
    asm.write_text(".text\n invlpg (%rax)\n")
    subprocess.run(["as", "--64", "-o", str(output / "oracle.o"), str(asm)], check=True)
    oracle = text_bytes(output, "oracle-copy", (output / "oracle.o").read_bytes())
    if machine.count(oracle) != 1:
        raise AssertionError("GNU as INVLPG oracle not found exactly once")
    dishonest = machine.replace(oracle, b"\x90" * len(oracle), 1)
    if dishonest.count(oracle) != 0:
        raise AssertionError("dishonest NOP control not detected")
    (output / "dishonest.text").write_bytes(dishonest)

    refusals = {
        "missing-effect": program(effect=""),
        "legacy-profile": program(profile=LEGACY),
        "legacy-opcode": program(profile=LEGACY, effect=""),
        "legacy-declaration": program(profile=LEGACY, op=""),
        "wrong-type": program(typ="u32"),
        "zero-operand": program(op="  _ = x86.tlb.invlpg()\n"),
        "extra-operand": program(op="  _ = x86.tlb.invlpg(v0,v0)\n"),
        "result": program(op="  v1:u64 = x86.tlb.invlpg(v0)\n"),
        "attribute": program(op='  _ = x86.tlb.invlpg(v0) {"trust_me":true}\n'),
        "duplicate-effect": program(effect="privilege,privilege"),
        "flat-profile": program(module="selfhost"),
        "missing-exports": program(exports=""),
    }
    for label, bad in refusals.items():
        compile_cli(exe, bad, output, label, expected=2)
    legacy = compile_cli(exe, program(profile=LEGACY, effect="", op=""), output, "legacy-scalar")
    if not legacy.startswith(b"\x7fELF"):
        raise AssertionError("legacy scalar ELF failed")
    report = {"status": "PASS", "source_sha256": digest(source),
        "compiler_sha256": digest(exe.read_bytes()), "elf_sha256": digest(first),
        "text_sha256": digest(machine), "oracle_hex": oracle.hex(),
        "native_generations": 3, "empty_path_rebuilds": 2, "refusals": list(refusals),
        "shape": shape, "guest_execution": "NOT_RUN", "full_linux_acceptance": "HOLD",
        "locked_compiler_changed": False, "privilege_authority_proved": False}
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.output.resolve())
