"""Execute the conditional owned-runtime helpers through a native HIA author.

The unchanged selfhost compiler compiles an HIA byte-emitter program containing
the proposed helpers. That native emitter produces the tested machine fixtures.
This exercises the helper SOURCE after the B0 boundary without adding owned
opcodes to the selfhost parser or changing its supported inventory. General
Core reference/negative fixtures are qualified separately and kept alongside.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_machine_x64 import Code
from tools import generate_hia_selfhost as generator
from tools.hia_selfhost_owned_runtime import SOURCE, PROFILE, RUNTIME_ASSUMPTIONS, fragment_manifest
from tools.hia_selfhost_owned_cases import run_reference


def wire(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def data(code):
    result, relocations = code.finalize()
    if relocations:
        raise AssertionError("fixture has an unresolved external dependency")
    return result


def slot(variable, word=0):
    return -32 - variable * 16 + word * 8


class Case:
    def __init__(self, name, expected=None, *, trap=False):
        self.name, self.expected, self.trap = name, expected, trap
        self.lines = []
        c = Code()
        c.push("rbp"); c.mov_rr("rbp", "rsp"); c.alu_imm("sub", "rsp", 512)
        for variable, registers in enumerate((("rdi", "rsi"), ("rdx", "rcx"), ("r8", "r9"))):
            for word, register in enumerate(registers):
                c.store("rbp", slot(variable, word), register)
        self.raw(data(c))

    def raw(self, value):
        for offset in range(0, len(value), 8):
            chunk = value[offset:offset + 8]
            self.lines.append(f"    emit_bytes(o, w, {int.from_bytes(chunk, 'little')}, {len(chunk)})")

    def call(self, name, *arguments):
        self.lines.append(f"    {name}(o, w, " + ", ".join(map(str, arguments)) + ")")

    def constant(self, variable, value):
        c = Code(); c.mov_imm("rax", value); c.store("rbp", slot(variable), "rax"); self.raw(data(c))

    def observe(self, variable, index, word=0):
        c = Code(); c.load("rdi", "rbp", slot(1)); c.load("rax", "rbp", slot(variable, word))
        c.store("rdi", index * 8, "rax"); self.raw(data(c))

    def write_payload(self, variable, index, value):
        c = Code(); c.load("rdi", "rbp", slot(variable)); c.mov_imm("rax", value)
        c.store_u8("rdi", index, "rax"); self.raw(data(c))

    def observe_payload(self, variable, index, output_index):
        c = Code(); c.load("rax", "rbp", slot(variable)); c.load_u8("rax", "rax", index)
        c.load("rdi", "rbp", slot(1)); c.store("rdi", output_index * 8, "rax"); self.raw(data(c))

    def all_zero(self, variable, result):
        c = Code(); c.load("rdi", "rbp", slot(variable)); c.load("rcx", "rbp", slot(variable, 1))
        c.test("rcx", "rcx"); c.jcc("e", "empty")
        c.mov_imm("rax", 0); c.emit(b"\xfc\xf3\xae\x0f\x94\xc0\x0f\xb6\xc0"); c.jmp("done")
        c.label("empty"); c.mov_imm("rax", 1)
        c.label("done"); c.store("rbp", slot(result), "rax"); self.raw(data(c))

    def finish(self, number):
        c = Code(); c.mov_imm("rax", 0); c.emit(b"\xc9"); c.ret(); self.raw(data(c))
        return (f"def owned_case_{number}(o:mutbuf, w:mutbuf) -> u64:\n" +
                "\n".join(self.lines) + "\n    return 0\n")


def native_cases():
    cases = []
    for name, size, success in (("empty-try-allocation", 0, 1), ("ordinary-try-allocation", 8192, 1),
                               ("larger-than-compiler-workspace", 2 * 1024**2 + 17, 1),
                               ("unsigned-object-size-refusal", 1 << 63, 0),
                               ("kernel-allocation-failure", 1 << 62, 0)):
        case = Case(name, [success, size if success else 0, 1])
        case.constant(3, size); case.call("owned_allocate", 3, 4, 5, 0)
        case.observe(5, 0); case.observe(4, 1, 1); case.all_zero(4, 6); case.observe(6, 2)
        case.call("owned_drop", 4, 8); cases.append(case)
    case = Case("trapping-object-size-refusal", trap=True)
    case.constant(3, 1 << 63); case.call("owned_allocate", 3, 4, 5, 1); cases.append(case)

    case = Case("owner-move-preserves-buffer", [17, 41, 249])
    case.constant(3, 17); case.call("owned_allocate", 3, 4, 5, 1); case.call("owned_move", 4, 6)
    case.write_payload(6, 0, 41); case.write_payload(6, 16, 249)
    case.observe(6, 0, 1); case.observe_payload(6, 0, 1); case.observe_payload(6, 16, 2)
    case.call("owned_drop", 6, 8); cases.append(case)

    case = Case("empty-chain-pop", [0, 1, 0])
    case.call("owned_empty", 4); case.call("owned_pop", 4, 5, 6, 7); case.call("owned_is_empty", 5, 8)
    case.observe(7, 0); case.observe(8, 1); case.observe(6, 2, 1)
    case.call("owned_drop", 6, 8); case.call("owned_drop", 5, 9); cases.append(case)

    case = Case("chain-roundtrip-and-loans", [1, 0, 171, 205, 1, 37, 99, 1])
    case.constant(3, 37); case.call("owned_allocate", 3, 4, 5, 1)
    case.write_payload(4, 0, 171); case.write_payload(4, 36, 205)
    case.call("owned_empty", 6); case.call("owned_push", 6, 4, 7, 8, 9)
    case.observe(9, 0); case.observe(8, 1, 1); case.call("owned_drop", 8, 8)
    case.call("owned_head", 7, 10); case.observe_payload(10, 0, 2); case.observe_payload(10, 36, 3)
    # Local loan transitions are statically checked by the separate Core
    # fixture; at runtime the two views use the same checked payload descriptor.
    case.call("owned_head", 7, 13); case.write_payload(13, 0, 99)
    case.call("owned_pop", 7, 14, 15, 16); case.call("owned_is_empty", 14, 17)
    case.observe(16, 4); case.observe(15, 5, 1); case.observe_payload(15, 0, 6); case.observe(17, 7)
    case.call("owned_drop", 15, 8); case.call("owned_drop", 14, 9); cases.append(case)

    case = Case("empty-chain-head-trap", trap=True)
    case.call("owned_empty", 4); case.call("owned_head", 4, 5); cases.append(case)

    case = Case("iterative-5000-node-drop", [0])
    case.constant(3, 1); case.constant(20, 5000); case.call("owned_empty", 4)
    case.lines.append("    loop = get(w, 56)")
    case.call("owned_allocate", 3, 5, 21, 1); case.call("owned_push", 4, 5, 6, 7, 8)
    c = Code(); c.load("rax", "rbp", slot(8)); c.test("rax", "rax"); c.jcc("ne", "ok"); c.ud2(); c.label("ok")
    case.raw(data(c)); case.call("owned_drop", 7, 8); case.call("owned_move", 6, 4)
    c = Code(); c.load("rax", "rbp", slot(20)); c.alu_imm("sub", "rax", 1)
    c.store("rbp", slot(20), "rax"); c.test("rax", "rax"); c.emit(b"\x0f\x85")
    case.raw(data(c)); case.lines.append("    emit4(o, w, loop - get(w, 56) - 4)")
    case.call("owned_is_empty", 4, 9); case.observe(9, 0); case.call("owned_drop", 4, 9); cases.append(case)
    return cases


def author_document(cases):
    """Use the existing restricted authoring aid, then canonical Core checking."""
    from hepta.hia_program import verify_program
    from hepta.hia_agent_assembly import render_assembly
    generated = generator.source_program()
    definitions = {node.name: ast.get_source_segment(generated, node) for node in ast.parse(generated).body}
    source = '''def compile(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 1 or length(w) < 1024:
        return 4294967295
    put(w, 48, 2)
    put(w, 56, 0)
    choice = byte(s, 0)
'''
    for number in range(len(cases)):
        source += f"    if choice == {number}:\n        owned_case_{number}(o, w)\n"
    source += "    return get(w, 56)\n"
    source += "\n".join(case.finish(number) for number, case in enumerate(cases))
    source += "\n" + SOURCE + "\n"
    source += "\n".join(definitions[name] for name in (
        "load_var", "store_var", "mem", "emit8", "emit4", "emit", "emit_bytes", "fail", "put", "get"))
    nodes = ast.parse(source).body
    names = {node.name: "f" + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    functions = []
    for node in nodes:
        builder = generator.Builder(node, names, signatures); builder.statements(node.body)
        functions.append({"name": names[node.name], "params": [builder.param(p) for p in builder.params],
            "returns": [builder.returns], "effects": ["read", "write", "trap"], "entry": "b0", "blocks": builder.blocks})
    document = {"schema": "hepta.hia.program.v8", "module": "selfhost", "functions": functions}
    verified = verify_program(document)
    return render_assembly(verified).encode(), source, verified.sha256


def qualify(directory):
    from tools.qualify_hia_selfhost import build_seed, compile_stage, invoke
    directory = Path(directory); directory.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.hia.selfhost-owned-runtime-qualification.v1", "status": "started",
        "profile": PROFILE, "runtime_assumptions": list(RUNTIME_ASSUMPTIONS),
        "scope": "native helper emission/execution and independent canonical Core fixtures; no owned selfhost admission",
        "selfhost_owned_opcodes_admitted": False, "full_core_closed": False,
        "universal_refinement_proved": False, "default_allocator_profile_changed": False,
        "native_failure_sequence_equivalent_to_vm_injection": False, "fragments": fragment_manifest()}
    try:
        report["reference"] = run_reference()
        cases = native_cases()
        assembly, author, core_digest = author_document(cases)
        (directory / "helper-author.py.txt").write_text(author)
        (directory / "helper-author.hiaasm").write_bytes(assembly)
        report["helper_author"] = {"source_sha256": sha256(assembly).hexdigest(), "core_sha256": core_digest,
                                   "source_bytes": len(assembly)}
        seed, report["seed"] = build_seed(directory)
        native_author, report["native_author_build"] = compile_stage(directory, "native-helper-author", seed,
            assembly, image_format="seed-shared")
        native = []
        for number, case in enumerate(cases):
            image, build = compile_stage(directory, "emit-" + case.name, native_author, bytes([number]))
            observed, output = invoke(directory, "run-" + case.name, image, b"", capacity=64,
                workspace_size=0, output_initial=bytes(64), observe_trap_writes=True)
            if case.trap:
                success = (observed.get("status") == "child_failed" and observed.get("returncode") == -4
                           and len(output) == 64 and output == bytes(64))
            else:
                expected = b"".join(value.to_bytes(8, "little") for value in case.expected).ljust(64, b"\0")
                success = (observed.get("status") == "returned" and observed.get("core_u32") == 0
                           and observed.get("source_unchanged") and output == expected)
            native.append({"name": case.name, "expected": case.expected, "expected_trap": case.trap,
                           "build": build, "observation": observed, "output_hex": output.hex(), "pass": bool(success)})
            report["native"] = native
            if not success:
                raise AssertionError(native[-1])
        report["status"] = "PASS_CONDITIONAL_RUNTIME_HELPERS_ONLY"
        report["remaining"] = ["owned type/opcode admission and effect accounting",
            "multiple-output parser and resource transitions on every CFG edge",
            "default-profile allocator ABI decision; syscall helper assumptions differ from libc",
            "general multi-result function/call/return ABI (existing function result area is too small)",
            "same-source self-bootstrap, mutation, negative/cold replay after actual integration",
            "general Core and machine refinement proofs"]
    finally:
        report["source_files"] = {path: sha256((ROOT / path).read_bytes()).hexdigest() for path in (
            "tools/hia_selfhost_owned_runtime.py", "tools/hia_selfhost_owned_cases.py",
            "tools/qualify_hia_selfhost_owned_runtime.py", "tools/generate_hia_selfhost.py",
            "examples/hia_bootstrap/selfhost.hiaasm", "hepta/hia_program_runtime.py",
            "hepta/hia_program.py", "tools/hia_selfhost_child.py")}
        (directory / "qualification.json").write_text(wire(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = qualify(args.output)
    print(wire({"status": report["status"], "native_cases": len(report["native"]),
                "reference_cases": len(report["reference"]["cases"]),
                "negative_cases": len(report["reference"]["rejections"]), "output": str(args.output)}), end="")


if __name__ == "__main__":
    main()
