#!/usr/bin/env python3
"""Qualify the closed CMOVNE register leaf extension against actual supplied ELF.

No linker metadata is mutated and no unsupported artifact is executed. Positive
proofs quantify over the existing Safe Core caller contract. Native witnesses
are finite corroboration; neither kind proves a compiler or its extension.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.machinery
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
U64 = (1 << 64) - 1
WIDTHS = {"u8": 8, "u32": 32, "u64": 64, "usize": 64, "bool": 1}
LINK_FLAGS = ["-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
              "-z", "relro", "-z", "now", "--hash-style=both", "--build-id=none"]


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def checked_program(params, ops, result="answer", return_type="u64"):
    from hepta.hia_program import verify_program
    parameters = [{"name": name, "type": typ} for name, typ in params]
    return verify_program({"schema": "hepta.hia.program.v8", "module": "cmovne_leaf",
        "functions": [{"name": "choose", "params": parameters, "returns": [return_type],
            "effects": [], "entry": "entry", "blocks": [{"id": "entry",
                "params": parameters, "ops": ops, "term": {"op": "ret", "values": [result]}}]}]})


def instruction(opcode, args, name, typ="u64", attrs=None):
    return {"op": opcode, "args": args, "out": [{"name": name, "type": typ}],
            "attrs": {} if attrs is None else attrs}


def selection_core(typ="u64", alias=False):
    params = [("condition", "bool"), ("yes", typ), ("no", typ)]
    return checked_program(params, [instruction("select", ["condition", "yes", "yes" if alias else "no"],
                                                "answer", typ)], return_type=typ)


def flags_core(kind):
    if kind == "zf_preserved":
        return checked_program([("condition", "bool"), ("yes", "u64"), ("no", "u64")], [
            instruction("select", ["condition", "yes", "no"], "first"),
            instruction("select", ["condition", "no", "yes"], "second"),
            instruction("int.add.wrap", ["first", "second"], "answer")])
    return checked_program([("left", "u64"), ("right", "u64")], [
        instruction("compare.ne", ["left", "right"], "different", "bool"),
        instruction("select", ["different", "left", "right"], "picked"),
        instruction("const", [], "one", attrs={"value": 1}),
        instruction("int.add.wrap", ["picked", "one"], "incremented"),
        instruction("compare.lt", ["left", "right"], "less", "bool"),
        instruction("select", ["less", "incremented", "picked"], "answer")])


def producer_object(core):
    from hepta.hia_machine_plan import MACHINE_V3
    from hepta.hia_program_native import emit_program_machine
    plan = {"schema": MACHINE_V3, "core_sha256": core.sha256, "block_order": {},
        "function_order": ["choose"], "scratch_registers": {"r10": "r10", "r11": "r11"},
        "instruction_selection": {"move_immediate": "movabs", "alu_immediate": "imm32",
                                  "scalar_select": "cmov_scalar"},
        "function_alignment": 1, "value_registers": {}}
    image = emit_program_machine(core, machine_plan=plan)
    return image.object_bytes, plan


def leaf_object(kind):
    """Emit normal two-function/import shape; vary only leaf instructions."""
    from hepta.hia_machine_elf import write_elf_object
    from hepta.hia_machine_x64 import Code
    code = Code()
    if kind == "cf_preserved":
        code.mov_rr("rax", "rsi")
        code.cmp("rdi", "rsi")
        code.cmov("ne", "rax", "rdi")
        code.jcc("ae", "done")
        code.alu_imm("add", "rax", 1)
        code.label("done")
    elif kind == "zf_preserved":
        code.alu_imm("and", "rdi", 1)
        for dst, src in (("rax", "rdx"), ("rcx", "rsi"), ("r8", "rsi"), ("r9", "rdx")):
            code.mov_rr(dst, src)
        code.test("rdi", "rdi")
        code.cmov("ne", "rax", "rcx")
        code.cmov("ne", "r8", "r9")
        code.add("rax", "r8")
    else:
        if kind != "missing_bool_mask":
            code.alu_imm("and", "rdi", 1)
        dst, src = {"rex_b": ("rax", "r8"), "rex_r": ("r8", "rax"),
                    "rex_rb": ("r8", "r9"), "alias_low": ("rax", "rax"),
                    "alias_high": ("r8", "r8"), "saved_r12": ("r12", "rsi"),
                    "clobbered_r12": ("r12", "rsi")}.get(kind, ("rax", "rcx"))
        if kind == "saved_r12":
            code.push("r12")
        code.mov_rr(dst, "rsi" if kind.startswith("alias_") else "rdx")
        if src != dst:
            code.mov_rr(src, "rsi")
        if kind == "swapped_values":
            code.mov_rr(dst, "rsi")
            code.mov_rr(src, "rdx")
        elif kind == "narrow_true_value":
            code.alu_imm("and", src, 255)
        code.test("rdi", "rdi")
        if kind == "clobbered_zf":
            code.test(dst, dst)
        if kind == "wrong_rex_destination":
            code.mov_rr("r8", "rdx")
            code.cmov("ne", "r8", src)
        elif kind == "unsupported_cmove":
            code.cmov("e", dst, src)
        elif kind == "unsupported_32bit":
            code.emit(bytes.fromhex("0f45c1"))
        elif kind == "unsupported_memory":
            code.emit(bytes.fromhex("480f458e00000000"))
        else:
            code.cmov("ne", dst, src)
        if dst != "rax":
            code.mov_rr("rax", dst)
        if kind == "saved_r12":
            code.pop("r12")
    code.ret()
    # This unreachable ordinary abort site retains the established artifact
    # profile. Its bytes are decoded; native witness control never reaches it.
    code.call("abort")
    code.emit(b"\x0f\x0b")
    wrapper = code.offset
    code.push("rbp")
    code.mov_rr("rbp", "rsp")
    code.call("__hia_native_fn_0")
    code.emit(b"\xc9")
    code.ret()
    text, relocations = code.finalize()
    symbols = [{"name": "__hia_native_fn_0", "offset": 0, "size": wrapper, "global": False},
               {"name": "choose", "offset": wrapper, "size": len(text) - wrapper, "global": True}]
    return write_elf_object(text, symbols, relocations)


def cases():
    rows = [{"id": "producer_" + typ, "kind": "producer", "type": typ,
             "expected": "smt_validated"} for typ in WIDTHS]
    rows.extend({"id": kind, "kind": kind, "type": "u64", "expected": "smt_validated"}
                for kind in ("rex_b", "rex_r", "rex_rb", "alias_low", "alias_high",
                             "saved_r12", "zf_preserved", "cf_preserved"))
    rows.extend({"id": kind, "kind": kind, "type": "u64", "expected": "refuted"}
                for kind in ("swapped_values", "missing_bool_mask", "clobbered_zf",
                             "narrow_true_value", "wrong_rex_destination", "clobbered_r12"))
    rows.extend({"id": kind, "kind": kind, "type": "u64", "expected": "unsupported"}
                for kind in ("unsupported_cmove", "unsupported_32bit", "unsupported_memory"))
    return rows


def case_core(case):
    return (flags_core(case["kind"]) if case["kind"] in {"zf_preserved", "cf_preserved"}
            else selection_core(case["type"], case["kind"].startswith("alias_")))


def witness_vectors(case):
    pairs = [(0, U64), (U64, 0), (1, 2), (1 << 63, (1 << 63) - 1),
             (1 << 32, (1 << 32) - 1), (255, 256), (0, 0), (U64, U64)]
    if case["kind"] == "cf_preserved":
        return [list(pair) for pair in pairs + [(2, 1), (1, 1), (U64 - 1, U64), (U64, U64 - 1)]]
    return [[condition, left, right] for condition in (0, 1, 2, 3, U64) for left, right in pairs]


def mathematical_result(case, vector):
    kind = case["kind"]
    if kind == "cf_preserved":
        left, right = vector
        return (left + (1 if left < right else 0)) & U64
    condition, yes, no = vector
    if kind == "zf_preserved":
        return (yes + no) & U64
    value = yes if kind.startswith("alias_") or condition & 1 else no
    return value & ((1 << WIDTHS[case["type"]]) - 1)


def decoder_refusals():
    return {
        "no_rex_32bit": "0f45c1", "rex_without_w": "400f45c1",
        "operand_size_16bit": "660f45c1", "rex_x": "4a0f45c1",
        "memory_indirect": "480f4501", "memory_disp8": "480f454100",
        "memory_disp32": "480f458100000000", "memory_sib": "480f45842400000000",
        "memory_rip_relative": "480f450500000000", "cmove": "480f44c1",
        "cmovb": "480f42c1", "cmovg": "480f4fc1", "lock_prefix": "f0480f45c1",
        "double_rex": "48480f45c1", "truncated_escape": "480f",
        "truncated_modrm": "480f45", "unreachable_unsupported": "c3480f44c1",
    }


def qualify_decoder():
    from hepta.hia_safe_core_x64 import decode, SafeCoreMachineRejected
    accepted, refused = [], []
    for destination in range(16):
        for source in range(16):
            raw = bytes([0x48 | ((destination >> 3) << 2) | (source >> 3), 0x0f, 0x45,
                         0xc0 | ((destination & 7) << 3) | (source & 7)])
            decoded = decode(raw)
            instruction = decoded[0]
            if (len(decoded), instruction.op, instruction.args, instruction.size) != (
                    1, "cmovne", (destination, source), 4):
                raise AssertionError("CMOVNE register decode differs from the operand bit fields")
            accepted.append({"bytes": raw.hex(), "destination": destination, "source": source})
    for name, encoded in decoder_refusals().items():
        try:
            decode(bytes.fromhex(encoded))
        except SafeCoreMachineRejected as exc:
            refused.append({"id": name, "bytes": encoded, "status": "unsupported", "error": str(exc)})
        else:
            raise AssertionError("unreviewed CMOV encoding accepted: " + name)
    return {"register_combinations": accepted, "refusals": refused,
            "decoder_only_does_not_authorize_native_execution": True}


def source_files():
    paths = list((ROOT / "hepta").glob("*.py")) + [Path(__file__).resolve(),
        ROOT / "tools/hia_safe_core_cmovne_child.py"]
    return {str(path.relative_to(ROOT)): {"sha256": sha256(path.read_bytes()).hexdigest(),
                                         "bytes": path.stat().st_size} for path in sorted(paths)}


def cache_state(output):
    prefix = output / "empty-bytecode-cache"
    if (not sys.dont_write_bytecode or sys.pycache_prefix is None or
            Path(sys.pycache_prefix).resolve() != prefix.resolve()):
        raise RuntimeError("qualification requires its fresh isolated bytecode prefix and -B")
    entries = sorted(str(path.relative_to(prefix)) for path in prefix.rglob("*") if path.is_file())
    if entries:
        raise RuntimeError("isolated bytecode cache is not empty")
    return {"dont_write_bytecode": True, "isolated_prefix": str(prefix), "cache_files": entries}


def qualified_case(case, output, linker):
    from hepta.hia_safe_core import validate_safe_core_artifact, SafeCoreRejected
    from hepta.hia_safe_core_x64 import decode, SafeCoreMachineRejected
    directory = output / case["id"]
    directory.mkdir()
    core = case_core(case)
    write_json(directory / "core.json", core.as_dict())
    if case["kind"] == "producer":
        object_bytes, plan = producer_object(core)
        write_json(directory / "machine-plan.json", plan)
    else:
        object_bytes = leaf_object(case["kind"])
    object_path, image_path = directory / "subject.o", directory / "subject.so"
    object_path.write_bytes(object_bytes)
    command = [linker, *LINK_FLAGS, str(object_path), "-lc", "-o", str(image_path)]
    process = subprocess.run(command, text=True, capture_output=True, timeout=30, check=False)
    write_json(directory / "link.json", {"command": command, "returncode": process.returncode,
                                         "stdout": process.stdout, "stderr": process.stderr})
    if process.returncode:
        raise RuntimeError("normal leaf link failed: " + case["id"])
    final_bytes = image_path.read_bytes()
    row = {**case, "core_sha256": core.sha256, "object_sha256": sha256(object_bytes).hexdigest(),
           "final_image_sha256": sha256(final_bytes).hexdigest(), "native_calls": 0}
    try:
        proof = validate_safe_core_artifact(core, object_bytes, final_bytes,
                                           query_directory=directory / "queries")
    except SafeCoreRejected as exc:
        row.update(status=(exc.validation or {}).get("status", "rejected"), error=str(exc),
                   counterexample=exc.counterexample)
        write_json(directory / "validation.json", {"error": str(exc), "validation": exc.validation,
                                                    "counterexample": exc.counterexample})
        if (case["expected"] != "refuted" or row["status"] != "refuted" or
                exc.counterexample is None or not exc.validation or exc.validation["ok"]):
            raise
        expected_obligation = ("sysv_stack_alignment_and_preservation" if case["kind"] == "clobbered_r12"
                               else "core_to_final_image_return_abort_and_caller_bytes")
        if exc.counterexample["obligation"] != expected_obligation:
            raise AssertionError("negative subject failed a different property")
    except SafeCoreMachineRejected as exc:
        row.update(status="unsupported", error=str(exc))
        write_json(directory / "validation.json", {"status": "unsupported", "error": str(exc),
                                                    "proof_issued": False})
        if case["expected"] != "unsupported":
            raise
    else:
        write_json(directory / "validation.json", proof)
        if case["expected"] != "smt_validated" or proof["status"] != "smt_validated" or not proof["complete"]:
            raise AssertionError("negative subject unexpectedly obtained a proof")
        row["status"] = proof["status"]
        start = proof["image_binding"]["linked_text_file_offset"]
        # The bound decoder records are a review aid, never an alternative to
        # the independent validator's exact final-byte computation.
        from hepta.hia_safe_core_elf import bind_final_artifact
        binding = bind_final_artifact(object_bytes, final_bytes, "choose")
        instructions = decode(binding["text"])
        cmovs = [{"offset": at, "file_offset": start + at, "bytes": binding["text"][at:at + ins.size].hex(),
                  "destination": ins.args[0], "source": ins.args[1]}
                 for at, ins in instructions.items() if ins.op == "cmovne"]
        if not cmovs:
            raise AssertionError("positive subject has no actual CMOVNE bytes")
        row["cmovne_instructions"] = cmovs
        vectors = witness_vectors(case)
        request = {"image": str(image_path), "image_sha256": row["final_image_sha256"],
                   "argument_count": len(vectors[0]), "vectors": vectors}
        write_json(directory / "native-request.json", request)
        native_command = [sys.executable, "-B", str(ROOT / "tools/hia_safe_core_cmovne_child.py")]
        native = subprocess.run(native_command, input=json.dumps(request), text=True, capture_output=True,
                                timeout=15, check=False, env=dict(os.environ))
        write_json(directory / "native-process.json", {"command": native_command, "returncode": native.returncode,
                                                       "stdout": native.stdout, "stderr": native.stderr})
        if native.returncode:
            raise AssertionError("native leaf witness failed: " + case["id"])
        observed = json.loads(native.stdout)
        expected = [mathematical_result(case, vector) for vector in vectors]
        if (observed["image_sha256"] != row["final_image_sha256"] or observed["vectors"] != vectors or
                observed["results"] != expected):
            raise AssertionError("native leaf differs from independent integer selection semantics")
        write_json(directory / "native-expected.json", {"results": expected, "finite_witnesses_only": True})
        row["native_calls"] = len(vectors)
    if row["status"] != case["expected"]:
        raise AssertionError("unexpected subject status")
    write_json(directory / "result.json", row)
    return row


def worker(output, linker):
    # No project module has been imported before this startup assertion. Python
    # reads caches from this fresh prefix, so stale adjacent __pycache__ files
    # cannot substitute for the source bytes identified below.
    before_cache = cache_state(output)
    before = source_files()
    sys.path.insert(0, str(ROOT))
    started = time.monotonic()
    write_json(output / "source-before.json", before)
    write_json(output / "decoder.json", qualify_decoder())
    rows = []
    for case in cases():
        rows.append(qualified_case(case, output, linker))
        write_json(output / "progress.json", rows)
    imports = {}
    for name, module in sorted(sys.modules.items()):
        if name == "hepta" or name.startswith("hepta.") or name == "z3" or name.startswith("z3."):
            origin = Path(module.__file__).resolve()
            if origin.suffix != ".py" or not isinstance(module.__loader__, importlib.machinery.SourceFileLoader):
                raise AssertionError("unexpected project/solver import loader")
            imports[name] = {"path": str(origin), "sha256": sha256(origin.read_bytes()).hexdigest(),
                             "loader": type(module.__loader__).__name__}
    after = source_files()
    if before != after:
        raise AssertionError("qualification source changed during execution")
    write_json(output / "source-imports.json", imports)
    cache_after = cache_state(output)
    summary = {"schema": "hepta.hia.safe-core-cmovne-qualification.v1", "status": "PASS",
        "subject_scope": "the listed exact Safe Core/scalar leaf object and final image pairs",
        "claim": "existing all-input independent-model refinement obligations, under their unchanged assumptions",
        "whole_compiler_or_original_agent_delta_proved": False,
        "original_agent_four_claim_gate": "HOLD", "hardware_isa_refinement_proved": False,
        "source_identity": before, "source_only_imports": {"before": before_cache, "after": cache_after},
        "environment": {"python": sys.version, "platform": platform.platform(), "linker": linker},
        "cases": rows, "counts": {"smt_validated": sum(row["status"] == "smt_validated" for row in rows),
            "refuted": sum(row["status"] == "refuted" for row in rows),
            "unsupported": sum(row["status"] == "unsupported" for row in rows),
            "native_calls": sum(row["native_calls"] for row in rows),
            "decoded_register_combinations": 256, "decoder_refusals": len(decoder_refusals())},
        "elapsed_seconds": time.monotonic() - started}
    write_json(output / "qualification.json", summary)
    print(json.dumps({"status": summary["status"], "counts": summary["counts"]}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--linker", default="ld")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    output = args.output.resolve()
    linker = shutil.which(args.linker)
    if linker is None:
        raise RuntimeError("linker is unavailable")
    if args.worker:
        worker(output, linker)
        return
    output.mkdir(parents=True, exist_ok=False)
    prefix = output / "empty-bytecode-cache"
    prefix.mkdir()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPYCACHEPREFIX=str(prefix))
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", "--output", str(output),
               "--linker", linker]
    process = subprocess.run(command, text=True, capture_output=True, timeout=180, check=False,
                             cwd=ROOT, env=env)
    write_json(output / "worker-process.json", {"command": command, "returncode": process.returncode,
        "stdout": process.stdout, "stderr": process.stderr, "isolated_bytecode_prefix": str(prefix)})
    print(process.stdout, end="")
    if process.returncode:
        print(process.stderr, end="", file=sys.stderr)
        raise SystemExit(process.returncode)


if __name__ == "__main__":
    main()
