"""Check a real standalone HIA u32 program against a fixed external Lean spec.

The independent Lean machine consumes an exported register instruction list.
The receipt binds that list to actual verified HIA bytes, the exporter, model,
proof checker and retained positive/negative outputs. Exporter correctness and
LLVM/native refinement are explicitly not machine-proved by this experiment.
"""
from __future__ import annotations

import argparse
import copy
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_program import verify_core
from hepta.hia_program_runtime import execute_program
from tools.evidence_checks import normalized_errors, strict_equal

SCHEMA = "hepta.hia.selected-formal.v1"
MODEL = ROOT / "formal/HiaSelectedCore.lean"
SELECTED = ROOT / "formal/selected_u32_bias.hia.json"
THEOREMS = frozenset({"run_append", "selected_program_correct"})
MUTATIONS = ("first_add_becomes_sub", "return_first_argument")
CLAIMS = {
    "selected_imported_program_all_u32_inputs_proved": True,
    "actual_core_operations_reverified_before_export": True,
    "independent_lean_register_semantics_used": True,
    "changed_actual_core_rejected_against_fixed_specification": True,
    "python_exporter_refinement_proved": False,
    "python_verifier_soundness_proved": False,
    "llvm_or_native_refinement_proved": False,
    "whole_language_soundness_proved": False,
    "resource_lifetimes_or_concurrency_proved": False,
}
LIMITS = [
    "The all-input theorem concerns the generated Lean Program under the independent Lean semantics.",
    "The Python exporter-to-HIA correspondence is audited and hash-bound, not proved by Lean.",
    "The selected profile is one straight-line function with two u32 inputs, u32 constants, wrapping add/sub and one u32 return.",
    "Memory, borrowing, resource cancellation, control-flow loops, FFI and concurrent programs are outside this theorem.",
    "Optional native execution is a finite differential check and does not prove LLVM/native refinement.",
    "Lean standard libraries/runtime, the kernel executable and host are trusted; receipts do not attest a hostile producer.",
]
SPECIFICATION = "for all x,y : BitVec 32, result = x + y modulo 2^32"
SOURCE_FILES = (
    "formal/HiaSelectedCore.lean", "formal/toolchain-lock.json", "formal/proof-dependencies.txt",
    "tools/qualify_hia_selected_formal.py", "hepta/hia_program.py", "hepta/hia_opcodes.py", "hepta/hia_schema.py",
    "hepta/hia_program_runtime.py", "hepta/hia_bounded_memory.py", "tools/evidence_checks.py",
)


def digest(data):
    return sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _model_text():
    source = MODEL.read_text(encoding="utf-8")
    require(re.findall(r"(?m)^import ([^\n]+)$", source) == ["Lean.Elab.Tactic.Omega"],
            "unexpected Lean model import")
    require(re.search(r"(?m)^\s*(axiom|unsafe|opaque|constant|initialize|builtin_initialize|"
                      r"run_elab|run_cmd|elab|macro|syntax|set_option|#)\b|\bsorry\b", source) is None,
            "unreviewed Lean model declaration or placeholder")
    require(re.findall(r"(?m)^theorem (\w+)", source) == ["run_append"],
            "independent model theorem inventory changed")
    return source


def export_program(document):
    """Translate verified SSA to positional registers, never to a copied spec."""
    checked = verify_core(document)
    require(checked.structured_bytes is None, "selected proof requires an explicit standalone primitive Core")
    core = checked.as_dict()
    require(len(core["functions"]) == 1, "selected proof accepts exactly one function")
    fn = core["functions"][0]
    require(len(fn["params"]) == 2 and all(p["type"] == "u32" for p in fn["params"])
            and fn["returns"] == ["u32"] and fn["effects"] == [], "selected proof signature/effects differ")
    require(len(fn["blocks"]) == 1 and fn["blocks"][0]["term"]["op"] == "ret",
            "selected proof requires one straight-line return block")
    block = fn["blocks"][0]
    require(1 <= len(block["ops"]) <= 128, "selected proof instruction budget exceeded")
    registers = {p["name"]: index for index, p in enumerate(fn["params"])}
    emitted, mapping = [], []
    for index, operation in enumerate(block["ops"]):
        require(len(operation["out"]) == 1 and operation["out"][0]["type"] == "u32",
                "selected proof supports only one u32 result per instruction")
        opcode = operation["op"]
        require(opcode in {"const", "int.add.wrap", "int.sub.wrap"},
                "instruction is outside selected formal profile")
        operands = [registers[name] for name in operation["args"]]
        if opcode == "const":
            literal = operation["attrs"]["value"]
            emitted.append(f".literal (BitVec.ofNat 32 {literal})")
        else:
            emitted.append(f".{('add' if opcode == 'int.add.wrap' else 'sub')} {operands[0]} {operands[1]}")
        output = operation["out"][0]["name"]
        slot = len(registers)
        registers[output] = slot
        mapping.append({"operation_index": index, "hia_operation": copy.deepcopy(operation),
                        "operand_registers": operands, "result_register": slot,
                        "lean_operation": emitted[-1]})
    result = registers[block["term"]["values"][0]]
    model = _model_text()
    generated = model + "\nnamespace HiaSelectedCore\n"
    generated += "def selectedProgram : Program := {\n  code := [" + ", ".join(emitted)
    generated += f"],\n  result := {result}\n}}\n"
    generated += (
        "theorem selected_program_correct (x y : Word) :\n"
        "    execute selectedProgram [x, y] = some (specification x y) := by\n"
        "  simp [selectedProgram, execute, run, executeOne, evaluate, read, specification, BitVec.add_sub_cancel]\n"
        "end HiaSelectedCore\n"
        "#print axioms HiaSelectedCore.run_append\n"
        "#print axioms HiaSelectedCore.selected_program_correct\n"
    )
    return checked, generated, {"function": fn["name"], "input_registers": [0, 1],
                                "instructions": mapping, "result_register": result}


def mutation_documents(core):
    changed = copy.deepcopy(core)
    operations = changed["functions"][0]["blocks"][0]["ops"]
    additions = [op for op in operations if op["op"] == "int.add.wrap"]
    require(additions, "selected negative control requires a real wrapping add")
    additions[0]["op"] = "int.sub.wrap"
    returned = copy.deepcopy(core)
    fn = returned["functions"][0]
    fn["blocks"][0]["term"]["values"] = [fn["params"][0]["name"]]
    return dict(zip(MUTATIONS, (changed, returned)))


def theorem_dependencies(log, *, broken=False):
    found = re.findall(r"^'HiaSelectedCore\.([^']+)' depends on axioms: \[([^\]]*)\]$", log, re.M)
    found += [(name, "") for name in re.findall(r"^'HiaSelectedCore\.([^']+)' does not depend on any axioms$", log, re.M)]
    require(len(found) == 2 and {name for name, _ in found} == THEOREMS,
            "Lean theorem dependency inventory differs")
    allowed = {"propext", "Quot.sound", "Classical.choice"} | ({"sorryAx"} if broken else set())
    result = {name: [part.strip() for part in text.split(",") if part.strip()] for name, text in found}
    require(all(set(used) <= allowed for used in result.values()), "unexpected theorem axioms")
    if not broken:
        require("error:" not in log and "sorryAx" not in log, "positive proof contains an error or placeholder")
    return result


def _source_identity():
    return {name: digest((ROOT / name).read_bytes()) for name in SOURCE_FILES}


def _support_identity(executable):
    root = executable.parent.parent
    names = ["lib/lean/libInit_shared.so", "lib/lean/libleanshared.so", "lib/lean/libleanshared_1.so"]
    names += ["lib/lean/" + value for value in (ROOT / "formal/proof-dependencies.txt").read_text().splitlines()
              if value and not value.startswith("#")]
    return {name: digest((root / name).read_bytes()) for name in names}


def _run_lean(executable, path):
    environment = dict(os.environ)
    environment.pop("LEAN_PATH", None)
    environment.pop("LEAN_SRC_PATH", None)
    environment["LEAN_SYSROOT"] = str(executable.parent.parent)
    result = subprocess.run([str(executable), str(path)], cwd=path.parent, env=environment,
                            capture_output=True, text=True, timeout=60)
    require(len(result.stdout) + len(result.stderr) <= 1048576, "Lean output budget exceeded")
    return {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
            "output_sha256": digest((result.stdout + result.stderr).encode())}


def native_case_arguments():
    boundaries = [0, 1, 2, 16, 17, 18, 65535, 65536, 2**31-1, 2**31, 2**32-2, 2**32-1]
    pairs = [[a, b] for a in boundaries for b in boundaries]
    rng = random.Random(20261026)
    pairs += [[rng.randrange(2**32), rng.randrange(2**32)] for _ in range(128)]
    return pairs


def _native(checked, clang, output):
    from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm

    ir = emit_program_llvm(checked)
    (output / "program.ll").write_text(ir.text, encoding="ascii")
    receipt = compile_program_llvm(ir, program=checked, output=output / "program.so", clang=clang)
    function = checked.as_dict()["functions"][0]["name"]
    native = getattr(ctypes.CDLL(str(output / "program.so")), function)
    native.argtypes, native.restype = [ctypes.c_uint32, ctypes.c_uint32], ctypes.c_uint32
    cases = []
    for a, b in native_case_arguments():
        expected = (a + b) & (2**32 - 1)
        vm = execute_program(checked, function, [a, b])["result"]
        observed = native(a, b)
        cases.append({"arguments": [a, b], "external_specification": expected,
                      "vm_result": vm, "native_result": observed})
        require(expected == vm == observed, "selected native/VM/specification disagreement")
    return {"performed": True, "passed": True, "cases_count": len(cases),
            "cases": cases, "compilation": receipt, "refinement_proved": False}


def qualify(lean, output_directory, *, core_path=SELECTED, clang=None):
    executable = Path(lean).resolve(strict=True)
    executable_sha = digest(executable.read_bytes())
    lock = json.loads((ROOT / "formal/toolchain-lock.json").read_bytes())
    require(executable_sha == lock["lean_binary_sha256"], "Lean must match the pinned binary SHA-256")
    source_bytes = Path(core_path).read_bytes()
    checked, generated, mapping = export_program(source_bytes)
    source_identity = _source_identity()
    support_identity = _support_identity(executable)
    output = Path(output_directory).absolute()
    output.mkdir(parents=True, exist_ok=False)
    (output / "source.hia.json").write_bytes(source_bytes)
    (output / "program.hia.json").write_bytes(checked.canonical_bytes)
    (output / "positive.lean").write_text(generated, encoding="utf-8")
    _json(output / "instruction-map.json", mapping)
    _json(output / "lean-support-files.json", support_identity)
    report = {"schema": SCHEMA, "ok": False, "status": "running",
              "source_sha256": digest(source_bytes), "core_sha256": checked.sha256,
              "generated_lean_sha256": digest(generated.encode()),
              "instruction_map_sha256": digest((output / "instruction-map.json").read_bytes()),
              "source_identity": source_identity, "lean_binary_sha256": executable_sha,
              "lean_support_manifest_sha256": digest((output / "lean-support-files.json").read_bytes()),
              "external_specification": SPECIFICATION,
              "input_domain_size": str(2**64), "claims": dict(CLAIMS), "limits": list(LIMITS),
              "negative_mutations": []}
    try:
        positive = _run_lean(executable, output / "positive.lean")
        report["positive"] = positive
        require(positive["returncode"] == 0, "Lean rejected selected actual Core: " + positive["stdout"] + positive["stderr"])
        report["theorems"] = theorem_dependencies(positive["stdout"] + positive["stderr"])
        for name, document in mutation_documents(checked.as_dict()).items():
            mutant, broken, _ = export_program(document)
            (output / (name + ".hia.json")).write_bytes(mutant.canonical_bytes)
            (output / (name + ".lean")).write_text(broken, encoding="utf-8")
            observation = _run_lean(executable, output / (name + ".lean"))
            log = observation["stdout"] + observation["stderr"]
            require(observation["returncode"] == 1 and "error:" in log,
                    "changed actual Core was not rejected by Lean: " + name)
            dependencies = theorem_dependencies(log, broken=True)
            require("sorryAx" in dependencies["selected_program_correct"],
                    "negative control did not reach the selected theorem")
            report["negative_mutations"].append({"mutation": name, "status": "rejected_as_expected",
                "core_sha256": mutant.sha256, "generated_lean_sha256": digest(broken.encode()),
                "theorems": dependencies, **observation})
        report["native"] = (_native(checked, clang, output) if clang is not None else
                            {"performed": False, "passed": False, "refinement_proved": False})
        require(_source_identity() == source_identity and digest(executable.read_bytes()) == executable_sha
                and _support_identity(executable) == support_identity,
                "proof source, exporter or checker support changed during qualification")
        report.update(ok=True, status="passed")
        validate_report(report, output)
    except Exception as exc:
        report.update(ok=False, status="failed", error=f"{type(exc).__name__}: {exc}")
        report["claims"] = {**CLAIMS,
            "selected_imported_program_all_u32_inputs_proved": False,
            "changed_actual_core_rejected_against_fixed_specification": False}
        _json(output / "qualification.json", report)
        raise
    _json(output / "qualification.json", report)
    return report


@normalized_errors
def validate_report(report, directory):
    """Recompute bound source/terms and check retained observations, not attestation."""
    directory = Path(directory)
    require(type(report) is dict and report.get("schema") == SCHEMA and report.get("ok") is True
            and report.get("status") == "passed", "selected formal status differs")
    checked, generated, mapping = export_program((directory / "source.hia.json").read_bytes())
    require((directory / "program.hia.json").read_bytes() == checked.canonical_bytes
            and report.get("core_sha256") == checked.sha256
            and report.get("source_sha256") == digest((directory / "source.hia.json").read_bytes())
            and (directory / "positive.lean").read_text() == generated
            and report.get("generated_lean_sha256") == digest(generated.encode()), "actual Core/Lean source binding differs")
    require(json.loads((directory / "instruction-map.json").read_text()) == mapping
            and report.get("instruction_map_sha256") == digest((directory / "instruction-map.json").read_bytes()),
            "instruction mapping differs from actual Core")
    require(report.get("source_identity") == _source_identity()
            and report.get("lean_binary_sha256") == json.loads((ROOT / "formal/toolchain-lock.json").read_text())["lean_binary_sha256"]
            and report.get("lean_support_manifest_sha256") == digest((directory / "lean-support-files.json").read_bytes()),
            "checker or source identity differs")
    require(strict_equal(report.get("claims"), CLAIMS) and report.get("limits") == LIMITS
            and report.get("external_specification") == SPECIFICATION
            and report.get("input_domain_size") == str(2**64), "selected proof scope changed")
    positive = report.get("positive", {})
    log = positive.get("stdout", "") + positive.get("stderr", "")
    require(type(positive.get("returncode")) is int and positive["returncode"] == 0
            and positive.get("output_sha256") == digest(log.encode())
            and theorem_dependencies(log) == report.get("theorems"), "positive kernel evidence differs")
    negative = report.get("negative_mutations", [])
    require(type(negative) is list and len(negative) == len(MUTATIONS)
            and {entry.get("mutation") for entry in negative} == set(MUTATIONS), "negative control denominator differs")
    for entry in negative:
        name = entry["mutation"]
        mutant, broken, _ = export_program(mutation_documents(checked.as_dict())[name])
        log = entry.get("stdout", "") + entry.get("stderr", "")
        require(entry.get("status") == "rejected_as_expected" and type(entry.get("returncode")) is int
                and entry["returncode"] == 1 and "error:" in log
                and entry.get("core_sha256") == mutant.sha256
                and entry.get("generated_lean_sha256") == digest(broken.encode())
                and (directory / (name + ".hia.json")).read_bytes() == mutant.canonical_bytes
                and (directory / (name + ".lean")).read_text() == broken
                and entry.get("output_sha256") == digest(log.encode())
                and theorem_dependencies(log, broken=True) == entry.get("theorems")
                and "sorryAx" in entry["theorems"]["selected_program_correct"], "changed-program rejection evidence differs")
    native = report.get("native", {})
    require(native.get("refinement_proved") is False, "native refinement claim is not justified")
    if native.get("performed") is True:
        from hepta.hia_program_llvm import emit_program_llvm

        regenerated = emit_program_llvm(checked)
        cases = native.get("cases", [])
        compilation = native.get("compilation", {})
        require(native.get("passed") is True and type(native.get("cases_count")) is int
                and native["cases_count"] == len(cases) == 272 and compilation.get("core_sha256") == checked.sha256
                and strict_equal([case["arguments"] for case in cases], native_case_arguments())
                and compilation.get("artifact_sha256") == digest((directory / "program.so").read_bytes())
                and compilation.get("llvm_ir_sha256") == digest((directory / "program.ll").read_bytes())
                == regenerated.sha256
                and compilation.get("implementation_sha256") == regenerated.implementation_sha256
                and (directory / "program.ll").read_text() == regenerated.text,
                "native artifact identity or differential denominator differs")
        for case in cases:
            a, b = case["arguments"]
            require(all(type(case[name]) is int for name in ("external_specification", "vm_result", "native_result"))
                    and case["external_specification"] == case["vm_result"] == case["native_result"]
                    == ((a + b) & (2**32 - 1)), "native finite result differs")
    else:
        require(native == {"performed": False, "passed": False, "refinement_proved": False},
                "unexpected unexecuted native claims")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lean", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--core", type=Path, default=SELECTED)
    parser.add_argument("--clang")
    args = parser.parse_args(argv)
    try:
        report = qualify(args.lean, args.output_directory, core_path=args.core, clang=args.clang)
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"ok": False, "status": "failed", "error": str(exc)}))
        return 2
    print(json.dumps({"ok": report["ok"], "status": report["status"],
                      "core_sha256": report["core_sha256"],
                      "negative_controls": len(report["negative_mutations"]),
                      "native_cases": report["native"].get("cases_count", 0)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
