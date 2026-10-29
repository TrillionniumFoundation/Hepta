#!/usr/bin/env python3
"""Retain actual scalar lowering SMT queries, results and adversarial controls."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hepta.hia_program import WIDTHS, verify_program  # noqa: E402
from hepta.hia_program_llvm import emit_program_llvm  # noqa: E402
from hepta.hia_scalar_lowering_check import ScalarLoweringRejected, verify_scalar_lowering  # noqa: E402


def _program(operation, argument_types, result, attrs=None, *, version=1):
    parameters = [{"name": f"a{i}", "type": typ} for i, typ in enumerate(argument_types)]
    effects = ["trap"] if "checked" in operation or attrs == {"mode": "checked"} else []
    return {"schema": f"hepta.hia.program.v{version}", "module": "scalar_lowering_obligation",
            "functions": [{"name": "selected", "params": parameters, "returns": [result],
            "effects": effects, "entry": "entry", "blocks": [{"id": "entry", "params": parameters,
            "ops": [{"op": operation, "args": [p["name"] for p in parameters],
                     "out": [{"name": "result", "type": result}], "attrs": attrs or {}}],
            "term": {"op": "ret", "values": ["result"]}}]}]}


def obligation_programs():
    """Fixed per-op/type matrix; each solver obligation quantifies over inputs.

    This is a finite inventory of lowering shapes, not a theorem for all
    programs of an instruction set or a finite sampling of operand values.
    """
    result = []
    binary = [f"int.{op}.{mode}" for op in ("add", "sub", "mul") for mode in ("wrap", "checked")]
    binary += [f"int.{op}.checked" for op in ("div", "rem", "shl", "shr")]
    binary += ["bit.and", "bit.or", "bit.xor"]
    for typ in sorted(WIDTHS):
        for op in binary:
            result.append((f"{typ}-{op}", _program(op, [typ, typ], typ)))
        for op in ("bit.not", "int.neg.checked"):
            result.append((f"{typ}-{op}", _program(op, [typ], typ)))
        for op in ("eq", "ne", "lt", "le", "gt", "ge"):
            result.append((f"{typ}-compare.{op}", _program(f"compare.{op}", [typ, typ], "bool")))
        result.append((f"{typ}-select", _program("select", ["bool", typ, typ], typ)))
        result.append((f"{typ}-const", _program("const", [], typ, {"value": 0})))
        for destination in sorted(WIDTHS):
            for mode in ("wrap", "checked"):
                result.append((f"{typ}-to-{destination}-{mode}",
                               _program("int.cast", [typ], destination, {"mode": mode})))
    for op in ("bool.not", "bool.and", "bool.or", "compare.eq", "compare.ne"):
        result.append((op, _program(op, ["bool"] * (1 if op == "bool.not" else 2), "bool")))
    for typ, value in (("bool", False), ("bool", True), ("unit", None)):
        result.append((f"{typ}-const-{value}", _program("const", [], typ, {"value": value})))
    result.append(("bool-select", _program("select", ["bool", "bool", "bool"], "bool")))
    # Unit is an internal scalar representation, not a native input ABI.
    unit = _program("select", ["bool"], "unit")
    unit_block = unit["functions"][0]["blocks"][0]
    unit_block["ops"][0]["args"] = ["a0", "yes", "no"]
    unit_block["ops"] = [{"op": "const", "args": [], "out": [{"name": name, "type": "unit"}],
                           "attrs": {"value": None}} for name in ("yes", "no")] + unit_block["ops"]
    result.append(("unit-select-internal", unit))
    result.append(("acyclic-branch-and-phi", branch_program()))
    # A chain of two checked operations exercises first abort and continuation,
    # not just a single return-value expression. Keep every primitive identity.
    for version in range(1, 9):
        program = _program("int.add.checked", ["i64", "i64"], "i64", version=version)
        block = program["functions"][0]["blocks"][0]
        block["ops"].append({"op": "int.div.checked", "args": ["result", "a1"],
                             "out": [{"name": "quotient", "type": "i64"}], "attrs": {}})
        block["term"]["values"] = ["quotient"]
        result.append((f"v{version}-composed-checked-add-div", program))
    return result


def branch_program():
    program = _program("compare.lt", ["u32", "u32"], "bool")
    fn = program["functions"][0]
    fn["returns"] = ["u32"]
    fn["blocks"][0]["term"] = {"op": "branch", "cond": "result",
                              "then": {"target": "yes", "args": ["a0"]},
                              "else": {"target": "no", "args": ["a1"]}}
    for name in ("yes", "no"):
        fn["blocks"].append({"id": name, "params": [{"name": name + "Value", "type": "u32"}],
                             "ops": [], "term": {"op": "jump", "target": "join", "args": [name + "Value"]}})
    fn["blocks"].append({"id": "join", "params": [{"name": "chosen", "type": "u32"}],
                         "ops": [], "term": {"op": "ret", "values": ["chosen"]}})
    return program


def _write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _source():
    names = ["hepta/hia_scalar_lowering_check.py", "tools/qualify_hia_scalar_lowering.py",
             "hepta/hia_program.py", "hepta/hia_program_runtime.py", "hepta/hia_program_llvm.py",
             "hepta/hia_optimization.py", "hepta/hia_schema.py"]
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in names}


def qualify(output, expected_head):
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)
    if head != expected_head or status:
        raise ValueError("qualification requires the exact clean expected source; "
                         f"expected={expected_head}, observed={head}, status={status!r}")
    output.mkdir(parents=True, exist_ok=False)
    before = _source()
    started = time.monotonic_ns()
    registration = {"schema": "hepta.hia.scalar-lowering-protocol.v1", "head": head,
                    "source": before, "timeout_ms": 5000,
                    "matrix": [name for name, _ in obligation_programs()],
                    "negative_controls": ["wrong_add", "missing_divisor_guard", "wrong_signed_shift", "wrong_cfg_branch", "unchecked_nsw"],
                    "native_execution": False, "profile_is_whole_language": False}
    _write(output / "registration.json", registration)
    rows = []
    for index, (name, program) in enumerate(obligation_programs()):
        checked = verify_program(program)
        ir = emit_program_llvm(checked)
        prefix = f"obligation-{index:03d}"
        (output / (prefix + ".hia.json")).write_bytes(checked.canonical_bytes)
        (output / (prefix + ".ll")).write_text(ir.text)
        report = verify_scalar_lowering(checked)
        (output / (prefix + ".smt2")).write_text(report.pop("smtlib") + "\n(check-sat)\n")
        report["name"] = name
        report["artifact_prefix"] = prefix
        _write(output / (prefix + ".json"), report)
        rows.append(report)
        _write(output / "progress.json", {"completed": len(rows), "last": name,
                                         "last_status": report["status"]})
    controls = []
    mutations = [
        ("wrong_add", _program("int.add.wrap", ["u32", "u32"], "u32"), " = add i32 ", " = sub i32 "),
        ("missing_divisor_guard", _program("int.div.checked", ["u32", "u32"], "u32"),
         " = icmp ne i32 %p_0_1, 0", " = icmp eq i32 %p_0_1, %p_0_1"),
        ("wrong_signed_shift", _program("int.shr.checked", ["i32", "i32"], "i32"), " = ashr i32 ", " = lshr i32 "),
        ("wrong_cfg_branch", branch_program(), " = icmp ult i32 ", " = icmp ugt i32 "),
        ("unchecked_nsw", _program("int.add.wrap", ["u32", "u32"], "u32"), " = add i32 ", " = add nsw i32 "),
    ]
    for name, program, old, new in mutations:
        checked = verify_program(program)
        original = emit_program_llvm(checked).text
        changed = original.replace(old, new)
        if changed == original:
            raise ValueError("negative control did not alter actual emitter output")
        (output / (name + ".ll")).write_text(changed)
        try:
            result = verify_scalar_lowering(checked, llvm_text=changed)
            (output / (name + ".smt2")).write_text(result.pop("smtlib") + "\n(check-sat)\n")
        except ScalarLoweringRejected as error:
            result = {"status": "rejected_profile", "reason": str(error)}
        controls.append({"name": name, **result})
    after = _source()
    final_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    final_status = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)
    passed = (all(row["verified"] for row in rows) and
              [row["status"] for row in controls] == ["refuted", "refuted", "refuted", "refuted", "rejected_profile"] and
              before == after and final_head == head and not final_status)
    report = {"schema": "hepta.hia.scalar-lowering-qualification.v1", "passed": passed,
              "source_commit": head, "source_unchanged": before == after and final_head == head and not final_status,
              "obligations": len(rows), "verified": sum(row["verified"] for row in rows),
              "unknown": sum(row["status"] == "unknown" for row in rows),
              "refuted": sum(row["status"] == "refuted" for row in rows),
              "negative_controls": controls, "wall_ns": time.monotonic_ns() - started,
              "scope": "Finite lowering-shape inventory; each SMT query covers all typed inputs of its selected emitted internal body.",
              "limits": ["Core encoder, LLVM subset parser and Z3 remain trusted.",
                         "No theorem for arbitrary programs, resource instructions, loops, C ABI, or machine code.",
                         "No production admission authority; no native execution is claimed."]}
    for start in range(0, len(rows), 25):
        (output / f"obligations-{start // 25:02d}.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows[start:start + 25]))
    _write(output / "qualification.json", report)
    manifest = {str(path.relative_to(output)): {"bytes": path.stat().st_size,
                "sha256": sha256(path.read_bytes()).hexdigest()}
                for path in sorted(output.iterdir()) if path.is_file()}
    _write(output / "manifest.json", manifest)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    args = parser.parse_args()
    output_was_new = not args.output.exists()
    try:
        report = qualify(args.output, args.expected_head)
    except Exception as error:
        failure = {"schema": "hepta.hia.scalar-lowering-qualification.v1", "passed": False,
                   "expected_head": args.expected_head, "error": f"{type(error).__name__}: {error}",
                   "traceback": traceback.format_exc()}
        if output_was_new and args.output.is_dir():
            _write(args.output / "failure.json", failure)
        print(json.dumps(failure))
        return 2
    print(json.dumps({key: report[key] for key in ("passed", "source_commit", "obligations", "verified", "unknown", "refuted")}))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
