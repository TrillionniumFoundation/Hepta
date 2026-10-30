#!/usr/bin/env python3
"""Exploratory codegen ablation; never an optimizer admission certificate.

Changing checked sums to wrapping sums changes semantics outside the benchmark's
finite input domain. This diagnostic deliberately labels that fact and does not
replace the benchmark or its thresholds. It attributes a generated-code cost.
"""
import argparse
import json
from pathlib import Path
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from hepta.hia_program_source import lower_source
from hepta.hia_program_llvm import emit_program_llvm, compile_program_llvm
from tools.qualify_hia_optimizer_bench import (KERNELS, CORRECTNESS_CHILD, correctness_cases,
    execute, identity, successful, timed_checksum, write_new)


def run(baseline_dir, output_dir, clang="/usr/bin/clang-20", objdump="/usr/bin/llvm-objdump-20"):
    baseline = Path(baseline_dir).absolute()
    out = Path(output_dir).absolute(); out.mkdir(parents=True, exist_ok=False)
    original_report = json.loads((baseline / "report.json").read_text())
    if identity(baseline / "hia.so") != original_report["artifacts_before"]["hia"] or identity(baseline / "driver") != original_report["driver_identity"]:
        raise ValueError("measured baseline artifacts changed")
    source = (baseline / "kernels.hepta").read_text()
    changed = source
    for owner in ("bytes", "second"):
        old = "total=total+(" + owner + "[i] as u64);"
        new = "total=wrapping_add(total," + owner + "[i] as u64);"
        if changed.count(old) != 1:
            raise ValueError("expected one reduction per kernel")
        changed = changed.replace(old, new)
    (out / "checked.hepta").write_text(source)
    (out / "wrapping.hepta").write_text(changed)
    plan = {"schema": "hepta.hia.codegen-ablation.v1", "baseline_report": identity(baseline / "report.json"),
            "baseline_library": identity(baseline / "hia.so"), "driver": identity(baseline / "driver"),
            "checked_source": identity(out / "checked.hepta"), "wrapping_source": identity(out / "wrapping.hepta"),
            "groups": 7, "workload": "reuse measured holdout solely as an exploratory codegen diagnostic",
            "semantics": "wrapping sums differ from checked sums outside the finite input domain",
            "admissible_replacement_proved": False, "compiler_fixed": False, "thresholds_changed": False,
            "optimization_admitted": False, "scheduled_samples": [
                {"group": group, "kernel": kernel, "variant": variant}
                for group in range(7) for kernel in KERNELS
                for variant in (("checked", "wrapping") if group % 2 == 0 else ("wrapping", "checked"))]}
    write_new(out / "plan.json", plan)
    started = time.perf_counter_ns()
    core = lower_source(changed, path=str(out / "wrapping.hepta"), module="optimizer_bench")
    ir = emit_program_llvm(core)
    (out / "wrapping.hia").write_bytes(core.canonical_bytes)
    (out / "wrapping.ll").write_text(ir.text)
    compiled = compile_program_llvm(ir, program=core, output=out / "wrapping.so", clang=clang)
    report = {"schema": plan["schema"], "plan": plan, "build_wall_ns": time.perf_counter_ns() - started,
              "receipt": compiled, "commands": [], "raw_samples": [], "disassembly": {},
              "tool_identity": identity(objdump), "tool_version": execute([objdump, "--version"])}
    command = execute([sys.executable, "-c", CORRECTNESS_CHILD, out / "wrapping.so", json.dumps(correctness_cases())])
    report["commands"].append(command)
    observations = [json.loads(line) for line in successful(command).splitlines()]
    report["finite_correctness"] = {"observations": observations,
        "ok": observations == [{**case, "actual": case["expected"]} for case in correctness_cases()]}
    for name, library in [(name, Path(item["path"])) for name, item in original_report["artifacts_before"].items()] + [("hia_wrapping_ablation", out / "wrapping.so")]:
        for kernel in KERNELS:
            command = execute([objdump, "-d", "--no-show-raw-insn", "--disassemble-symbols=" + kernel, library])
            report["commands"].append(command)
            text = successful(command)
            path = out / (name + "_" + kernel + ".asm.txt"); path.write_text(text)
            report["disassembly"][name + ":" + kernel] = {"library": identity(library), "text": identity(path)}
    for item in plan["scheduled_samples"]:
        library = baseline / "hia.so" if item["variant"] == "checked" else out / "wrapping.so"
        command = execute([baseline / "driver", library, item["kernel"], "holdout"])
        row = {**item, "execution": command, "ok": False}
        try:
            row["measurement"] = json.loads(successful(command))
            row["ok"] = row["measurement"]["checksum"] == timed_checksum(item["kernel"])
        except Exception as error:
            row["error"] = str(error)
        report["raw_samples"].append(row)
    report["completed"] = all(row["ok"] for row in report["raw_samples"])
    report["descriptive_wrapping_to_checked_ratios"] = {}
    if report["completed"]:
        values = {(row["group"], row["kernel"], row["variant"]): row["measurement"]["elapsed_ns"] for row in report["raw_samples"]}
        for kernel in KERNELS:
            ratios = [values[g, kernel, "wrapping"] / values[g, kernel, "checked"] for g in range(7)]
            report["descriptive_wrapping_to_checked_ratios"][kernel] = {"paired_ratios": ratios, "median": statistics.median(ratios)}
    report["claims"] = {key: plan[key] for key in ("admissible_replacement_proved", "compiler_fixed", "thresholds_changed", "optimization_admitted")}
    write_new(out / "report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    result = run(args.baseline_dir, args.output_dir)
    print(json.dumps({"completed": result["completed"], "finite_correctness": result["finite_correctness"]["ok"],
                      "ratios": result["descriptive_wrapping_to_checked_ratios"], "claims": result["claims"]}))
