"""Measure explicit machine choices separately on one retained native fixture.

This is a finite native correctness/engineering-cost observation. It neither
models external Agent costs as zero nor claims a real-task strategy advantage.
"""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import platform
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_program import verify_program
from hepta.hia_program_native import _implementation_hash, compile_program_machine, emit_program_machine
from tests.test_hia_machine_plan import call_document, explicit_plan


def qualify(destination):
    destination = Path(destination)
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    started = time.monotonic_ns()
    before = _implementation_hash()
    document = call_document()
    program = verify_program(document)
    (destination / "input.core.json").write_bytes(program.canonical_bytes)
    preparation_ns = time.monotonic_ns() - started
    variants = {
        "canonical": None,
        "scratch_registers": explicit_plan(program, scratch_registers={"r10": "r11", "r11": "r10"}),
        "instruction_selection": explicit_plan(program, instruction_selection={
            "move_immediate": "mov32_if_exact", "alu_immediate": "imm8_if_exact"}),
        "function_layout": explicit_plan(program, function_order=["twice", "answer"], function_alignment=64),
        "combined": explicit_plan(program, scratch_registers={"r10": "r11", "r11": "r10"},
            instruction_selection={"move_immediate": "mov32_if_exact", "alu_immediate": "imm8_if_exact"},
            function_order=["twice", "answer"], function_alignment=64),
    }
    records, loaded = {}, {}
    values = [*range(256), (1 << 32) - 1, 1 << 63, (1 << 64) - 1]
    for name, plan in variants.items():
        start = time.monotonic_ns()
        image = emit_program_machine(program, machine_plan=plan)
        emission_ns = time.monotonic_ns() - start
        output = destination / (name + ".so")
        start = time.monotonic_ns()
        build = compile_program_machine(image, program=program, output=output, linker="ld", machine_plan=plan)
        build_ns = time.monotonic_ns() - start
        start = time.monotonic_ns()
        library = ctypes.CDLL(str(output))
        functions = {}
        for symbol, delta in (("answer", 7), ("twice", 14)):
            fn = getattr(library, symbol)
            fn.argtypes, fn.restype = [ctypes.c_uint64], ctypes.c_uint64
            for value in values:
                if fn(value) != (value + delta) & ((1 << 64) - 1):
                    raise AssertionError((name, symbol, value))
            functions[symbol] = fn
        verification_ns = time.monotonic_ns() - start
        loaded[name] = (library, functions)
        records[name] = {"plan": plan, "native_build": build,
            "phase_wall_ns": {"emit": emission_ns, "rederive_link_publish": build_ns,
                              "load_and_verify": verification_ns},
            "correct_cases": len(values) * 2, "timing_samples_ns": [],
            "whole_shared_bytes": output.stat().st_size, "object_bytes": len(image.object_bytes),
            "machine_text_bytes": len(image.text_bytes)}
    # Alternate order, with all arms using the exact same already checked calls.
    names = list(variants)
    for pair in range(7):
        for name in names if pair % 2 == 0 else list(reversed(names)):
            functions = loaded[name][1]
            start = time.monotonic_ns()
            total = 0
            for value in range(2048):
                total += functions["answer"](value) + functions["twice"](value)
            elapsed = time.monotonic_ns() - start
            if total != 2 * sum(range(2048)) + 2048 * 21:
                raise AssertionError("timing call checksum differs")
            records[name]["timing_samples_ns"].append(elapsed)
    for record in records.values():
        record["phase_wall_ns"]["observed_timing_campaign"] = sum(record["timing_samples_ns"])
        record["observed_arm_wall_ns"] = sum(record["phase_wall_ns"].values())
        record["median_python_to_native_batch_ns"] = statistics.median(record["timing_samples_ns"])
        record["timed_native_calls"] = 7 * 4096
    stable = before == _implementation_hash()
    report = {"schema": "hepta.hia.machine-choice-observation.v1", "fixture_kind": "synthetic_call_and_arithmetic",
        "ok": stable, "source_unchanged": stable, "backend_sha256": before, "core_sha256": program.sha256,
        "host": {"platform": platform.platform(), "python": sys.version},
        "shared_preparation_wall_ns": preparation_ns, "arms": records,
        "observed_campaign_wall_ns": time.monotonic_ns() - started,
        "external_agent_model_cost": None, "discovery_cost": None,
        "failed_search_campaign_cost": None, "full_search_cost_complete": False,
        "real_task_strategy_benefit_proved": False, "universal_backend_refinement_proved": False,
        "notes": ["Each choice is measured separately and combined; canonical arm uses identical Core.",
                  "Emission is performed once explicitly and again during independent build rederivation; both costs are charged.",
                  "Timings include Python/ctypes dispatch and are not a hardware-only latency claim.",
                  "Code-size changes and correctness controls are not evidence of Agent or NDU economic benefit."]}
    (destination / "result.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    report = qualify(args.out)
    print(json.dumps({"ok": report["ok"], "output": str(Path(args.out) / "result.json"),
                      "arms": {name: {key: row[key] for key in ("correct_cases", "machine_text_bytes", "object_bytes", "whole_shared_bytes")}
                               for name, row in report["arms"].items()}}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
