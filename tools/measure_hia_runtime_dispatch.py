"""Retain paired full-interpreter timings; no native or release qualification."""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import platform
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta import hia_program_runtime as candidate
from hepta.hia_program import verify_program
from tools.qualify_hia_program import qualification_program

STUDY = ROOT / "benchmarks/hia_runtime_dispatch"


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def baseline_runtime(protocol):
    path = STUDY / "runtime_ab1c1a5.py"
    if digest(path) != protocol["baseline_runtime_sha256"]:
        raise ValueError("retained baseline runtime differs from registered source")
    name = "hepta._runtime_dispatch_baseline"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def measure(output):
    # A new directory keeps original observations immutable on repeat runs.
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    protocol_bytes = (STUDY / "PROTOCOL.json").read_bytes()
    protocol = json.loads(protocol_bytes)
    (output / "PROTOCOL.json").write_bytes(protocol_bytes)
    baseline = baseline_runtime(protocol)
    wire = verify_program(qualification_program()).canonical_bytes
    (output / "program.hia").write_bytes(wire)
    modules = {"baseline": baseline, "candidate": candidate}
    sources = ["hepta/hia_program_runtime.py", "hepta/hia_program.py",
               "hepta/hia_opcodes.py", "hepta/hia_capability_flow.py",
               "hepta/hia_schema.py", "tools/qualify_hia_program.py",
               "tools/measure_hia_runtime_dispatch.py"]
    source_hashes = {path: digest(ROOT / path) for path in sources}
    expected = {}
    for case in protocol["cases"]:
        expected[case["id"]] = baseline.execute_program(
            wire, case["function"], case["arguments"])
        for _ in range(protocol["warmups_per_arm_per_case"]):
            for module in modules.values():
                observed = module.execute_program(wire, case["function"], case["arguments"])
                if observed != expected[case["id"]]:
                    raise ValueError("warmup execution report differs: " + case["id"])
    (output / "execution-reports.json").write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n")
    samples = []
    with (output / "samples.jsonl").open("x") as retained:
        for round_index in range(protocol["rounds"]):
            cases = protocol["cases"]
            shift = round_index % len(cases)
            for case in cases[shift:] + cases[:shift]:
                arms = ("baseline", "candidate") if round_index % 2 == 0 else ("candidate", "baseline")
                for arm in arms:
                    start = time.perf_counter_ns()
                    observed = modules[arm].execute_program(wire, case["function"], case["arguments"])
                    elapsed = time.perf_counter_ns() - start
                    if observed != expected[case["id"]]:
                        raise ValueError("measured execution report differs: " + case["id"])
                    row = {"round": round_index, "case": case["id"], "arm": arm,
                           "elapsed_ns": elapsed, "complete_report_equal": True}
                    samples.append(row)
                    retained.write(json.dumps(row, sort_keys=True) + "\n")
                    retained.flush()
    if source_hashes != {path: digest(ROOT / path) for path in sources}:
        raise ValueError("implementation changed during measurement")
    summary = {}
    for case in protocol["cases"]:
        medians = {arm: statistics.median(row["elapsed_ns"] for row in samples
                    if row["arm"] == arm and row["case"] == case["id"])
                   for arm in modules}
        summary[case["id"]] = {"median_ns": medians,
            "median_reduction_percent": 100 * (1 - medians["candidate"] / medians["baseline"])}
    report = {"schema": "hepta.hia.runtime-dispatch-observation.v1", "summary": summary,
        "protocol_sha256": sha256(protocol_bytes).hexdigest(), "program_sha256": sha256(wire).hexdigest(),
        "sources": source_hashes, "baseline_runtime_sha256": protocol["baseline_runtime_sha256"],
        "samples": len(samples), "python": sys.version, "platform": platform.platform(),
        "complete_reports_equal": True, "native_performance_measured": False,
        "release_qualification": False, "authority": "DENY_ALL"}
    (output / "RESULT.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    print(json.dumps(measure(parser.parse_args().output), indent=2, sort_keys=True))
