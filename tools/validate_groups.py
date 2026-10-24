"""Compile and execute bounded-group evidence; never substitute emitted source.

The recorded timings are observations of these programs on this host, not a
cancellation deadline, throughput comparison, or termination proof.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.backend import compile_rust, find_rustc, toolchain_info
from hepta.pipeline import analyze


SCENARIOS = {
    "bounded_pipeline": ["received_sum", "completed_tasks", "peak_queued", "send_waits", "admitted_input_bytes", "active_tasks"],
    "admission_budgets": ["admitted_tasks", "task_budget_rejections", "admitted_input_bytes", "input_budget_rejections", "zero_budget_completed"],
    "cancellation": ["completed_tasks", "active_tasks", "waiting_senders", "discarded_values", "worker_result_sum"],
    "worker_failure": ["failure_code", "completed_tasks", "active_tasks", "waiting_senders", "received_before_close"],
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_scenario(name: str, *, rustc: str | None = None, repeats: int = 1) -> dict:
    if name not in SCENARIOS:
        raise ValueError("unknown group scenario: " + name)
    selected = find_rustc(rustc)
    source_path = ROOT / "examples" / "groups" / (name + ".hepta")
    source = source_path.read_text()
    analysis = analyze(source, str(source_path), rustc=selected, native=True, crate_type="bin")
    if not analysis.report["ok"]:
        raise RuntimeError(json.dumps(analysis.report, indent=2))
    with tempfile.TemporaryDirectory(prefix="hepta-groups-") as temporary:
        output = Path(temporary) / name
        build = compile_rust(analysis.rust, rustc=selected, crate_type="bin", output=output)
        if not build["ok"]:
            raise RuntimeError(json.dumps(build, indent=2))
        runs = []
        for _ in range(repeats):
            start = time.perf_counter_ns()
            proc = subprocess.run([str(output)], text=True, capture_output=True, timeout=20)
            elapsed = time.perf_counter_ns() - start
            if proc.returncode:
                raise RuntimeError(f"{name} exited {proc.returncode}: {proc.stderr}")
            values = [int(line) for line in proc.stdout.splitlines()]
            if len(values) != len(SCENARIOS[name]):
                raise RuntimeError(f"unexpected output from {name}: {proc.stdout!r}")
            runs.append({"returncode": proc.returncode, "elapsed_ms": round(elapsed / 1_000_000, 3),
                         "metrics": dict(zip(SCENARIOS[name], values))})
        artifact_hash = digest(output.read_bytes())
    return {
        "scenario": name, "status": "passed", "source": str(source_path.relative_to(ROOT)),
        "source_sha256": analysis.report["source_sha256"],
        "compiler_sha256": analysis.report["compiler_sha256"],
        "rust_sha256": analysis.report["rust_sha256"], "artifact_sha256": artifact_hash,
        "backend_validation": analysis.report["checks"],
        "resource_contracts": analysis.report["resource_contracts"], "runs": runs,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    compiler = find_rustc(args.rustc)
    report = {
        "schema": "hepta.groups.evidence.v1", "status": "passed",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "toolchain": toolchain_info(compiler),
        "scope": "bounded group-owned u64 channels and one TaskGroup admission budget",
        "limits": ["Budgets are per group, not global process bounds.",
                   "Input-byte budgets count cumulative admitted Buffer lengths, not worker allocations or RSS.",
                   "Task limits count total admissions for the group's lifetime; completed slots are not recycled.",
                   "Cancellation and group_fail are cooperative; arbitrary worker termination is not proved.",
                   "panic=abort remains process-fatal; cooperative error reporting is not panic containment.",
                   "Observed elapsed times are not latency bounds or Rust performance superiority evidence."],
        "scenarios": [run_scenario(name, rustc=compiler, repeats=args.repeats) for name in SCENARIOS],
    }
    output = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output)
        print(json.dumps({"status": "passed", "output": str(args.output), "scenarios": len(SCENARIOS), "runs_per_scenario": args.repeats}))
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
