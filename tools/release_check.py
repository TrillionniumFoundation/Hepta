#!/usr/bin/env python3
"""Run concrete release gates and bind their evidence to an unchanged snapshot."""
from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.pipeline import compiler_hash


def snapshot():
    # Generated evidence is bound separately, avoiding a self-referential hash.
    excluded = {".git", "__pycache__", "artifacts", "evidence", "build", ".venv"}
    files = {}
    for p in sorted(ROOT.rglob("*")):
        if p.is_file() and not excluded.intersection(p.relative_to(ROOT).parts) and p.suffix not in {".pyc", ".bundle"} and not p.name.endswith(".hepta-lock"):
            files[str(p.relative_to(ROOT))] = hashlib.sha256(p.read_bytes()).hexdigest()
    identity = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"sha256": identity, "files": files}


def require_qualification(name, evidence):
    """An outer success must not hide a required inner check marked not_run."""
    if name == "native_and_performance":
        results = evidence.get("results", {})
        required = {"c_abi": "passed", "no_std": "passed", "kernel_correctness": "passed",
                    "safe_borrowed": "passed", "kernel_codegen": "completed", "benchmarks": "completed"}
        if any(results.get(key, {}).get("status") != value for key, value in required.items()):
            raise ValueError("A required native qualification did not complete")
        targets = results["no_std"].get("targets", {})
        for target in ("host", "aarch64-unknown-linux-gnu", "thumbv7em-none-eabi", "x86_64-pc-windows-msvc"):
            if targets.get(target, {}).get("status") != "passed":
                raise ValueError(f"Required no_std object target not qualified: {target}")
    elif name == "representative_performance":
        if (evidence.get("correctness", {}).get("status") != "passed"
                or evidence.get("function_bytes", {}).get("status") != "completed"
                or evidence.get("measurements", {}).get("status") != "completed"):
            raise ValueError("Representative correctness/code comparison/timing did not all complete")
    elif name == "formal_core":
        if len(evidence.get("theorems", [])) != 11 or len(evidence.get("negative_mutations", [])) != 2:
            raise ValueError("Expected 11 checked theorems and two rejected negative mutations")
    elif name == "aarch64_execution":
        cases = {case.get("case"): case for case in evidence.get("cases", [])}
        if (cases.get("correct", {}).get("returncode") != 0
                or cases.get("wrong_sum_negative_control", {}).get("returncode") != 11):
            raise ValueError("Cross-execution positive and negative controls did not both qualify")
    elif name == "agent_evaluator_fixtures":
        if (evidence.get("actual_ai_model_runs") != 0
                or evidence.get("ai_comparison_eligible") is not False
                or evidence.get("oracle_fixture_runs") != 8):
            raise ValueError("Fixture evidence must retain its exact non-AI qualification scope")


def main():
    artifacts = ROOT / "artifacts"
    artifacts.mkdir(exist_ok=True)
    before = snapshot()
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    fixture_output = f"artifacts/agent-fixtures-{run_id}.json"
    report = {"schema": "hepta.release.v2", "scope": "prototype-0.2-qualified-subsets",
              "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "source_snapshot": before, "compiler_sha256": compiler_hash(), "status": "running",
              "gates": [], "evidence": {}, "whole_project_blockers_closed": False,
              "claims": {"whole_language_soundness_proved": False,
                         "global_memory_budget_proved": False,
                         "physical_hardware_executed": False,
                         "general_rust_performance_superiority_established": False,
                         "actual_ai_model_runs": 0,
                         "general_agent_productivity_advantage_established": False},
              "open_production_blockers": [f"P{i:02d}" for i in range(1, 13)]}
    commands = [
        ("unit_and_integration", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], 180),
        ("parser_example", [sys.executable, "-m", "hepta", "run", "examples/parser.hepta", "--json"], 60),
        ("ownership_example", [sys.executable, "-m", "hepta", "run", "examples/ownership.hepta", "--json"], 60),
        ("tasks_example", [sys.executable, "-m", "hepta", "run", "examples/tasks.hepta", "--json"], 60),
        ("results_example", [sys.executable, "-m", "hepta", "run", "examples/results.hepta", "--json"], 60),
        ("locked_package_example", [sys.executable, "-m", "hepta", "run", "examples/packages/app", "--locked", "--json"], 60),
        ("bounded_concurrency", [sys.executable, "tools/validate_groups.py", "--repeats", "3", "--output", "evidence/groups/native_validation.json"], 180),
        ("abi_matrix", [sys.executable, "tools/abi_fuzz.py", "--output", "artifacts/abi-matrix.json"], 180),
        ("native_and_performance", [sys.executable, "tools/validate.py", "--bench", "--output", "artifacts/native-validation.json"], 180),
        ("representative_performance", [sys.executable, "tools/benchmark_suite.py", "--output", "artifacts/representative-benchmarks.json"], 240),
        ("formal_core", [sys.executable, "tools/verify_formal.py", "--output", "artifacts/formal-validation.json"], 180),
        ("aarch64_execution", [sys.executable, "tools/validate_cross.py", "--output", "artifacts/cross-execution.json"], 120),
        ("agent_evaluator_fixtures", [sys.executable, "-m", "experiments.agent_eval", "qualify-fixtures", "--output", fixture_output], 240),
    ]
    evidence_outputs = {
        "bounded_concurrency": "evidence/groups/native_validation.json",
        "abi_matrix": "artifacts/abi-matrix.json",
        "native_and_performance": "artifacts/native-validation.json",
        "representative_performance": "artifacts/representative-benchmarks.json",
        "formal_core": "artifacts/formal-validation.json",
        "aarch64_execution": "artifacts/cross-execution.json",
        "agent_evaluator_fixtures": fixture_output,
    }
    for name, command, timeout in commands:
        started = time.monotonic()
        try:
            p = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
            text = p.stdout + p.stderr
            gate = {"name": name, "command": command, "exit_code": p.returncode,
                    "status": "passed" if p.returncode == 0 else "failed"}
        except subprocess.TimeoutExpired as exc:
            text = str(exc)
            gate = {"name": name, "command": command, "status": "unknown_timeout"}
        log = artifacts / (name + ".log")
        log.write_text(text)
        gate.update({"seconds": round(time.monotonic() - started, 3), "log": str(log.relative_to(ROOT)),
                     "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()})
        if name == "unit_and_integration":
            match = re.search(r"Ran (\d+) tests", text)
            if match:
                gate["test_count"] = int(match.group(1))
            skipped = re.search(r"skipped=(\d+)", text)
            gate["skipped"] = int(skipped.group(1)) if skipped else 0
            if not gate.get("test_count") or gate["skipped"]:
                gate["status"] = "failed"
                gate["reason"] = "Release qualification requires an actual nonempty suite with zero skips"
        if gate["status"] == "passed" and name in evidence_outputs:
            evidence_path = ROOT / evidence_outputs[name]
            try:
                evidence_bytes = evidence_path.read_bytes()
                evidence = json.loads(evidence_bytes)
                expected = "qualified_fixtures_only" if name == "agent_evaluator_fixtures" else "passed"
                if evidence.get("status") != expected:
                    raise ValueError(f"Expected evidence status {expected!r}, got {evidence.get('status')!r}")
                require_qualification(name, evidence)
                report["evidence"][evidence_outputs[name]] = {
                    "sha256": hashlib.sha256(evidence_bytes).hexdigest(),
                    "bytes": len(evidence_bytes), "gate": name,
                }
            except (OSError, ValueError) as exc:
                gate["status"] = "failed"
                gate["reason"] = str(exc)
        report["gates"].append(gate)
        print(json.dumps(gate), flush=True)
        if gate["status"] != "passed":
            break
    after = snapshot()
    report["snapshot_unchanged"] = before == after
    report["status"] = "passed" if len(report["gates"]) == len(commands) and all(g["status"] == "passed" for g in report["gates"]) and before == after else "failed"
    report["completed_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (artifacts / "release-validation.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"status": report["status"], "source_snapshot_sha256": before["sha256"], "whole_project_blockers_closed": False}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
