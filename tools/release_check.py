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
    elif name in {"c_project_migration", "upstream_c_modules"}:
        migration = evidence.get("migration", {})
        coverage = migration.get("coverage", {})
        if (evidence.get("ok") is not True or migration.get("ok") is not True
                or migration.get("native_validation") != "passed"
                or migration.get("declaration_inventory_complete") is not True
                or sum(coverage.get("status_counts", {}).values()) != coverage.get("active_project_declarations")):
            raise ValueError("C module capture, full declaration accounting and native build must complete")
        execution = evidence.get("execution", {})
        if name == "upstream_c_modules":
            if (execution.get("total_differential_cases") != 25302
                    or execution.get("wrong_result_control_rejected") is not True
                    or execution.get("same_address_read_alias_cases") != 8434):
                raise ValueError("Upstream C differential controls and alias cases did not qualify")
        else:
            faults = execution.get("fault_injection", [])
            if (sum(execution.get("differential_cases", {}).values()) != 1046 or len(faults) != 10
                    or any(f.get("c_live_allocations") != 0 or f.get("hepta_live_allocations") != 0 for f in faults)):
                raise ValueError("C allocation refusal, recovery and cleanup evidence is incomplete")
    elif name == "cpp_library_interop":
        execution = evidence.get("execution", {})
        if (evidence.get("ok") is not True or evidence.get("native_link_qualified") is not True
                or any(execution.get(k) is not True for k in ("bidirectional_native", "borrowed", "cpp_templates", "negative_boundaries", "std_string", "std_vector"))
                or evidence.get("performance", {}).get("status") != "measured"
                or len(evidence["performance"].get("measurements", [])) != 6):
            raise ValueError("C++ library execution and separately measured bridge costs must complete")
    elif name == "independent_resource_ir":
        projects = evidence.get("projects", [])
        if evidence.get("ok") is not True or len(projects) != 2:
            raise ValueError("Expected two natively executed independently resource-verified projects")
        for project in projects:
            if (project.get("execution", {}).get("exit_code") != 0
                    or project.get("native_gate", {}).get("ok") is not True
                    or project.get("native_build", {}).get("ok") is not True
                    or project.get("resource_verifier", {}).get("ok") is not True
                    or project["resource_verifier"].get("frontend_modules_imported") != []):
                raise ValueError("Resource verification or real native execution did not complete")
        if not evidence.get("adversarial_checks") or any(c.get("ok") is not True for c in evidence["adversarial_checks"]):
            raise ValueError("Resource IR adversarial rejection controls did not qualify")
    elif name == "crossfile_agent_fixtures":
        if (evidence.get("actual_ai_model_runs") != 0 or evidence.get("provider_tokens") != 0
                or evidence.get("ai_comparison_eligible") is not False
                or evidence.get("fixture_runs") != 20 or evidence.get("starter_runs") != 10
                or evidence.get("hidden_native_cases_passed") != 1248
                or len(evidence.get("runs", [])) != 20 or len(evidence.get("starters", [])) != 10):
            raise ValueError("Cross-file fixture qualification must cover all four arms and retain its non-AI scope")
        if any(r.get("status") != "fixture_scored" or r.get("score", {}).get("ok") is not True for r in evidence.get("runs", [])):
            raise ValueError("A cross-file fixture failed or did not run")
        if any(r.get("starter_compiles_without_new_contract", {}).get("ok") is not True
               or r.get("starter_fails_target_oracle") is not True for r in evidence["starters"]):
            raise ValueError("A starter failed to compile or already passed its target oracle")


def main():
    artifacts = ROOT / "artifacts"
    artifacts.mkdir(exist_ok=True)
    before = snapshot()
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    fixture_output = f"artifacts/agent-fixtures-{run_id}.json"
    next_stage = f"artifacts/next-stage-{run_id}"
    report = {"schema": "hepta.release.v2", "scope": "prototype-0.2-owned-migration-agent-qualified-subsets",
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
        ("unit_and_integration", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], 420),
        ("parser_example", [sys.executable, "-m", "hepta", "run", "examples/parser.hepta", "--json"], 60),
        ("ownership_example", [sys.executable, "-m", "hepta", "run", "examples/ownership.hepta", "--json"], 60),
        ("tasks_example", [sys.executable, "-m", "hepta", "run", "examples/tasks.hepta", "--json"], 60),
        ("results_example", [sys.executable, "-m", "hepta", "run", "examples/results.hepta", "--json"], 60),
        ("owned_library_example", [sys.executable, "-m", "hepta", "run", "examples/owned/main.hepta", "--json"], 60),
        ("independent_resource_ir", [sys.executable, "-m", "tools.validate_resources", "--output", next_stage + "/resources.json"], 120),
        ("c_project_migration", [sys.executable, "tools/qualify_c_migration.py", "--output", next_stage + "/c_project.json"], 120),
        ("upstream_c_modules", [sys.executable, "tools/qualify_c_algorithms.py", "--output", next_stage + "/upstream_c.json"], 120),
        ("cpp_library_interop", [sys.executable, "tools/validate_cpp.py", "--iterations", "1000000", "--output", next_stage + "/cpp.json"], 120),
        ("locked_package_example", [sys.executable, "-m", "hepta", "run", "examples/packages/app", "--locked", "--json"], 60),
        ("bounded_concurrency", [sys.executable, "tools/validate_groups.py", "--repeats", "3", "--output", "evidence/groups/native_validation.json"], 180),
        ("abi_matrix", [sys.executable, "tools/abi_fuzz.py", "--output", "artifacts/abi-matrix.json"], 180),
        ("native_and_performance", [sys.executable, "tools/validate.py", "--bench", "--output", "artifacts/native-validation.json"], 180),
        ("representative_performance", [sys.executable, "tools/benchmark_suite.py", "--output", "artifacts/representative-benchmarks.json"], 240),
        ("formal_core", [sys.executable, "tools/verify_formal.py", "--output", "artifacts/formal-validation.json"], 180),
        ("aarch64_execution", [sys.executable, "tools/validate_cross.py", "--output", "artifacts/cross-execution.json"], 120),
        ("agent_evaluator_fixtures", [sys.executable, "-m", "experiments.agent_eval", "qualify-fixtures", "--output", fixture_output], 240),
        ("crossfile_agent_fixtures", [sys.executable, "-m", "experiments.crossfile_eval", "qualify-fixtures", "--output", next_stage + "/crossfile_agent.json"], 360),
    ]
    evidence_outputs = {
        "bounded_concurrency": "evidence/groups/native_validation.json",
        "abi_matrix": "artifacts/abi-matrix.json",
        "native_and_performance": "artifacts/native-validation.json",
        "representative_performance": "artifacts/representative-benchmarks.json",
        "formal_core": "artifacts/formal-validation.json",
        "aarch64_execution": "artifacts/cross-execution.json",
        "agent_evaluator_fixtures": fixture_output,
        "independent_resource_ir": next_stage + "/resources.json",
        "c_project_migration": next_stage + "/c_project.json",
        "upstream_c_modules": next_stage + "/upstream_c.json",
        "cpp_library_interop": next_stage + "/cpp.json",
        "crossfile_agent_fixtures": next_stage + "/crossfile_agent.json",
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
                if name in {"independent_resource_ir", "c_project_migration", "upstream_c_modules", "cpp_library_interop"}:
                    if evidence.get("ok") is not True:
                        raise ValueError("Required native qualification did not report ok=true")
                else:
                    expected = "qualified_fixtures_only" if name in {"agent_evaluator_fixtures", "crossfile_agent_fixtures"} else "passed"
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
