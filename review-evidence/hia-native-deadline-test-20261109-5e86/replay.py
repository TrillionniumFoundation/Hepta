#!/usr/bin/env python3
"""Retain the real runner outcomes of the two deadline fixture tests."""
import argparse
from hashlib import sha256
import io
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from hepta import hia_agent_runner as runner


def replay(output):
    output = Path(output).absolute()
    output.mkdir(parents=False, exist_ok=False)
    real_reference, real_owner = runner.run_reference_batch, runner.run_native_batch
    references, owners = [], []

    def observe_reference(program, cases, **options):
        row = {"program_sha256": program.sha256, "cases": cases, "options": options,
               "started_wall_ns": str(time.time_ns())}
        result = real_reference(program, cases, **options)
        row.update(ended_wall_ns=str(time.time_ns()), result=result)
        references.append(row)
        return result

    def observe_owner(*arguments, **options):
        row = {"mode": options.get("_mode", "native"), "timeout_ms": options["timeout_ms"],
               "started_wall_ns": str(time.time_ns())}
        result = real_owner(*arguments, **options)
        row.update(ended_wall_ns=str(time.time_ns()), result=result)
        owners.append(row)
        return result

    names = ["tests.test_hia_agent_native_tools.NativeLifecycleTests." + method for method in (
        "test_reference_loop_cannot_restart_or_overrun_frozen_context_deadline",
        "test_expired_evaluation_is_rejected_before_any_reference_or_native_runner")]
    log = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    with patch.object(runner, "run_reference_batch", side_effect=observe_reference), \
         patch.object(runner, "run_native_batch", side_effect=observe_owner):
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    (output / "tests.log").write_text(log.getvalue())
    passed = result.wasSuccessful() and result.testsRun == len(names) and not result.skipped
    passed = passed and len(references) == len(owners) == 1 and owners[0]["mode"] == "reference"
    passed = passed and references[0]["result"]["started"] and references[0]["result"]["termination_confirmed"]
    passed = passed and references[0]["result"]["status"] == "budget_exceeded"
    paths = ["tests/test_hia_agent_native_tools.py", "hepta/hia_agent_service.py",
             "hepta/hia_agent_runner.py", "tools/hia_agent_native_qualification.py"]
    report = {"schema": "hepta.hia.deadline-fixture-replay.v1", "ok": passed,
        "tests": {"inventory": names, "count": result.testsRun,
            "failures": [{"test": test.id(), "detail": text} for test, text in result.failures],
            "errors": [{"test": test.id(), "detail": text} for test, text in result.errors],
            "skipped": [{"test": test.id(), "reason": reason} for test, reason in result.skipped]},
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_identity": {path: sha256((ROOT / path).read_bytes()).hexdigest() for path in paths},
        "reference_calls": references, "process_owner_calls": owners,
        "native_mode_calls": sum(row["mode"] == "native" for row in owners),
        "original_total_wall_ms": 3000, "original_native_wall_ms": 1000,
        "absolute_cleanup_slack_ns": "650000000", "production_source_changed": False,
        "online_service_exercised": False, "six_track_acceptance": "HOLD"}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"ok": passed, "tests": result.testsRun, "reference_calls": len(references),
                      "owner_calls": len(owners), "output": str(output)}))
    return 0 if passed else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    raise SystemExit(replay(parser.parse_args().output))
