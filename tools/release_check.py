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
    excluded = {".git", "__pycache__", "artifacts", "build", ".venv"}
    files = {}
    for p in sorted(ROOT.rglob("*")):
        if p.is_file() and not excluded.intersection(p.relative_to(ROOT).parts) and p.suffix not in {".pyc", ".bundle"} and not p.name.endswith(".hepta-lock"):
            files[str(p.relative_to(ROOT))] = hashlib.sha256(p.read_bytes()).hexdigest()
    identity = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"sha256": identity, "files": files}


def main():
    artifacts = ROOT / "artifacts"
    artifacts.mkdir(exist_ok=True)
    before = snapshot()
    report = {"schema": "hepta.release.v1", "scope": "bootstrap-0.1-supported-subset",
              "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "source_snapshot": before, "compiler_sha256": compiler_hash(), "status": "running",
              "gates": [], "whole_project_blockers_closed": False,
              "open_production_blockers": [f"P{i:02d}" for i in range(1, 13)]}
    commands = [
        ("unit_and_integration", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], 180),
        ("parser_example", [sys.executable, "-m", "hepta", "run", "examples/parser.hepta", "--json"], 60),
        ("ownership_example", [sys.executable, "-m", "hepta", "run", "examples/ownership.hepta", "--json"], 60),
        ("tasks_example", [sys.executable, "-m", "hepta", "run", "examples/tasks.hepta", "--json"], 60),
        ("abi_matrix", [sys.executable, "tools/abi_fuzz.py", "--output", "artifacts/abi-matrix.json"], 180),
        ("native_and_performance", [sys.executable, "tools/validate.py", "--bench", "--output", "artifacts/native-validation.json"], 180),
    ]
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
        report["gates"].append(gate)
        print(json.dumps(gate), flush=True)
        if gate["status"] != "passed":
            break
    after = snapshot()
    report["snapshot_unchanged"] = before == after
    report["status"] = "passed" if len(report["gates"]) == len(commands) and all(g["status"] == "passed" for g in report["gates"]) and before == after else "failed"
    report["completed_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report["evidence"] = {}
    for name in ["abi-matrix.json", "native-validation.json"]:
        p = artifacts / name
        if p.exists():
            report["evidence"][name] = {"sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "bytes": p.stat().st_size}
    (artifacts / "release-validation.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"status": report["status"], "source_snapshot_sha256": before["sha256"], "whole_project_blockers_closed": False}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
