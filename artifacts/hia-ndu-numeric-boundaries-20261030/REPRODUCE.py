#!/usr/bin/env python3
"""Run the frozen numeric boundary gate; any skipped test fails this gate."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    source = here / "sources"
    identity = json.loads((here / "SOURCE_IDENTITY.json").read_bytes())
    for name, expected in identity.items():
        if sha256((source / name).read_bytes()).hexdigest() != expected:
            raise SystemExit("frozen source mismatch: " + name)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    environment = os.environ.copy()
    environment.update(
        HEPTA_NDU_IDENTITY=str(args.identity.resolve()),
        HEPTA_NDU_BOUNDARY_EVIDENCE=str(output),
        PYTHONPATH=str(source),
        PYTHONDONTWRITEBYTECODE="1",
    )
    command = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p",
               "test_hia_planning_boundaries.py", "-v"]
    write(output / "COMMAND.json", {"argv": command, "cwd": str(source),
          "environment_selectors": {name: environment[name] for name in
              ("HEPTA_NDU_IDENTITY", "HEPTA_NDU_BOUNDARY_EVIDENCE", "PYTHONPATH",
               "PYTHONDONTWRITEBYTECODE")}})
    completed = subprocess.run(command, cwd=source, env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (output / "TESTS.log").write_bytes(completed.stdout)
    log = completed.stdout.decode("utf-8", errors="replace")
    match = re.search(r"Ran (\d+) tests?", log)
    count = int(match.group(1)) if match else 0
    recheck_path = output / "SOURCE_RECHECK.json"
    recheck = json.loads(recheck_path.read_bytes()) if recheck_path.is_file() else {}
    passed = (completed.returncode == 0 and count == 11 and "skipped" not in log
              and recheck.get("unchanged") is True
              and recheck.get("before") == identity)
    result = {
        "schema": "hepta.hia.ndu.numeric-boundary-gate-result.v1",
        "tests_run": count, "skipped": 0 if "skipped" not in log else "see log",
        "exit_code": completed.returncode,
        "source_unchanged": recheck.get("unchanged", False),
        "actual_native_invocations": recheck.get("actual_native_invocations", 0),
        "passed": passed, "expected_native_request_rejections": 2,
        "production_source_change": False,
    }
    write(output / "GATE.json", result)
    write(output / "INDEX.json", {
        str(path.relative_to(output)): sha256(path.read_bytes()).hexdigest()
        for path in sorted(output.rglob("*")) if path.is_file() and path.name != "INDEX.json"
    })
    print(log, end="")
    print(json.dumps(result, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
