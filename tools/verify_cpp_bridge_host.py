"""Reproducible host-only P4 regression receipt; never a whole-stage pass.

Must run in a local checkout of the exact Hepta candidate, never against stale
prior-release artifacts. All test successes are tied to sources and toolchains.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import io
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

FILES = ("hepta/cpp_bridge.py", "hepta/c2hepta.py", "tests/test_cpp_bridge.py",
         "tools/verify_cpp_bridge_host.py")
REPO = Path(__file__).resolve().parents[1]


def _hash(file: Path) -> str:
    return sha256(file.read_bytes()).hexdigest()


def _tool(command: str) -> dict:
    path = shutil.which(command)
    if not path:
        return {"status": "unavailable", "requested": command}
    executable = Path(path).resolve()
    try:
        proc = subprocess.run([str(executable), "--version"], capture_output=True,
                              text=True, timeout=10, check=False)
        if proc.returncode:
            raise ValueError("compiler identity query failed")
        return {"status": "identified", "path": str(executable),
                "version": proc.stdout.splitlines()[0], "executable_sha256": _hash(executable)}
    except (OSError, ValueError, subprocess.SubprocessError, IndexError) as exc:
        return {"status": "error", "message": str(exc)}


def validate() -> dict:
    compiler = {"c": _tool("gcc"), "cpp": _tool("clang++")}
    results = {"tests_run": 0, "passed": False, "failures": 0, "errors": 0,
               "skipped": 0, "test_output": "", "status": "not_run"}
    if all(x["status"] == "identified" for x in compiler.values()):
        current = Path.cwd()
        try:
            # Running unittest directly avoids subprocess return-code ambiguity
            # and distinguishes skipped from passed test cases.
            import os
            os.chdir(REPO)
            sys.path.insert(0, str(REPO))
            tests = unittest.defaultTestLoader.loadTestsFromName("tests.test_cpp_bridge")
            stream = io.StringIO()
            outcome = unittest.TextTestRunner(stream=stream, verbosity=2).run(tests)
            results.update({"tests_run": outcome.testsRun, "failures": len(outcome.failures),
                            "errors": len(outcome.errors), "skipped": len(outcome.skipped),
                            "test_output": stream.getvalue(),
                            "passed": outcome.wasSuccessful() and not outcome.skipped and outcome.testsRun >= 5})
            results["status"] = "passed" if results["passed"] else "failed"
        finally:
            if sys.path and sys.path[0] == str(REPO):
                sys.path.pop(0)
            os.chdir(current)
    result = {"schema": "hepta.cpp-bridge-host-validation.v1",
              "created_utc": datetime.now(timezone.utc).isoformat(),
              "scope": "host-C-caller-to-C++-bridge-only",
              "status": "passed" if results["passed"] else "incomplete",
              "source_sha256": {f: _hash(REPO / f) for f in FILES},
              "toolchain": compiler, "host": {"platform": platform.platform(),
                                             "machine": platform.machine(),
                                             "python": sys.version.split()[0]},
              "tests": results,
              "claims": {"cpp_exception_containment_tested": results["passed"],
                         "cpp_raii_cleanup_tested": results["passed"],
                         "cpp_native_abi_proved": False,
                         "foreign_cpp_memory_safe": False,
                         "hepta_ffi_validated": False,
                         "whole_p4_gate_closed": False,
                         "whole_project_blockers_closed": False}}
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    opts = parser.parse_args(argv)
    report = validate()
    target = Path(opts.output).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=target.parent, encoding="utf-8",
                                     prefix=".cpp-bridge-receipt-", delete=False) as fd:
        temporary = Path(fd.name)
        json.dump(report, fd, indent=2, sort_keys=True)
        fd.write("\n")
        fd.flush()
    temporary.replace(target)
    print(json.dumps({"status": report["status"], "output": str(target),
                      "tests_run": report["tests"]["tests_run"]}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
