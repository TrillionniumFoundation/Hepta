#!/usr/bin/env python3
"""Exact scoped versioned-context check, not the inherited full package gate."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

GUARD = '''            if units[path].package.root != pkg.root:
                fail("E_MODULE_PACKAGE_CONTEXT", "Module " + str(path) + " is imported under conflicting package roots: "
                     + str(units[path].package.root) + " and " + str(pkg.root), span)
'''


def blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def verify_inputs():
    from tools.verify_package_kind_context_sources import verify
    verify()
    manifest = json.loads((ROOT / "tools/versioned_package_context_sources.json").read_text())
    for path, expected in manifest["parent_files"].items():
        data = (ROOT / path).read_bytes()
        if path == "hepta/modules.py":
            if data.count(GUARD.encode()) != 1:
                raise SystemExit("Expected exactly one original context guard")
            data = data.replace(GUARD.encode(), b"", 1)
        if blob(data) != expected:
            raise SystemExit("Parent source differs: " + path)
    for group in ("supplier_files", "reviewed_files"):
        for path, expected in manifest[group].items():
            if blob((ROOT / path).read_bytes()) != expected:
                raise SystemExit("Scoped source differs: " + path)
    return manifest


def identities():
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(ROOT.rglob("*")) if p.is_file()
            and "__pycache__" not in p.parts and p.suffix != ".pyc"}


class StrictResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started, self.finished, self.passed = [], [], []

    def startTest(self, test):
        self.started.append(test.id())
        super().startTest(test)

    def stopTest(self, test):
        self.finished.append(test.id())
        super().stopTest(test)

    def addSuccess(self, test):
        self.passed.append(test.id())
        super().addSuccess(test)


def main():
    if sys.flags.optimize:
        raise SystemExit("Python assertions must remain enabled")
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["PYTHONPATH"] = str(ROOT)
    if os.environ.get("HEPTA_PACKAGE_TEST_BACKEND", "c") != "c":
        raise SystemExit("This scoped local qualifier requires the C backend")
    if os.environ.get("CC", "gcc") != "gcc":
        raise SystemExit("Use the selected GCC consistently: CC must be gcc")
    os.chdir(ROOT)
    manifest = verify_inputs()
    planned = json.loads((ROOT / "tests/versioned_package_context_scoped_inventory.json").read_text())
    if len(planned) != 83 or len(set(planned)) != 83:
        raise SystemExit("Expected 83 unique frozen scoped methods")
    toolchain = subprocess.run(["gcc", "--version"], capture_output=True, text=True, check=True)
    before = identities()
    print("VERSIONED_CONTEXT_IDENTITY " + json.dumps({"python": sys.version,
          "gcc": toolchain.stdout, "source_sha256": before,
          "unexecuted_inherited": manifest["unexecuted_inherited"]}, sort_keys=True), flush=True)
    if "--inputs-only" in sys.argv:
        print("VERSIONED_CONTEXT_INPUTS_PASS", flush=True)
        return
    suite = unittest.TestLoader().loadTestsFromNames(planned)
    result = unittest.TextTestRunner(verbosity=2, resultclass=StrictResult).run(suite)
    report = {"planned": planned, "started": result.started, "finished": result.finished,
              "passed": result.passed, "failures": len(result.failures), "errors": len(result.errors),
              "skips": len(result.skipped), "expected_failures": len(result.expectedFailures),
              "unexpected_successes": len(result.unexpectedSuccesses)}
    print("VERSIONED_CONTEXT_METHODS " + json.dumps(report, sort_keys=True), flush=True)
    if (not result.wasSuccessful() or planned != result.started or planned != result.finished
            or planned != result.passed or result.skipped or result.expectedFailures
            or result.unexpectedSuccesses):
        raise SystemExit("Scoped method check failed; inherited gates remain separate")
    # The unchanged #698 oracle has only acyclic package graphs. Its two other
    # graph oracles and its full 65-method runner remain unchanged and separate.
    subprocess.run([sys.executable, "-B", "-m", "tests.package_integration_oracle"],
                   cwd=ROOT, check=True)
    subprocess.run([sys.executable, "-B", str(ROOT / "tools/versioned_package_context_oracle.py")],
                   cwd=ROOT, check=True)
    verify_inputs()
    if before != identities():
        raise SystemExit("Source changed during scoped checks")
    print("VERSIONED_CONTEXT_SCOPED_PASS " + json.dumps({"methods": 83,
          "full_698_gate": "not_run", "full_665_gate": "not_run",
          "source_unchanged": True}, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
