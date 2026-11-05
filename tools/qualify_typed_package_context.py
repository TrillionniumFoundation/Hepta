#!/usr/bin/env python3
"""Scoped typed/context composition; original full aggregate remains separate."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests"), str(ROOT / "tools")]

def blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def verify_inputs():
    manifest = json.loads((ROOT / "tools/typed_package_context_sources.json").read_bytes())
    if manifest["parent"] != "b67d1a00acec941ecc7f4218020a2eae8f6cd2b4" or len(manifest["parent_files"]) != 308:
        raise ValueError("Expected complete exact #719 source inventory")
    if manifest["supplier"] != "54f4c67ec93ccbd997f7a4d56b3046221949e67c" or len(manifest["supplier_files"]) != 4:
        raise ValueError("Expected four exact #720 qualification files")
    for path, expected in manifest["parent_files"].items():
        actual_path = manifest["originals"].get(path, path)
        if blob((ROOT / actual_path).read_bytes()) != expected:
            raise ValueError("Changed #719 source: " + actual_path)
    for group in ("supplier_files", "reviewed_files"):
        for path, expected in manifest[group].items():
            if blob((ROOT / path).read_bytes()) != expected:
                raise ValueError("Changed composed source: " + path)
    from verify_versioned_typed_sources import verify
    verify()
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
    if sys.argv[1:] not in ([], ["--inputs-only"]):
        raise SystemExit("Expected no arguments or --inputs-only")
    if os.environ.get("HEPTA_VERSIONED_TYPED_BACKEND", "c") != "c":
        raise SystemExit("This scoped qualifier requires the C backend")
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["PYTHONPATH"] = str(ROOT)
    if os.environ.get("HEPTA_PACKAGE_TEST_BACKEND", "c") != "c":
        raise SystemExit("This scoped local qualifier requires the C backend")
    if os.environ.get("CC", "gcc") != "gcc":
        raise SystemExit("Use the selected GCC consistently: CC must be gcc")
    os.chdir(ROOT)
    manifest = verify_inputs()
    planned = json.loads((ROOT / "tools/typed_package_context_inventory.json").read_text())
    if len(planned) != 99 or len(set(planned)) != 99:
        raise SystemExit("Expected 99 unique frozen scoped methods")
    toolchain = subprocess.run(["gcc", "--version"], capture_output=True, text=True, check=True)
    inherited = json.loads((ROOT / "tests/versioned_package_context_scoped_inventory.json").read_bytes())
    typed = json.loads((ROOT / "tools/versioned_typed_inventory.json").read_bytes())
    if planned[:95] != inherited + typed:
        raise SystemExit("Expected exact inherited83 and original typed12 prefix")
    before = identities()
    print("TYPED_CONTEXT_IDENTITY " + json.dumps({"python": sys.version,
          "gcc": toolchain.stdout, "source_sha256": before,
          "full_parent_aggregate": "not_run"}, sort_keys=True), flush=True)
    if "--inputs-only" in sys.argv:
        print("TYPED_CONTEXT_INPUTS_PASS", flush=True)
        return
    suite = unittest.TestLoader().loadTestsFromNames(planned)
    result = unittest.TextTestRunner(verbosity=2, resultclass=StrictResult).run(suite)
    report = {"planned": planned, "started": result.started, "finished": result.finished,
              "passed": result.passed, "failures": len(result.failures), "errors": len(result.errors),
              "skips": len(result.skipped), "expected_failures": len(result.expectedFailures),
              "unexpected_successes": len(result.unexpectedSuccesses)}
    print("TYPED_CONTEXT_METHODS " + json.dumps(report, sort_keys=True), flush=True)
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
    subprocess.run([sys.executable, "-B", str(ROOT / "tools/typed_package_context_oracle.py"),
                    "--root", str(ROOT), "--native"], cwd=ROOT, check=True)
    verify_inputs()
    if before != identities():
        raise SystemExit("Source changed during scoped checks")
    print("TYPED_CONTEXT_SCOPED_PASS " + json.dumps({"methods": 99,
          "full_719_gate": "not_run", "full_698_gate": "not_run", "full_665_gate": "not_run",
          "source_unchanged": True}, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
