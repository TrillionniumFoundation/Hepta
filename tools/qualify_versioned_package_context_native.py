#!/usr/bin/env python3
"""Additional strict native gate; every inherited gate and source stays intact."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
MANIFEST_SHA256 = "17b97a6d9f8e11060c0b5bb87300692917ecb7bb00cea7b790baeec707a693a1"
PREFIX = "tests.test_versioned_package_context_native.VersionedPackageContextNativeTests."
METHOD_COUNTS = {
    "test_fixed_and_versioned_aliases_share_selected_context": 8,
    "test_highest_version_both_orders_and_lock_modes": 16,
    "test_invalid_candidate_refresh_preserves_lock_then_recovers": 8,
    "test_public_cli_runs_locked_rust_and_c": 0,
    "test_selected_context_rejects_before_compilers_and_recovers": 8,
    "test_transitive_fallback_both_orders_and_lock_modes": 16,
    "test_unselected_local_file_uses_application_context": 8,
    "test_upgrade_stales_lock_then_refresh_changes_native_result": 8,
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_sources():
    path = ROOT / "tools/versioned_package_context_native_sources.json"
    if sha(path) != MANIFEST_SHA256:
        raise SystemExit("Native context origin manifest changed")
    manifest = json.loads(path.read_text())
    if (manifest["base_commit"] != "8e0ce934ddea988896086035fb560d1498f4c2f6"
            or manifest["base_tree"] != "a18218177d4f8aed8615a64535b13e23ca333472"
            or len(manifest["files"]) != 187):
        raise SystemExit("Native context origin identity differs")
    for relative, expected in manifest["files"].items():
        source = ROOT / relative
        if source.is_symlink() or not source.is_file():
            raise SystemExit("Missing/nonregular inherited source: " + relative)
        data = source.read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if actual != expected:
            raise SystemExit("Inherited source differs: " + relative)
    # Preserve the original #759 composition and its earlier origin obligations.
    from tools.verify_package_kind_context_sources import verify
    verify()


def identities():
    return {str(p.relative_to(ROOT)): sha(p) for p in sorted(ROOT.rglob("*"))
            if p.is_file() and ".git" not in p.relative_to(ROOT).parts
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
        raise SystemExit("Only --inputs-only is supported")
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["PYTHONPATH"] = str(ROOT)
    os.chdir(ROOT)
    verify_sources()
    before = identities()
    if "--inputs-only" in sys.argv:
        print("VERSIONED_CONTEXT_NATIVE_INPUTS_PASS " + json.dumps({"inherited_files": 187,
              "native_run": False, "source_sha256": before}, sort_keys=True), flush=True)
        return
    from hepta.backend import find_rustc, toolchain_info
    from tests import test_versioned_package_context_native as native
    rustc = find_rustc()
    rust_identity = toolchain_info(rustc)
    gcc = shutil.which("gcc")
    if not gcc:
        raise SystemExit("Real GCC is required")
    if os.environ.get("CC", "gcc") != "gcc":
        raise SystemExit("CC must be gcc for native comparison")
    os.environ["RUSTC"] = rustc
    os.environ["CC"] = "gcc"
    gcc_version = subprocess.run([gcc, "--version"], capture_output=True, text=True, check=True, timeout=30).stdout
    tools_before = {rustc: sha(Path(rustc)), gcc: sha(Path(gcc))}
    print("VERSIONED_CONTEXT_NATIVE_IDENTITY " + json.dumps({"python": sys.version,
          "rust": rust_identity, "gcc": gcc_version, "tool_sha256": tools_before,
          "source_sha256": before, "inherited_files": 187}, sort_keys=True), flush=True)
    planned = [PREFIX + name for name in METHOD_COUNTS]
    discovered = unittest.TestLoader().getTestCaseNames(native.VersionedPackageContextNativeTests)
    if discovered != list(METHOD_COUNTS):
        raise SystemExit("Native method inventory differs")
    suite = unittest.TestLoader().loadTestsFromNames(planned)
    result = unittest.TextTestRunner(verbosity=2, resultclass=StrictResult).run(suite)
    report = {"planned": planned, "started": result.started, "finished": result.finished,
              "passed": result.passed, "failures": len(result.failures), "errors": len(result.errors),
              "skips": len(result.skipped), "expected_failures": len(result.expectedFailures),
              "unexpected_successes": len(result.unexpectedSuccesses)}
    print("VERSIONED_CONTEXT_NATIVE_METHODS " + json.dumps(report, sort_keys=True), flush=True)
    if (not result.wasSuccessful() or planned != result.started or planned != result.finished
            or planned != result.passed or result.skipped or result.expectedFailures or result.unexpectedSuccesses):
        raise SystemExit("Native method qualification failed")
    for name, count in METHOD_COUNTS.items():
        receipts = [r for r in native.RECEIPTS if r["method"] == PREFIX + name]
        if len(receipts) != count:
            raise SystemExit("Native execution count differs: " + name)
        for backend in ("c", "rust"):
            for optimize in (False, True):
                if sum(r["backend"] == backend and r["optimize"] == optimize for r in receipts) != count // 4:
                    raise SystemExit("Native backend/optimization coverage differs: " + name)
    if len(native.RECEIPTS) != 72 or [r["backend"] for r in native.CLI_RECEIPTS] != ["c", "rust"]:
        raise SystemExit("Native/CLI receipt inventory differs")
    verify_sources()
    if before != identities() or tools_before != {path: sha(Path(path)) for path in tools_before}:
        raise SystemExit("Source or compiler changed during qualification")
    print("VERSIONED_CONTEXT_NATIVE_PASS " + json.dumps({"methods": 8, "native_executions": 72,
          "c_ubsan_executions": 36, "rust_executions": 36, "cli_executions": 2,
          "source_unchanged": True, "tools_unchanged": True,
          "scope": "finite acyclic versioned package contexts only; inherited gates remain separate"}, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
