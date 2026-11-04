"""Require the frozen CLI input-preservation inventory and real toolchains."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

MODULES = (
    "tests.test_cli_input_protection", "tests.test_modules",
    "tests.test_debug_info", "tests.test_source_map",
    "tests.test_c_backend.CBackendTests.test_check_only_produces_real_nonempty_native_object",
    "tests.test_c_backend.CBackendTests.test_explicit_unroll_profile_is_used_by_cli_check_and_final_build",
    "tests.test_c_backend.CBackendTests.test_invalid_or_unoptimized_named_profile_fails_closed",
)
INVENTORY = ROOT / "tools/cli_input_protection_inventory.json"


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


class ExactResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started = []
        self.passed = []
        self.subtests = []

    def startTest(self, test):
        self.started.append(test.id())
        super().startTest(test)

    def addSuccess(self, test):
        self.passed.append(test.id())
        super().addSuccess(test)

    def addSubTest(self, test, subtest, error):
        self.subtests.append({"method": test.id(), "id": subtest.id(), "passed": error is None})
        super().addSubTest(test, subtest, error)


def main():
    if not shutil.which("gcc"):
        raise SystemExit("Real GCC is required")
    rustc = os.environ.get("RUSTC")
    if not rustc or not Path(rustc).is_file() or not os.access(rustc, os.X_OK):
        raise SystemExit("RUSTC must identify the real pinned compiler")
    import hepta
    from hepta.backend import toolchain_info
    if Path(hepta.__file__).resolve().parents[1] != ROOT:
        raise SystemExit("Imported compiler is not the reviewed checkout")
    print("COMPILER_ROOT:", ROOT, flush=True)
    print("RUST_TOOLCHAIN:", json.dumps(toolchain_info(rustc), sort_keys=True), flush=True)
    sources = ("hepta/cli.py", "tests/test_cli_input_protection.py",
               "tools/test_cli_input_protection.py", "tools/cli_input_protection_inventory.json")
    print("SOURCE_HASHES:", json.dumps({p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
                                       for p in sources}, sort_keys=True), flush=True)
    tests = list(flatten(unittest.defaultTestLoader.loadTestsFromNames(MODULES)))
    ids = [test.id() for test in tests]
    expected = json.loads(INVENTORY.read_text(encoding="utf-8"))
    if not expected or len(set(expected)) != len(expected) or ids != expected:
        raise SystemExit("Discovered tests differ from the frozen ordered unique inventory")
    print("PLANNED_TEST_IDS:", json.dumps(ids), flush=True)
    result = unittest.TextTestRunner(verbosity=2, resultclass=ExactResult).run(unittest.TestSuite(tests))
    print("EXECUTED_TEST_IDS:", json.dumps(result.started), flush=True)
    print("PASSED_TEST_IDS:", json.dumps(result.passed), flush=True)
    print("SUBTEST_RESULTS:", json.dumps(result.subtests), flush=True)
    if (not result.wasSuccessful() or result.skipped or result.expectedFailures
            or result.unexpectedSuccesses or result.started != ids or result.passed != ids
            or result.testsRun != len(ids)):
        raise SystemExit("Frozen inventory did not pass without skips/xfails/xpasses")
    print("COMPLETE_HOSTED_PASS", len(ids), flush=True)


if __name__ == "__main__":
    main()
