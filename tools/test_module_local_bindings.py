"""Run the finite module-local binding regression gate without missing native controls."""
from pathlib import Path
import os
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

MODULES = ("tests.test_module_local_bindings", "tests.test_checker",
           "tests.test_c_backend", "tests.test_owned_generics",
           "tests.test_borrowed_returns", "tests.test_modules",
           "tests.test_cross_feature_audit", "tests.test_project_protocol",
           "tests.test_workspace_query_cli")
EXPECTED_COUNT = 276


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

    def startTest(self, test):
        self.started.append(test.id())
        super().startTest(test)


def main():
    for command in ("gcc",):
        if not shutil.which(command):
            raise SystemExit("Real " + command + " is required")
    rustc = os.environ.get("RUSTC")
    if not rustc or not Path(rustc).is_file() or not os.access(rustc, os.X_OK):
        raise SystemExit("RUSTC must identify the real pinned compiler")
    from hepta.backend import toolchain_info
    print("RUST_TOOLCHAIN:", toolchain_info(rustc), flush=True)
    tests = list(flatten(unittest.defaultTestLoader.loadTestsFromNames(MODULES)))
    ids = [test.id() for test in tests]
    if len(ids) != EXPECTED_COUNT or len(set(ids)) != EXPECTED_COUNT:
        raise SystemExit(f"Expected exactly {EXPECTED_COUNT} unique module-local binding and adjacent controls")
    print("PLANNED_TEST_IDS:", ids, flush=True)
    result = unittest.TextTestRunner(verbosity=2, resultclass=ExactResult).run(unittest.TestSuite(tests))
    if (not result.wasSuccessful() or result.skipped or result.expectedFailures
            or result.unexpectedSuccesses or result.started != ids or result.testsRun != len(ids)):
        raise SystemExit("Exact inventory did not pass without skips/xfails/xpasses")
    print("COMPLETE_HOSTED_PASS", len(ids), flush=True)


if __name__ == "__main__":
    main()
