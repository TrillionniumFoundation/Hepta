"""Require exact module/package-context controls and real native toolchains."""
from pathlib import Path
import os
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

MODULES = (
    "tests.test_module_package_context", "tests.test_modules",
    "tests.test_project_protocol", "tests.test_protocol_v3",
    "tests.test_workspace", "tests.test_cross_feature_audit",
    "tests.test_c_import", "tests.test_c_import_prototypes",
    "tests.test_c_import_typedefs", "tests.test_c_import_capture",
    "tests.test_workspace_query_cli",
)
EXPECTED_COUNT = 124


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

    def startTest(self, test):
        self.started.append(test.id())
        super().startTest(test)

    def addSuccess(self, test):
        self.passed.append(test.id())
        super().addSuccess(test)


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
    print("RUST_TOOLCHAIN:", toolchain_info(rustc), flush=True)
    tests = list(flatten(unittest.defaultTestLoader.loadTestsFromNames(MODULES)))
    ids = [test.id() for test in tests]
    if len(ids) != EXPECTED_COUNT or len(set(ids)) != EXPECTED_COUNT:
        raise SystemExit(f"Expected exactly {EXPECTED_COUNT} unique package-context controls")
    print("PLANNED_TEST_IDS:", ids, flush=True)
    result = unittest.TextTestRunner(verbosity=2, resultclass=ExactResult).run(unittest.TestSuite(tests))
    # Native receipt prints can interrupt unittest's progress-line formatting.
    # Emit full explicit identities rather than relying on parsing those lines.
    print("EXECUTED_TEST_IDS:", result.started, flush=True)
    print("PASSED_TEST_IDS:", result.passed, flush=True)
    if (not result.wasSuccessful() or result.skipped or result.expectedFailures
            or result.unexpectedSuccesses or result.started != ids or result.passed != ids
            or result.testsRun != len(ids)):
        raise SystemExit("Exact inventory did not pass without skips/xfails/xpasses")
    print("COMPLETE_HOSTED_PASS", len(ids), flush=True)


if __name__ == "__main__":
    main()
