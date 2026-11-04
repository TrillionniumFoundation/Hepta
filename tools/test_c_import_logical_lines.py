"""Run the C header logical-line gate with a complete native GCC test inventory."""
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

MODULES = ("tests.test_c_import_logical_lines", "tests.test_c_import",
           "tests.test_c_import_typedefs", "tests.test_c_import_prototypes",
           "tests.test_c_import_capture")


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
    gcc = shutil.which("gcc")
    if gcc is None:
        raise SystemExit("A real native GCC compiler is required")
    version = subprocess.run([gcc, "--version"], capture_output=True, text=True,
                             check=True, timeout=30)
    print("GCC_TOOLCHAIN:", gcc, version.stdout, flush=True)
    tests = list(flatten(unittest.defaultTestLoader.loadTestsFromNames(MODULES)))
    ids = [test.id() for test in tests]
    if len(ids) != 43 or len(set(ids)) != 43:
        raise SystemExit("Expected exactly 43 unique C header import controls")
    print("PLANNED_TEST_IDS:", ids, flush=True)
    result = unittest.TextTestRunner(verbosity=2, resultclass=ExactResult).run(unittest.TestSuite(tests))
    if (not result.wasSuccessful() or result.skipped or result.expectedFailures
            or result.unexpectedSuccesses or result.started != ids or result.testsRun != len(ids)):
        raise SystemExit("Exact inventory did not pass without skips/xfails/xpasses")
    print("COMPLETE_HOSTED_PASS", len(ids), flush=True)


if __name__ == "__main__":
    main()
