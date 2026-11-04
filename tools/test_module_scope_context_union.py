"""Require the exact scope/package-context composition and actual native tools."""
from pathlib import Path
import hashlib
import importlib
import json
import os
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.test_module_same_source_generic_scope import MODULES as SCOPE_MODULES
from tools.test_module_package_context import MODULES as CONTEXT_MODULES

MODULES = tuple(dict.fromkeys((*SCOPE_MODULES, *CONTEXT_MODULES,
                              "tests.test_module_scope_context_union")))
INVENTORY = Path(__file__).with_name("module_scope_context_union_inventory.json")


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
        raise SystemExit("Imported compiler is not the physical scope/context checkout")
    print("COMPILER_ROOT:", ROOT, flush=True)
    print("RUST_TOOLCHAIN:", toolchain_info(rustc), flush=True)
    expected = json.loads(INVENTORY.read_text())
    if (not isinstance(expected, list) or not all(isinstance(item, str) for item in expected)
            or len(expected) != len(set(expected))):
        raise SystemExit("Frozen inventory must contain unique test identities")
    tests = list(flatten(unittest.defaultTestLoader.loadTestsFromNames(MODULES)))
    ids = [test.id() for test in tests]
    if ids != expected or len(ids) != len(set(ids)):
        raise SystemExit("Discovered scope/context tests differ from the frozen ordered inventory")
    identities = {}
    for name in (*MODULES, "hepta.modules", "hepta.module_bindings", "hepta.checker",
                 "hepta.pipeline", "hepta.backend", "hepta.c_backend"):
        path = Path(importlib.import_module(name).__file__).resolve()
        if not path.is_relative_to(ROOT):
            raise SystemExit("Imported module is outside the physical checkout: " + name)
        identities[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    for path in (Path(__file__).resolve(), INVENTORY):
        identities[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    print("SOURCE_IDENTITIES:", json.dumps(identities, sort_keys=True), flush=True)
    print("PLANNED_TEST_IDS:", json.dumps(ids), flush=True)
    result = unittest.TextTestRunner(verbosity=2, resultclass=ExactResult).run(unittest.TestSuite(tests))
    print("EXECUTED_TEST_IDS:", json.dumps(result.started), flush=True)
    print("PASSED_TEST_IDS:", json.dumps(result.passed), flush=True)
    if (not result.wasSuccessful() or result.skipped or result.expectedFailures
            or result.unexpectedSuccesses or result.started != expected or result.passed != expected
            or result.testsRun != len(expected)):
        raise SystemExit("Exact composition inventory did not pass without skips/xfails/xpasses")
    print("COMPLETE_HOSTED_PASS", len(ids), flush=True)


if __name__ == "__main__":
    main()
