"""Require exact module-scope/CLI-input composition with real native tools."""
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

from tools.test_module_scope_context_union import MODULES as SCOPE_MODULES

# The scope runner already selects all of test_c_backend. Do not append the
# CLI runner's three individual selectors and execute those methods twice.
MODULES = (*SCOPE_MODULES, "tests.test_cli_input_protection", "tests.test_debug_info",
           "tests.test_source_map", "tests.test_module_scope_cli_input_union")
INVENTORY = Path(__file__).with_name("module_scope_cli_input_union_inventory.json")
COMPONENT_INVENTORIES = (
    ROOT / "tools/module_scope_context_union_inventory.json",
    ROOT / "tools/cli_input_protection_inventory.json",
)


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


def inventory(path):
    value = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(value, list) or not value
            or not all(isinstance(item, str) for item in value)
            or len(value) != len(set(value))):
        raise SystemExit("Inventory must contain unique complete method identities: " + str(path))
    return value


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
        raise SystemExit("Imported compiler is not the physical scope/CLI-input checkout")
    print("COMPILER_ROOT:", ROOT, flush=True)
    print("RUST_TOOLCHAIN:", json.dumps(toolchain_info(rustc), sort_keys=True), flush=True)
    expected = inventory(INVENTORY)
    inherited = set().union(*(inventory(path) for path in COMPONENT_INVENTORIES))
    if len(inherited) != 525 or not inherited.issubset(expected):
        raise SystemExit("The 525 inherited scope and CLI-input methods must all remain present")
    tests = list(flatten(unittest.defaultTestLoader.loadTestsFromNames(MODULES)))
    ids = [test.id() for test in tests]
    if ids != expected or len(ids) != len(set(ids)):
        raise SystemExit("Discovered composition tests differ from the frozen ordered inventory")
    identities = {}
    for name in (*MODULES, "hepta.cli", "hepta.modules", "hepta.module_bindings",
                 "hepta.packages", "hepta.checker", "hepta.pipeline", "hepta.backend",
                 "hepta.c_backend", "tools.test_module_scope_context_union",
                 "tools.test_cli_input_protection"):
        path = Path(importlib.import_module(name).__file__).resolve()
        if not path.is_relative_to(ROOT):
            raise SystemExit("Imported module is outside the physical checkout: " + name)
        identities[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    for path in (Path(__file__).resolve(), INVENTORY, *COMPONENT_INVENTORIES):
        identities[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    print("SOURCE_IDENTITIES:", json.dumps(identities, sort_keys=True), flush=True)
    print("PLANNED_TEST_IDS:", json.dumps(ids), flush=True)
    result = unittest.TextTestRunner(verbosity=2, resultclass=ExactResult).run(unittest.TestSuite(tests))
    print("EXECUTED_TEST_IDS:", json.dumps(result.started), flush=True)
    print("PASSED_TEST_IDS:", json.dumps(result.passed), flush=True)
    print("SUBTEST_RESULTS:", json.dumps(result.subtests), flush=True)
    if (not result.wasSuccessful() or result.skipped or result.expectedFailures
            or result.unexpectedSuccesses or result.started != expected or result.passed != expected
            or result.testsRun != len(expected)):
        raise SystemExit("Exact composition inventory did not pass without skips/xfails/xpasses")
    print("COMPLETE_HOSTED_PASS", len(ids), flush=True)


if __name__ == "__main__":
    main()
