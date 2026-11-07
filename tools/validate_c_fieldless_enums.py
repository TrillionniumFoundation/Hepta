#!/usr/bin/env python3
"""Run an exact, no-skip inventory; native Rust is opt-in and explicit."""
from pathlib import Path
import hashlib
import json
import os
import platform
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
MODULES = ["test_c_fieldless_enums", "test_c_backend", "test_parser", "test_checker",
           "test_language.LanguageSyntax", "test_language.LanguageRejections",
           "test_cross_feature_audit.CIntegrationAudit.test_new_language_features_fail_before_c_codegen_or_artifact_replacement"]


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


class TrackedResult(unittest.TextTestResult):
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
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in MODULES)
    planned = [test.id() for test in flatten(suite)]
    expected = json.loads((ROOT / "tools/c_fieldless_enum_test_ids.json").read_text())
    if planned != expected or len(set(planned)) != len(planned):
        raise SystemExit("Test inventory differs from frozen unique method IDs")
    inputs = [str(path.relative_to(ROOT)) for path in sorted((ROOT / "hepta").glob("*.py"))]
    inputs += sorted({"tests/" + name.split(".")[0] + ".py" for name in MODULES})
    inputs += ["examples/fieldless_enums.hepta", "tools/c_fieldless_enum_test_ids.json",
               "tools/validate_c_fieldless_enums.py"]
    hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in inputs}
    print(json.dumps({"python": sys.version, "host": platform.platform(),
                      "rust_required": os.environ.get("HEPTA_ENUM_REQUIRE_RUST") == "1",
                      "source_sha256": hashes, "planned": planned}), flush=True)
    result = unittest.TextTestRunner(verbosity=2, resultclass=TrackedResult).run(suite)
    ok = (result.wasSuccessful() and not result.skipped and not result.expectedFailures
          and not result.unexpectedSuccesses and planned == result.started == result.finished == result.passed
          and all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
                  for name, digest in hashes.items()))
    print(json.dumps({"tests_run": result.testsRun, "started": result.started,
                      "finished": result.finished, "passed": result.passed,
                      "complete_pass": ok}), flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
