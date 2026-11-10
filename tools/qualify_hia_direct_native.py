"""Reproducible, source-bound finite qualification of the direct HIA backend.

All named tests must execute: failures, errors, unexpected successes and skips
make the result fail. The same run preserves the complete test inventory and
source hashes. This is evidence of finite execution, not a safety certificate.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

SUITES = (
    "tests.test_hia_machine_x64",
    "tests.test_hia_program_native",
    "tests.test_hia_machine_lowering_edges",
    "tests.test_hia_program_native_review",
    "tests.test_hia_program",
    "tests.test_hia_program_composite",
    "tests.test_hia_routes",
    "tests.test_hia_opcode_catalog",
    "tests.test_hia_capability_flow",
    "tests.test_hia_json_preflight",
    "tests.test_hia_returned_loans.ReturnedLoans",
    "tests.test_hia_returned_loans.ReturnedLoanSemantics",
    "tests.test_hia_recursive_chain.HIARecursiveChainTests",
)


def source_identity():
    files = {}
    for folder in ("hepta", "tests", "tools"):
        for path in sorted((ROOT / folder).rglob("*")):
            if path.suffix == ".py" or folder == "hepta" and path.suffix == ".hiaasm":
                files[path.relative_to(ROOT).as_posix()] = sha256(path.read_bytes()).hexdigest()
    for folder in ("hia_program", "hia_recursive_chain"):
        for path in sorted((ROOT / "examples" / folder).rglob("*")):
            if path.is_file() and path.suffix in {".hia", ".json", ".hepta", ".c"}:
                files[path.relative_to(ROOT).as_posix()] = sha256(path.read_bytes()).hexdigest()
    for name in ("docs/HIA_OPCODE_REFERENCE.md", "docs/hia-opcode-catalog.v8.json",
                 "docs/HIA_DIRECT_NATIVE.md", ".github/workflows/hia-direct-native.yml"):
        files[name] = sha256((ROOT / name).read_bytes()).hexdigest()
    wire = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {"sha256": sha256(wire).hexdigest(), "files": files}


def _git(*args):
    run = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, timeout=10)
    return run.stdout.strip() if run.returncode == 0 else None


def _ids(suite):
    result = []
    for item in suite:
        result.extend(_ids(item) if isinstance(item, unittest.TestSuite) else [item.id()])
    return result


class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed_ids = []
        self.case_counts = {}

    def startTest(self, test):
        self.executed_ids.append(test.id())
        super().startTest(test)

    def stopTest(self, test):
        if getattr(test, "case_counts", None):
            self.case_counts[test.id()] = dict(test.case_counts)
        super().stopTest(test)


def qualify():
    started = time.monotonic()
    before = source_identity()
    report = {"schema": "hepta.hia.direct-native-qualification.v1",
              "started_utc": datetime.now(timezone.utc).isoformat(),
              "git_head": _git("rev-parse", "HEAD"), "git_tree": _git("rev-parse", "HEAD^{tree}"),
              "git_status": _git("status", "--porcelain", "--untracked-files=all"),
              "host": {"platform": platform.platform(), "machine": platform.machine(),
                       "python": sys.version, "libc": list(platform.libc_ver())},
              "suites": list(SUITES), "source": before,
              "claims": {"finite_same_source_test_run": False, "production_qualified": False,
                         "backend_refinement_proved": False, "self_hosted": False,
                         "faster_than_llvm_proved": False, "other_architectures_qualified": False}}
    suite = unittest.defaultTestLoader.loadTestsFromNames(SUITES)
    inventory = _ids(suite)
    report["test_inventory"] = inventory
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2, resultclass=Result).run(suite)
    after = source_identity()
    report.update(tests_run=result.testsRun, executed_ids=result.executed_ids,
                  case_counts=result.case_counts,
                  failures=[{"id": test.id(), "traceback": trace} for test, trace in result.failures],
                  errors=[{"id": test.id(), "traceback": trace} for test, trace in result.errors],
                  skipped=[{"id": test.id(), "reason": reason} for test, reason in result.skipped],
                  expected_failures=[{"id": test.id(), "traceback": trace} for test, trace in result.expectedFailures],
                  unexpected_successes=[test.id() for test in result.unexpectedSuccesses],
                  source_unchanged=before == after,
                  elapsed_seconds=time.monotonic() - started,
                  completed_utc=datetime.now(timezone.utc).isoformat())
    complete = len(inventory) == len(set(inventory)) and sorted(result.executed_ids) == sorted(inventory)
    report["inventory_complete"] = complete
    report["ok"] = (result.wasSuccessful() and not result.skipped and not result.expectedFailures
                    and complete and before == after)
    report["claims"]["finite_same_source_test_run"] = report["ok"]
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="new JSON result file; existing output is never replaced")
    args = parser.parse_args(argv)
    destination = Path(args.output).absolute()
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        parser.error("--output must be a new file in an existing directory")
    report = qualify()
    from hepta.artifact_publication import publish_verified
    payload = (json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode()
    with tempfile.TemporaryDirectory(prefix=".hia-qualification-", dir=destination.parent) as directory:
        stage = Path(directory) / "result.json"
        stage.write_bytes(payload)
        publish_verified(stage, destination, payload)
    print(json.dumps({"ok": report["ok"], "tests_run": report["tests_run"],
                      "source_sha256": report["source"]["sha256"], "output": str(destination)}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
