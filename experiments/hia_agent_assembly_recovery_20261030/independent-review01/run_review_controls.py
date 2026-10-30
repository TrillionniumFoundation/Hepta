#!/usr/bin/env python3
"""Run this independent bounded review once and retain its complete receipt."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time
import traceback
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
RECOVERY = HERE.parent
ROOT = RECOVERY.parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_ids(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from test_ids(item)
        else:
            yield item.id()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    old = ROOT / "experiments/hia_agent_assembly_v4_20261030"
    original = json.loads((old / "REGISTRATION.json").read_bytes())
    files = set(RECOVERY.glob("*.py")) | {HERE / "test_recovery_review.py", Path(__file__).resolve(),
        RECOVERY / "PROTOCOL.json", RECOVERY / "PARENT_RUNTIME_ENVIRONMENT.json",
        ROOT / ".github/workflows/hepta-agent-recovery.yml", old / "REGISTRATION.json", old / "PROTOCOL.json",
        ROOT / "experiments/hia_agent_assembly_v4_readout_20261030/FROZEN_COHORT_RESULT.json"}
    files |= {ROOT / name for name in original["sources"]}
    files |= {ROOT / "experiments/hia_agent_assembly_v4_readout_20261030" / name
              for name in ("readout.py", "diagnose.py", "archive_evidence.py")}
    before = {str(path.relative_to(ROOT)): sha(path) for path in sorted(files)}
    blocked = []
    started = time.monotonic_ns()
    result = None
    identifiers = []
    load_error = None

    def refuse(*_args, **_kwargs):
        blocked.append("external process or connection attempted")
        raise AssertionError("independent review permits only bounded fakes, without external processes or connections")

    with (output / "controls.log").open("x") as log:
        try:
            with mock.patch("subprocess.Popen", side_effect=refuse), \
                 mock.patch("subprocess.run", side_effect=refuse), \
                 mock.patch("subprocess.check_output", side_effect=refuse), \
                 mock.patch("socket.socket.connect", side_effect=refuse), \
                 mock.patch("urllib.request.urlopen", side_effect=refuse):
                specification = importlib.util.spec_from_file_location(
                    "independent_recovery_controls", HERE / "test_recovery_review.py")
                module = importlib.util.module_from_spec(specification)
                sys.modules[specification.name] = module
                specification.loader.exec_module(module)
                suite = unittest.defaultTestLoader.loadTestsFromModule(module)
                identifiers = list(test_ids(suite))
                result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
        except BaseException as error:
            load_error = {"type": type(error).__name__, "message": str(error)}
            traceback.print_exc(file=log)
    wall_ns = time.monotonic_ns() - started
    after = {str(path.relative_to(ROOT)): sha(path) for path in sorted(files)}
    passed = bool(result is not None and result.wasSuccessful() and not result.skipped
                  and result.testsRun == len(identifiers) == 26 and not blocked and before == after)
    record = {"schema": "hepta.agent.recovery.independent-controls.v1", "passed": passed,
        "scope": "Pure source/protocol comparisons and bounded mock launch/API/cohort execution; no real model, compiler, native candidate, archive extraction or network calls",
        "tests_run": result.testsRun if result else 0, "test_ids": identifiers,
        "failures": len(result.failures) if result else None,
        "errors": len(result.errors) if result else None,
        "skipped": len(result.skipped) if result else None,
        "load_error": load_error, "wall_ns_including_imports": wall_ns,
        "model_completions": 0, "native_compiler_or_candidate_executions": 0,
        "blocked_external_attempts": blocked, "source_before": before, "source_after": after,
        "source_unchanged": before == after, "log_sha256": sha(output / "controls.log")}
    with (output / "controls.json").open("x") as stream:
        json.dump(record, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"passed": passed, "tests_run": record["tests_run"],
        "failures": record["failures"], "errors": record["errors"], "skipped": record["skipped"],
        "source_unchanged": record["source_unchanged"], "wall_ns": wall_ns,
        "blocked_external_attempts": len(blocked), "model_completions": 0, "native_executions": 0}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
