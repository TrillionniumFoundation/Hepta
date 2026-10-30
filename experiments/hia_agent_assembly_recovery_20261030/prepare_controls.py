#!/usr/bin/env python3
"""Fresh environment controls for an unchanged, independently copied v4 source."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time
import unittest
from unittest import mock


def save(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def identifiers(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from identifiers(item)
        else:
            yield item.id()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--phase", choices=("unit", "native"), required=True)
    parser.add_argument("--clang")
    parser.add_argument("--rustc")
    args = parser.parse_args()
    snapshot = Path(args.snapshot).resolve(strict=True)
    study = snapshot / "experiments/hia_agent_assembly_v4_20261030"
    output = Path(args.output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(snapshot))
    started = time.monotonic_ns()
    if args.phase == "unit":
        suite = unittest.defaultTestLoader.discover(str(study), pattern="test_protocol.py",
                                                    top_level_dir=str(study))
        ids = list(identifiers(suite))
        blocked = []

        def refuse(*_args, **_kwargs):
            blocked.append("external execution or socket connection")
            raise AssertionError("orchestration controls cannot invoke a native process or model")

        with (output / "controls.log").open("x") as log:
            with mock.patch("subprocess.Popen", side_effect=refuse), mock.patch("socket.socket.connect", side_effect=refuse):
                result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
        record = {"tests_run": result.testsRun, "test_ids": ids,
            "failures": len(result.failures), "errors": len(result.errors),
            "skipped": len(result.skipped), "passed": bool(result.wasSuccessful()
                and result.testsRun == 20 and not result.skipped and not blocked),
            "source_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                              for path in sorted(study.glob("*.py"))},
            "wall_ns": time.monotonic_ns() - started, "blocked_external_attempts": blocked,
            "model_completions": 0, "native_executions": 0}
        save(output / "UNIT_CONTROLS.json", record)
        with (output / "UNIT_CONTROLS.json").open("rb") as source, (study / "UNIT_CONTROLS.json").open("xb") as target:
            shutil.copyfileobj(source, target)
        print(json.dumps({"phase": "unit", "passed": record["passed"], "tests_run": result.testsRun}))
        return 0 if record["passed"] else 1

    if not args.clang or not args.rustc:
        raise ValueError("the actual native compiler paths are required")
    from experiments.hia_agent_assembly_v4_20261030 import fixtures, evaluator, controls
    reference = evaluator.reference_controls(fixtures.make_fixtures(), output / "reference",
                                             args.clang, args.rustc)
    hostile = controls.run(output / "hostile", args.clang, args.rustc)
    actual_native = sum(row["build"]["native_built"] and row.get("execution") is not None
                        for row in reference["rows"])
    passed = bool(reference["count"] == reference["passed"] == 36
        and hostile["count"] == hostile["passed"] == 9 and actual_native == 24)
    for source, name in ((output / "reference/CONTROLS.json", "DEVELOPMENT_CONTROLS.json"),
                         (output / "hostile/CONTROLS.json", "HOSTILE_CONTROLS.json")):
        with source.open("rb") as reader, (study / name).open("xb") as writer:
            shutil.copyfileobj(reader, writer)
    summary = {"passed": passed, "reference_controls": reference["count"],
        "reference_passed": reference["passed"], "reference_native_builds_and_executions": actual_native,
        "reference_expected_refusals": reference["count"] - actual_native,
        "hostile_native_controls": hostile["count"], "hostile_passed": hostile["passed"],
        "model_completions": 0, "reference_answers_are_model_answers": False,
        "wall_ns": time.monotonic_ns() - started}
    save(output / "SUMMARY.json", summary)
    print(json.dumps(summary), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
