#!/usr/bin/env python3
"""Freeze current implementation plus the unchanged v4 protocol, then qualify it.

This is a source-snapshot reproduction of previously disclosed tasks. It does
not create a new blind study, alter old artifacts, or weaken any v4 gate.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import unittest

HERE = Path(__file__).resolve().parent
STUDY = Path("experiments/hia_agent_assembly_v4_20261030")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical(value) + b"\n")


def identity(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "git_blob_sha1": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()}


def resources():
    result = {"unix_ns": time.time_ns(), "cpu_affinity": sorted(os.sched_getaffinity(0)),
              "disk_free_bytes": shutil.disk_usage("/tmp").free}
    for name in ("cpu.max", "memory.max", "memory.current", "memory.stat", "memory.events"):
        try:
            result[name] = (Path("/sys/fs/cgroup") / name).read_text()
        except OSError as error:
            result[name] = {"type": type(error).__name__, "message": str(error)}
    return result


def freeze(source, protocol_source, output):
    started = time.monotonic_ns()
    source, protocol_source, output = map(lambda x: Path(x).resolve(), (source, protocol_source, output))
    output.mkdir(parents=True, exist_ok=False)
    target = output / "source"
    target.mkdir()
    original = json.loads((HERE / "PROTOCOL_SOURCE_BLOBS.json").read_bytes())
    files, origins = {}, {}
    for directory in ("hepta", "tools", "tests"):
        for path in sorted((source / directory).rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            relative = path.relative_to(source)
            data = path.read_bytes()
            files[str(relative)] = identity(data)
            origins[str(relative)] = path
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
    for name in ("pyproject.toml",):
        if (source / name).is_file():
            data = (source / name).read_bytes()
            (target / name).write_bytes(data)
            files[name], origins[name] = identity(data), source / name
    for name, expected in original["files"].items():
        path = protocol_source / name
        data = path.read_bytes()
        actual = identity(data)
        if any(actual[key] != value for key, value in expected.items()):
            raise RuntimeError("original protocol source differs from pinned Git blob: " + name)
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        files[name], origins[name] = actual, path
    if any(identity(path.read_bytes()) != files[name] for name, path in origins.items()):
        raise RuntimeError("source changed during snapshot creation; retain this failed freeze")
    for name in files:
        (target / name).chmod(0o444)
    result = {"schema": "hepta.agent-replication.source-snapshot.v1", "baseline_commit": original["baseline_commit"],
              "interpretation": "new implementation snapshot; previously disclosed v4 tasks; not new blind tasks",
              "source": str(source), "protocol_source": str(protocol_source), "snapshot": str(target),
              "files": dict(sorted(files.items())), "content_sha256": hashlib.sha256(canonical(files)).hexdigest(),
              "source_unchanged_during_freeze": True, "created_unix_ns": time.time_ns(),
              "wall_ns": time.monotonic_ns() - started, "resources": resources()}
    save(output / "SOURCE_SNAPSHOT.json", result)
    print(json.dumps({key: result[key] for key in ("snapshot", "content_sha256", "wall_ns")}), flush=True)


def test_ids(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from test_ids(item)
        else:
            yield item.id()


def controls(snapshot, output, clang, rustc):
    snapshot, output = map(lambda x: Path(x).resolve(), (snapshot, output))
    output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(snapshot))
    prefix = "experiments.hia_agent_assembly_v4_20261030."
    fixtures = importlib.import_module(prefix + "fixtures")
    evaluator = importlib.import_module(prefix + "evaluator")
    hostile = importlib.import_module(prefix + "controls")
    test_module = importlib.import_module(prefix + "test_protocol")
    study = snapshot / STUDY
    started = time.monotonic_ns()
    suite = unittest.defaultTestLoader.loadTestsFromModule(test_module)
    ids = list(test_ids(suite))
    with (output / "UNIT_CONTROLS.log").open("x") as log:
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    unit = {"tests_run": result.testsRun, "test_ids": ids, "failures": len(result.failures),
            "errors": len(result.errors), "skipped": len(result.skipped), "passed": result.wasSuccessful() and not result.skipped,
            "source_sha256": {path.name: identity(path.read_bytes())["sha256"] for path in sorted(study.glob("*.py"))},
            "wall_ns": time.monotonic_ns() - started}
    save(output / "UNIT_CONTROLS.json", unit)
    if not unit["passed"]:
        raise RuntimeError("original v4 orchestration controls failed")
    before = time.monotonic_ns()
    reference = evaluator.reference_controls(fixtures.make_fixtures(), output / "reference", clang, rustc)
    reference_ns = time.monotonic_ns() - before
    before = time.monotonic_ns()
    hostile_result = hostile.run(output / "hostile", clang, rustc)
    hostile_ns = time.monotonic_ns() - before
    save(output / "DEVELOPMENT_CONTROLS.json", reference)
    save(output / "HOSTILE_CONTROLS.json", hostile_result)
    passed = reference["count"] == reference["passed"] == 36 and hostile_result["count"] == hostile_result["passed"] == 9
    summary = {"passed": passed, "reference_count": reference["count"], "reference_passed": reference["passed"],
               "hostile_count": hostile_result["count"], "hostile_passed": hostile_result["passed"],
               "unit_tests": unit["tests_run"], "unit_wall_ns": unit["wall_ns"], "reference_wall_ns": reference_ns,
               "hostile_wall_ns": hostile_ns, "whole_controls_wall_ns": time.monotonic_ns() - started,
               "model_requests": 0, "model_answers": False}
    save(output / "RESULT.json", summary)
    if not passed:
        raise RuntimeError("original v4 native controls failed")
    for name in ("UNIT_CONTROLS.json", "DEVELOPMENT_CONTROLS.json", "HOSTILE_CONTROLS.json"):
        with (study / name).open("xb") as stream:
            stream.write((output / name).read_bytes())
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    freeze_args = sub.add_parser("freeze")
    for name in ("source", "protocol-source", "output"):
        freeze_args.add_argument("--" + name, required=True)
    control_args = sub.add_parser("controls")
    for name in ("snapshot", "output", "clang", "rustc"):
        control_args.add_argument("--" + name, required=True)
    arguments = vars(parser.parse_args())
    action = arguments.pop("action")
    {"freeze": freeze, "controls": controls}[action](**arguments)
