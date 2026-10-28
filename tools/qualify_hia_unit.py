#!/usr/bin/env python3
"""Execute the complete discovery inventory in isolated module processes.

This is a module-partitioned regression, not a single-process unittest run.
Every discovered ID must start and finish exactly once. A missing module,
changed discovery set, skip, expected failure, timeout or incomplete receipt
prevents qualification. The runner never retries failed modules.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.clang_capture import CaptureRejected, check_capture_deadline, run_bounded, scoped_capture_deadline
from tools.release_check import _read_regular_evidence, _stable_source_digest, _strict_json

SCHEMA = "hepta.hia.partitioned-unit-qualification.v1"
CHILD_SCHEMA = "hepta.hia.unit-module.v1"
MODULE_PATTERN = re.compile(r"test_[A-Za-z0-9_]+\Z")
MODULE_DEADLINE_SECONDS = 600
MODULE_PROCESS_SECONDS = 900
WORKERS = 2


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def write_new(path, value):
    with Path(path).open("xb") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n")


def flatten(suite):
    for case in suite:
        if isinstance(case, unittest.TestSuite):
            yield from flatten(case)
        else:
            yield case


def discover(root=ROOT, module=None):
    if module is not None and MODULE_PATTERN.fullmatch(module) is None:
        raise ValueError("invalid test module")
    loader = unittest.TestLoader()
    suite = loader.discover(str(Path(root) / "tests"), pattern="test*.py" if module is None else module + ".py")
    ids = [case.id() for case in flatten(suite)]
    if loader.errors or not ids or len(ids) != len(set(ids)):
        raise ValueError("discovery must be nonempty, unique and free of loader errors: " + repr(loader.errors))
    for identifier in ids:
        name = identifier.split(".", 1)[0]
        if MODULE_PATTERN.fullmatch(name) is None or (module is not None and name != module):
            raise ValueError("discovery escaped its declared module")
    return suite, ids


class ObservedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started_ids = []
        self.finished_ids = []

    def startTest(self, test):
        check_capture_deadline()
        self.started_ids.append(test.id())
        super().startTest(test)

    def stopTest(self, test):
        self.finished_ids.append(test.id())
        super().stopTest(test)


def run_module(module, output, root=ROOT):
    output = Path(output)
    report = {"schema": CHILD_SCHEMA, "module": module, "ok": False,
              "status": "started", "deadline_seconds": MODULE_DEADLINE_SECONDS}
    # Reserve the exact new pathname before discovery or execution.
    with output.open("x", encoding="utf-8") as stream:
        started = time.monotonic()
        try:
            with scoped_capture_deadline(MODULE_DEADLINE_SECONDS) as deadline:
                suite, ids = discover(root, module)
                report["discovered_ids"] = ids
                result = unittest.TextTestRunner(verbosity=1, resultclass=ObservedResult).run(suite)
                report.update(started_ids=result.started_ids, finished_ids=result.finished_ids,
                              tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                              skipped=len(result.skipped), expected_failures=len(result.expectedFailures),
                              unexpected_successes=len(result.unexpectedSuccesses), status="completed")
            report["deadline_expired"] = deadline.expired
            report["ok"] = (not deadline.expired and result.wasSuccessful()
                            and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses
                            and Counter(ids) == Counter(result.started_ids) == Counter(result.finished_ids)
                            and result.testsRun == len(ids))
        except BaseException as error:
            report.update(status="interrupted", error={"type": type(error).__name__, "message": str(error)})
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
        finally:
            report["seconds"] = time.monotonic() - started
            json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
    return report


def validate_module(row, expected_ids):
    """Replay the child receipt and terminal unittest denominator together."""
    from tools.qualify_hia_unified import unittest_outcome
    child = row.get("child")
    if type(child) is not dict or child.get("schema") != CHILD_SCHEMA:
        return False
    expected = Counter(expected_ids)
    observed = unittest_outcome(row.get("stderr_text", ""), row.get("returncode"))
    return (type(row.get("returncode")) is int and row["returncode"] == 0
            and row.get("capture_error") is None and child.get("ok") is True
            and child.get("status") == "completed" and child.get("module") == row.get("module")
            and child.get("deadline_seconds") == MODULE_DEADLINE_SECONDS
            and child.get("deadline_expired") is False
            and all(type(child.get(key)) is list and all(type(item) is str for item in child[key])
                    and Counter(child[key]) == expected
                    for key in ("discovered_ids", "started_ids", "finished_ids"))
            and type(child.get("tests_run")) is int and child["tests_run"] == len(expected_ids)
            and all(type(child.get(key)) is int and child[key] == 0 for key in
                    ("failures", "errors", "skipped", "expected_failures", "unexpected_successes"))
            and observed["passed"] and observed["tests_run"] == len(expected_ids))


def execute_module(item, output, python, root):
    module = item["module"]
    child_path = output / (module + ".json")
    argv = [str(python), str(Path(__file__).resolve()), "--module", module, "--output", str(child_path),
            "--test-root", str(root)]
    row = {"module": module, "argv": argv, "expected_ids": item["expected_ids"], "passed": False}
    start = time.monotonic()
    try:
        capture = run_bounded(argv, cwd=root, timeout=MODULE_PROCESS_SECONDS, stdin_limit=0,
                              stdout_limit=4 * 1024 * 1024, stderr_limit=8 * 1024 * 1024)
        row.update(returncode=capture.returncode, stdout_text=capture.stdout, stderr_text=capture.stderr)
    except CaptureRejected as error:
        partial = error.capture
        row.update(returncode=None, capture_error=error.code,
                   stdout_text="" if partial is None else partial.stdout.decode("utf-8", errors="replace"),
                   stderr_text="" if partial is None else partial.stderr.decode("utf-8", errors="replace"))
    row["seconds"] = time.monotonic() - start
    for channel in ("stdout", "stderr"):
        data = row[channel + "_text"].encode()
        path = output / (module + "." + channel + ".log")
        with path.open("xb") as stream:
            stream.write(data)
        row[channel] = {"path": path.name, "sha256": digest(data), "bytes": len(data)}
    try:
        raw, _ = _read_regular_evidence(child_path)
        row["child"] = _strict_json(raw)
        row["child_receipt"] = {"path": child_path.name, "sha256": digest(raw), "bytes": len(raw)}
    except (OSError, ValueError, RecursionError) as error:
        row["receipt_error"] = {"type": type(error).__name__, "message": str(error)}
    row["passed"] = validate_module(row, item["expected_ids"])
    # Retain raw logs once, and bind them by digest in the aggregate.
    row.pop("stdout_text")
    row.pop("stderr_text")
    write_new(output / (module + ".result.json"), row)
    return row


def qualify(output, *, python=sys.executable, root=ROOT, workers=WORKERS):
    if type(workers) is not int or not 1 <= workers <= 4:
        raise ValueError("workers must be an integer in 1..4")
    output, root = Path(output).absolute(), Path(root).absolute()
    output.mkdir(parents=True, exist_ok=False)
    # Discovery stdout is evidence too; no test import output can forge a CLI
    # status. Imports and test code remain trusted local qualification code.
    captured = io.StringIO()
    with redirect_stdout(captured):
        _, ids = discover(root)
    write_new(output / "discovery.json", {"ids": ids, "count": len(ids), "stdout": captured.getvalue()})
    groups = defaultdict(list)
    for identifier in ids:
        groups[identifier.split(".", 1)[0]].append(identifier)
    plan = [{"module": name, "expected_ids": sorted(values)} for name, values in
            sorted(groups.items(), key=lambda item: (-len(item[1]), item[0]))]
    write_new(output / "plan.json", {"schema": SCHEMA, "workers": workers, "modules": plan,
                                    "id_inventory_sha256": digest(canonical(sorted(ids))),
                                    "module_deadline_seconds": MODULE_DEADLINE_SECONDS,
                                    "module_process_seconds": MODULE_PROCESS_SECONDS,
                                    "order": "descending test count, alphabetical ties", "retries": 0})
    report = {"schema": SCHEMA, "ok": False, "status": "running", "workers": workers,
              "discovered_ids": sorted(ids), "id_inventory_sha256": digest(canonical(sorted(ids))),
              "expected_module_count": len(plan), "modules": [], "single_process_full_suite": False,
              "module_deadline_scope": "cooperative tool polls and test boundaries; outer child process bound 900s",
              "process_tree_scope": "POSIX process-group cleanup; child-created sessions are outside that guarantee"}
    start = time.monotonic()
    try:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="hia-unit") as pool:
            futures = {pool.submit(execute_module, item, output, python, root): item["module"] for item in plan}
            for future in as_completed(futures):
                row = future.result()
                report["modules"].append(row)
                write_new(output / ("progress-" + str(len(report["modules"])).zfill(4) + ".json"),
                          {"completed": len(report["modules"]), "expected": len(plan),
                           "module": row["module"], "passed": row["passed"], "seconds": row["seconds"]})
                print(json.dumps({"unit_module": row["module"], "passed": row["passed"],
                                  "completed": len(report["modules"]), "expected": len(plan)}), flush=True)
        report["status"] = "completed"
    finally:
        report["modules"].sort(key=lambda row: row["module"])
        report["seconds"] = time.monotonic() - start
        report["completed_module_count"] = len(report["modules"])
        report["passed_module_count"] = sum(row["passed"] for row in report["modules"])
        report["failed_modules"] = [row["module"] for row in report["modules"] if not row["passed"]]
        children = [row.get("child", {}) for row in report["modules"]]
        report["reported_tests_run"] = sum(child.get("tests_run", 0) for child in children if type(child.get("tests_run", 0)) is int)
        report["ok"] = (report["status"] == "completed" and len(report["modules"]) == len(plan)
                        and all(row["passed"] for row in report["modules"]))
        write_new(output / "qualification.json", report)
    return report


def validate_report(report, directory, *, expected_ids):
    """Re-read actual module logs/receipts; flags alone cannot qualify a run."""
    if (type(report) is not dict or report.get("schema") != SCHEMA or report.get("ok") is not True
            or report.get("status") != "completed" or type(report.get("modules")) is not list
            or type(report.get("discovered_ids")) is not list or not report["discovered_ids"]
            or any(type(value) is not str for value in report["discovered_ids"])
            or len(report["discovered_ids"]) != len(set(report["discovered_ids"]))):
        raise ValueError("incomplete partitioned unit report")
    ids = report["discovered_ids"]
    if (type(expected_ids) is not list or not expected_ids
            or any(type(value) is not str for value in expected_ids)
            or len(expected_ids) != len(set(expected_ids))
            or Counter(ids) != Counter(expected_ids)):
        raise ValueError("reported unit inventory differs from independent discovery")
    groups = defaultdict(list)
    for identifier in ids:
        module = identifier.split(".", 1)[0]
        if MODULE_PATTERN.fullmatch(module) is None:
            raise ValueError("invalid discovered test module")
        groups[module].append(identifier)
    if (report.get("id_inventory_sha256") != digest(canonical(sorted(ids)))
            or len(report["modules"]) != len(groups)
            or type(report.get("completed_module_count")) is not int
            or report.get("completed_module_count") != len(groups)
            or type(report.get("expected_module_count")) is not int
            or report.get("expected_module_count") != len(groups)
            or Counter(row.get("module") for row in report["modules"] if type(row) is dict) != Counter(groups.keys())):
        raise ValueError("partitioned unit inventory mismatch")
    if (type(report.get("reported_tests_run")) is not int or report["reported_tests_run"] != len(ids)
            or type(report.get("passed_module_count")) is not int or report["passed_module_count"] != len(groups)
            or type(report.get("workers")) is not int or report["workers"] != WORKERS
            or report.get("failed_modules") != [] or report.get("single_process_full_suite") is not False):
        raise ValueError("partitioned unit summary contradicts the observed inventory")
    directory = Path(directory)
    for row in report["modules"]:
        name = row["module"]
        if (row.get("passed") is not True or type(row.get("expected_ids")) is not list
                or row["expected_ids"] != sorted(groups[name])):
            raise ValueError("unit module summary contradicts the independent inventory")
        replay = dict(row)
        for key, suffix in (("child_receipt", ".json"), ("stderr", ".stderr.log"), ("stdout", ".stdout.log")):
            binding = row.get(key)
            if type(binding) is not dict or binding.get("path") != name + suffix:
                raise ValueError("unit receipt path mismatch")
            path = directory / binding["path"]
            if key == "stdout" and binding.get("bytes") == 0:
                if _stable_source_digest(path) != digest(b"") or binding.get("sha256") != digest(b""):
                    raise ValueError("empty unit log changed")
                continue
            raw, _ = _read_regular_evidence(path)
            if digest(raw) != binding.get("sha256") or len(raw) != binding.get("bytes"):
                raise ValueError("unit receipt bytes changed")
            if key == "child_receipt":
                replay["child"] = _strict_json(raw)
                if replay["child"] != row.get("child"):
                    raise ValueError("unit child report changed")
            elif key == "stderr":
                replay["stderr_text"] = raw.decode("utf-8")
        if not validate_module(replay, groups[name]):
            raise ValueError("unit module did not execute the exact successful inventory")
    return len(ids)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=WORKERS)
    parser.add_argument("--module", help=argparse.SUPPRESS)
    parser.add_argument("--test-root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.module is not None:
        result = run_module(args.module, args.output, root=args.test_root)
    else:
        result = qualify(args.output, workers=args.workers)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
