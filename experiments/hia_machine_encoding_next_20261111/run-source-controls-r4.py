"""Fresh source controls after explicit HIA instruction-byte integration.

This controller regenerates checked declarations, retains complete before/after
source snapshots, then runs every loaded test in the six source-control groups.
It never starts a native cold replay or promotes historical test observations.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time
import traceback
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.hia_selfhost_contract import CONTRACT_PATH, file_digests

BASE = "d8cee49bb7eb00d53b89c5bc25416923b38cca38"
BASE_TREE = "4581491a06bf279a8129c1476fc86f6d747d4ce8"
GROUPS = (
    "tests.test_hia_integrated_workflow",
    "tests.test_hia_json_wire_native.WireSourceTests",
    "tests.test_hia_worker_report_native.WorkerReportSourceTests",
    "tests.test_hia_machine_plan_native.MachinePlanSourceTests",
    "tests.test_hia_machine_encoding_native.MachineEncodingSourceTests",
    "tests.test_hia_selfhost_linked_observer.LinkedObserverSourceTests",
)
COVERAGE = "docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n")


def source_snapshot(directory, name):
    paths = sorted(set(file_digests(ROOT)) | {
        CONTRACT_PATH, Path(__file__).relative_to(ROOT).as_posix()})
    manifest = {}
    archive = directory / (name + ".zip")
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9) as saved:
        for relative in paths:
            path = ROOT / relative
            if path.is_symlink() or not path.is_file():
                raise ValueError("snapshot input is not a regular file: " + relative)
            raw = path.read_bytes()
            mode = path.stat().st_mode & 0o777
            manifest[relative] = {"bytes": len(raw), "sha256": digest(raw), "mode": mode}
            info = zipfile.ZipInfo(relative, (2026, 11, 11, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            saved.writestr(info, raw)
    with zipfile.ZipFile(archive) as saved:
        if saved.namelist() != paths or len(set(saved.namelist())) != len(paths):
            raise ValueError("snapshot archive membership differs")
        for relative in paths:
            raw = saved.read(relative)
            expected = manifest[relative]
            if (len(raw) != expected["bytes"] or digest(raw) != expected["sha256"]
                    or (saved.getinfo(relative).external_attr >> 16) & 0o777 != expected["mode"]):
                raise ValueError("snapshot archive readback differs: " + relative)
    write_json(directory / (name + ".manifest.json"), manifest)
    return {"path": archive.name, "bytes": archive.stat().st_size,
            "sha256": digest(archive.read_bytes()), "members": len(paths),
            "decoded_bytes": sum(row["bytes"] for row in manifest.values()),
            "every_member_bytes_hash_and_mode_read_back": True}, manifest


def ids(suite):
    result = []
    for item in suite:
        result.extend(ids(item) if isinstance(item, unittest.TestSuite) else [item.id()])
    return result


class ObservedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed = []

    def startTest(self, test):
        self.executed.append(test.id())
        super().startTest(test)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    report = {
        "schema": "hepta.hia.v66.source-controls.v4",
        "scope": "SOURCE_ONLY_NOT_COLD_OR_FULL",
        "status": "STARTED_NOT_A_RESULT",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "materialized_base": BASE, "materialized_base_tree": BASE_TREE,
        "materialization_is_full_git_checkout": False,
        "python": sys.version, "python_executable": sys.executable,
        "platform": platform.platform(), "groups": list(GROUPS),
        "historical_results_relabelled": False,
        "cold_or_native_caller_qualification_executed": False,
        "steps": [],
    }
    write_json(directory / "report.json", report)
    started = time.monotonic()
    try:
        archive, before = source_snapshot(directory, "before-regeneration")
        report["before_regeneration_archive"] = archive
        commands = [
            [sys.executable, "-B", "tools/generate_hia_selfhost_contract.py"],
            [sys.executable, "-B", "tests/test_hia_selfhost_language_coverage.py", "--generate-inventory"],
            [sys.executable, "-B", "tools/generate_hia_selfhost_contract.py"],
            [sys.executable, "-B", "tools/generate_hia_selfhost_contract.py", "--check"],
            [sys.executable, "-B", "-c",
             "from tests.test_hia_selfhost_language_coverage import validate_inventory; "
             "validate_inventory(); print('LANGUAGE_INVENTORY_CURRENT')"],
        ]
        for index, command in enumerate(commands, 1):
            begin = time.monotonic()
            process = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=120)
            prefix = f"regeneration-{index}"
            (directory / (prefix + ".stdout.log")).write_bytes(process.stdout)
            (directory / (prefix + ".stderr.log")).write_bytes(process.stderr)
            report["steps"].append({"argv": command, "returncode": process.returncode,
                "seconds": time.monotonic() - begin, "stdout_path": prefix + ".stdout.log",
                "stderr_path": prefix + ".stderr.log"})
            write_json(directory / "report.json", report)
            if process.returncode:
                raise RuntimeError("declaration regeneration failed at step " + str(index))
        archive, selected = source_snapshot(directory, "executed-source")
        report["executed_source_archive"] = archive
        changed = sorted(path for path in before if before[path] != selected[path])
        if sorted(before) != sorted(selected) or set(changed) - {CONTRACT_PATH, COVERAGE}:
            raise ValueError("regeneration changed unapproved source members")
        report["regenerated_paths"] = changed
        report["declared_source_files"] = len(file_digests(ROOT))
        report["source_manifest_before_tests"] = selected
        loader = unittest.TestLoader()
        suite = unittest.TestSuite(loader.loadTestsFromName(group) for group in GROUPS)
        loaded = ids(suite)
        report["loaded_ids"] = loaded
        report["loader_errors"] = list(loader.errors)
        if not loaded or loader.errors or len(set(loaded)) != len(loaded):
            raise ValueError("source suite is empty, duplicated or did not load completely")
        write_json(directory / "report.json", report)
        begin = time.monotonic()
        with (directory / "unittest.log").open("x") as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2,
                resultclass=ObservedResult).run(suite)
        report["test_seconds"] = time.monotonic() - begin
        report["executed_ids"] = result.executed
        report["testsRun"] = result.testsRun
        for kind in ("failures", "errors", "skipped", "expectedFailures"):
            report[kind] = [[test.id(), detail] for test, detail in getattr(result, kind)]
        report["unexpectedSuccesses"] = [test.id() for test in result.unexpectedSuccesses]
        current = {path: {"bytes": (ROOT / path).stat().st_size,
            "sha256": digest((ROOT / path).read_bytes()),
            "mode": (ROOT / path).stat().st_mode & 0o777} for path in selected}
        report["source_manifest_after_tests"] = current
        report["source_unchanged_during_tests"] = current == selected
        report["status"] = "PASS" if (
            result.testsRun == len(loaded) and result.executed == loaded
            and current == selected and not any(report[kind] for kind in
                ("failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses"))
        ) else "FAIL"
    except BaseException:
        report["status"] = "FAIL"
        report["controller_exception"] = traceback.format_exc()
    report["seconds"] = time.monotonic() - started
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    write_json(directory / "report.json", report)
    print(json.dumps({key: report[key] for key in
        ("schema", "scope", "status", "seconds")} |
        {"testsRun": report.get("testsRun"), "declared_source_files": report.get("declared_source_files")}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
