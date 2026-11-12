"""Run the exact original eight methods and observe all seven unchanged CLI children.

No method is selected out. Original subprocess commands and20-second deadlines
are unchanged. All parent/child imports use the same newly built source-bound
native manifest, while the retained Python policy code object is forbidden.
"""
from __future__ import annotations
import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import traceback
import unittest

sys.path.insert(0, str(Path(__file__).absolute().parent))
from source_common import _create_directory, create, pin, read, require, wire

TEST_SHA256 = "8e885163d57ec41e869d5b8cb206de1b9942e0c636bcacf3b362bd5e669317c6"
REFERENCE_CLI_SHA256 = "596b331db95ad2ebd3dba637fc4c34e8d2b0129bef63f8858edf02961e752aa4"
EXPECTED_IDS = (
    "tests.test_hia_program_tools.HIAProgramToolsTests.test_cli_bad_program_returns_structured_error",
    "tests.test_hia_program_tools.HIAProgramToolsTests.test_cli_trap_and_budget_are_distinct_structured_outcomes",
    "tests.test_hia_program_tools.HIAProgramToolsTests.test_cli_verify_run_inspect_and_patch_need_no_rust_or_high_level_source",
    "tests.test_hia_program_tools.HIAProgramToolsTests.test_patch_cannot_remove_required_effect_or_use_undefined_value",
    "tests.test_hia_program_tools.HIAProgramToolsTests.test_patch_rechecks_and_executes_changed_operations_without_source",
    "tests.test_hia_program_tools.HIAProgramToolsTests.test_patch_rejects_unknown_fields_bool_indices_and_nonfinite",
    "tests.test_hia_program_tools.HIAProgramToolsTests.test_publication_is_a_complete_verified_new_snapshot",
    "tests.test_hia_program_tools.HIAProgramToolsTests.test_stale_duplicate_and_overlapping_edits_reject",
)
MODULE = "tests.test_hia_program_tools"
SITE = b"from caller_observer import install_child\ninstall_child()\n"


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


class ActualResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed_ids = []
    def startTest(self, test):
        self.executed_ids.append(test.id())
        super().startTest(test)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    source = args.source_root.resolve(strict=True)
    output = args.output.parent.resolve(strict=True) / args.output.name
    require(output != source and source not in output.parents, "caller evidence entered source")
    _create_directory(output)
    _create_directory(output / "hook")
    _create_directory(output / "children")
    report = {"schema": "hepta.hia.bounded-read-original-eight.v1", "status": "HOLD",
        "expected_ids": list(EXPECTED_IDS), "loaded_ids": [], "executed_ids": [],
        "original_method_denominator": 8, "original_CLI_child_denominator": 7,
        "original_CLI_timeout_seconds": 20, "tests": [], "errors": [],
        "anomalies": {}, "children": [], "cold_qualification": False,
        "whole_native_delivery_qualified": False}
    control = Path(__file__).absolute().parent
    observation = None
    previous = {}
    started = time.monotonic_ns()
    try:
        require(os.getcwd() == str(source) and sys.dont_write_bytecode,
                "fixed source cwd and no bytecode writes required")
        source_pins = {}
        for name in ("tests/test_hia_program_tools.py", "tools/hia_core_reference.py",
                     "hepta/hia_program_tools.py", "hepta/hia_bounded_read_native.py",
                     "examples/hia_bootstrap/bounded_read.hiaasm"):
            raw, actual = read(source / name)
            source_pins[name] = pin(raw)
        require(source_pins["tests/test_hia_program_tools.py"]["sha256"] == TEST_SHA256
                and source_pins["tools/hia_core_reference.py"]["sha256"] == REFERENCE_CLI_SHA256,
                "original eight module or its actual CLI source changed")
        report["source_pins"] = source_pins
        manifest_raw, manifest_record = read(args.manifest, 16384)
        manifest = json.loads(manifest_raw)
        report["manifest"] = manifest_record
        require(os.environ.get("HEPTA_HIA_BOUNDED_READ_MANIFEST") == str(args.manifest),
                "parent native selector differs")
        for name in ("caller_observer.py", "source_common.py"):
            raw, actual = read(control / name, 1 << 20)
            create(output / "hook" / name, raw)
            report.setdefault("hook_inputs", {})[name] = actual
        create(output / "hook/sitecustomize.py", SITE)
        policy = {"schema": "hepta.hia.bounded-read-original-eight-child-policy.v1",
            "source": str(source), "source_pins": source_pins,
            "manifest": str(args.manifest), "manifest_sha256": sha256(manifest_raw).hexdigest(),
            "image_sha256": manifest["image_sha256"], "parent_pid": os.getpid(),
            "children": str(output / "children"), "parent_record": str(output / "parent-original.json")}
        policy_raw = wire(policy)
        policy_record = create(output / "child-policy.json", policy_raw)
        report["child_policy"] = policy_record
        environment = {
            "HIA_BOUNDED_READ_CHILD_POLICY": str(output / "child-policy.json"),
            "HIA_BOUNDED_READ_CHILD_POLICY_SHA256": sha256(policy_raw).hexdigest(),
            "PYTHONPATH": str(output / "hook") + os.pathsep + str(source),
            "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
        }
        for key, value in environment.items():
            previous[key] = os.environ.get(key)
            os.environ[key] = value
        sys.path.insert(0, str(source))
        from caller_observer import Observation
        observation = Observation(policy, sha256(policy_raw).hexdigest(), "parent")
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromNames([MODULE])
        loaded = list(flatten(suite))
        report["loaded_ids"] = [test.id() for test in loaded]
        report["loader_errors"] = list(loader.errors)
        require(report["loaded_ids"] == list(EXPECTED_IDS) and not loader.errors,
                "exact original eight loaded IDs differ")
        with (output / "unittest.log").open("x", encoding="utf-8") as log:
            result = unittest.TextTestRunner(stream=log, verbosity=2,
                                             resultclass=ActualResult).run(suite)
        report["executed_ids"] = result.executed_ids
        report["testsRun"] = result.testsRun
        report["anomalies"] = {
            "failures": [(t.id(), detail) for t, detail in result.failures],
            "errors": [(t.id(), detail) for t, detail in result.errors],
            "skips": [(t.id(), detail) for t, detail in result.skipped],
            "expected_failures": [(t.id(), detail) for t, detail in result.expectedFailures],
            "unexpected_successes": [t.id() for t in result.unexpectedSuccesses],
        }
        parent = observation.finish()
        report["parent"] = parent
        observation = None
        names = sorted(path.name for path in (output / "children").iterdir())
        completions = sorted(name for name in names if name.startswith("child-") and name.endswith(".json"))
        starts = sorted(name for name in names if name.startswith("start-") and name.endswith(".json"))
        require(len(names) == 14 and len(completions) == len(starts) == 7,
                "exact seven original CLI starts/completions missing")
        commands, child_reads, child_returns = Counter(), 0, 0
        child_pids = set()
        for name in completions:
            raw, record = read(output / "children" / name, 4 << 20)
            child = json.loads(raw)
            pid = child.get("pid")
            require(type(pid) is int and pid not in child_pids and name == "child-%d.json" % pid,
                    "duplicate/mismatched child identity")
            child_pids.add(pid)
            start_raw, start_record = read(output / "children" / ("start-%d.json" % pid), 65536)
            beginning = json.loads(start_raw)
            require(beginning["pid"] == pid and beginning["parent_pid"] == os.getpid()
                    and beginning["policy_sha256"] == policy_record["sha256"],
                    "actual original child start differs")
            require(child.get("schema") == "hepta.hia.bounded-read-original-caller-observer.v1"
                    and child.get("status") == "ORIGINAL_CALLER_OBSERVER_PASS"
                    and child.get("role") == "child" and child.get("parent_pid") == os.getpid()
                    and child.get("policy_sha256") == policy_record["sha256"]
                    and child.get("source") == str(source) and child.get("manifest") == str(args.manifest)
                    and child.get("retained_owner_calls") == []
                    and child["source_before"] == child["source_after"]
                    and child["bundle_before"] == child["bundle_after"]
                    and child["native_before"] == child["native_after"],
                    "actual original child source/bundle/owner differs")
            argv = child["argv"]
            require(argv[0] == str(source / "tools/hia_core_reference.py")
                    and argv[1] in ("verify", "run", "inspect", "patch"),
                    "another command entered original child set")
            commands[argv[1]] += 1
            expected_reads = 2 if argv[1] == "patch" else 1
            calls = child["read_calls"]
            require(len(calls) == expected_reads
                    and all(row["outcome"] == "returned"
                            and row["native_calls_after"] == row["native_calls_before"] + 1
                            and row["native_transitions_after"] > row["native_transitions_before"]
                            for row in calls)
                    and child["ledger_after"]["calls"] - child["ledger_before"]["calls"] == expected_reads,
                    "actual original CLI native read completions differ")
            child_reads += len(calls)
            child_returns += sum(row["outcome"] == "returned" for row in calls)
            report["children"].append({"record": record, "start": start_record, "result": child})
        require(commands == Counter({"verify": 2, "run": 3, "inspect": 1, "patch": 1})
                and child_reads == child_returns == 8, "original CLI command/call population differs")
        require(parent["status"] == "ORIGINAL_CALLER_OBSERVER_PASS"
                and parent["retained_owner_calls"] == [] and len(parent["read_calls"]) == 4
                and Counter(row["outcome"] for row in parent["read_calls"])
                    == Counter({"returned": 3, "raised": 1}),
                "parent ordinary/symlink native read population differs")
        report["actual_native_read_attempts"] = child_reads + len(parent["read_calls"])
        report["actual_native_read_returns"] = child_returns + 3
        require(report["testsRun"] == 8 and report["executed_ids"] == list(EXPECTED_IDS)
                and all(not rows for rows in report["anomalies"].values())
                and report["actual_native_read_attempts"] == 12,
                "complete original eight actual result conjunction failed")
        report["status"] = "ORIGINAL_EIGHT_AND_SEVEN_CLI_CHILDREN_PASS"
    except BaseException as error:
        report["status"] = "HOLD"
        report["errors"].append({"type": type(error).__name__, "text": str(error),
                                 "traceback": traceback.format_exc()})
    finally:
        if observation is not None and not observation.finished:
            try:
                report["parent"] = observation.finish()
            except BaseException as error:
                report["status"] = "HOLD"
                report["errors"].append({"phase": "parent_finish",
                    "type": type(error).__name__, "text": str(error)})
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        report["wall_ns"] = time.monotonic_ns() - started
        create(output / "report.json", wire(report))
    print(json.dumps({"status": report["status"], "loaded": len(report["loaded_ids"]),
                      "executed": len(report["executed_ids"]), "children": len(report["children"])}))
    return 0 if report["status"] == "ORIGINAL_EIGHT_AND_SEVEN_CLI_CHILDREN_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
