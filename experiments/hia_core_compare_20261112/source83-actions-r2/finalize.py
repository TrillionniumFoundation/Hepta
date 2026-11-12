"""Independently bind the one source83 owner and its complete actual originals.

This is readback only. It never starts a child, a compiler, a native image or
a test. A successful readback is source-only and does not establish external
artifact custody, a matching-cold result, installation, or whole-Core closure.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import sys
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from files import absolute, json_read, read, require, save
from adapt_request import adapted_control, context, fixed_policy, git, old_request, operation_root


FALSE_SCOPES = ("native_executed", "complete18_executed", "complete116_executed",
                "cold_executed", "installed_executed")
ANOMALIES = ("loader_errors", "errors", "failures", "skipped",
             "expectedFailures", "unexpectedSuccesses", "native_or_compiler_or_process_attempts")


def file_paths(root):
    root = absolute(root)
    rows = []
    import stat
    require(stat.S_ISDIR(root.lstat().st_mode), "fixed original directory required")
    for current, directories, names in os.walk(root, followlinks=False):
        for name in directories:
            require(stat.S_ISDIR((Path(current) / name).lstat().st_mode),
                    "original directory alias refused")
        for name in names:
            path = Path(current) / name
            require(stat.S_ISREG(path.lstat().st_mode), "original nonregular leaf refused")
            rows.append(path)
    return sorted(rows)


def exact_pin(expected, root):
    require(type(expected) is dict and type(expected.get("path")) is str,
            "complete original pin required")
    path = absolute(expected["path"])
    require(path.is_relative_to(root), "original pin escapes this operation")
    _, actual = read(path, expected, owned=True)
    require(actual == expected, "full physical original pin differs")
    return actual


def content(rows):
    return [{key: row[key] for key in ("relative_path", "size", "sha256", "git_blob_sha1", "mode")}
            for row in rows]


def owner_binding(operation, request):
    folder = operation / "actual-source"
    life, life_raw, life_pin = json_read(folder / "lifecycle.json", owned=True)
    wrapper, _, wrapper_pin = json_read(folder / "wrapper.json", owned=True)
    original, raw, original_pin = json_read(folder / "lifecycle.json.request.json", owned=True)
    command = [request["runtime"]["path"], "-I", "-S", "-B", str(operation / "control/worker.py")]
    require(original["schema"] == life["schema"] == "hepta.hia.selfhost-process-owner.v1"
            and original["command"] == command and original["cwd"] == str(operation)
            and original["stdout_path"] == str(folder / "child.stdout.log")
            and original["stderr_path"] == str(folder / "child.stderr.log")
            and original["receipt_path"] == str(folder / "lifecycle.json")
            and original["qualification_seconds"] == life["qualification_seconds"] == 180
            and original["cleanup_seconds"] == life["cleanup_seconds"] == 3
            and original["implementation_sha256"] == life["implementation_sha256"]
                == request["process_owner"]["sha256"]
            and life["request_sha256"] == sha256(raw).hexdigest(),
            "original owner request/command/path/implementation binding differs")
    require(type(original["started_ns"]) is int and type(original["deadline_ns"]) is int
            and original["deadline_ns"] - original["started_ns"] == 180_000_000_000,
            "original owner deadline differs")
    environment = original["env"]
    require(type(environment) is dict
            and set(environment) <= {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TZ",
                                     "PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX"}
            and environment["PYTHONDONTWRITEBYTECODE"] == "1"
            and environment["PYTHONPYCACHEPREFIX"] == str(folder / "unused-pycache")
            and all(type(key) is str and type(value) is str for key, value in environment.items()),
            "original narrow child environment differs")
    require(wrapper["receipt_sha256"] == sha256(life_raw).hexdigest()
            and all(wrapper.get(key) == value for key, value in life.items()),
            "wrapper and original receipt differ")
    cleanup = life["cleanup"]
    closed = (cleanup.get("attempted") is True and cleanup.get("complete") is True
              and cleanup.get("observed_echild") is True and cleanup.get("leader_reaped") is True
              and cleanup.get("deadline_exceeded") is False
              and cleanup.get("remaining_direct_children") == [] and cleanup.get("errors") == []
              and type(wrapper.get("supervisor_returncode")) is int)
    natural = (closed and life["status"] == "OWNED_PROCESS_COMPLETED"
               and type(life["returncode"]) is int and life["returncode"] == 0
               and wrapper["supervisor_returncode"] == 0
               and life["qualification_started"] is True and life["subreaper_enabled"] is True
               and life["exit_observed_before_deadline"] is True and life["event_overflow"] is False
               and life["interrupted_signals"] == [] and life.get("owner_error") is None
               and life.get("timed_out") is False
               and [row["kind"] for row in life["events"]] == [
                   "qualification_started", "owned_child_observed",
                   "qualification_exit_observed", "owned_child_reaped"])
    return {"closed": closed, "natural": natural, "lifecycle": life_pin,
            "wrapper": wrapper_pin, "owner_request": original_pin,
            "status": life["status"], "returncode": life["returncode"],
            "supervisor_returncode": wrapper.get("supervisor_returncode"),
            "event_kinds": [row["kind"] for row in life["events"]]}


def validate_tests(tests, request):
    require(tests["schema"] == "hepta.hia.core-compare-integration-source-child.v1"
            and tests["status"] == "SOURCE_CHILD_PASS" and tests["operation"] == "tests"
            and tests.get("error") is None and tests["runtime_identity"] == request["runtime"]
            and tests["expected_ids"] == tests["loaded_ids"] == tests["executed_ids"] == request["expected_ids"]
            and type(tests["tests_run"]) is int and tests["tests_run"] == 83
            and all(tests[key] == [] for key in ANOMALIES),
            "complete 83 source method report differs")
    for name in ("native_executed", "complete18_executed", "complete116_executed", "cold_executed"):
        require(tests[name] is False, "source child scope differs")


def command_specs(request):
    rows = []
    for index, name in enumerate(request["generator_names"]):
        rows.append(("generator-" + format(index + 1, "02d") + "-" + name,
                     "module", ["tools.generate_hia_" + name]))
    for prefix in ("derive-", "idempotence-"):
        for index, (path, arguments) in enumerate(request["derivations"]):
            rows.append((prefix + str(index + 1), "script", [path, *arguments]))
    rows.append(("source-tests", "tests", []))
    require(len(rows) == 71 and len({row[0] for row in rows}) == 71, "fixed command denominator differs")
    return rows


def validate_originals(final, operation, result):
    folder = operation / "actual-source"
    expected = final["actual_originals"]
    require(type(expected) is list and len({row["path"] for row in expected}) == len(expected),
            "duplicate original pin")
    observed = [exact_pin(row, folder) for row in expected]
    require({row["path"] for row in observed}
            == {str(path) for path in file_paths(folder) if path != folder / "FINAL.json"},
            "complete original file set differs")
    result["complete_originals"] = {"count": len(observed), "bytes": sum(row["size"] for row in observed),
                                    "original_pins_are_in": str(folder / "FINAL.json")}
    return observed


def validate_run(operation, request, old, policy, result):
    folder, evidence = operation / "actual-source", operation / "actual-source/evidence"
    binding = owner_binding(operation, request)
    result["owner"] = binding
    require(binding["closed"], "current owner closure is unconfirmed; do not read mutable child originals")
    final, _, final_pin = json_read(folder / "FINAL.json", owned=True)
    result["original_final"] = final_pin
    require(binding["natural"], "source owner did not return naturally within its original budget")
    require(final["schema"] == "hepta.hia.core-compare-integration-source-final.v1"
            and final["status"] == "SOURCE_INTEGRATION_PASS" and final.get("error") is None
            and final["qualification_seconds"] == 180 and final["cleanup_seconds"] == 3
            and final["request"] == read(operation / "REQUEST.json", owned=True)[1]
            and final["command"] == [request["runtime"]["path"], "-I", "-S", "-B",
                                    str(operation / "control/worker.py")]
            and all(final[name] is False for name in FALSE_SCOPES), "original launcher final differs")
    validate_originals(final, operation, result)
    worker, _, worker_pin = json_read(evidence / "report.json", owned=True)
    result["worker"] = worker_pin
    require(worker["schema"] == "hepta.hia.core-compare-integration-source-run.v1"
            and worker["status"] == "SOURCE_INTEGRATION_PASS"
            and worker["scope"] == "GITHUB_ACTIONS_EXACT_PARTIAL_SOURCE_GENERATION_AND_SOURCE_VM_CONTROLS_ONLY"
            and worker.get("error") is None and worker.get("preservation_error") is None
            and worker["base_commit"] == policy["base_commit"] and worker["base_tree"] == policy["base_tree"]
            and worker["actual_git_HEAD_claimed"] is False and worker["runtime"] == request["runtime"]
            and worker["generator_count"] == 62 and worker["original61_prefix"] == request["generator_names"][:61]
            and worker["expected_ids"] == request["expected_ids"]
            and worker["allowed_derived_changes"] == request["allowed_derived_changes"]
            and worker["source_preserved_after_derivation"] is True
            and worker["remote_triggered_by_worker"] is False
            and worker["remote_execution_environment"] == "GitHub Actions"
            and all(worker[name] is False for name in FALSE_SCOPES), "worker source-only contract differs")
    records = {}
    for name in ("source-before.json", "source-after-generators.json", "source-derived.json", "source-after.json"):
        records[name], _, _ = json_read(evidence / name, owned=True)
        require(len(records[name]) == 1653
                and len({row["relative_path"] for row in records[name]}) == 1653,
                "source physical denominator differs")
    prepared, _, _ = json_read(operation / "SOURCE-PHYSICAL-PINS.json", owned=True)
    require(records["source-before.json"] == prepared
            and content(prepared) == request["source_files"] == old["source_files"]
            and content(records["source-after-generators.json"]) == content(prepared),
            "generator byte/mode idempotence differs")
    before = {row["relative_path"]: row for row in content(prepared)}
    derived = {row["relative_path"]: row for row in content(records["source-derived.json"])}
    require(set(before) == set(derived), "derivation source path set differs")
    changed = [name for name in before if before[name] != derived[name]]
    require(set(changed) <= set(request["allowed_derived_changes"])
            and worker["actual_derived_changes"] == changed,
            "actual derived-change set differs")
    require(content(records["source-derived.json"]) == content(records["source-after.json"])
            == worker["final_source_content"], "complete source after derivation/tests differs")
    source = operation / "source"
    require({str(source / row["relative_path"]) for row in records["source-after.json"]}
            == {str(path) for path in file_paths(source)}, "current physical source file set differs")
    for expected in records["source-after.json"]:
        pin = {key: value for key, value in expected.items() if key != "relative_path"}
        require(pin["path"] == str(source / expected["relative_path"]), "source pin path differs")
        exact_pin(pin, source)
    for name in request["allowed_derived_changes"]:
        source_raw, source_pin = read(source / name, owned=True)
        captured_raw, captured_pin = read(evidence / ("derived-" + Path(name).name), owned=True)
        require(source_raw == captured_raw, "actual generated document capture differs")
        result.setdefault("actual_derived_originals", []).append(captured_pin)
    require(len(worker["commands"]) == 71, "command count differs")
    for row, (label, operation_name, arguments) in zip(worker["commands"], command_specs(request)):
        command = [request["runtime"]["path"], "-I", "-S", "-B", str(operation / "control/child.py"),
                   operation_name, *arguments]
        report_path = evidence / ("source-tests.json" if operation_name == "tests" else label + ".report.json")
        require(row["label"] == label and row["command"] == command
                and type(row["returncode"]) is int and row["returncode"] == 0
                and type(row["started_monotonic_ns"]) is int and type(row["ended_monotonic_ns"]) is int
                and row["ended_monotonic_ns"] >= row["started_monotonic_ns"]
                and row["stdout"]["path"] == str(evidence / (label + ".stdout.log"))
                and row["stderr"]["path"] == str(evidence / (label + ".stderr.log"))
                and row["report"]["path"] == str(report_path), "actual child command/identity differs")
        for key in ("stdout", "stderr", "report"):
            exact_pin(row[key], evidence)
        child, _, _ = json_read(report_path, owned=True)
        require(child["schema"] == "hepta.hia.core-compare-integration-source-child.v1"
                and child["status"] == "SOURCE_CHILD_PASS" and child["operation"] == operation_name
                and child.get("error") is None and child["native_or_compiler_or_process_attempts"] == []
                and child["runtime_identity"] == request["runtime"]
                and all(child[key] is False for key in
                        ("native_executed", "complete18_executed", "complete116_executed", "cold_executed")),
                "actual child source-only report differs")
        if operation_name == "tests":
            validate_tests(child, request)
            require(child == worker["tests"], "worker and actual full source-test report differ")
            result["source_test_report"] = row["report"]
            result["expected_ids"] = child["expected_ids"]
            result["loaded_ids"] = child["loaded_ids"]
            result["executed_ids"] = child["executed_ids"]
    worker_originals, _, _ = json_read(evidence / "ORIGINALS.json", owned=True)
    require(len(worker_originals) == len({row["path"] for row in worker_originals})
            and {row["path"] for row in worker_originals}
            == {str(path) for path in file_paths(evidence) if path != evidence / "ORIGINALS.json"},
            "worker complete original list differs")
    for expected in worker_originals:
        exact_pin(expected, evidence)
    result["actual_derived_changes"] = changed
    result["generator_count"] = 62
    result["command_count"] = 71
    result["source_method_count"] = 83
    result["source_class_count"] = 10
    result["worker_seconds"] = worker["seconds"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter-checkout", type=Path, required=True)
    parser.add_argument("--source-controls-checkout", type=Path, required=True)
    parser.add_argument("--control-commit", required=True)
    parser.add_argument("--policy-sha256", required=True)
    arguments = parser.parse_args()
    policy, adapter = fixed_policy(arguments)
    current = context(policy)
    operation = operation_root(policy, current)
    result = {"schema": "hepta.hia.numeric-source83-actions-readback.v1", "status": "HOLD",
              "context": current, "adapter": adapter, "owner": {"closed": False, "natural": False},
              "external_artifact_custody_complete": False, "product_results_inherited": False,
              "native_executed": False, "complete18_executed": False, "complete116_executed": False,
              "cold_executed": False, "installed_executed": False}
    try:
        preparation, _, preparation_pin = json_read(operation / "PREPARATION.json", owned=True)
        result["preparation"] = preparation_pin
        require(preparation["schema"] == "hepta.hia.numeric-source83-actions-preparation.v1"
                and preparation["status"] == "NEW_SOURCE_REQUEST_PREPARED_NOT_EXECUTED"
                and preparation.get("error") is None and preparation["context"] == current
                and preparation["adapter"] == adapter, "current preparation differs")
        source_controls = absolute(arguments.source_controls_checkout)
        require(git(source_controls, "rev-parse", "HEAD").decode().strip() == policy["source_controls_commit"],
                "frozen source-control checkout changed")
        frozen, old, _ = old_request(source_controls, policy)
        request, _, request_pin = json_read(operation / "REQUEST.json", preparation["new_request"], owned=True)
        result["request"] = request_pin
        require(request["remote_execution_context"] == current and request["remote_triggered"] is True
                and request["revision"] == "github-actions-cpython31404-source83-r2"
                and request["source_root"] == str(operation / "source")
                and request["evidence_root"] == str(operation / "actual-source")
                and request["runtime"] == preparation["runtime"], "fresh request environment differs")
        for key in policy["unchanged_request_fields"]:
            require(request[key] == old[key], "protected source request changed: " + key)
        require(read(Path(sys.executable).resolve(strict=True))[1] == request["runtime"],
                "actual setup-python runtime changed")
        require(len(request["control_inputs"]) == 4, "source control count differs")
        by_name = {Path(row["path"]).name: row for row in request["control_inputs"]}
        require(len(by_name) == 4 and set(by_name) == {row["name"] for row in policy["original_controls"]},
                "source control identity set differs")
        for expected in policy["original_controls"]:
            path = operation / "control" / expected["name"]
            raw, observed = read(path, by_name[expected["name"]], owned=True)
            require(raw == adapted_control(frozen, expected, policy) and observed == by_name[expected["name"]],
                    "source control changed after preparation")
        exact_pin(request["process_owner"], operation / "source")
        require(request["process_owner"]["sha256"] == policy["process_owner"]["sha256"],
                "process-owner source changed")
        validate_run(operation, request, old, policy, result)
        result["status"] = "SOURCE83_SOURCE_VALIDATION_PASS"
    except BaseException:
        result["status"] = "HOLD"
        result["error"] = traceback.format_exc()
    output = operation.with_name(operation.name + ".postprocess.json")
    save(output, result)
    print(json.dumps({"status": result["status"], "owner": result["owner"],
                      "source_method_count": result.get("source_method_count"),
                      "external_artifact_custody_complete": False}, sort_keys=True))
    return 0 if result["status"] == "SOURCE83_SOURCE_VALIDATION_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
