"""Prepare a fresh Actions source83 request from frozen local-request bytes.

No generator, test, compiler, native image, or process owner is invoked here.
The separately frozen workflow invokes the unchanged original launcher once.
The old local templates remain unexecuted; the prior remote operation is retained as FAIL.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import sys
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from files import absolute, json_read, mkdir_new, put, read, require, save

HERE = Path(__file__).resolve().parent


def git(root, *arguments):
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("GIT_", "LD_"))}
    result = subprocess.run(["git", "--no-replace-objects", "-c", "protocol.allow=never",
                             "-c", "core.fsmonitor=false", "-C", str(root), *arguments],
                            env=environment, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(result.returncode == 0 and not result.stderr, "read-only exact Git identity query failed")
    return result.stdout


def relative(value):
    require(type(value) is str, "fixed source path must be a string")
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value and path.parts
            and all(part not in ("", ".", "..") for part in path.parts),
            "fixed source path differs")
    return path


def context(policy):
    names = ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA", "GITHUB_REF_NAME",
             "GITHUB_EVENT_NAME", "GITHUB_REPOSITORY", "GITHUB_WORKFLOW_REF",
             "RUNNER_OS", "RUNNER_ARCH", "pythonLocation", "NUMERIC_SOURCE83_WORKFLOW_SHA")
    value = {name: os.environ.get(name) for name in names}
    require(value["GITHUB_REPOSITORY"] == policy["repository"]
            and value["GITHUB_EVENT_NAME"] == "create"
            and value["GITHUB_REF_NAME"] == policy["execution_branch"]
            and value["GITHUB_RUN_ATTEMPT"] == "1"
            and type(value["GITHUB_RUN_ID"]) is str and value["GITHUB_RUN_ID"].isdigit()
            and int(value["GITHUB_RUN_ID"]) > 0
            and type(value["GITHUB_SHA"]) is str
            and re.fullmatch("[0-9a-f]{40}", value["GITHUB_SHA"]) is not None
            and value["NUMERIC_SOURCE83_WORKFLOW_SHA"] == value["GITHUB_SHA"]
            and value["GITHUB_WORKFLOW_REF"] == policy["repository"] + "/" + policy["workflow_path"]
                + "@refs/heads/" + policy["execution_branch"]
            and value["RUNNER_OS"] == "Linux" and value["RUNNER_ARCH"] == "X64",
            "new fixed workflow/run identity differs")
    return value


def fixed_policy(arguments):
    require(re.fullmatch("[0-9a-f]{40}", arguments.control_commit) is not None,
            "exact adapter control commit required")
    policy, raw, pin = json_read(HERE / "POLICY.json",
                                {"sha256": arguments.policy_sha256}, owned=True)
    require(policy["schema"] == "hepta.hia.numeric-source83-actions-adaptation.v1"
            and policy["status"] == "FROZEN_UNEXECUTED_ROOT_TRIGGER_ONLY",
            "execution policy schema/status differs")
    control_root = absolute(arguments.adapter_checkout)
    require(control_root == control_root.resolve(strict=True)
            and HERE == control_root / policy["adapter_prefix"].rstrip("/")
            and git(control_root, "rev-parse", "HEAD").decode().strip() == arguments.control_commit,
            "adapter checkout is not the separately reviewed exact A commit")
    observations = []
    for expected in policy["adapter_inputs"]:
        path = HERE / relative(expected["name"])
        content, observed = read(path, expected, owned=True)
        if path.suffix == ".py":
            ast.parse(content, filename=str(path))
        observations.append(observed)
    return policy, {"control_commit": arguments.control_commit,
                    "policy": pin, "inputs": observations,
                    "syntax_parse_performed_on_this_runtime": True}


def old_request(source_controls, policy):
    frozen = source_controls / policy["source_controls_prefix"]
    old, raw, pin = json_read(frozen / "REQUEST.json",
                             {"sha256": policy["source_controls_request_sha256"]}, owned=True)
    require(old["status"] == "FROZEN_UNEXECUTED" and old["qualification_seconds"] == 180
            and old["cleanup_seconds"] == 3 and old["expected_methods"] == 83
            and len(old["expected_ids"]) == len(set(old["expected_ids"])) == 83
            and len(old["test_classes"]) == 10 and len(old["generator_names"]) == 62,
            "fixed original source denominator or limits differ")
    return frozen, old, pin


def adapted_control(frozen, expected, policy):
    raw = read(frozen / "control" / expected["name"], expected, owned=True)[0]
    if expected["name"] == "worker.py":
        for item in policy["worker_metadata_substitutions"]:
            before, after = item["old_text"].encode(), item["new_text"].encode()
            require(raw.count(before) == 1, "worker metadata projection differs")
            raw = raw.replace(before, after, 1)
        require(sha256(raw).hexdigest() == policy["adapted_worker"]["sha256"],
                "adapted worker has a non-metadata change")
    ast.parse(raw, filename="source83/" + expected["name"])
    return raw


def operation_root(policy, value):
    runner_temp = absolute(os.environ["RUNNER_TEMP"])
    require(runner_temp == runner_temp.resolve(strict=True), "runner temp root alias refused")
    return runner_temp / (policy["operation_prefix"] + value["GITHUB_RUN_ID"] + "-1")


def prepare(arguments):
    policy, adapter = fixed_policy(arguments)
    require(platform.python_implementation() == "CPython"
            and sys.version_info[:3] == (3, 14, 4)
            and platform.system() == "Linux" and platform.machine() == "x86_64",
            "new runner requires actual CPython 3.14.4 on Linux x86_64")
    forbidden = sorted(key for key, value in os.environ.items()
                       if value and key.startswith(("GIT_", "LD_")))
    require(not forbidden, "ambient Git/loader overrides are forbidden: " + repr(forbidden))
    current = context(policy)
    source_controls = absolute(arguments.source_controls_checkout)
    base = absolute(arguments.base_checkout)
    require(source_controls == source_controls.resolve(strict=True)
            and base == base.resolve(strict=True), "checkout root aliases refused")
    require(git(source_controls, "rev-parse", "HEAD").decode().strip() == policy["source_controls_commit"],
            "source-control checkout is not the frozen exact S2 HEAD")
    require(git(base, "rev-parse", "HEAD").decode().strip() == policy["base_commit"]
            and git(base, "rev-parse", "HEAD^{tree}").decode().strip() == policy["base_tree"],
            "base checkout HEAD/tree differs")
    frozen, old, original_request = old_request(source_controls, policy)
    delta, _, _ = json_read(frozen / "SOURCE-DELTA.json",
                            {"sha256": policy["source_delta_sha256"]}, owned=True)
    changes = {row["path"]: row for row in delta["delta"]}
    require(len(changes) == len(delta["delta"]) == 4, "frozen source delta differs")
    metadata, _, _ = json_read(frozen / "BASE-GIT-TREE.json",
                               {"sha256": policy["base_tree_metadata_sha256"]}, owned=True)
    expected_tree = {row["path"]: (row["mode"], row["type"], row["sha"]) for row in metadata["leaves"]}
    actual_tree = {}
    for record in git(base, "ls-tree", "-r", "-z", "--full-tree", "HEAD").split(b"\0"):
        if not record:
            continue
        attributes, path = record.split(b"\t", 1)
        mode, kind, digest = attributes.decode("ascii").split()
        name = path.decode("utf-8")
        require(name not in actual_tree, "duplicate Git tree path")
        actual_tree[name] = (mode, kind, digest)
    require(actual_tree == expected_tree and len(actual_tree) == policy["base_complete_leaf_count"],
            "complete Git tree name/mode/blob identities differ")
    python_root = absolute(current["pythonLocation"])
    require(python_root == python_root.resolve(strict=True), "setup-python prefix alias refused")
    binary = Path(sys.executable).resolve(strict=True)
    require(binary.parent == python_root / "bin" and binary.name in ("python3.14", "python3"),
            "actual interpreter is not within this setup-python installation")
    _, binary_pin = read(binary)
    require(binary_pin["uid"] in (0, os.geteuid()), "setup-python runtime owner differs")
    operation = operation_root(policy, current)
    require(absolute(arguments.output) == operation, "new operation output root differs")
    available = os.statvfs(operation.parent)
    resource = {"available_bytes": available.f_bavail * available.f_frsize,
                "free_inodes": available.f_favail, "threshold_bytes": old["minimum_available_bytes"],
                "threshold_inodes": old["minimum_available_inodes"]}
    require(resource["available_bytes"] >= resource["threshold_bytes"]
            and resource["free_inodes"] >= resource["threshold_inodes"], "fresh original resource threshold failed")
    mkdir_new(operation)
    report = {"schema": "hepta.hia.numeric-source83-actions-preparation.v1", "status": "HOLD",
              "context": current, "adapter": adapter, "resource_precondition": resource,
              "base_commit": policy["base_commit"], "base_tree": policy["base_tree"],
              "base_complete_tree_ids_read": len(actual_tree),
              "original_control_commit": policy["source_controls_commit"],
              "original_local_request": original_request, "runtime_version": list(sys.version_info[:3]),
              "runtime_version_text": sys.version, "runtime_executable_spelling": sys.executable,
              "source_or_test_or_native_execution_performed": False,
              "old_local_runtime_or_native_result_inherited": False, "copied_files": []}
    try:
        controls = operation / "control"
        mkdir_new(controls)
        for expected in policy["original_controls"]:
            put(controls / expected["name"], adapted_control(frozen, expected, policy), 0o644)
        spec = importlib.util.spec_from_file_location("new_actions_source83_file_metadata", controls / "common.py")
        common = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(common)
        source = operation / "source"
        mkdir_new(source)
        for expected in old["source_files"]:
            name = relative(expected["relative_path"]).as_posix()
            if name in changes:
                row = changes[name]
                raw = read(frozen / "inputs" / name, expected, owned=True)[0]
                if row["before"] is not None:
                    baseline = row["before"]
                    _, actual = read(base / name, owned=True)
                    require(actual["git_blob_sha1"] == baseline["sha"] and actual["size"] == baseline["size"],
                            "original base overlay target differs")
            else:
                raw = read(base / name, expected, owned=True)[0]
            put(source / name, raw, expected["mode"])
            report["copied_files"].append(name)
        physical = common.snapshot(source)
        require(common.content(physical) == old["source_files"]
                and len(physical) == policy["physical_source_count"]
                and sum(row["size"] for row in physical) == policy["physical_source_bytes"],
                "complete new physical source differs from frozen on-v89 content/modes")
        fresh = dict(old)
        fresh.update(revision="github-actions-cpython31404-source83-r2",
            status="FRESH_RUNTIME_BOUND_UNEXECUTED", source_root=str(source),
            evidence_root=str(operation / "actual-source"),
            runtime=common.pin(binary), process_owner=common.pin(source / "tools/hia_selfhost_process_owner.py"),
            control_inputs=[common.pin(path) for path in sorted(controls.glob("*.py"))],
            remote_execution_context=current, remote_triggered=True)
        require(fresh["runtime"] == binary_pin, "runtime changed during preparation")
        require(fresh["process_owner"]["sha256"] == policy["process_owner"]["sha256"],
                "original process-owner source changed")
        for key in policy["unchanged_request_fields"]:
            require(fresh[key] == old[key], "protected request field changed: " + key)
        report["new_request"] = save(operation / "REQUEST.json", fresh)
        report["physical_source_pins"] = save(operation / "SOURCE-PHYSICAL-PINS.json", physical)
        report["run_context"] = save(operation / "RUN-CONTEXT.json", current)
        launch = {"schema": "hepta.hia.numeric-source83-actions-launch.v1",
            "status": "FRESH_RUNTIME_BOUND_REQUEST_NOT_YET_EXECUTED",
            "request": common.pin(operation / "REQUEST.json"),
            "command": [str(binary), "-I", "-S", "-B", str(controls / "launch.py")],
            "cwd": str(operation), "qualification_seconds": 180, "cleanup_seconds": 3,
            "old_local_launch_reused": False}
        report["new_launch"] = save(operation / "LAUNCH.json", launch)
        report["runtime"] = fresh["runtime"]
        report["status"] = "NEW_SOURCE_REQUEST_PREPARED_NOT_EXECUTED"
    except BaseException:
        report["status"] = "HOLD"
        report["error"] = traceback.format_exc()
        raise
    finally:
        save(operation / "PREPARATION.json", report)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter-checkout", type=Path, required=True)
    parser.add_argument("--source-controls-checkout", type=Path, required=True)
    parser.add_argument("--base-checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--control-commit", required=True)
    parser.add_argument("--policy-sha256", required=True)
    return prepare(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
