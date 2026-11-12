"""One new source import, new prerequisite supply/probes, then original v10 --full.

This child runs entirely beneath the unchanged 10800-second guardian. It never
loads historical qualification results or retries a previously started capsule.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

from full_common import LIMITS, PACKAGE_PINS, checkpoint, clean_environment, create, file_record, read_json, require, wire
import workflow_process


CONTRACT = "docs/HIA_SELFHOST_CORE_SUPPORT.json"


def observe_source(root, expected, helper_pin):
    helper = root / "tools/hia_core_source_identity.py"
    file_record(helper, expected=helper_pin)
    spec = importlib.util.spec_from_file_location("v87_current_git_source_identity", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(module.ROOT == root, "source observer belongs to another checkout")
    value = module._source_state()
    require(value["head"] == expected["commit"] and value["tree"] == expected["tree"]
            and value["status"] == "" and len(value["files"]) == expected["regular_leaves"],
            "complete source HEAD/tree/population/clean state differs")
    # Verify physical directory nodes as well as the original helper's exact
    # regular-file bytes and owner executable bits.
    listing = module._git("ls-tree", "-r", "-t", "--full-tree", "-z", expected["tree"])
    import stat
    for record in listing.split(b"\0")[:-1]:
        metadata, raw_name = record.split(b"\t", 1)
        mode, kind, unused = metadata.split(b" ")
        if mode == b"040000" and kind == b"tree":
            require(stat.S_ISDIR((root / raw_name.decode("utf-8")).lstat().st_mode),
                    "physical Git tree directory is not a real directory")
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.root
    control = root / "control"
    setup, setup_pin = read_json(control / "SETUP.json")
    policy, policy_pin = read_json(control / "policy.json")
    require(policy["ready_for_dispatch"] is True and setup["root"] == str(root)
            and policy_pin == setup["policy"], "unfrozen or different capsule setup")
    require(sys.version_info[:3] == (3, 14, 4)
            and Path(sys.executable).absolute() == Path(setup["python"]["path"]),
            "full capsule requires the exact prepared Python 3.14.4 venv")
    file_record(Path(sys.executable).resolve(strict=True), expected=setup["python"]["resolved_image"])
    before_controls = {name: file_record(control / name, expected=pin)
                       for name, pin in setup["control_files"].items()}
    require(Path(workflow_process.__file__).resolve() == control / "workflow_process.py",
            "original workflow supervisor is not adjacent")
    for name in ("source", "supply", "preparation", "t", "qualification", "preparation-logs"):
        require(not os.path.lexists(root / name), "create-only destination already exists: " + name)
    logs = root / "preparation-logs"
    logs.mkdir(mode=0o700)
    environment = clean_environment(network=True)
    report = {"schema": "hia.v87.full-retained-preparation.v1", "status": "PREPARATION_HOLD",
              "setup": setup_pin, "policy": policy_pin, "started_unix_ns": time.time_ns(),
              "steps": [], "limits": LIMITS, "qualification_executed": False,
              "qualification_exec_requested": False, "historical_job_replayed": False,
              "whole_native_delivery_qualified": False, "controls_before": before_controls}

    def save():
        checkpoint(root, "preparation", report)

    def run(name, command, seconds, *, cwd=root):
        print(json.dumps({"stage": "FULL_V87_PREPARATION", "name": name}), flush=True)
        receipt = workflow_process.run_workflow_step(
            list(map(str, command)), cwd=cwd, env=environment,
            stdout_path=logs / (name + ".stdout.log"), stderr_path=logs / (name + ".stderr.log"),
            receipt_path=logs / (name + ".owner.json"), seconds=seconds)
        report["steps"].append({"name": name, "command": list(map(str, command)), "receipt": receipt})
        save()
        require(receipt.get("status") == "WORKFLOW_STEP_COMPLETED" and receipt.get("returncode") == 0
                and receipt.get("timed_out") is False and receipt.get("cleanup", {}).get("complete") is True
                and receipt["cleanup"].get("errors") == [] and receipt["cleanup"].get("signalled") == [],
                "original preparation subprocess failed or needed cleanup: " + name)

    def git_observation(name, command, *, cwd):
        run(name, command, 60, cwd=cwd)
        return (logs / (name + ".stdout.log")).read_text().strip()

    def current_state(path):
        return observe_source(path, policy["source"], policy["source_identity_helper"])

    try:
        supplied = Path(setup["source_input"])
        input_before = current_state(supplied)
        create(root / "source-input-before.json", wire(input_before))
        source = root / "source"
        run("exact-source-clone", ["git", "--no-replace-objects", "clone", "--quiet", "--no-hardlinks",
                                   "--no-checkout", str(supplied), str(source)],
            LIMITS["source_materialization_seconds"])
        run("exact-source-detach", ["git", "--no-replace-objects", "checkout", "--quiet", "--detach",
                                    policy["source"]["commit"]], 60, cwd=source)
        run("exact-source-fsck", ["git", "--no-replace-objects", "fsck", "--full", "--strict", "--no-dangling"],
            LIMITS["source_materialization_seconds"], cwd=source)
        commit_raw = git_observation("actual-commit-headers", ["git", "--no-replace-objects", "cat-file",
                                                               "commit", policy["source"]["commit"]], cwd=source)
        require(commit_raw.splitlines()[0] == "tree " + policy["source"]["tree"], "actual commit tree differs")
        shallow = git_observation("actual-shallow-boundary", ["git", "--no-replace-objects", "rev-parse",
                                                               "--is-shallow-repository"], cwd=source)
        require(shallow in {"true", "false"}, "unrecognized shallow observation")
        source_before = current_state(source)
        require(source_before == input_before and current_state(supplied) == input_before,
                "actual clone/source input bytes or Git identity differ")
        create(root / "source-before.json", wire(source_before))
        objects_input = supplied / ".git/objects"
        objects_source = source / ".git/objects"
        shared = []
        for path in objects_source.rglob("*"):
            if path.is_file():
                corresponding = objects_input / path.relative_to(objects_source)
                if corresponding.is_file():
                    left, right = path.stat(), corresponding.stat()
                    if (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino):
                        shared.append(str(path.relative_to(objects_source)))
        require(not shared and not (objects_source / "info/alternates").exists(),
                "clone shares objects/alternates with its input")
        contract, contract_pin = read_json(source / CONTRACT, policy["source"]["contract"])
        require(contract.get("profile") == policy["source"]["profile"]
                and len(contract["source_identity"]["files"]) == policy["source"]["declared_sources"]
                and all(source_before["files"].get(name) == digest
                        for name, digest in contract["source_identity"]["files"].items()),
                "actual contract and complete Git source disagree")
        for name, binding in policy["source_harness"].items():
            file_record(source / binding["source_path"], expected=binding)
            file_record(control / name, expected=binding)
        report["source_materialization"] = {
            "source": str(source), "input": str(supplied), "head": source_before["head"],
            "tree": source_before["tree"], "regular_leaves": len(source_before["files"]),
            "raw_git_tree_blobs_modes_checked": True, "fsck_full_strict": True,
            "shared_object_hardlinks": shared, "actual_shallow_repository": shallow == "true",
            "ancestry_beyond_actual_object_boundary_claimed": False, "contract": contract_pin}
        create(root / "source-materialization.json", wire(report["source_materialization"]))
        save()

        # Fresh, real supply uses current source locks and original builders.
        # Downloads/builds do not imply qualification and are not historical READY.
        run("fresh-prerequisite-supply", [sys.executable, "-B", control / "supply_v87.py",
            "--source", source, "--output", root / "supply", "--python", sys.executable,
            "--configuration", control / "supply-plan.json"], LIMITS["supply_seconds"])
        supply, report["supply"] = read_json(root / "supply/SUPPLY.json", limit=16 << 20)
        require(supply.get("status") == "INPUTS_BUILT_PENDING_ORIGINAL_PREPARATION"
                and supply.get("qualification_executed") is False,
                "supply did not produce its complete current input set")
        run("fresh-original-prerequisites", [sys.executable, "-B", control / "prepare_environment.py",
            "--supply", root / "supply/SUPPLY.json", "--source", source,
            "--head", policy["source"]["commit"], "--tree", policy["source"]["tree"],
            "--output", root / "preparation", "--temporary-root", root / "t"],
            LIMITS["prerequisite_seconds"])
        preparation, report["prerequisite_report"] = read_json(root / "preparation/preparation.json", limit=16 << 20)
        prepared_environment, report["prerequisite_environment"] = read_json(root / "preparation/environment.json", limit=16 << 20)
        require(preparation.get("status") == "READY" and preparation.get("missing") == []
                and preparation.get("qualification_executed") is False
                and preparation.get("source") == str(source)
                and prepared_environment.get("source") == str(source)
                and prepared_environment.get("python") == str(Path(sys.executable).absolute()),
                "original fresh preparation did not admit the current source/environment")
        require(preparation["checks"]["python"]["version_info"] == [3, 14, 4]
                and all(preparation["checks"]["python"]["packages"].get(name) == version
                        for name, version in PACKAGE_PINS.items()), "exact Python/package gate differs")
        report["source_after_preparation"] = current_state(source)
        require(report["source_after_preparation"] == source_before and current_state(supplied) == input_before,
                "source changed during supply/preparation")
        create(root / "source-after-preparation.json", wire(report["source_after_preparation"]))
        report["controls_after"] = {name: file_record(control / name, expected=pin)
                                   for name, pin in setup["control_files"].items()}
        require(report["controls_after"] == before_controls, "control bytes changed during preparation")
        command = [str(sys.executable), "-B", str(root / "preparation/launch.py"),
                   str(control / "run_hia_qualification_v10.py"), "--source", str(source),
                   "--output", str(root / "qualification"), "--prerequisite-environment",
                   str(root / "preparation/environment.json"), "--prerequisite-report",
                   str(root / "preparation/preparation.json"), "--full"]
        report.update(status="CURRENT_INPUTS_READY_V10_FULL_EXEC_REQUESTED", qualification_exec_requested=True,
                      command=command, full_retained_seconds=5400, controller_seconds=10800)
        save()
        # The original v10 performs its own exact current admission, a second
        # source-reproduction clone, all original gates, and full discovery.
        os.execve(str(sys.executable), command, clean_environment())
    except BaseException as error:
        report.update(status="PREPARATION_HOLD", error_type=type(error).__name__,
                      traceback=traceback.format_exc(), ended_unix_ns=time.time_ns())
        save()
        raise


if __name__ == "__main__":
    main()
