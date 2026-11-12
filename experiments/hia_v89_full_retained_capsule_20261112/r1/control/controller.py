"""One create-only full-retained capsule: prepare, original guardian, custody.

All four entries refuse an unfrozen policy. This draft has no trigger code.
The root-reviewed workflow provides its immutable control commit separately,
avoiding a self-referential commit/hash in the policy committed inside it.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.metadata
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import traceback

from full_common import (GUARDIAN_SHA256, LIMITS, OWNER_SHA256, PACKAGE_PINS,
                         clean_environment, closed_guardian, create, file_record,
                         natural_guardian, read_json, require, wire)


def root_path():
    run = os.environ.get("GITHUB_RUN_ID", "")
    require(re.fullmatch(r"[0-9]{1,20}", run) and os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
            "one original Actions run/attempt 1 is required; no rerun")
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    root = home / ("hf" + run + "a1")
    require(home.is_absolute() and home.resolve(strict=True) == home
            and len(os.fsencode(root / "t")) <= 40, "ordinary-home temporary path is not admissible")
    return root


def context(policy, control_commit):
    require(policy.get("ready_for_dispatch") is True
            and policy.get("schema") == "hia.v87.full-retained-capsule-policy.v1"
            and policy.get("limits") == LIMITS
            and policy.get("packages") == PACKAGE_PINS,
            "draft/unreviewed policy or changed original limits")
    require(re.fullmatch(r"[0-9a-f]{40}", control_commit)
            and os.environ.get("GITHUB_EVENT_NAME") == "create"
            and os.environ.get("GITHUB_REF_TYPE") == "branch"
            and os.environ.get("GITHUB_REPOSITORY") == "TrillionniumFoundation/Hepta"
            and os.environ.get("GITHUB_REF") == "refs/heads/" + policy["intended_branch"],
            "workflow event/branch/repository/control identity differs")
    require(sys.version_info[:3] == (3, 14, 4) and sys.prefix != sys.base_prefix
            and Path(sys.prefix).stat().st_uid == os.getuid(), "Python 3.14.4 owned venv is required")
    packages = {name: importlib.metadata.version(name) for name in PACKAGE_PINS}
    require(packages == PACKAGE_PINS, "four exact package versions differ")
    require(re.fullmatch(r"[0-9a-f]{40}", policy["source"]["commit"])
            and re.fullmatch(r"[0-9a-f]{40}", policy["source"]["tree"])
            and type(policy["source"]["regular_leaves"]) is int
            and policy["source"]["regular_leaves"] > 0, "final pure Git pins are absent")
    return {"event": "create", "attempt": 1, "run_id": int(os.environ["GITHUB_RUN_ID"]),
            "trigger_head": os.environ["GITHUB_SHA"], "control_commit": control_commit,
            "ref": os.environ["GITHUB_REF"], "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF"),
            "python_version": list(sys.version_info[:3]), "packages": packages,
            "runtime_platform": sys.platform, "runtime_uname": list(os.uname())}


def verify_prior_ci(package, policy):
    """Bind retained official terminal records; never infer success from a label."""
    ci = policy["standard_ci"]
    require(ci["source_commit"] == policy["source"]["commit"]
            and ci["source_tree"] == policy["source"]["tree"]
            and ci["attempt"] == 1 and ci["conclusion"] == "success"
            and re.fullmatch(r"[0-9a-f]{40}", ci["root_review_commit"]),
            "same-source standard CI and exact root review must precede dispatch")
    run, run_pin = read_json(package / ci["run_record"]["path"], ci["run_record"])
    require(run.get("id") == ci["run_id"] and run.get("run_attempt") == 1
            and run.get("head_sha") == policy["source"]["commit"]
            and run.get("path") == ".github/workflows/hia-core.yml"
            and run.get("status") == "completed" and run.get("conclusion") == "success",
            "actual same-source standard workflow record differs")
    jobs = []
    require(len(ci["job_records"]) == 2 and {item["name"] for item in ci["job_records"]} == {"source", "native"},
            "both original source/native jobs are required")
    for item in ci["job_records"]:
        job, pin = read_json(package / item["path"], item)
        require(job.get("id") == item["job_id"] and job.get("run_id") == ci["run_id"]
                and job.get("head_sha") == policy["source"]["commit"]
                and job.get("name") == item["name"]
                and job.get("status") == "completed" and job.get("conclusion") == "success",
                "actual source/native terminal job record differs")
        jobs.append(pin)
    require(len({item["job_id"] for item in ci["job_records"]}) == 2, "duplicate standard CI job")
    return {"run": run_pin, "jobs": jobs, "root_review_commit": ci["root_review_commit"]}


def full_request(root, setup, policy, setup_pin):
    controls = root / "control"
    identities = {str(controls / name): item["sha256"] for name, item in setup["control_files"].items()}
    identities.update({str(controls / "policy.json"): setup["policy"]["sha256"],
                       str(controls / "SETUP.json"): setup_pin["sha256"],
                       setup["python"]["resolved_image"]["path"]: setup["python"]["resolved_image"]["sha256"]})
    identities.update({row["path"]: row["sha256"] for row in setup["prior_evidence"].values()})
    return {"schema": "hia-external-guardian-request.v1", "controller_seconds": 10800,
            "command": setup["command"], "cwd": str(root), "source_identities": identities,
            "expected_qualification": {"path": str(root / "qualification/QUALIFICATION.json"),
                "head": policy["source"]["commit"], "tree": policy["source"]["tree"],
                "cold_source_count": policy["source"]["declared_sources"] + 1,
                "contract_sha256": policy["source"]["contract"]["sha256"]}}


def prepare(args):
    public = args.public
    require(public == Path(os.environ["RUNNER_TEMP"]) / "hia-v87-full-public"
            and public.is_absolute() and public.resolve(strict=False) == public,
            "fixed absolute public output required")
    public.mkdir(mode=0o700, exist_ok=False)
    try:
        policy, policy_pin = read_json(args.policy)
        require(policy_pin["sha256"] == args.policy_sha256, "frozen policy SHA differs")
        actual_context = context(policy, args.control_commit)
        root = root_path()
        require(not public.is_relative_to(root) and not root.is_relative_to(public), "public/root paths overlap")
        package = Path(__file__).resolve().parent.parent
        control_head = subprocess.check_output(["git", "--no-replace-objects", "rev-parse", "HEAD"],
                                               cwd=package, env=clean_environment(), timeout=30).decode().strip()
        require(control_head == args.control_commit, "actual control checkout differs from workflow pin")
        original_ci = verify_prior_ci(package, policy)
        source_input = args.source_input
        require(source_input.is_absolute() and source_input.resolve(strict=True) == source_input
                and (source_input / ".git").is_dir(), "complete original Git input checkout is required")
        root.mkdir(mode=0o700, exist_ok=False)
        control, guard = root / "control", root / "guard"
        control.mkdir(mode=0o700)
        guard.mkdir(mode=0o700)
        prior = root / "prior-evidence"
        prior.mkdir(mode=0o700)
        evidence_inputs = {"standard-ci-run.original.json": policy["standard_ci"]["run_record"],
                           **{"standard-ci-" + item["name"] + ".original.json": item
                              for item in policy["standard_ci"]["job_records"]},
                           **policy["prior_evidence"]}
        prior_evidence = {}
        for name, item in evidence_inputs.items():
            require(Path(name).name == name, "unsafe prior evidence name")
            _, raw = file_record(package / item["path"], expected=item, body_limit=16 << 20)
            prior_evidence[name] = create(prior / name, raw)
        copied = {}
        for name, item in policy["control_files"].items():
            require(Path(name).name == name and name not in {"SETUP.json", "policy.json"}, "unsafe control name")
            _, raw = file_record(package / item["path"], expected=item, body_limit=4 << 20)
            copied[name] = create(control / name, raw)
        require(copied["guardian.py"]["sha256"] == GUARDIAN_SHA256
                and copied["process_owner_impl.py"]["sha256"] == OWNER_SHA256,
                "original guardian/process owner differs")
        _, policy_raw = file_record(args.policy, expected=policy_pin, body_limit=4 << 20)
        installed_policy = create(control / "policy.json", policy_raw)
        python_path = Path(sys.executable).absolute()
        python = {"path": str(python_path), "resolved_image": file_record(python_path.resolve(strict=True)),
                  "prefix": sys.prefix, "base_prefix": sys.base_prefix}
        command = [str(python_path), "-B", str(control / "driver.py"), "--root", str(root)]
        setup = {"schema": "hia.v87.full-retained-capsule-setup.v1", "root": str(root),
                 "public": str(public), "source_input": str(source_input), "python": python,
                 "context": actual_context, "standard_ci": original_ci, "policy": installed_policy,
                 "prior_evidence": prior_evidence,
                 "control_files": copied, "command": command, "cwd": str(root),
                 "setup_is_not_qualification": True, "full_started": False}
        setup_pin = create(control / "SETUP.json", wire(setup))
        request = full_request(root, setup, policy, setup_pin)
        require(len(wire(request)) <= 262144, "original guardian request cap exceeded")
        request_pin = create(guard / "request.json", wire(request))
        create(public / "SETUP.json", wire(setup))
        create(public / "GUARDIAN-REQUEST.json", wire(request))
        create(public / "PREPARED.json", wire({"schema": "hia.v87.prepared-capsule.v1",
               "status": "FROZEN_PREPARED_NOT_STARTED", "root": str(root), "setup": setup_pin,
               "guardian_request": request_pin, "historical_run_replayed": False}))
        output = os.environ.get("GITHUB_OUTPUT")
        if output:
            with open(output, "a") as stream:
                stream.write("root=" + str(root) + "\npublic=" + str(public) + "\n")
    except BaseException:
        create(public / "PREPARE-HOLD.json", wire({"status": "PREPARATION_HOLD",
               "traceback": traceback.format_exc(), "qualification_started": False}))
        raise


def load_setup(args, *, current_controls=True):
    root = root_path()
    external, external_pin = read_json(args.policy)
    require(external_pin["sha256"] == args.policy_sha256, "external immutable policy SHA differs")
    public = Path(os.environ["RUNNER_TEMP"]) / "hia-v87-full-public"
    setup, setup_copy = read_json(public / "SETUP.json")
    policy = external
    require(setup["policy"]["sha256"] == args.policy_sha256
            and setup["root"] == str(root) and setup["public"] == str(public)
            and setup["context"]["control_commit"] == args.control_commit,
            "installed setup/policy differs")
    context(policy, args.control_commit)
    require(set(setup["control_files"]) == set(policy["control_files"]), "installed control population differs")
    for name, expected in setup["control_files"].items():
        require(all(expected[key] == policy["control_files"][name][key] for key in ("bytes", "sha256")),
                "installed control pin differs from external policy")
        if current_controls:
            file_record(root / "control" / name, expected=expected)
    expected_evidence = {"standard-ci-run.original.json": policy["standard_ci"]["run_record"],
                        **{"standard-ci-" + item["name"] + ".original.json": item
                           for item in policy["standard_ci"]["job_records"]},
                        **policy["prior_evidence"]}
    require(set(setup["prior_evidence"]) == set(expected_evidence), "prior evidence population differs")
    for name, actual in setup["prior_evidence"].items():
        require(actual["path"] == str(root / "prior-evidence" / name)
                and all(actual[key] == expected_evidence[name][key] for key in ("bytes", "sha256")),
                "prior evidence original pin differs")
        if current_controls:
            file_record(Path(actual["path"]), expected=actual)
    require(setup["command"] == [setup["python"]["path"], "-B", str(root / "control/driver.py"),
                                 "--root", str(root)], "driver command differs")
    request, unused = read_json(public / "GUARDIAN-REQUEST.json")
    require(request == full_request(root, setup, policy, setup_copy), "original guardian request differs")
    if current_controls:
        current_setup, setup_pin = read_json(root / "control/SETUP.json")
        require(current_setup == setup and setup_pin["sha256"] == setup_copy["sha256"], "setup bytes changed")
        installed_policy, record = read_json(root / "control/policy.json")
        require(installed_policy == external and record == setup["policy"], "installed policy bytes changed")
        actual_request, unused = read_json(root / "guard/request.json")
        require(actual_request == request, "actual guardian request changed")
    return root, public, setup, policy


def run(args):
    root, public, setup, policy = load_setup(args)
    request, pin = read_json(root / "guard/request.json")
    require(request["controller_seconds"] == 10800 and request["command"] == setup["command"],
            "full request differs")
    create(root / "RUN-INTENT.json", wire({"status": "SINGLE_EXEC_INTENT_NOT_ACK_OR_COMPLETION",
           "request": pin, "context": setup["context"], "replay_permitted": False}))
    command = [setup["python"]["path"], "-I", "-S", "-B", str(root / "control/guardian.py"),
               "--config", str(root / "guard/request.json"), "--config-sha256", pin["sha256"],
               "--implementation", str(root / "control/process_owner_impl.py")]
    os.execve(setup["python"]["path"], command, clean_environment(network=True))


def custody_request(root, public, setup, policy):
    """Reconstruct the one evidence-only request from current fixed originals."""
    controls = public / "custody-controls"
    identities = {}
    for name in ("retain.py", "full_common.py", "guardian.py", "process_owner_impl.py"):
        record = file_record(controls / name, expected=policy["control_files"][name])
        identities[record["path"]] = record["sha256"]
    for path in (root / "guard/guardian.json", public / "GUARDIAN-REQUEST.json", public / "SETUP.json"):
        identities[str(path)] = file_record(path)["sha256"]
    image = setup["python"]["resolved_image"]
    file_record(Path(image["path"]), expected=image)
    identities[image["path"]] = image["sha256"]
    return {"schema": "hia-external-guardian-request.v1", "controller_seconds": LIMITS["custody_seconds"],
            "command": [setup["python"]["path"], "-B", str(controls / "retain.py"),
                        "--root", str(root), "--public", str(public)],
            "cwd": str(root), "source_identities": identities}


def capture(args):
    root, public, setup, policy = load_setup(args, current_controls=False)
    try:
        request, request_pin = read_json(public / "GUARDIAN-REQUEST.json")
        guardian, guardian_pin = read_json(root / "guard/guardian.json")
        closed_guardian(guardian, request)
        guard = public / "custody-guard"
        guard.mkdir(mode=0o700, exist_ok=False)
        controls = public / "custody-controls"
        controls.mkdir(mode=0o700, exist_ok=False)
        package = Path(__file__).resolve().parent.parent
        for name in ("retain.py", "full_common.py", "guardian.py", "process_owner_impl.py"):
            expected = policy["control_files"][name]
            _, raw = file_record(package / expected["path"], expected=expected, body_limit=4 << 20)
            create(controls / name, raw)
        request = custody_request(root, public, setup, policy)
        pin = create(guard / "request.json", wire(request))
        command = [setup["python"]["path"], "-I", "-S", "-B", str(controls / "guardian.py"),
                   "--config", str(guard / "request.json"), "--config-sha256", pin["sha256"],
                   "--implementation", str(controls / "process_owner_impl.py")]
        os.execve(setup["python"]["path"], command, clean_environment())
    except BaseException:
        create(public / "CAPTURE-ADMISSION-HOLD.json", wire({"status": "CUSTODY_HOLD",
               "traceback": traceback.format_exc(), "incomplete_or_unclosed_tree_read": False,
               "historical_status_upgraded": False}))
        raise


def qualification(root, policy, catalog, guardian):
    path = root / "qualification/QUALIFICATION.json"
    result, result_pin = read_json(path, limit=128 << 20)
    require(result.get("schema") == "hepta.hia.native-rewrite-qualification.v5"
            and result.get("harness_revision") == "v10" and result.get("status") == "FULL_RETAINED_PASS",
            "original complete v10 result is not PASS")
    require(all(result.get(key) is True for key in (
        "cold_qualified", "source_preserved", "harness_preserved", "full_retained_regression_requested",
        "full_retained_regression_executed", "full_retained_regression_qualified")),
        "original complete/current-source/full flags differ")
    require(result.get("whole_native_delivery_qualified") is False,
            "whole-native delivery scope unexpectedly changed")
    gates = result.get("mandatory_v10_gates")
    require(type(gates) is dict and set(gates) == set(policy["mandatory_gate_keys"])
            and len(gates) == 32 and all(value is True for value in gates.values()),
            "exact original32 gate conjunction differs")
    source = result["source_identity"]
    require(source["head"] == policy["source"]["commit"] and source["tree"] == policy["source"]["tree"]
            and source["raw_git_tree_blobs_and_modes_checked"] is True,
            "qualified source differs from frozen source")
    rows = {row["path"]: row for row in catalog["originals"]}
    require(rows["qualification/QUALIFICATION.json"]["sha256"] == result_pin["sha256"]
            and guardian["qualification"]["path"] == str(path)
            and guardian["qualification"]["sha256"] == result_pin["sha256"],
            "complete original qualification differs from guardian and captured bytes")

    def recorded_json(record):
        named = Path(record["path"])
        require(named.is_relative_to(root), "qualification pointer escapes owned root")
        value, pin = read_json(named, limit=128 << 20)
        require(pin["sha256"] == record["sha256"]
                and rows[named.relative_to(root).as_posix()]["sha256"] == pin["sha256"],
                "original report pointer/captured bytes differ")
        return value

    before, after = recorded_json(source["before"]), recorded_json(source["after"])
    require(before == after and before["status"] == ""
            and before["head"] == policy["source"]["commit"] and before["tree"] == policy["source"]["tree"]
            and len(before["files"]) == policy["source"]["regular_leaves"],
            "actual complete before/after source snapshots differ")
    require(all(rows["source/" + name]["sha256"] == expected for name, expected in before["files"].items()),
            "captured current source differs from complete accepted Git bytes")
    full = result["full_retained_regression"]
    actual = recorded_json(full["result"])
    ids = actual.get("loaded_test_ids")
    require(full.get("passed") is True and full.get("completed") is True
            and full.get("discovery") is True and actual.get("successful") is True
            and type(ids) is list and ids and all(type(item) is str for item in ids)
            and ids == actual.get("executed_test_ids")
            and type(actual.get("expected_test_count")) is int and type(actual.get("tests_run")) is int
            and actual.get("expected_test_count") == actual.get("tests_run") == len(ids)
            and all(actual.get(key) == [] for key in (
                "errors", "failures", "skipped", "expected_failures", "unexpected_successes")),
            "full discovery did not execute every loaded ID with zero original anomalies")
    steps = [step for step in result["steps"] if step.get("name") == "full-retained-regression"]
    require(len(steps) == 1, "complete full discovery step missing/duplicated")
    owner = steps[0]["owner"]
    actual_owner, owner_pin = read_json(root / "qualification/full-retained-regression.owner.json")
    require(actual_owner == owner
            and rows["qualification/full-retained-regression.owner.json"]["sha256"] == owner_pin["sha256"],
            "full workflow owner report/captured original differs")
    require(owner.get("workflow_seconds") == 5400 and owner.get("status") == "WORKFLOW_STEP_COMPLETED"
            and owner.get("returncode") == 0 and owner.get("timed_out") is False
            and owner.get("cleanup", {}).get("complete") is True
            and owner["cleanup"].get("signalled") == [] and owner["cleanup"].get("errors") == [],
            "original full5400 workflow transport did not complete naturally")
    for name, expected in owner["logs"].items():
        path = Path(name)
        require(path.is_relative_to(root), "full log path escapes owned root")
        require(file_record(path)["sha256"] == expected
                == rows[path.relative_to(root).as_posix()]["sha256"], "full original log bytes differ")
    return {"original_result": result_pin, "tests_run": len(ids), "mandatory_gate_count": 32,
            "status": "FULL_RETAINED_PASS", "whole_native_delivery_qualified": False}


def finish(args):
    root, public, setup, policy = load_setup(args, current_controls=False)
    result = {"schema": "hia.v87.full-retained-capsule-result.v1", "status": "HOLD",
              "original_qualification_status": None, "complete_custody": False, "errors": [],
              "context": setup["context"], "source": policy["source"], "limits": LIMITS,
              "historical_run_replayed": False, "whole_native_delivery_qualified": False}
    # Qualification and custody remain two separate outcomes. A failed original
    # full run can still have complete exact custody, never an upgraded PASS.
    try:
        custody_config, _ = read_json(public / "custody-guard/request.json")
        require(custody_config == custody_request(root, public, setup, policy),
                "evidence-only original request differs from fixed command/inputs")
        custody_guardian, result["custody_guardian"] = read_json(public / "custody-guard/guardian.json")
        natural_guardian(custody_guardian, custody_config)
        custody, result["custody_report"] = read_json(public / "CUSTODY.json")
        require(custody.get("status") == "COMPLETE_TYPED_ORIGINALS_PENDING_CUSTODY_GUARDIAN"
                and custody.get("all_regular_bytes_read_back") is True
                and custody.get("original_namespace_preserved") is True, "complete typed custody missing")
        require(custody["archive"]["path"] == str(public / "full-retained-originals.tar.gz")
                and custody["catalog"]["path"] == str(public / "ORIGINAL-CATALOG.json"),
                "custody output paths differ")
        require(file_record(Path(custody["archive"]["path"]), expected=custody["archive"]) == custody["archive"],
                "sealed custody archive identity changed")
        catalog, catalog_pin = read_json(Path(custody["catalog"]["path"]), custody["catalog"], limit=128 << 20)
        require(catalog_pin == custody["catalog"], "typed original catalog identity changed")
        result["complete_custody"] = True
        request, unused = read_json(public / "GUARDIAN-REQUEST.json")
        guardian, result["qualification_guardian"] = read_json(root / "guard/guardian.json")
        require(catalog["closed_original_guardian"] == result["qualification_guardian"]
                and catalog["original_guardian_request"]["sha256"] == unused["sha256"],
                "captured qualification closure or original request differs")
        closed_guardian(guardian, request)
        copies_root = public / "qualification-guardian-originals"
        copies, unused = read_json(copies_root / "COPIES.json")
        require(copies.get("schema") == "hia.v87.closed-guardian-original-copies.v1"
                and copies.get("errors") == {} and set(copies.get("files", {}))
                == {"guardian.json", "request.json", "child.stdout.log", "child.stderr.log"},
                "four independent original guardian copies are incomplete")
        originals = {row["path"]: row for row in catalog["originals"]}
        for name, copied in copies["files"].items():
            original_path = root / "guard" / name
            require(copied["original"]["path"] == str(original_path)
                    and copied["copy"]["path"] == str(copies_root / name)
                    and file_record(original_path, expected=copied["original"]) == copied["original"]
                    and file_record(copies_root / name, expected=copied["original"]) == copied["copy"]
                    and originals["guard/" + name]["sha256"] == copied["original"]["sha256"],
                    "original guardian copy/captured root identity differs")
            if name in {"child.stdout.log", "child.stderr.log"}:
                require(copied["original"]["sha256"] == guardian["logs"][str(original_path)],
                        "original guardian stream no longer matches its report")
        try:
            q, unused = read_json(root / "qualification/QUALIFICATION.json", limit=128 << 20)
            result["original_qualification_status"] = q.get("status")
        except FileNotFoundError:
            result["original_qualification_status"] = "MISSING_ORIGINAL_REPORT"
        natural_guardian(guardian, request)
        require(guardian.get("status") == "GUARDIAN_FULL_RETAINED_PASS", "original full guardian did not pass")
        result["qualification"] = qualification(root, policy, catalog, guardian)
        result["status"] = "FULL_RETAINED_PASS_WITH_COMPLETE_CUSTODY"
    except BaseException:
        result["errors"].append(traceback.format_exc())
    create(public / "FINAL.json", wire(result))
    print(json.dumps({"status": result["status"], "complete_custody": result["complete_custody"],
                      "original_qualification_status": result["original_qualification_status"]}), flush=True)
    return 0 if result["status"] == "FULL_RETAINED_PASS_WITH_COMPLETE_CUSTODY" else 1


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    first = commands.add_parser("prepare")
    first.add_argument("--policy", type=Path, required=True)
    first.add_argument("--policy-sha256", required=True)
    first.add_argument("--control-commit", required=True)
    first.add_argument("--source-input", type=Path, required=True)
    first.add_argument("--public", type=Path, required=True)
    for name in ("run", "capture", "finish"):
        sub = commands.add_parser(name)
        sub.add_argument("--policy", type=Path, required=True)
        sub.add_argument("--policy-sha256", required=True)
        sub.add_argument("--control-commit", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    return prepare(args) if args.command == "prepare" else {"run": run, "capture": capture, "finish": finish}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
