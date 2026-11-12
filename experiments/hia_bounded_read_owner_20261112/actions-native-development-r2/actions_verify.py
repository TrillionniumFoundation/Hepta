"""Independent readback of one closed bounded-read Actions development run.

This reader does not import a product module, execute a native image or reuse
the worker's PASS flag as proof. Its caller must first bind the original outer
guardian to this exact request and prove a closed ECHILD boundary.
"""
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path

from source_common import fixed_read, measurements, pin, read, require, snapshot
from native_support import (CANDIDATE, CANDIDATE_TREE, GENERATED, LIMITS,
    NATIVE_LIMITS, OWNER_SHA, SELECTOR, generated_rows, natural_process,
    observe_compiler_bundle, source_manifest)
from git_binding import source_git

ANOMALIES = {"skips", "expected_failures", "unexpected_successes", "failures", "errors"}

def original(path, expected=None, maximum=8 << 20):
    raw, actual = read(path, maximum)
    if expected is not None:
        require(expected["path"] == str(path) and expected["bytes"] == len(raw)
                and expected["sha256"] == actual["sha256"], "retained original bytes differ")
        if "identity" in expected:
            require(expected["identity"] == actual["identity"], "retained original identity differs")
        if "git_blob_sha1" in expected:
            require(expected["git_blob_sha1"] == pin(raw)["git_blob_sha1"], "original Git blob differs")
    return json.loads(raw), actual

def verify_inner(step, evidence, source, command, environment, seconds):
    label = step["label"]
    base = evidence / "processes"
    out, err = base / (label + ".stdout.log"), base / (label + ".stderr.log")
    receipt_path = base / (label + ".process-owner.json")
    request_path = Path(str(receipt_path) + ".request.json")
    receipt, receipt_pin = original(receipt_path, step["receipt"], 4 << 20)
    request, request_pin = original(request_path, step["request"], 1 << 20)
    returned = dict(receipt, supervisor_returncode=0, receipt_sha256=receipt_pin["sha256"])
    require(step["status"] == "OWNED_STEP_PASS" and step["cleanup_closed_before_original_read"] is True
            and not step.get("custody_errors") and not step.get("custody_deferred_until_outer_cleanup")
            and step["command"] == command and step["cwd"] == str(source)
            and step["qualification_seconds"] == seconds and step["cleanup_seconds"] == 3
            and step["owner_returned"] == returned,
            "actual inner owner returned projection differs")
    require(request["schema"] == receipt["schema"] == "hepta.hia.selfhost-process-owner.v1"
            and request["stdout_path"] == str(out) and request["stderr_path"] == str(err)
            and request["receipt_path"] == str(receipt_path)
            and request["implementation_sha256"] == receipt["implementation_sha256"] == OWNER_SHA
            and receipt["request_sha256"] == request_pin["sha256"]
            and type(request["started_ns"]) is int and type(request["deadline_ns"]) is int
            and request["deadline_ns"] - request["started_ns"] == int(seconds * 1000000000),
            "inner original request/receipt identity or deadline differs")
    natural_process(receipt, returned, request, command, source, environment, seconds)
    paths = (out, err, receipt_path, request_path, Path(str(receipt_path) + ".stdout.log"),
             Path(str(receipt_path) + ".stderr.log"))
    actual_files = [read(path, 16 << 20)[1] for path in paths]
    require(step["original_files"] == actual_files and step["stdout"] == actual_files[0]
            and step["stderr"] == actual_files[1], "complete six inner owner originals differ")
    stored, _ = original(base / (label + ".step.json"))
    require(stored == step, "inner stored step differs from driver report")
    return {"label": label, "request": request_pin, "receipt": receipt_pin,
            "qualification_pid": receipt["qualification_pid"], "seconds": seconds,
            "cleanup_seconds": 3, "natural_ECHILD": True}

def population(group, report):
    ids = group["expected_ids"]
    require(group["method_count"] == len(ids) and len(set(ids)) == len(ids)
            and report["schema"] == group["schema"] and report["status"] == group["status"]
            and report["expected_ids"] == report["loaded_ids"] == report["executed_ids"] == ids
            and report["errors"] == [] and set(report["anomalies"]) == ANOMALIES
            and all(type(v) is list and not v for v in report["anomalies"].values()),
            "original complete population or five-anomaly result differs")

def verify_callers(source, evidence, report, manifest_pin, manifest, parent_pid, python):
    base = evidence / "original-eight"
    require(report["testsRun"] == report["original_method_denominator"] == 8
            and report["original_CLI_child_denominator"] == len(report["children"]) == 7
            and report["actual_native_read_attempts"] == 12 and report["actual_native_read_returns"] == 11
            and report["original_CLI_timeout_seconds"] == 20 and report["loader_errors"] == [],
            "original eight and seven CLI denominator differs")
    require(report["manifest"] == manifest_pin, "callers actual manifest differs")
    require(set(report["source_pins"]) == {"tests/test_hia_program_tools.py", "tools/hia_core_reference.py",
        "hepta/hia_program_tools.py", "hepta/hia_bounded_read_native.py", GENERATED},
        "complete original caller source map differs")
    for name, expected in report["source_pins"].items():
        require(pin(read(source / name, 1 << 20)[0]) == expected, "callers actual source differs")
    policy, policy_pin = original(base / "child-policy.json", report["child_policy"], 1 << 20)
    require(policy == {"schema": "hepta.hia.bounded-read-original-eight-child-policy.v1",
        "source": str(source), "source_pins": report["source_pins"], "manifest": manifest_pin["path"],
        "manifest_sha256": manifest_pin["sha256"], "image_sha256": manifest["image_sha256"],
        "parent_pid": parent_pid, "children": str(base / "children"),
        "parent_record": str(base / "parent-original.json")}, "original child selector policy differs")
    parent, parent_pin = original(base / "parent-original.json", maximum=4 << 20)
    require(parent == report["parent"] and parent["pid"] == parent_pid, "actual original parent differs")
    def observer(value, role):
        require(value["schema"] == "hepta.hia.bounded-read-original-caller-observer.v1"
                and value["status"] == "ORIGINAL_CALLER_OBSERVER_PASS" and value["role"] == role
                and value["policy_sha256"] == policy_pin["sha256"] and value["source"] == str(source)
                and value["manifest"] == manifest_pin["path"] and value["retained_owner_calls"] == []
                and value["source_before"] == value["source_after"]
                and value["bundle_before"] == value["bundle_after"]
                and value["native_before"] == value["native_after"]
                and value["actual_executable"] == python
                and value["original_CLI_timeout_seconds_unchanged"] == 20,
                "actual caller source/image/retained owner observation differs")
        for name, expected in value["source_after"].items():
            raw, actual = read(source / name, 1 << 20)
            require(expected == actual,
                    "actual observer source pin differs")
        require(value["bundle_after"] == {"manifest": manifest_pin,
                "image": read(Path(manifest_pin["path"]).parent / manifest["image_path"], 1 << 20)[1]},
                "observer actual native bundle differs")
        calls = value["read_calls"]
        require(calls and value["ledger_after"]["calls"] - value["ledger_before"]["calls"] == len(calls)
                and all(row["native_calls_after"] == row["native_calls_before"] + 1
                        and row["native_transitions_after"] > row["native_transitions_before"]
                        and row["outcome"] in ("returned", "raised") for row in calls),
                "actual native caller attempts/returns differ")
    observer(parent, "parent")
    require(len(parent["read_calls"]) == 4 and Counter(r["outcome"] for r in parent["read_calls"])
            == Counter({"returned": 3, "raised": 1}), "parent ordinary and symlink calls differ")
    commands, seen, rows, total = Counter(), set(), [], 0
    for entry in report["children"]:
        child = entry["result"]
        pid = child["pid"]
        require(type(pid) is int and pid > 0 and pid not in seen, "duplicate original child PID")
        seen.add(pid)
        actual, child_pin = original(base / "children" / ("child-%d.json" % pid), entry["record"], 4 << 20)
        beginning, start_pin = original(base / "children" / ("start-%d.json" % pid), entry["start"], 65536)
        require(actual == child and child["parent_pid"] == parent_pid
                and beginning["schema"] == "hepta.hia.bounded-read-original-caller-start.v1"
                and beginning["pid"] == pid and beginning["parent_pid"] == parent_pid
                and beginning["policy_sha256"] == policy_pin["sha256"]
                and beginning["source"] == str(source) and beginning["manifest"] == manifest_pin["path"]
                and beginning["native_identity"] == child["native_before"], "child start/completion differs")
        observer(child, "child")
        argv = child["argv"]
        require(argv[0] == str(source / "tools/hia_core_reference.py")
                and argv[1] in ("verify", "run", "inspect", "patch"), "another CLI entered population")
        count = 2 if argv[1] == "patch" else 1
        require(len(child["read_calls"]) == count
                and all(r["outcome"] == "returned" for r in child["read_calls"]), "CLI read count differs")
        commands[argv[1]] += 1
        total += count
        rows.append({"start": start_pin, "completion": child_pin})
    actual_names = {p.name for p in (base / "children").iterdir()}
    require(actual_names == {kind + "-%d.json" % pid for pid in seen for kind in ("start", "child")}
            and len(seen) == 7 and total == 8
            and commands == Counter({"verify": 2, "run": 3, "inspect": 1, "patch": 1}),
            "complete seven CLI namespace and command population differs")
    return {"parent": parent_pin, "policy": policy_pin, "children": rows,
            "original_methods": 8, "CLI_children": 7, "native_attempts": 12, "native_returns": 11}

def verify_outputs(root, setup, policy):
    context = setup["context"]
    source, evidence, control = Path(context["source"]), root / "evidence", root / "control"
    report, report_pin = original(evidence / "report.json", maximum=16 << 20)
    require(report["schema"] == "hepta.hia.bounded-read-native-development.v1"
            and report["status"] == "BOUNDED_READ_DEVELOPMENT_PASS_PENDING_OUTER_GUARDIAN"
            and report["candidate_commit"] == CANDIDATE and report["candidate_tree"] == CANDIDATE_TREE
            and report["finite_component_cases"] == 55 and report["original_methods"] == 8
            and report["original_CLI_children"] == 7 and report["errors"] == []
            and report["not_completed_groups"] == [] and report["all_started_inner_owners_closed"] is True
            and report["source_stable_except_new_resource"] is True
            and report["outer_qualification_seconds_required"] == 180
            and report["outer_cleanup_seconds_required"] == 3
            and report["outer_guardian_verified_here"] is False
            and report["fresh_B0_B1_B2_requested"] is True and report["old_B3_input_reused"] is False
            and all(report[name] is False for name in ("cold_qualification", "installed_qualification",
                "formal_git_consumer_qualified", "all_input_equivalence_proved", "CPython_cyclic_GC_schedule_proved",
                "whole_native_delivery_qualified", "checked_in_global_contract_updated",
                "checked_in_contract_and_coverage_qualification_claimed")), "actual driver conjunction differs")
    ctl, ctl_pin = original(control / "control-manifest.json", report["control_manifest"], 1 << 20)
    require(ctl_pin["sha256"] == context["control_manifest_sha256"]
            and ctl["schema"] == "hepta.hia.bounded-read-native-development-control-manifest.v1"
            and ctl["candidate_commit"] == CANDIDATE and ctl["candidate_tree"] == CANDIDATE_TREE
            and ctl["outer_qualification_seconds"] == 180 and ctl["outer_cleanup_seconds"] == 3
            and ctl["dispatch_authorized_by_this_file"] is False
            and ctl["files"] == {k: v for k, v in policy["controls"].items() if k != "control-manifest.json"},
            "exact independent control population differs")
    actual_controls = {name: fixed_read(control / name, expected)[1] for name, expected in ctl["files"].items()}
    require(report["control_before"] == report["control_after"] == actual_controls, "controls drifted")
    rows, _, source_manifest_pin = source_manifest(control / "source-manifest.json")
    before, before_pin = original(evidence / "source-before.json", report["source_before"], 8 << 20)
    assembly, assembly_pin = read(source / GENERATED, 1 << 20)
    now = snapshot(source, generated_rows(rows, assembly))
    require(len(before) == 4025 and len(now) == 4026 and [r for r in now if r["path"] != GENERATED] == before,
            "complete actual source changed beyond sole new generated member")
    for name, key in (("source-prepared.json", "source_prepared"), ("source-after.json", "source_after")):
        value, _ = original(evidence / name, report[key], 8 << 20)
        require(value == now, "full source physical observation differs")
    git = source_git(source, rows)
    require(git == report["source_git_before"] == report["source_git_after"] == setup["source_actual_HEAD"],
            "actual complete Git source identity differs")
    build, build_pin = original(evidence / "build/report.json", report["build"]["record"], 8 << 20)
    require(build["schema"] == "hepta.hia.bounded-read-native-development-build.v1"
            and build["status"] == report["build"]["status"] == "NATIVE_DEVELOPMENT_IMAGE_BUILT_NOT_QUALIFICATION"
            and build["candidate_commit"] == CANDIDATE and build["candidate_tree"] == CANDIDATE_TREE
            and build["compiler_limits_changed"] is False and build["compiler_wall_seconds"] == 20
            and build["original_authoring_limits"] == LIMITS and build["original_native_limits"] == NATIVE_LIMITS
            and build["core_roundtrip"] is True and build["deterministic_source"] is True
            and build["source_preserved_except_new_resource"] is True
            and build["host_successor_compiler_calls"] == []
            and build.get("error") is None and build.get("final_error") is None
            and build["checked_in_global_contract_updated"] is False
            and build["checked_in_contract_and_coverage_qualification_claimed"] is False,
            "actual original preparation result differs")
    require(build["source_manifest"] == source_manifest_pin and build["source_git_before"] == build["source_git_after"] == git,
            "preparation source binding differs")
    for name, key, expected in (("source-before.json", "source_before", before),
            ("source-generated.json", "source_generated", now), ("source-after.json", "source_after", now)):
        value, _ = original(evidence / "build" / name, build[key], 8 << 20)
        require(value == expected, "actual preparation full source records differ")
    copied, copied_pin = read(evidence / "build/bounded-read.hiaasm", 1 << 20)
    require(copied == assembly and copied_pin == build["assembly"] and assembly_pin == build["generated_source"],
            "actual generated HIA copy differs")
    document, document_pin = original(evidence / "build/bounded-read.hia.json", build["core_document"], 4 << 20)
    measures, functions = measurements(document, assembly)
    require(measures == build["measurements"] and functions == build["functions"] and measures["functions"] == 14
            and all(measures[name] <= maximum for name, maximum in LIMITS.items()), "original compiler cap differs")
    compiler = observe_compiler_bundle(source, evidence / "build")
    require(compiler == build["compiler_bundle_before"] == build["compiler_bundle_after"]
            == report["compiler_bundle_before"] == report["compiler_bundle_after"], "fresh compiler bundle drifted")
    seed, seed_pin = original(evidence / "build/B0.receipt.json", maximum=8 << 20)
    seed_image_pin = read(evidence / "build/B0.so", 16 << 20)[1]
    selfhost_pin = read(source / "examples/hia_bootstrap/selfhost.hiaasm", 1 << 20)[1]
    require(build["fresh_seed"] == {"receipt": seed, "image": seed_image_pin, "selfhost": selfhost_pin}
            and seed["python"]["path"] == context["python"]["resolved"]
            and seed["python"]["sha256"] == context["python"]["binary"]["sha256"]
            and seed["python"]["version"] == context["python"]["version"],
            "actual B0 seed report/interpreter binding differs")
    require(build["development_compiler"] == {
        "scope": "CURRENT_SOURCE_B0_B1_B2_DEVELOPMENT_NOT_COLD",
        "B1": compiler["stages"]["B1"]["receipt"], "B2": compiler["stages"]["B2"]["receipt"],
        "B1_equals_B2": True, "compiler_sha256": compiler["compiler_sha256"],
        "old_compiler_reused": False, "cold_qualification_claimed": False,
        "B3_or_mutation_qualification_claimed": False}
        and build["native_compile_receipt"] == compiler["stages"]["bounded-read"]["receipt"],
        "fresh compiler receipts differ from actual originals")
    compiler_pin = read(evidence / "build/B2.image.bin", 1 << 20)[1]
    require(compiler_pin == build["compiler_before"] == build["compiler_after"]
            == report["compiler_before"] == report["compiler_after"], "actual B2 compiler changed")
    manifest, manifest_pin = original(evidence / "build/manifest.json", build["manifest_file"], 16384)
    image_pin = read(evidence / "build/bounded-read.image.bin", 1 << 20)[1]
    require(manifest == build["manifest"] == {"schema": "hepta.hia.bounded-read-native.v3",
        "source_sha256": assembly_pin["sha256"], "image_path": "bounded-read.image.bin",
        "image_sha256": image_pin["sha256"], "compiler_sha256": compiler_pin["sha256"]}
        and image_pin == build["image"]
        and report["bundle_before"] == report["bundle_after"] == {
            "manifest": manifest_pin, "source": assembly_pin, "image": image_pin}, "actual native bundle differs")
    abi, abi_pin = original(evidence / "build/entry-abi.json", build["entry_abi_file"], 65536)
    require(abi == {"schema": "hepta.hia.bounded-read-generated-entry-abi.v1",
        "function": document["functions"][0]["name"], "parameters": document["functions"][0]["params"],
        "returns": document["functions"][0]["returns"], "source_sha256": assembly_pin["sha256"],
        "image_sha256": image_pin["sha256"], "compiler_sha256": compiler_pin["sha256"],
        "qualification_claimed": False}, "actual generated entry ABI differs")
    require(abi["function"] == "f0" and [v["type"] for v in abi["parameters"]]
            == ["readbuf", "mutbuf", "mutbuf"] and abi["returns"] == ["u32"],
            "original fixed entry signature differs")
    linker = build["linker"]
    require(read(Path(linker["resolved"]), 64 << 20, system_binary=True)[1]
            == linker["binary_before"] == linker["binary_after"], "actual linker changed")
    for stream in ("stdout", "stderr"):
        require(read(evidence / "build" / ("linker-version." + stream + ".log"), 1 << 20)[1]
                == linker["version_" + stream], "actual linker version original differs")
    plan, plan_pin = original(control / "populations.json", report["population_plan"], 1 << 20)
    groups = plan["groups"]
    require([g["name"] for g in groups] == ["reject", "lifetime", "permission", "filesystem", "original-eight"]
            and [len(g["expected_ids"]) for g in groups] == [12, 24, 10, 9, 8]
            and [g["qualification_seconds"] for g in groups] == [30, 30, 30, 30, 180]
            and [g["name"] for g in groups] == [g["name"] for g in report["groups"]]
            and [s["label"] for s in report["processes"]] == ["prepare-native"] + [g["name"] for g in groups]
            and report["group_execution"] == {g["name"]: "ACTUAL_COMPLETE_PASS" for g in groups},
            "complete original group/process plan differs")
    python = context["python"]["resolved"]
    require(report["python"]["executable"] == report["python"]["resolved"] == python
            and report["python"]["version"] == context["python"]["version"]
            and report["python"]["binary"] == context["python"]["binary"]
            and report["owner_module"] == read(control / "process_owner_impl.py", 1 << 20)[1],
            "actual driver interpreter or original owner module differs")
    environment = {"PATH": context["inner_PATH"], "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                   "PYTHONDONTWRITEBYTECODE": "1"}
    command = [python, "-I", "-S", "-B", str(control / "prepare_native.py"),
        "--source-root", str(source), "--source-manifest", str(control / "source-manifest.json"),
        "--output", str(evidence / "build")]
    owners = [verify_inner(report["processes"][0], evidence, source, command, environment, 60)]
    summaries, callers = [], None
    for group, step, declared in zip(groups, report["processes"][1:], report["groups"], strict=True):
        name = group["name"]
        flags = ["-B"] if name == "original-eight" else ["-I", "-S", "-B"]
        command = [python, *flags, str(control / group["script"]), "--source-root", str(source),
            "--manifest", manifest_pin["path"], "--output", str(evidence / name)]
        if group["oracle"]:
            command += ["--oracle", str(control / "read_bounded.original.py")]
        selected_environment = dict(environment, **{SELECTOR: manifest_pin["path"]})
        owner = verify_inner(step, evidence, source, command, selected_environment, group["qualification_seconds"])
        owners.append(owner)
        value, value_pin = original(evidence / name / "report.json", declared["record"], 8 << 20)
        population(group, value)
        require(declared["status"] == value["status"] and declared["expected_ids"] == value["expected_ids"]
                and declared["executed_ids"] == value["executed_ids"], "driver group observation differs")
        if name == "original-eight":
            callers = verify_callers(source, evidence, value, manifest_pin, manifest, owner["qualification_pid"], python)
        else:
            require([c["id"] for c in value["cases"]] == group["expected_ids"], "case raw denominator differs")
            for case in value["cases"]:
                data, _ = original(evidence / name / (case["id"] + ".json"),
                                   case["original"] if name == "reject" else case["record"], 8 << 20)
                require(data["id"] == case["id"] and data["status"] == case["status"] == "PASS",
                        "case original outcome differs")
            if name in ("reject", "lifetime"):
                require(value["source_preserved"] is True and value["source_before"] == value["source_after"],
                        "finite original source observations differ")
            if name == "reject":
                require(value["image_identity_before"] == value["image_identity_after"]
                        and value["manifest_before"] == value["manifest_after"]
                        == {"path": manifest_pin["path"], "sha256": manifest_pin["sha256"]}, "reject image differs")
            elif name == "lifetime":
                require(value["native_before"] == value["native_after"]
                        and value["manifest_before"] == value["manifest_after"] == manifest_pin["sha256"],
                        "lifetime bundle differs")
            else:
                require(value["native_before"] == value["native_after"]
                        and value["manifest_before"] == value["manifest_after"] == manifest_pin,
                        "permission/filesystem actual bundle differs")
        summaries.append({"name": name, "report": value_pin, "expected_ids": group["expected_ids"],
                          "loaded_ids": value["loaded_ids"], "executed_ids": value["executed_ids"]})
    return {"report": report_pin, "build_report": build_pin, "population_plan": plan_pin,
        "source_before": before_pin, "source_manifest": source_manifest_pin, "actual_Git": git,
        "generated_HIA": copied_pin, "generated_Core_document": document_pin, "generated_entry_ABI": abi_pin,
        "manifest": manifest_pin, "image": image_pin, "fresh_B2": compiler_pin,
        "compiler_lineage_scope": compiler["scope"], "finite_cases": 55, "original_methods": 8,
        "original_CLI_children": 7, "groups": summaries, "inner_owners": owners, "callers": callers,
        "scope": "FINITE_NATIVE_DEVELOPMENT_NOT_COLD_OR_FULL_DOMAIN_QUALIFICATION"}
