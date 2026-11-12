"""Full finite bounded-read development gate, pending its independent outer owner.

STATIC UNEXECUTED. No workflow or stable dispatch key is supplied by this file.
All inner commands use the unchanged process owner. Only a separate, exact
180-second/3-second outer receipt can complete the development conjunction.
"""
from __future__ import annotations
import argparse
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import traceback

sys.path.insert(0, str(Path(__file__).absolute().parent))
from source_common import (_checked_parent, _create_directory, create, fixed_read,
    pin, read, require, snapshot, wire)
from native_support import (BASE, CANDIDATE, CANDIDATE_TREE,
    GENERATED, OWNER_SHA, SELECTOR, generated_rows, load_fixed_module, owned_step, source_manifest,
    observe_compiler_bundle)
from git_binding import source_git

ANOMALIES = {"skips", "expected_failures", "unexpected_successes", "failures", "errors"}

def controls(path, wanted):
    raw, record = read(path, 1 << 20)
    require(record["sha256"] == wanted, "outer-bound control manifest differs")
    value = json.loads(raw)
    require(value["schema"] == "hepta.hia.bounded-read-native-development-control-manifest.v1"
            and value["candidate_commit"] == CANDIDATE
            and value["candidate_tree"] == CANDIDATE_TREE
            and value["outer_qualification_seconds"] == 180
            and value["outer_cleanup_seconds"] == 3
            and value["dispatch_authorized_by_this_file"] is False,
            "fixed native control header differs")
    root = Path(__file__).absolute().parent
    observed = {}
    require(type(value["files"]) is dict and value["files"], "fixed control file set missing")
    for name, expected in value["files"].items():
        require("/" not in name and "\\" not in name and name not in ("", ".", "..")
                and "\0" not in name, "control leaf name refused")
        data, actual = fixed_read(root / name, expected)
        observed[name] = actual
    return value, raw, record, observed

def bundle(source, manifest, compiler_sha256):
    raw, manifest_record = read(manifest, 16384)
    value = json.loads(raw)
    require(value["schema"] == "hepta.hia.bounded-read-native.v3"
            and value["compiler_sha256"] == compiler_sha256
            and type(value["image_path"]) is str
            and "/" not in value["image_path"] and "\\" not in value["image_path"]
            and value["image_path"] not in ("", ".", ".."), "new native manifest differs")
    source_raw, source_record = read(source / GENERATED, 1 << 20)
    image_raw, image_record = read(manifest.parent / value["image_path"], 1 << 20)
    require(sha256(source_raw).hexdigest() == value["source_sha256"]
            and sha256(image_raw).hexdigest() == value["image_sha256"],
            "actual generated source/image differs from manifest")
    return {"manifest": manifest_record, "source": source_record, "image": image_record}, source_raw

def validate_population(group, report):
    expected = group["expected_ids"]
    require(report["schema"] == group["schema"] and report["status"] == group["status"]
            and report["expected_ids"] == expected and report["loaded_ids"] == expected
            and report["executed_ids"] == expected and not report["errors"],
            "complete actual component population/status differs")
    require(set(report["anomalies"]) == ANOMALIES
            and all(type(x) is list and not x for x in report["anomalies"].values()),
            "nonzero or incomplete five-anomaly accounting")
    if group["name"] != "original-eight":
        require([case["id"] for case in report["cases"]] == expected
                and all(case["status"] == "PASS" for case in report["cases"]),
                "case originals do not cover the exact component population")
    else:
        require(report["testsRun"] == 8 and len(report["children"]) == 7
                and report["actual_native_read_attempts"] == 12
                and report["actual_native_read_returns"] == 11
                and report["original_CLI_timeout_seconds"] == 20,
                "original caller/CLI actual population differs")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--control-manifest", type=Path, required=True)
    parser.add_argument("--control-manifest-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source_root, args.output
    require(source.is_absolute() and output.is_absolute() and ".." not in source.parts
            and ".." not in output.parts and source != output and source not in output.parents,
            "separate absolute owned source/output roots required")
    with _checked_parent(source / ".source-spine-probe"):
        pass
    _create_directory(output)
    _create_directory(output / "processes")
    report = {"schema": "hepta.hia.bounded-read-native-development.v1",
        "status": "HOLD", "base_commit": BASE, "candidate_commit": CANDIDATE,
        "candidate_tree": CANDIDATE_TREE, "processes": [], "groups": [], "errors": [],
        "finite_component_cases": 55, "original_methods": 8, "original_CLI_children": 7,
        "group_execution": {name: "NOT_STARTED" for name in
            ("reject", "lifetime", "permission", "filesystem", "original-eight")},
        "outer_qualification_seconds_required": 180, "outer_cleanup_seconds_required": 3,
        "outer_guardian_verified_here": False, "all_input_equivalence_proved": False,
        "CPython_cyclic_GC_schedule_proved": False, "formal_git_consumer_qualified": False,
        "cold_qualification": False, "installed_qualification": False,
        "whole_native_delivery_qualified": False, "fresh_B0_B1_B2_requested": True,
        "old_B3_input_reused": False, "checked_in_global_contract_updated": False,
        "checked_in_contract_and_coverage_qualification_claimed": False}
    rows = before = source_manifest_record = None
    control_value = control_raw = control_record = control_before = compiler_before = None
    generated = None
    bundle_before = None
    configuration = None
    compiler_lineage = git_before = None
    try:
        require(sys.version_info[:3] == (3, 14, 4) and sys.dont_write_bytecode,
                "fixed actual CPython 3.14.4/no-bytecode target differs")
        require(os.getcwd() == str(source), "fixed source cwd differs")
        require(not any(name.startswith(("HEPTA_HIA_", "LD_"))
                    or name in ("PYTHONPATH", "PYTHONHOME") for name in os.environ),
                "ambient selector or loader redirection refused")
        control_value, control_raw, control_record, control_before = controls(
            args.control_manifest, args.control_manifest_sha256)
        report["control_manifest"] = control_record
        report["control_before"] = control_before
        root = Path(__file__).absolute().parent
        require(args.source_manifest == root / "source-manifest.json",
                "source manifest must be the bound control input")
        rows, source_manifest_raw, source_manifest_record = source_manifest(args.source_manifest)
        before = snapshot(source, rows)
        report["source_before"] = create(output / "source-before.json", wire(before))
        git_before = source_git(source, rows)
        report["source_git_before"] = git_before
        owner, report["owner_module"] = load_fixed_module(
            "_bounded_read_owned_process", root / "process_owner_impl.py", OWNER_SHA)
        require(owner.QUALIFICATION_SECONDS == 180 and owner.CLEANUP_SECONDS == 3,
                "original owner budgets differ")
        plan_raw, report["population_plan"] = read(root / "populations.json", 1 << 20)
        configuration = json.loads(plan_raw)
        require(configuration["schema"] == "hepta.hia.bounded-read-native-development-populations.v1"
                and configuration["finite_component_cases"] == 55
                and configuration["original_methods"] == 8
                and configuration["original_CLI_children"] == 7
                and configuration["original_CLI_child_timeout_seconds"] == 20
                and [row["name"] for row in configuration["groups"]]
                    == ["reject", "lifetime", "permission", "filesystem", "original-eight"]
                and [len(row["expected_ids"]) for row in configuration["groups"]] == [12, 24, 10, 9, 8],
                "five complete test populations differ")
        # Parse only the newly frozen controller inputs in the actual target.
        # This never constitutes execution of their test methods.
        for name in control_value["files"]:
            if name.endswith(".py"):
                ast.parse(read(root / name, 1 << 20)[0], filename=str(root / name))
        report["control_python_syntax_checked"] = sorted(
            name for name in control_value["files"] if name.endswith(".py"))
        environment = {"PATH": os.environ["PATH"], "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                       "PYTHONDONTWRITEBYTECODE": "1"}
        python = str(Path(sys.executable).absolute())
        report["python"] = {"executable": python, "version": sys.version,
                           "resolved": str(Path(sys.executable).resolve()),
                           "binary": read(Path(sys.executable).resolve(), 64 << 20,
                                          system_binary=True)[1]}
        prepare_command = [python, "-I", "-S", "-B", str(root / "prepare_native.py"),
            "--source-root", str(source), "--source-manifest", str(args.source_manifest),
            "--output", str(output / "build")]
        owned_step(owner, output / "processes", report, "prepare-native", prepare_command,
                   source, environment, 60)
        build_raw, build_record = read(output / "build/report.json", 4 << 20)
        build = json.loads(build_raw)
        report["build"] = {"record": build_record, "status": build["status"]}
        require(build["status"] == "NATIVE_DEVELOPMENT_IMAGE_BUILT_NOT_QUALIFICATION"
                and build["candidate_commit"] == CANDIDATE
                and build["candidate_tree"] == CANDIDATE_TREE
                and build["source_preserved_except_new_resource"] is True
                and build["core_roundtrip"] is True and build["deterministic_source"] is True
                and build["host_successor_compiler_calls"] == [],
                "real generation/native compilation did not complete")
        compiler_lineage = observe_compiler_bundle(source, output / "build")
        require(build["compiler_bundle_before"] == build["compiler_bundle_after"] == compiler_lineage
                and build["source_git_before"] == build["source_git_after"] == git_before,
                "actual fresh compiler lineage/Git identity differs")
        compiler_before = read(output / "build/B2.image.bin", 1 << 20)[1]
        report["compiler_before"] = compiler_before
        report["compiler_bundle_before"] = compiler_lineage
        manifest = output / "build/manifest.json"
        bundle_before, generated = bundle(source, manifest, compiler_before["sha256"])
        prepared = snapshot(source, generated_rows(rows, generated))
        require([row for row in prepared if row["path"] != GENERATED] == before,
                "preparation changed another candidate source")
        report["source_prepared"] = create(output / "source-prepared.json", wire(prepared))
        report["bundle_before"] = bundle_before
        selected_environment = dict(environment, **{SELECTOR: str(manifest)})
        for group in configuration["groups"]:
            target = output / group["name"]
            # The original eight needs ordinary site initialization for its
            # unchanged subprocesses; its own private hook binds all seven CLI
            # children. The finite fixture groups run isolated without site.
            flags = ["-B"] if group["name"] == "original-eight" else ["-I", "-S", "-B"]
            command = [python, *flags, str(root / group["script"]), "--source-root", str(source),
                       "--manifest", str(manifest), "--output", str(target)]
            if group["oracle"]:
                command += ["--oracle", str(root / "read_bounded.original.py")]
            report["group_execution"][group["name"]] = "OWNER_CALL_REQUESTED"
            owned_step(owner, output / "processes", report, group["name"], command,
                       source, selected_environment, group["qualification_seconds"])
            actual_raw, actual_record = read(target / "report.json", 8 << 20)
            actual = json.loads(actual_raw)
            observed = {"name": group["name"], "record": actual_record,
                        "status": actual.get("status"), "expected_ids": group["expected_ids"],
                        "executed_ids": actual.get("executed_ids", [])}
            report["groups"].append(observed)
            validate_population(group, actual)
            report["group_execution"][group["name"]] = "ACTUAL_COMPLETE_PASS"
            require(bundle(source, manifest, compiler_before["sha256"])[0] == bundle_before,
                    "actual source/manifest/image changed across component")
        require(len(report["groups"]) == 5, "incomplete native/original caller gate")
        report["status"] = "FINITE_DEVELOPMENT_PENDING_FINAL_SOURCE_CHECK"
    except BaseException as error:
        report["status"] = "HOLD"
        report["errors"].append({"type": type(error).__name__, "text": str(error),
                                  "traceback": traceback.format_exc()})
    finally:
        closed = all(step.get("cleanup_closed_before_original_read") is True
                     for step in report["processes"])
        report["all_started_inner_owners_closed"] = closed
        if not closed:
            report["status"] = "HOLD"
            report["source_and_output_readback_deferred_until_outer_ECHILD"] = True
        else:
            try:
                if rows is not None and before is not None:
                    # A failed preparer may have published the sole new source.
                    # Preserve that actual file even when no image/report is ready.
                    if os.path.lexists(source / GENERATED):
                        actual_generated, generated_record = read(source / GENERATED, 1 << 20)
                        generated = actual_generated
                        report["generated_source_at_terminal"] = generated_record
                    expected = generated_rows(rows, generated) if generated is not None else rows
                    after = snapshot(source, expected)
                    report["source_after"] = create(output / "source-after.json", wire(after))
                    require([row for row in after if row["path"] != GENERATED] == before,
                            "candidate source drifted before terminal")
                    report["source_stable_except_new_resource"] = True
                if compiler_before is not None:
                    report["compiler_after"] = read(output / "build/B2.image.bin", 1 << 20)[1]
                    require(report["compiler_after"] == compiler_before, "fresh B2 input changed")
                if compiler_lineage is not None:
                    report["compiler_bundle_after"] = observe_compiler_bundle(source, output / "build")
                    require(report["compiler_bundle_after"] == compiler_lineage, "fresh compiler lineage changed")
                if git_before is not None:
                    report["source_git_after"] = source_git(source, rows)
                    require(report["source_git_after"] == git_before, "candidate Git identity changed")
                if control_before is not None:
                    _, current_raw, current_record, current = controls(
                        args.control_manifest, args.control_manifest_sha256)
                    require(current_raw == control_raw and current_record == control_record
                            and current == control_before, "control input drifted before terminal")
                    report["control_after"] = current
                if bundle_before is not None:
                    report["bundle_after"] = bundle(source, output / "build/manifest.json", compiler_before["sha256"])[0]
                    require(report["bundle_after"] == bundle_before,
                            "mapped bundle physical files changed before terminal")
                if report["status"] == "FINITE_DEVELOPMENT_PENDING_FINAL_SOURCE_CHECK":
                    require(report.get("source_stable_except_new_resource") is True
                            and len(report["groups"]) == 5 and not report["errors"],
                            "finite gate final conjunction incomplete")
                    report["status"] = "BOUNDED_READ_DEVELOPMENT_PASS_PENDING_OUTER_GUARDIAN"
            except BaseException as error:
                report["status"] = "HOLD"
                report["errors"].append({"phase": "final_readback", "type": type(error).__name__,
                                          "text": str(error), "traceback": traceback.format_exc()})
        # Fixed paths, not only successful report fields, are the later outer
        # custody scope. NOT_STARTED is distinct from an owner call whose
        # process failed or whose cleanup could not be confirmed.
        completed = {row["name"] for row in report["groups"]}
        report["not_completed_groups"] = [name for name in
            ("reject", "lifetime", "permission", "filesystem", "original-eight")
            if name not in completed]
        report["fixed_evidence_roots"] = ["processes", "build", "reject", "lifetime",
                                          "permission", "filesystem", "original-eight"]
        create(output / "report.json", wire(report))
    print(json.dumps({"status": report["status"], "completed_groups": len(report["groups"]),
        "outer_guardian_verified_here": False, "cold_qualification": False}), flush=True)
    return 0 if report["status"] == "BOUNDED_READ_DEVELOPMENT_PASS_PENDING_OUTER_GUARDIAN" else 1

if __name__ == "__main__":
    raise SystemExit(main())
