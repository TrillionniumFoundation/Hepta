#!/usr/bin/env python3
"""Requalify the fixed musl 1.2.5 -> 1.2.6 unchanged-body release update.

This protocol is a maintenance regression, not a fresh semantic holdout or a
model/productivity experiment. A changed function, adapter, production compiler,
toolchain or observation matrix requires a separate versioned protocol.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_program import verify_program
from tools.qualify_hia_musl_strncmp import (
    FIXTURE, PROTOCOL, SUCCESSOR_FIXTURE, UPSTREAM_PROFILES,
    cases, identity, require, run, source_bindings, verify_upstream, write,
)

UPDATE_PROTOCOL = {
    "schema": "hepta.hia.musl-strncmp-release-update-protocol.v1",
    "baseline_version": "1.2.5", "successor_version": "1.2.6",
    "profile": "unchanged_body_subsequent_official_release",
    "fixed_conditions": [
        "exact_registered_release_archives_and_complete_component_bytes",
        "unchanged_upstream_function_bytes",
        "unchanged_authored_header_contract_and_clients",
        "unchanged_production_hepta_python_sources",
        "identical_clang_python_and_frontend_loader_identities",
        "identical_fixed_386_by_3_regression_matrix",
        "fresh_capture_direct_llvm_build_and_2316_native_processes",
        "1158_new_vm_runs_and_matching_value_resource_observations",
        "identical_readmitted_core_program",
        "no_manual_migrated_body_edits",
    ],
    "changed_body_auto_adaptation_qualified": False,
    "all_input_semantic_or_backend_proof": False,
    "new_holdout_or_model_experiment": False,
    "labor_or_performance_advantage_measured": False,
}


def validate_archive(path, version):
    """Read fixed members without extracting arbitrary archive paths."""
    metadata = verify_upstream(version=version)
    observed = identity(path)
    require(all(observed[key] == metadata["release_archive"][key]
                for key in ("bytes", "sha256")), "release archive differs")
    fixture = UPSTREAM_PROFILES[version]["fixture"]
    with tarfile.open(path, "r:gz") as archive:
        require(archive.extractfile("musl-" + version + "/VERSION").read() == (version + "\n").encode(),
                "release VERSION differs")
        for row in metadata["files"]:
            member = archive.extractfile("musl-" + version + "/" + row["upstream_path"]).read()
            require(member == (fixture / row["local_path"]).read_bytes(), "release member differs")
    return observed


def oracle(arguments, refusal):
    """Recompute packed-byte and resource expectations outside the main runner."""
    count, left, right = arguments
    if count > 8:
        value, attempts, allocations = -259, 0, 0
    elif count == 0:
        value, attempts, allocations = 0, 0, 0
    elif refusal:
        value, attempts, allocations = -256 - refusal, refusal, refusal - 1
    else:
        value, attempts, allocations = 0, 2, 2
        for offset in range(count):
            a, b = (left >> (8 * offset)) & 255, (right >> (8 * offset)) & 255
            if a != b or a == 0:
                value = a - b
                break
    return {"result": value, "attempts": attempts, "allocations": allocations,
            "frees": allocations, "live": 0}


def validate_qualification(directory, version):
    """Rehash retained files and recompute every matrix cell from raw receipts.

    Paths may be relocated as a complete directory. This checks receipt
    consistency; it is neither independent execution nor signed attestation.
    """
    directory = Path(directory)
    report = json.loads((directory / "qualification.json").read_text())
    require(report["ok"] and report["status"] == "completed_finite_component_qualification",
            "completed component qualification required")
    require(report["protocol"] == PROTOCOL and report["upstream"] == verify_upstream(version=version),
            "upstream or fixed matrix protocol differs")
    original_root = Path(report["commands"][0]["cwd"])
    for row in report["retained_files"]:
        path = directory / Path(row["path"]).relative_to(original_root)
        observed = identity(path)
        require(all(observed[key] == row[key] for key in ("bytes", "sha256")), "retained artifact differs")
    processes = [json.loads(line) for line in (directory / "processes.jsonl").read_text().splitlines()]
    require([{key: value for key, value in row.items() if key not in ("stdout", "stderr")}
             for row in processes] == report["commands"], "raw process ledger differs from report")
    inputs = cases()
    require(json.loads((directory / "input-cases.json").read_text()) == inputs, "input matrix differs")
    rows = [json.loads(line) for line in (directory / "observations.jsonl").read_text().splitlines()]
    planned = {(row["case"], refusal) for row in inputs for refusal in PROTOCOL["refusal_indices"]}
    seen, used_commands = set(), set()
    for row in rows:
        key = (row["case"], row["refuse_at"])
        require(key in planned and key not in seen, "duplicate or unplanned matrix cell")
        seen.add(key)
        require({name: row[name] for name in ("case", "category", "arguments", "expected")}
                == inputs[row["case"]], "input case changed")
        expected = oracle(row["arguments"], row["refuse_at"])
        require(row["resource_expected"] == expected, "stored oracle differs")
        require(set(row["native"]) == {"original_c_native", "hia_llvm_native"}, "native route missing")
        for route, native in row["native"].items():
            index = native["command_index"]
            require(index not in used_commands, "native command reused")
            used_commands.add(index)
            process = processes[index]
            require(process["stage"] == "native_observation" and process["returncode"] == 0
                    and Path(process["argv"][0]).name == route
                    and process["argv"][1:] == list(map(str, [*row["arguments"], row["refuse_at"]]))
                    and process["wall_ns"] == native["wall_ns"]
                    and json.loads(process["stdout"]) == native["observed"] == expected,
                    "native process receipt or observation differs")
        vm = row["vm"]["observed"]
        stats = vm["resources"]
        require(vm["result"] == expected["result"] and stats["live_owners"] == 0
                and stats["loans_started"] == stats["loans_ended"]
                and all(stats[a] == expected[b] for a, b in (("allocation_attempts", "attempts"),
                        ("allocations", "allocations"), ("frees", "frees"))), "VM observation differs")
    require(seen == planned and len(rows) == report["completed_cases"] == report["planned_cases"] == 1158
            and len(used_commands) == report["native_observations"] == 2316
            and report["vm_observations"] == 1158, "incomplete finite matrix")
    core = verify_program((directory / "capture/program.hia.json").read_bytes())
    require(core.sha256 == report["migration"]["program_sha256"], "Core receipt differs")
    return report, {
        "rows_recomputed": len(rows), "processes_matched": len(used_commands),
        "retained_files_rehashed": len(report["retained_files"]),
        "vm_execution_wall_ns_sum": sum(row["vm"]["wall_ns"] for row in rows),
        "native_process_wall_ns_sum": sum(processes[index]["wall_ns"] for index in used_commands),
        "independent_agent_review": False,
    }


def run_update(*, baseline, release_archive, acquisition_receipt, output, clang, source_sha):
    started = time.monotonic_ns()
    out = Path(output).absolute()
    out.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.hia.musl-strncmp-release-update.v1", "protocol": UPDATE_PROTOCOL,
              "ok": False, "status": "incomplete", "human_effort_measured": False}
    try:
        before = time.monotonic_ns()
        old, old_replay = validate_qualification(baseline, "1.2.5")
        report["baseline_validation_wall_ns"] = time.monotonic_ns() - before
        report["baseline"] = {"qualification": identity(Path(baseline) / "qualification.json"),
                              "source_commit": old["source_commit"], "receipt_replay": old_replay}
        before = time.monotonic_ns()
        report["release_archive"] = validate_archive(release_archive, "1.2.6")
        report["archive_validation_wall_ns"] = time.monotonic_ns() - before
        acquisition = json.loads(Path(acquisition_receipt).read_text())
        require(acquisition["ok"] and acquisition["archive"]["sha256"] == report["release_archive"]["sha256"]
                and acquisition["commit"] == UPSTREAM_PROFILES["1.2.6"]["commit"], "acquisition receipt differs")
        shutil.copyfile(acquisition_receipt, out / "acquisition.json")
        report["acquisition"] = {"receipt": identity(out / "acquisition.json"), "wall_ns": acquisition["wall_ns"],
                                 "requests": len(acquisition["processes"]),
                                 "includes_earlier_unmeasured_discovery_or_failed_requests": False}
        for path in ("strncmp.c", "platform/string.h", "contracts.json"):
            require((FIXTURE / path).read_bytes() == (SUCCESSOR_FIXTURE / path).read_bytes(),
                    "changed-body or adapter update requires a new protocol")
        current = source_bindings()
        protected = {path: digest for path, digest in old["source_bindings"].items()
                     if path.startswith(("hepta/", "examples/hia_musl_strncmp/"))}
        protected_current = {path: digest for path, digest in current.items()
                             if path.startswith(("hepta/", "examples/hia_musl_strncmp/"))}
        require(protected and protected_current == protected,
                "production compiler or client changes require a new protocol")
        successor = run(output=out / "successor", clang=clang, source_sha=source_sha, upstream_version="1.2.6")
        require(successor["ok"], "fresh successor qualification failed")
        new, new_replay = validate_qualification(out / "successor", "1.2.6")
        require(all(old[key] == new[key] for key in ("tool", "python", "frontend_loader")),
                "toolchain or loader changes require a new protocol")
        require(old["migration"]["program_sha256"] == new["migration"]["program_sha256"]
                and old["migration"]["manual_migrated_body_edits"] == new["migration"]["manual_migrated_body_edits"] == 0,
                "Core or migrated-body changes require a new protocol")
        report["successor"] = {"qualification": identity(out / "successor/qualification.json"),
            "source_commit": new["source_commit"], "receipt_replay": new_replay,
            "core_sha256": new["migration"]["program_sha256"],
            "fresh_native_observations": new["native_observations"], "fresh_vm_observations": new["vm_observations"]}
        report["source_delta"] = {"function_bytes_changed": 0, "authored_adapter_bytes_changed": 0,
            "production_hepta_source_files_changed": 0, "manual_migrated_body_edits": 0,
            "copyright_bytes": {"baseline": (FIXTURE / "COPYRIGHT").stat().st_size,
                                "successor": (SUCCESSOR_FIXTURE / "COPYRIGHT").stat().st_size}}
        report["measured_costs"] = {
            "successor_capture_lowering_verification_wall_ns": new["migration"]["wall_ns"],
            "successor_direct_llvm_native_build_wall_ns": new["native_build_wall_ns"],
            "successor_reference_observer_build_link_wall_ns_sum": sum(row["wall_ns"] for row in new["commands"]
                if row["stage"] in ("original_c_capture_replay", "authored_c_client", "observer_build",
                                    "original_c_native_link", "hia_llvm_native_link")),
            "successor_whole_qualification_wall_ns": new["whole_qualification_wall_ns"],
            "native_hia_object_bytes": identity(out / "successor/hia.o")["bytes"],
            "native_original_function_object_bytes": identity(out / "successor/original.o")["bytes"],
            "comparative_human_or_model_effort_measured": False, "runtime_performance_comparison": False,
        }
        report.update(ok=True, status="completed_unchanged_body_release_maintenance",
                      accepted_conditions=list(UPDATE_PROTOCOL["fixed_conditions"]))
    except Exception as error:
        report.update(ok=False, status="failed", error={"type": type(error).__name__,
                                                      "code": getattr(error, "code", None), "message": str(error)})
    finally:
        report["maintenance_wall_ns_excluding_acquisition"] = time.monotonic_ns() - started
        write(out / "update.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("baseline", "release-archive", "acquisition-receipt", "output", "source-sha"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    result = run_update(**vars(parser.parse_args()))
    print(json.dumps({key: result[key] for key in ("ok", "status", "maintenance_wall_ns_excluding_acquisition", "error") if key in result}))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
