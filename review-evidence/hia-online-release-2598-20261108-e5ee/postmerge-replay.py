#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Replay the retained post-merge observations; no endpoint call or deployment."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ENTRY = "bd4b846359a7f3200593750304aa744422221793"
LOCK_SHA = "9000d6eaa089f6bed92ea07a6561d91381a6f913263f0b1016d4f99e8789c1d3"
CHECKER_SHA = "ff9669c365b4056de643129376a3e4868396745f542adf90ef1fb4c114014542"
ZIP_SHA = "c40ae57156623ff949c71d9be78ced12ad6415c11ad9ca99fb3a8ba70d7d8952"


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def raw(name):
    return (HERE / name).read_bytes()


def read(name):
    return json.loads(raw(name))


def payload(value):
    return value.get("structuredContent") or json.loads(value["content"][0]["text"])


def api(value):
    value = payload(value)
    return json.loads(value["content"]) if isinstance(value.get("content"), str) else value


def retained_envelope(item):
    data = item["envelope_json_utf8"].encode()
    need(len(data) == item["bytes"] and sha(data) == item["sha256"], "retained metadata envelope differs")
    return json.loads(data)


def observed_time(value):
    return datetime.strptime(value["current_time"], "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)


def main():
    checker_raw = (ROOT / "tools/check_hia_online_readback.py").read_bytes()
    need(sha(checker_raw) == CHECKER_SHA, "unchanged main checker required")
    checker = {"__name__": "retained_postmerge_checker"}
    exec(compile(checker_raw, "tools/check_hia_online_readback.py", "exec"), checker)
    current_lock = (ROOT / "releases/hia-current.json").read_bytes()
    need(current_lock == raw("postmerge-public-lock.json") == raw("release-lock.json"), "current, post-merge and original source-CI locks differ")
    need(sha(current_lock) == LOCK_SHA, "selected source-CI lock digest differs")
    lock = checker["decode"](current_lock)

    description_raw = raw("postmerge-formal-hia-describe-result.json")
    read_raw = raw("postmerge-formal-hia-read-result.json")
    verification = checker["check_readback"](current_lock, LOCK_SHA, description_raw, read_raw)
    need(verification == read("postmerge-readback-verification.json"), "recorded unchanged-checker result differs")
    need(verification["passed"] and all(verification["matches"].values()), "installation readback differs")
    report_bytes = (json.dumps(verification, sort_keys=True, indent=2) + "\n").encode()
    need(report_bytes == raw("postmerge-readback-verification.json"), "checker stdout bytes differ")
    execution = read("postmerge-checker-execution.json")
    need(execution["exit_code"] == 0 and execution["entry_commit"] == ENTRY, "checker execution did not pass against the entry")
    for key, digest in {
        "checker_sha256": CHECKER_SHA, "lock_sha256": LOCK_SHA,
        "describe_sha256": sha(description_raw), "read_sha256": sha(read_raw),
        "manifest_sha256": sha(raw("postmerge-formal-manifest.json")),
        "stdout_sha256": sha(report_bytes), "stderr_sha256": sha(b""),
    }.items():
        need(execution[key] == digest, "checker execution binding differs: " + key)
    description = checker["completed_envelope"](description_raw, "describe")
    successful_read = checker["completed_envelope"](read_raw, "read")
    manifest_raw = successful_read["result"]["content"].encode()
    need(manifest_raw == raw("postmerge-formal-manifest.json") and len(manifest_raw) == 7048, "exact complete manifest bytes differ")

    timeout = read("postmerge-formal-hia-read-timeout.json")
    need(timeout["isError"] is True and "-32603" in timeout["content"][0]["text"] and "MCP request timed out" in timeout["content"][0]["text"], "original transport timeout must remain a failure")
    calls = read("postmerge-call-observations.json")
    need(calls["read_attempt_1"]["parameters"]["max_bytes"] == 16384 and calls["read_attempt_2"]["parameters"]["max_bytes"] == 8192, "independent read observations must retain their windows")
    need(calls["read_attempt_1"]["status"] == "transport_timeout_original_response_unobserved", "first call was relabelled")
    need(calls["read_attempt_2"]["parameters"]["artifact"] == description["result"]["manifest"], "independent read must use the newly described reference")
    need(observed_time(calls["describe"]["returned_at"]) <= observed_time(calls["read_attempt_1"]["started_at"]) < observed_time(calls["read_attempt_1"]["returned_at"]) < observed_time(calls["read_attempt_2"]["started_at"]) < observed_time(calls["read_attempt_2"]["returned_at"]), "formal-call chronology differs")
    expected_service_id = "r-" + sha(canonical({"tool": "hia_read", "arguments": calls["read_attempt_2"]["parameters"]}))
    need(successful_read["request_id"] == expected_service_id, "successful service request does not bind the recorded read parameters")

    metadata = read("postmerge-ci-raw-metadata.json")["observations"]
    observed = {name: api(retained_envelope(value)) for name, value in metadata.items()}
    for label, run_id in [("public_install", 42552762057), ("online_readback", 42552762051)]:
        run = observed[label + "_run"]
        need(run["id"] == run_id and run["head_sha"] == ENTRY and run["head_branch"] == "main" and run["event"] == "push" and run["status"] == "completed" and run["conclusion"] == "success", "exact main CI gate differs")
        need(datetime.fromisoformat(run["updated_at"].replace("Z", "+00:00")) < observed_time(calls["describe"]["started_at"]), "formal observation predates the successful main gate")
        jobs = observed[label + "_jobs"]["jobs"]
        need(len(jobs) == 1, "one retained main CI job required")
        job = jobs[0]
        need(job["head_sha"] == ENTRY and job["run_id"] == run_id and job["conclusion"] == "success", "main job binding differs")
        need(all(step["status"] == "completed" and step["conclusion"] == "success" for step in job["steps"]), "main CI contains a failed or incomplete step")
    artifacts = observed["public_install_artifacts"]["artifacts"]
    need(len(artifacts) == 1, "one public installation artifact required")
    artifact = artifacts[0]
    need(artifact["id"] == 13645358721 and artifact["size_in_bytes"] == 95427 and artifact["digest"] == "sha256:" + ZIP_SHA and artifact["workflow_run"]["id"] == 42552762057 and artifact["workflow_run"]["head_sha"] == ENTRY, "official artifact metadata binding differs")
    inventory = read("postmerge-ci-artifact-files.json")
    need(inventory["artifact_id"] == artifact["id"] and inventory["run_id"] == 42552762057 and inventory["bytes"] == 95427 and inventory["sha256"] == ZIP_SHA and len(inventory["members"]) == 9, "downloaded artifact observation differs")
    members = {item["name"]: item for item in inventory["members"]}
    for member, file in [("installation.json", "postmerge-ci-installation.json"), ("check.log", "postmerge-ci-check.json"), ("direct-native.json", "postmerge-ci-direct-native.json"), ("public-inputs.json", "postmerge-ci-public-inputs.json")]:
        data = raw(file)
        need(sha(data) == members[member]["sha256"] and len(data) == members[member]["bytes"], "retained CI member differs: " + member)
    need(read("postmerge-ci-installation.json") == lock["installation"] == verification["observed_installation"], "lock, public CI and formal installation differ")
    contract_check = read("postmerge-ci-check.json")
    need(contract_check == {"status": "source_contract_verified", "release_lock_sha256": LOCK_SHA, "production_deployed": False}, "original source qualification flags or check differ")
    inputs = read("postmerge-ci-public-inputs.json")
    need(inputs["entry_commit"] == ENTRY and inputs["release_lock_sha256"] == LOCK_SHA and inputs["hepta_source"] == lock["sources"]["hepta"] and inputs["ok"] is True, "materialized public inputs differ")
    native = read("postmerge-ci-direct-native.json")
    need(native["ok"] and native["tests_run"] == 173 and native["inventory_complete"] and native["source_unchanged"] and native["git_head"] == lock["sources"]["hepta"]["commit"] and native["git_tree"] == lock["sources"]["hepta"]["tree"] and native["git_status"] == "", "native artifact source qualification differs")
    need(all(native[key] == [] for key in ["errors", "failures", "skipped", "unexpected_successes"]), "native artifact contains unsuccessful cases")
    provenance = read("postmerge-ci-provenance.json")
    for file, binding in provenance["job_log_files"].items():
        need(sha(raw(file)) == binding["sha256"] and len(raw(file)) == binding["bytes"], "decoded CI log differs")
    need(provenance["public_install_artifact"]["downloaded_zip_sha256"] == ZIP_SHA and provenance["qualification_flags_modified"] is False, "artifact provenance or unchanged flags differ")

    guard = read("postmerge-main-guard.json")
    for key in ["before", "after_successful_read"]:
        need(api(retained_envelope(guard[key]))["object"]["sha"] == ENTRY, "main selection changed between retained observations")
    need(guard["default_lock_read_after_success"]["sha256"] == LOCK_SHA and guard["default_lock_read_after_success"]["bytes"] == len(current_lock), "default main lock differs")
    recovery = read("postmerge-operation-recovery.json")
    old = recovery["matching_original_operation"]
    worker_request = old["worker_request"]
    body = {key: value for key, value in worker_request.items() if key != "request_sha256"}
    need(sha(canonical(body)) == worker_request["request_sha256"], "historical WorkerRequest binding differs")
    need(old["idempotency_key"] == "hia-agent-" + sha(canonical({"tool": "hia_read", "readonly_request_sha256": worker_request["request_sha256"]})), "historical durable key differs")
    need(sha(canonical(worker_request) + b"\n") == old["worker_request_raw_utf8_sha256"], "original worker stdin including newline differs")
    need(worker_request["arguments"] == calls["read_attempt_1"]["parameters"], "historical request differs from timed-out invocation inputs")
    original = payload(read("postmerge-original-operation-status.json"))
    need(original["job_id"] == old["job_id"] and original["state"] == "succeeded" and original["exit_code"] == 0 and original["output_complete"] and original["output_durable"] and original["terminal_publication_confirmed"], "historical original terminal state differs")
    need(recovery["independent_successful_observation"]["new_native_execution_established"] is False, "new worker execution must not be asserted")
    diagnostics = read("postmerge-preserved-diagnostics.json")
    probe = diagnostics["controller_registry_probe"]
    failed = payload(retained_envelope(probe["status_observation"]))
    failure_output = payload(retained_envelope(probe["read_observation"]))
    need(failed["state"] == "failed" and failed["exit_code"] == 1 and "AssertionError" in failure_output["stderr"]["text"] and probe["records_read_before_failure"] == 0, "bounded probe failure must remain visible")

    result = {
        "schema": "hepta.hia.postmerge-readback-replay.v1",
        "status": "PASS_POSTMERGE_PUBLIC_INSTALL_AND_FORMAL_READBACK",
        "entry_commit": ENTRY, "release_lock_sha256": LOCK_SHA,
        "public_install_ci_run": 42552762057, "retained_online_replay_ci_run": 42552762051,
        "public_install_artifact_sha256": ZIP_SHA, "native_qualification_tests": 173,
        "formal_checker_status": verification["status"], "checker_sha256": CHECKER_SHA,
        "capture_sha256": verification["capture_sha256"], "manifest_artifact": verification["manifest_artifact"],
        "observed_installation": verification["observed_installation"],
        "initial_transport_timeout_preserved": True, "matching_original_operation": old["job_id"],
        "independent_successful_read_window_bytes": 8192,
        "new_native_worker_execution_established": False, "bounded_diagnostic_failure_preserved": True,
        "global_acceptance": "HOLD",
        "scope": "retained post-merge formal manifest identity matches the unchanged public source-CI lock after exact-main CI success",
        "does_not_establish": ["fresh endpoint observation by this replay", "original capture provenance without its retained tool observation", "loaded runtime executable or build provenance", "new native worker execution", "continuous endpoint availability or later state", "a deployment action", "whole-project six-gap acceptance"],
    }
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
