"""Prepare the exact R20 product tree and delta custody; never publish or run it.

The complete actual Source manifest was independently verified from the original
formal artifact.  Unchanged objects are reused from the earlier complete Native
checkout tree; only changed/new bytes are captured here.  No product is imported.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import time
import zipfile


ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent
ORIGINAL = BASE / "v120-source-parser-r20-original"
PREPARED = BASE / "v120-union-r20/source"
ACTUAL = ORIGINAL / "source-manifest-readback-r1"
OLD_TREE = BASE / "v116-source-parser-r19-harness/git-reuse-readonly-r1/LATEST-NATIVE-TREE.body.json"
OLD_COMMIT = ORIGINAL / "NATIVE-BASELINE-COMMIT.GET.json"
BASELINE_COMMIT = "abeef212e34023534d91f8f952280e2a8d0cbde6"
BASELINE_TREE = "f2bc61c11104136d3f56e3c4aefa00a4dada910b"
TARGET_TREE = "84df4b42f1e20fd7d0c7229e658cf3b458984ffb"
PARENTS = ["f33d8da316de8fdf27b504371f1a5310997ff548", "a733926a2786a3d4a37304bd2d18ebb2eac57ac9"]
BRANCH = "codex/hia-combined-native-v120-r20-20261114-dda7"
REPOSITORY = "TrillionniumFoundation/Hepta"
DERIVED = {
    "docs/HIA_NATIVE_REWRITE_INVENTORY.json",
    "docs/HIA_SELFHOST_CORE_SUPPORT.json",
    "hepta/hia_checker_identity.py",
}


def unique(pairs):
    answer = {}
    for key, value in pairs:
        assert key not in answer, ("duplicate JSON key", key)
        answer[key] = value
    return answer


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def checked(raw, expected):
    actual = pin(raw)
    assert actual == {key: expected[key] for key in actual}, (actual, expected)
    return actual


def safe(name):
    assert type(name) is str and name and "\\" not in name and "\0" not in name
    p = PurePosixPath(name)
    assert not p.is_absolute() and str(p) == name and not {".", ".."} & set(p.parts)
    return p


def read_actual(name, expected):
    safe(name)
    # The exact three-path routing is deliberate, never an existence fallback.
    path = ACTUAL / "changed-source" / name if name in DERIVED else PREPARED / name
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and not path.is_symlink()
    raw = path.read_bytes()
    after = path.lstat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mode, before.st_mtime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mode, after.st_mtime_ns)
    assert stat.S_IMODE(before.st_mode) == expected["mode"]
    checked(raw, expected)
    return raw, str(path)


def put(name, raw, mode=0o644):
    p = safe(name)
    parent = ROOT
    for part in p.parts[:-1]:
        parent /= part
        if parent.exists() or parent.is_symlink():
            assert parent.is_dir() and not parent.is_symlink()
        else:
            parent.mkdir()
    path = ROOT.joinpath(*p.parts)
    assert not path.exists() and not path.is_symlink(), ("exclusive output", str(path))
    with path.open("xb") as f:
        assert f.write(raw) == len(raw)
    path.chmod(mode)
    assert path.read_bytes() == raw and stat.S_IMODE(path.stat().st_mode) == mode
    return pin(raw)


def write_json(name, value):
    return put(name, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def git_tree(rows):
    direct, groups = {}, {}
    for path, mode, oid in rows:
        safe(path)
        name, sep, rest = path.partition("/")
        assert mode in ("100644", "100755") and re.fullmatch(r"[0-9a-f]{40}", oid)
        if sep:
            assert name not in direct
            groups.setdefault(name, []).append((rest, mode, oid))
        else:
            assert name not in direct and name not in groups
            direct[name] = (mode, oid, False)
    for name, children in groups.items():
        direct[name] = ("40000", git_tree(children), True)
    raw = b"".join(mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(oid)
                   for name, (mode, oid, _) in sorted(
                       direct.items(), key=lambda x: x[0].encode() + (b"/" if x[1][2] else b"")))
    return hashlib.sha1(b"tree " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def main():
    started = time.monotonic()
    assert not (ROOT / "INTENT.json").exists(), "do not replay completed or unknown preparation"
    source_raw = (ACTUAL / "CANDIDATE-MANIFEST.json").read_bytes()
    assert pin(source_raw)["git_blob"] == "9094a23b34d332dd115c79371b9400c3a34573bc"
    source = parse(source_raw)
    source_proof_raw = (ACTUAL / "REPORT.json").read_bytes()
    assert pin(source_proof_raw)["git_blob"] == "4577cef4d665051ccb5d52fc8ad7dc375d1b2ccb"
    proof = parse(source_proof_raw)
    assert proof["source_tree"] == TARGET_TREE and proof["source_tests_run"] == 1421
    assert proof["source_outcome"] == "PASS" and proof["all_source_bytes_individually_verified"]
    bounded_raw = (ORIGINAL / "bounded-manifest-readback-r1/REPORT.json").read_bytes()
    assert pin(bounded_raw)["git_blob"] == "30323ffc3ce49bdc6e0b4b490d3ab3a377be81db"
    custody_raw = (ORIGINAL / "custody-stream-r1/REPORT.json").read_bytes()
    assert pin(custody_raw)["git_blob"] == "ce599bb386537f08bf0255b203814ee816c8b644"
    custody = parse(custody_raw)
    assert custody["status"] == "CUSTODY_PASS_EXECUTION_STATUS_RECORDED_SEPARATELY"
    baseline_raw = OLD_TREE.read_bytes()
    assert hashlib.sha256(baseline_raw).hexdigest() == "2b505132a57508b3c9ddc1030d0bf1c64286765c61e42e64271e5925726c0222"
    baseline_tree = parse(baseline_raw)
    assert baseline_tree["sha"] == BASELINE_TREE and baseline_tree["truncated"] is False
    baseline = {row["path"]: row for row in baseline_tree["tree"] if row["type"] == "blob"}
    assert len(baseline) == 3055 and len(source) == 3177
    assert git_tree((p, r["mode"], r["sha"]) for p, r in baseline.items()) == BASELINE_TREE
    assert git_tree((p, r["git_mode"], r["git_blob"]) for p, r in source.items()) == TARGET_TREE
    old_response = parse(OLD_COMMIT.read_bytes())
    old_commit = parse(old_response["structuredContent"]["content"])
    assert old_commit["sha"] == BASELINE_COMMIT and old_commit["tree"]["sha"] == BASELINE_TREE
    assert [p["sha"] for p in old_commit["parents"]] == PARENTS
    assert set(baseline) <= set(source)
    delta, unchanged = {}, []
    for name, row in sorted(source.items()):
        assert row["mode"] in (0o644, 0o755)
        assert row["git_mode"] == ("100755" if row["mode"] == 0o755 else "100644")
        if name in baseline and (row["git_blob"], row["git_mode"]) == (
                baseline[name]["sha"], baseline[name]["mode"]):
            assert row["bytes"] == baseline[name]["size"]
            unchanged.append(name)
        else:
            delta[name] = row
    assert len(delta) == 148 and len(unchanged) == 3029
    assert sum(row["bytes"] for row in delta.values()) == 10362563
    free_before = shutil.disk_usage(ROOT).free
    assert free_before >= 64 * 1024 * 1024
    intent = {"schema": "hia.r20.native-complete-tree-preparation-intent.v1",
              "operation": "LOCAL_METADATA_AND_CHANGED_BYTES_ONLY",
              "target_tree": TARGET_TREE, "source_files": 3177,
              "baseline_commit": BASELINE_COMMIT, "baseline_tree": BASELINE_TREE,
              "changed_files": len(delta), "changed_bytes": sum(r["bytes"] for r in delta.values()),
              "source_manifest": pin(source_raw), "source_proof": pin(source_proof_raw),
              "bounded_proof": pin(bounded_raw), "custody_proof": pin(custody_raw),
              "free_bytes_before": free_before, "product_executions": 0, "Git_writes": 0,
              "complete_source_copy": False, "publication_authorized": False}
    write_json("INTENT.json", intent)
    blob_receipts, changes = [], []
    zip_path = ORIGINAL / "combined-source.zip"
    expected_zip = custody["outer_artifacts"]["combined-source"]["original"]
    assert zip_path.stat().st_size == expected_zip["bytes"]
    zip_before = zip_path.stat()
    with zipfile.ZipFile(zip_path) as archive:
        uploaded_raw = archive.read("raw/publication/UPLOADED-BLOBS.json")
        uploaded = parse(uploaded_raw)
        assert len(uploaded) == 523
        for name, row in delta.items():
            raw, provider = read_actual(name, row)
            raw.decode("utf-8", "strict")
            receipt_name = "raw/upload-readbacks/" + row["git_blob"] + ".json"
            receipt_raw = archive.read(receipt_name)
            receipt = parse(receipt_raw)
            expected_receipt = {"blob": row["git_blob"], "bytes": row["bytes"],
                                "sha256": row["sha256"], "full_readback_equal": True}
            assert uploaded[row["git_blob"]] == receipt == expected_receipt
            put("changed-source/" + name, raw, row["mode"])
            before = baseline.get(name)
            changes.append({"path": name, "kind": "modified" if before else "added",
                            "before": {"git_blob": before["sha"], "bytes": before["size"],
                                       "git_mode": before["mode"]} if before else None,
                            "after": row, "captured_from": provider})
            blob_receipts.append({"path": name, "blob": row["git_blob"],
                                  "original_member": receipt_name, "original_member_pin": pin(receipt_raw),
                                  "producer_full_readback": receipt,
                                  "independent_current_connector_full_GET": False})
    zip_after = zip_path.stat()
    assert (zip_before.st_ino, zip_before.st_size, zip_before.st_mtime_ns) == (
        zip_after.st_ino, zip_after.st_size, zip_after.st_mtime_ns)
    elements = [{"path": name, "mode": row["git_mode"], "type": "blob", "sha": row["git_blob"]}
                for name, row in sorted(source.items())]
    elements_pin = write_json("COMPLETE-TREE-ELEMENTS.json", elements)
    changes_pin = write_json("ACTUAL-PATH-DELTA.json", changes)
    receipts_pin = write_json("DELTA-PRODUCER-READBACKS.json", blob_receipts)
    workflow, _ = read_actual(".github/workflows/hia-core.yml", source[".github/workflows/hia-core.yml"])
    assert workflow.startswith(b"name: HIA Core-only\non: [push, pull_request, workflow_dispatch]\n")
    assert workflow.count(b"\n  native:\n") == 1
    native = workflow.split(b"\n  native:\n", 1)[1]
    source_job = workflow.split(b"\n  source:\n", 1)[1].split(b"\n  native:\n", 1)[0]
    assert b"\n    needs:" not in native and b"\n    needs:" not in source_job
    assert b"permissions:" not in workflow and b"timeout-minutes:" not in native
    steps = [s for s in re.split(rb"(?m)(?=^      - )", native) if s.startswith(b"      - ")]
    assert len(steps) == 123
    assert steps[0] == b"      - uses: actions/checkout@v4\n"
    assert b"python-version: '3.14.4'" in steps[1]
    assert steps[5].strip() == b'- run: python -B tools/replay_hia_selfhost_cold.py --output "$RUNNER_TEMP/hia-cold.json"'
    assert b"Native verified report bundle with matching cold" in steps[118]
    assert b"Native Linux file roundtrip with matching cold" in steps[119]
    assert b"if: always()" in steps[120] and b"if: always()" in steps[121] and b"if: always()" in steps[122]
    for path in (b"hia-cli-verified-report-matching-cold/", b"hia-linux-file-roundtrip-matching-cold/",
                 b"hia-linux-process-matching-cold/", b"hia-rust-caller-inputs.sha256"):
        assert path in steps[120]
    old_zip = BASE / "v116-source-parser-r19-original/combined-source.zip"
    with zipfile.ZipFile(old_zip) as archive:
        index = parse(archive.read("raw/terminal-worktree/INDEX.json"))
        old_row = next(r for r in index["files"] if r["path"] == ".github/workflows/hia-core.yml")
        old_member = "raw/" + old_row["content_custody"]["file"]
        old_workflow = archive.read(old_member)
        assert pin(old_workflow) == {"bytes": old_row["bytes"], "sha256": old_row["sha256"], "git_blob": old_row["blob"]}
        assert old_workflow.split(b"\n  native:\n", 1)[1] == native
    native_pin = put("NATIVE-123-FRAGMENT.yml", b"  native:\n" + native)
    step_map = [{"ordinal": i, "first_line": s.splitlines()[0].decode(), "bytes": len(s),
                 "sha256": hashlib.sha256(s).hexdigest()} for i, s in enumerate(steps, 1)]
    step_pin = write_json("NATIVE-123-STEPS.json", step_map)
    other_workflows = []
    for name in ("hia-candidate-bindings.yml", "hia-compiler-extension.yml", "hia-ndu-feedback.yml"):
        path = ".github/workflows/" + name
        raw, _ = read_actual(path, source[path])
        if name == "hia-ndu-feedback.yml":
            assert b"  push:" not in raw
            push = False
        else:
            assert b"branches: ['codex/hia-three-loop-*']" in raw
            assert not BRANCH.startswith("codex/hia-three-loop-")
            push = False
        other_workflows.append({"path": path, "pin": pin(raw), "proposed_branch_push_matches": push})
    workflow_report = {
        "workflow": {"path": ".github/workflows/hia-core.yml", **pin(workflow)},
        "source_and_native_jobs_independent": True, "event": "push",
        "branch_filters": None, "path_filters": None, "explicit_checkout_ref": None,
        "checkout_identity": "New product commit equals event GITHUB_SHA in both independent jobs.",
        "Python": "3.14.4", "Native_steps": 123,
        "complete_R19_native_fragment_exact": True,
        "R19_comparison": {"archive": str(old_zip), "member": old_member, "workflow": pin(old_workflow)},
        "native_fragment": native_pin, "ordered_steps": step_pin,
        "report_step": 119, "roundtrip_step": 120, "always_upload_steps": [121, 122, 123],
        "missing_matching_cold_input": {
            "producer_step": 6, "producer_command": steps[5].decode().strip(),
            "report": "$RUNNER_TEMP/hia-cold.json", "raw": "$RUNNER_TEMP/hia-cold.cold/",
            "required": "Actual current-source authority, B1/B2/B3, receipts and unchanged original admission guards.",
            "currently_available": False,
            "Source_and_bounded62_are_not_a_substitute": True},
        "new_report_command": steps[118].decode(), "new_roundtrip_command": steps[119].decode(),
        "all_step_bytes_conditions_budgets_unchanged": True,
        "normal_failure_behavior": "A failing Native gate keeps failure and skips later normal steps; all three original always uploads remain.",
        "workflow_permissions_and_job_timeout": "No edits or new values; exact existing workflow governs.",
        "other_workflows": other_workflows,
        "no_new_harness_or_rewritten_business_steps": True,
    }
    workflow_pin = write_json("WORKFLOW-AND-TRIGGER.json", workflow_report)
    commit_message = (
        "HIA: run exact R20 source candidate through complete Native qualification\n\n"
        "Formal CPython 3.14.4 Source: 1421/1421 PASS, run 43553551892.\n"
        "Original bounded 10+43+9 controls: 62/62 PASS with complete original evidence.\n"
        "All 3177 source leaves, bytes and modes verified; exact tree 84df4b42f1e20fd7d0c7229e658cf3b458984ffb.\n"
        "Preserve both fixed original parents and every existing Native step, condition and budget.\n"
        "Matching-current-source cold and full Native remain pending; whole_native=false."
    )
    plan = {
        "schema": "hia.r20.complete-native-product-publication-plan.v1",
        "status": "PREPARED_FOR_ROOT_REVIEW_NO_PRODUCT_PUBLICATION",
        "repository": REPOSITORY, "branch": BRANCH,
        "target_tree": TARGET_TREE, "files": 3177,
        "source_bytes": sum(r["bytes"] for r in source.values()),
        "baseline_commit": BASELINE_COMMIT, "baseline_tree": BASELINE_TREE,
        "ordered_parents": PARENTS,
        "parents_scope": "Proposed same ordered fixed original parents as the previous complete Native product candidate; no HEAD chase.",
        "complete_tree_elements": elements_pin, "actual_path_delta": changes_pin,
        "producer_readbacks": receipts_pin, "workflow_and_trigger": workflow_pin,
        "source_manifest": pin(source_raw), "formal_source_proof": pin(source_proof_raw),
        "bounded62_proof": pin(bounded_raw), "complete_custody_proof": pin(custody_raw),
        "existing_objects": {
            "unchanged_paths_reused": 3029, "changed_added_paths": 148,
            "delta_unique_blobs": 148, "delta_bytes": 10362563,
            "all_delta_blobs_have_actual_formal_producer_full_readback": True,
            "new_source_blob_POSTs_needed": 0,
            "fresh_independent_delta_connector_full_GET_count": 0,
            "before_commit": "Verify complete tree object and all 3177 exact path/mode/SHA entries; any unknown object is GET-reconciled, not blindly POSTed."},
        "create_tree_request": {"repository_full_name": REPOSITORY,
            "base_tree_sha": None, "tree_elements_file": str(ROOT / "COMPLETE-TREE-ELEMENTS.json")},
        "create_commit_request": {"repository_full_name": REPOSITORY,
            "parent_sha": PARENTS[0], "additional_parent_shas": PARENTS[1:],
            "tree_sha": TARGET_TREE, "message": commit_message},
        "ref_request_after_approved_commit_readback": {
            "repository_full_name": REPOSITORY, "branch_name": BRANCH,
            "sha": "EXACT_NEW_COMMIT_FROM_ACK_AND_FULL_GET"},
        "required_publication_order": [
            "Root reviews this exact full tree, parents, original workflow and trigger intent.",
            "GET the exact proposed branch; do not mutate an existing unexpected ref.",
            "Create or read back complete tree 84df; recursive full GET must be untruncated and equal all 3177 leaves and all computed directory objects.",
            "Create commit with only the approved tree/message/ordered parents; full GET must match.",
            "Reconfirm unique branch absence and create it exactly once at the verified commit; full GET exact ref.",
            "Observe the resulting push run at that exact head; do not add workflow_dispatch or duplicate the run.",
            "Preserve every API error, actual failure and skipped step; UNKNOWN writes are reconciled with GET before any next action.",
            "At terminal, collect complete Source/Native logs and all actual artifacts, verifying whole bytes/modes/CRC without transferring prior qualification."],
        "current_source_cold_qualification": False, "whole_native": False,
        "product_executions": 0, "Git_writes": 0, "ref_writes_authorized": False,
        "main_PR_audit_refs": "UNCHANGED",
    }
    plan_pin = write_json("PUBLICATION-PLAN.json", plan)
    result = {"schema": "hia.r20.native-complete-tree-preparation-result.v1", "status": "PASS_PREPARATION_ONLY",
              "actual_target_tree": TARGET_TREE, "complete_files": 3177,
              "complete_bytes": sum(r["bytes"] for r in source.values()),
              "baseline_files": len(baseline), "unchanged": len(unchanged),
              "added": sum(r["kind"] == "added" for r in changes),
              "modified": sum(r["kind"] == "modified" for r in changes), "deleted": 0,
              "changed_bytes_captured": sum(r["bytes"] for r in delta.values()),
              "all_148_delta_UTF8": True, "all_148_formal_producer_full_readback_receipts_exact": True,
              "independent_current_connector_delta_readback": 0,
              "no_second_complete_source_copy": True, "originals_deleted": False,
              "publication_plan": plan_pin, "files_generated": {
                  "COMPLETE-TREE-ELEMENTS.json": elements_pin, "ACTUAL-PATH-DELTA.json": changes_pin,
                  "DELTA-PRODUCER-READBACKS.json": receipts_pin, "NATIVE-123-FRAGMENT.yml": native_pin,
                  "NATIVE-123-STEPS.json": step_pin, "WORKFLOW-AND-TRIGGER.json": workflow_pin},
              "free_bytes_before": free_before, "free_bytes_after": shutil.disk_usage(ROOT).free,
              "seconds_for_evidence_preparation": time.monotonic() - started,
              "product_executions": 0, "Git_writes": 0, "ref_writes": 0}
    write_json("REPORT.json", result)
    print(json.dumps({k: result[k] for k in ("status", "actual_target_tree", "complete_files", "changed_bytes_captured", "added", "modified", "free_bytes_after")}))


if __name__ == "__main__":
    main()
