"""Inspect original Linux CI metadata, log and receipt; execute no project code."""
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent
REPO = ROOT.parents[1] / "hepta-successor-integration-review"
run = json.loads((ROOT / "linux-run-metadata.json").read_text())
jobs = json.loads((ROOT / "linux-jobs-metadata.json").read_text())["jobs"]
artifacts = json.loads((ROOT / "linux-artifacts-metadata.json").read_text())["artifacts"]
merge = json.loads((ROOT / "safe-prospective-metadata.json").read_text())
head = json.loads((ROOT / "safe-head-metadata.json").read_text())
assert run["id"] == 42565815367 and run["head_sha"] == head["sha"]
assert run["status"] == "completed" and run["conclusion"] == "success" and run["run_attempt"] == 1
assert len(jobs) == 1 and jobs[0]["id"] == 128991967620 and jobs[0]["conclusion"] == "success"
assert len(artifacts) == 1 and artifacts[0]["id"] == 13652647208
assert merge["sha"] == "16add3df22d58fd5486541837cdaf73a21317c49"
assert merge["tree"]["sha"] == head["tree"]["sha"] == "4c51962e030e9ea39c6498224c99eb40fbdd2f35"
log = (ROOT / "linux-job.log").read_text()
assert "+" + merge["sha"] + ":refs/remotes/pull/817/merge" in log
assert "git log -1 --format=%H" in log and "HEAD is now at 16add3d" in log
raw = (ROOT / "linux.zip").read_bytes()
assert len(raw) == artifacts[0]["size_in_bytes"]
assert "sha256:" + hashlib.sha256(raw).hexdigest() == artifacts[0]["digest"]
with zipfile.ZipFile(ROOT / "linux.zip") as z:
    assert z.namelist() == ["hia-linux-regressions.json"]
    receipt_raw = z.read("hia-linux-regressions.json")
    receipt = json.loads(receipt_raw)
assert receipt["schema"] == "hepta.hia.linux-regression-tests.v1" and receipt["status"] == "PASS"
assert receipt["source_before"] == receipt["source_after"] == {"commit": merge["sha"], "tree": merge["tree"]["sha"]}
assert receipt["source_status_after"] == ""
assert receipt["tests_planned"] == receipt["tests_executed"] == 83
for key in ["planned_ids", "started_ids", "finished_ids"]:
    assert len(receipt[key]) == len(set(receipt[key])) == 83
assert set(receipt["planned_ids"]) == set(receipt["started_ids"]) == set(receipt["finished_ids"])
assert hashlib.sha256(json.dumps(receipt["planned_ids"], separators=(",", ":")).encode()).hexdigest() == receipt["planned_ids_sha256"]
for key in ["errors", "failures", "expected_failures", "unexpected_successes", "skipped"]:
    assert receipt[key] == []
assert all(value is False for value in receipt["claims"].values())
logged_ids = re.findall(r"\((tests\.[^)]+)\) \.\.\. ok\r?$", log, re.M)
assert len(logged_ids) == len(set(logged_ids)) == 83 and set(logged_ids) == set(receipt["finished_ids"])
sources = []
for path in [run["path"], "tools/qualify_hia_linux_tests.py", *[name.replace(".", "/") + ".py" for name in receipt["modules"]]]:
    data = subprocess.run(["git", "show", merge["tree"]["sha"] + ":" + path], cwd=REPO, check=True, capture_output=True).stdout
    sources.append({"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "git_blob_sha1": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()})
(ROOT / "linux-receipt.json").write_bytes(receipt_raw)
audit = {"schema": "hepta.default-checkout.linux.readonly-review.v1", "reviewed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), "run_id": run["id"], "job_id": jobs[0]["id"], "run_head_sha": head["sha"], "actual_checkout_commit": merge["sha"], "actual_checkout_tree": merge["tree"]["sha"], "actual_checkout_parents": [x["sha"] for x in merge["parents"]], "actual_checkout_tree_equals_head_tree": True, "actual_checkout_is_not_head_commit": True, "artifact_id": artifacts[0]["id"], "artifact_bytes": len(raw), "artifact_sha256": hashlib.sha256(raw).hexdigest(), "official_digest_matches": True, "receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(), "source_before": receipt["source_before"], "source_after": receipt["source_after"], "source_status_after": receipt["source_status_after"], "test_count": 83, "planned_started_finished_id_sets_equal_and_unique": True, "original_job_log_success_ids_match_receipt": True, "failure_error_skip_expected_failure_unexpected_success_counts": {k: 0 for k in ["errors", "failures", "skipped", "expected_failures", "unexpected_successes"]}, "source_git_blobs": sources, "scope": receipt["scope"], "claims": receipt["claims"], "local_project_compiler_solver_native_or_tests_executed": False, "entire_final_B_workflow_cohort_qualified_by_this_review": False, "later_commit_qualification_transferred": False}
(ROOT / "linux-review.json").write_text(json.dumps(audit, indent=2) + "\n")
print(json.dumps({"status": "PASS_READONLY_LINUX_SOURCE_AND_RECEIPT_CONSISTENCY", "actual_checkout_commit": merge["sha"], "actual_checkout_tree": merge["tree"]["sha"], "artifact_id": artifacts[0]["id"], "logged_and_receipted_success_test_ids": len(logged_ids)}, indent=2))
