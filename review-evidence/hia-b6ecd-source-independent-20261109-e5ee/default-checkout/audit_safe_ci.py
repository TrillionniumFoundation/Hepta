"""Read original CI ZIP/JSON/Git bytes only; never import project code."""
import datetime
import hashlib
import json
import pathlib
import subprocess
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent
REPO = ROOT.parents[1] / "hepta-successor-integration-review"
SCOPES = {"subject", "property", "profile", "assumptions", "checker", "unproved_obligations"}
merge = json.loads((ROOT / "safe-prospective-metadata.json").read_text())
head = json.loads((ROOT / "safe-head-metadata.json").read_text())
run = json.loads((ROOT / "safe-run-metadata.json").read_text())
official = json.loads((ROOT / "safe-artifacts-metadata.json").read_text())["artifacts"]
tree = merge["tree"]["sha"]
assert run["status"] == "completed" and run["conclusion"] == "success"
assert run["head_sha"] == head["sha"] and head["sha"] in [x["sha"] for x in merge["parents"]]
assert tree == head["tree"]["sha"] == "4c51962e030e9ea39c6498224c99eb40fbdd2f35"
assert head["sha"] == "6ecd8023615a6e0b2dc269379fb059c656b38b6f"
cache = {}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source(path):
    if path not in cache:
        p = subprocess.run(["git", "show", tree + ":" + path], cwd=REPO, capture_output=True, check=True)
        cache[path] = {"sha256": sha(p.stdout), "bytes": len(p.stdout)}
    return cache[path]


def check_source(identity, short=False):
    result = []
    for path, expected in identity.items():
        actual_path = "hepta/" + path if short and "/" not in path else path
        actual = source(actual_path)
        assert actual["sha256"] == expected, actual_path
        result.append({"path": actual_path, **actual})
    return result


reviews = []
for suffix, artifact_id, logname in [("final", 13652870106, "safe-log_final.log"), ("v2", 13652591429, "safe-log_v2.log")]:
    a = next(x for x in official if x["id"] == artifact_id)
    archive = ROOT / ("safe-" + suffix + ".zip")
    raw = archive.read_bytes()
    assert len(raw) == a["size_in_bytes"] and "sha256:" + sha(raw) == a["digest"]
    log = (ROOT / logname).read_text()
    assert "+" + merge["sha"] + ":refs/remotes/pull/817/merge" in log
    assert "git log -1 --format=%H" in log and merge["sha"] in log
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        assert len(names) == len(set(names))
        manifest = json.loads(z.read("original-files.json"))
        assert set(manifest) == set(names) - {"original-files.json"}
        for path, pin in manifest.items():
            b = z.read(path)
            assert len(b) == pin["bytes"] and sha(b) == pin["sha256"], path
        q = json.loads(z.read("qualification.json"))
        assert q["git_head"] == merge["sha"] and q["source_unchanged"] is True and q["ok"] is True
        qualification_source = check_source(q["source_identity"])
        reports = []
        for kind in ["positive", "artifact_rechecks"]:
            for row in q[kind]:
                attempt = json.loads(z.read(row["report"]))
                assert row["ok"] is True and attempt["ok"] is True
                validation = attempt.get("validation", attempt.get("result", {}).get("validation"))
                assert validation["ok"] is True and SCOPES <= set(validation)
                assert validation["assumptions"] and validation["unproved_obligations"]
                identity = check_source(validation["source_identity"], short=True)
                checker = check_source(validation["checker"]["source_identity"], short=True)
                assert validation["checker"]["producer_reemission_used"] is False
                parent = pathlib.PurePosixPath(row["report"]).parent
                core = json.loads(z.read(str(parent / "core.hia.json")))
                canonical_core = json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
                assert sha(canonical_core) == validation["subject"]["core_sha256"]
                bindings = {}
                for field, extension in [("object_sha256", ".o"), ("final_image_sha256", ".so")]:
                    matches = [n for n, m in manifest.items() if pathlib.PurePosixPath(n).parent == parent and n.endswith(extension) and m["sha256"] == validation["subject"][field]]
                    assert matches, (row["report"], field)
                    bindings[field] = matches
                if kind == "artifact_rechecks":
                    assert attempt["compiler_invoked"] is False and attempt["linker_invoked"] is False
                    assert attempt["native_execution_observed"] is False and attempt["adopted"] is False
                reports.append({"kind": kind, "case": row["case"], "path": row["report"], "profile": validation["profile"], "scope_fields_present": sorted(SCOPES), "source_identity_entries_checked": len(identity), "checker_identity_entries_checked": len(checker), "core_canonical_sha256_matched": True, "artifact_subject_bindings": bindings, "unproved_obligations": validation["unproved_obligations"]})
        replays = q.get("query_replays", q.get("replay", []))
        negative_cases = {r["case"]: r["status"] for r in q.get("negative", [])}
        counterexample_replays = []
        for row in replays:
            expected_hash = row.get("query_sha256", row.get("sha256"))
            assert sha(z.read(row["query"])) == expected_hash
            result = json.loads(z.read(row["query"] + ".result.json"))
            assert result["query_sha256"] == expected_hash
            assert row["expected"] == row["result"] == result["result"]
            if result["expected"] != result["result"]:
                case = row["query"].split("/", 1)[0]
                assert negative_cases.get(case) == "rejected_with_sat_counterexample"
                assert result["expected"] == "unsat" and result["result"] == "sat"
                counterexample_replays.append({"case": case, "query": row["query"], "original_property_expected": result["expected"], "original_counterexample_result": result["result"], "replay_expected_and_observed": row["result"]})
        assert {r["case"] for r in counterexample_replays} == set(negative_cases)
        tests = q.get("tests")
        if tests:
            assert tests["count"] == len(tests["inventory"]) == len(tests["executed"])
            assert set(tests["inventory"]) == set(tests["executed"])
            assert not tests["errors"] and not tests["failures"] and not tests["skipped"]
        reviews.append({"artifact_id": artifact_id, "archive": archive.name, "bytes": len(raw), "sha256": sha(raw), "zip_members": len(names), "all_manifest_members_checked": len(manifest), "qualification_status": q["status"], "qualification_source": qualification_source, "positive_reports": len(q["positive"]), "independent_recheck_reports": len(q["artifact_rechecks"]), "negative_reports": len(q.get("negative", [])), "counterexample_replays": counterexample_replays, "retained_query_replay_records_checked": len(replays), "local_solver_replay_performed": False, "distinct_programs": q.get("distinct_programs"), "original_solver_obligations": q.get("original_solver_obligations"), "replayed_same_obligations": q.get("replayed_same_obligations"), "claims": q["claims"], "reports": reports, "reported_test_count": tests["count"] if tests else None})

diff = subprocess.run(["git", "diff", "--numstat", head["tree"]["sha"], tree], cwd=REPO, capture_output=True, text=True, check=True).stdout
assert diff.strip() == ""
audit = {"schema": "hepta.default-checkout.safe-core.readonly-review.v1", "reviewed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), "run_id": run["id"], "run_head_sha": head["sha"], "run_head_tree": head["tree"]["sha"], "actual_checkout_commit": merge["sha"], "actual_checkout_tree": tree, "actual_checkout_parents": [x["sha"] for x in merge["parents"]], "actual_checkout_source": "Both original job logs and both qualification.git_head fields", "checkout_tree_equals_head_tree": True, "checkout_diff_from_head_numstat": diff.strip(), "artifacts": reviews, "source_git_blobs": cache, "local_actions": "Original metadata, decoded logs, ZIP/JSON/hash reads and ordinary Git blob reads only", "compiler_solver_native_or_project_tests_executed": False, "qualification_transfers_to_other_commit_or_final_B": False, "scope": "Final B PR817 default-checkout provenance and finite Safe Core profiles only. These two successful jobs do not establish the entire B workflow cohort passed. No universal compiler, Core, hardware ISA, live activation or Agent adoption claim."}
(ROOT / "safe-review.json").write_text(json.dumps(audit, indent=2) + "\n")
print(json.dumps({"status": "PASS_READONLY_IDENTITY_AND_RECORD_CONSISTENCY", "actual_checkout_commit": merge["sha"], "actual_checkout_tree": tree, "artifacts": [{k: a[k] for k in ["artifact_id", "all_manifest_members_checked", "positive_reports", "independent_recheck_reports", "retained_query_replay_records_checked"]} for a in reviews], "distinct_git_source_paths_checked": len(cache)}, indent=2))
