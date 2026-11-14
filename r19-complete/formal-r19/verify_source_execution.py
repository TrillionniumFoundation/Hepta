"""Validate an actual complete R19 Source result and restore its exact source.

This script is independent of the product and does not run any product test.
It accepts a complete FAIL as a recorded execution outcome; it never turns an
execution failure into a PASS by successfully preserving the evidence.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import time
import traceback
import zipfile


ROOT = Path(__file__).resolve().parent
LOCAL = ROOT.parent / "v116-union-r19/source"
HARNESS = ROOT.parent / "v116-source-parser-r19-harness/formal-preparation-r1/harness"
OUT = ROOT / "source-readback-r1"


def unique(pairs):
    answer = {}
    for key, value in pairs:
        assert key not in answer, ("duplicate JSON key", key)
        answer[key] = value
    return answer


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)


def safe(name):
    assert type(name) is str and name and "\\" not in name and "\0" not in name
    p = PurePosixPath(name)
    assert not p.is_absolute() and str(p) == name and not {".", ".."} & set(p.parts)
    return p


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def check_pin(raw, expected):
    actual = pin(raw)
    assert actual["bytes"] == expected["bytes"] and actual["sha256"] == expected["sha256"]
    assert actual["git_blob"] == expected.get("git_blob", expected.get("blob"))
    return actual


def put(relative, raw, mode=0o644):
    p = safe(relative)
    target = OUT.joinpath(*p.parts)
    parent = OUT
    for part in p.parts[:-1]:
        parent = parent / part
        if parent.exists() or parent.is_symlink():
            assert parent.is_dir() and not parent.is_symlink()
        else:
            parent.mkdir()
    assert type(mode) is int and mode in (0o644, 0o755)
    assert not target.exists() and not target.is_symlink()
    target.open("xb").write(raw)
    target.chmod(mode)
    assert stat.S_IMODE(target.stat().st_mode) == mode


def write_json(name, value):
    put(name, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def tree(rows):
    direct, groups = [], {}
    for path, mode, oid in rows:
        name, sep, rest = path.partition("/")
        if sep:
            groups.setdefault(name, []).append((rest, mode, oid))
        else:
            direct.append((name, mode, oid, False))
    for name, children in groups.items():
        direct.append((name, "40000", tree(children), True))
    direct.sort(key=lambda row: row[0].encode() + (b"/" if row[3] else b""))
    raw = b"".join(mode.lstrip("0").encode() + b" " + name.encode() + b"\0" + bytes.fromhex(oid)
                   for name, mode, oid, _ in direct)
    return hashlib.sha1(b"tree " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def main():
    started = time.monotonic()
    config = parse((ROOT / "ARTIFACT-PINS.json").read_bytes())
    custody = parse((ROOT / "custody-stream-r1/REPORT.json").read_bytes())
    assert config["run"] == custody["run"] == 43544318748
    assert config["job"] == custody["job"] == 132291881222
    assert config["head"] == custody["head"] == "d2a88992381c2c7ab680b7c97bb7c8405c02c6c1"
    assert custody["status"] == "CUSTODY_PASS_EXECUTION_STATUS_RECORDED_SEPARATELY"
    original = ROOT / config["artifacts"]["combined-source"]["file"]
    assert not OUT.exists()
    OUT.mkdir()
    original_pin = custody["outer_artifacts"]["combined-source"]["original"]
    assert original.stat().st_size == original_pin["bytes"]
    with original.open("rb") as stream:
        assert hashlib.file_digest(stream, "sha256").hexdigest() == original_pin["sha256"]
    expected_raw = (HARNESS / "inputs/FORMAL-EXPECTED-IDS.json").read_bytes()
    expected = parse(expected_raw)
    plan_raw = (HARNESS / "inputs/MATERIALIZATION.json").read_bytes()
    plan = parse(plan_raw)
    with zipfile.ZipFile(original) as archive:
        raw = lambda name: archive.read("raw/" + str(safe(name)))
        read = lambda name: parse(raw(name))
        result = read("RESULT.json")
        manifest = parse(archive.read("EVIDENCE-MANIFEST.json"))
        assert result == manifest["result"]
        assert result["status"] in ("SOURCE_PASS", "SOURCE_FAIL") and not result["failures"]
        assert result["python"].startswith("3.14.4 ")
        assert result["product_tests_executed"] == 1411
        assert result["cold_qualifications"] == result["native_qualification_jobs_executed"] == 0
        for key in ("default_changed", "legacy_host_implementation_deleted", "product_ref_changed", "whole_native"):
            assert result[key] is False
        assert raw("harness/INPUTS.json") == plan_raw
        assert raw("harness/DRIVER.py") == (HARNESS / "tools/materialize_candidate_r16.py").read_bytes()
        for name in ("tools/run_source_gate.py", "inputs/ORIGINAL-SOURCE-IDS.json"):
            assert raw("harness/" + name) == (HARNESS / name).read_bytes()
        source_raw = raw("checks/SOURCE-TESTS.json")
        source = parse(source_raw)
        assert source == result["source_tests"] and source["complete"] is True
        assert type(source["expected"]) is int and type(source["tests_run"]) is int
        assert source["expected"] == source["tests_run"] == 1411
        ids = source["ordered_ids"]
        assert ids == expected["r19_expected_ordered_ids"]
        assert ids == source["actual_started_ids"] == source["actual_stopped_ids"]
        assert len(ids) == len(set(ids)) == 1411
        assert source["selectors"] == plan["source_registration"]["selectors"]
        assert len(source["selectors"]) == 239
        anomaly_keys = ("errors", "failures", "skipped", "expected_failures", "unexpected_successes",
                        "duplicate_ids", "missing_main_ids", "missing_a733_ids",
                        "missing_frozen_main_ids", "missing_frozen_a733_ids")
        source_pass = not any(source[key] for key in anomaly_keys)
        source_pass = source_pass and not any(source["loader_errors"].values())
        assert source["status"] == ("PASS" if source_pass else "FAIL")
        assert result["status"] == ("SOURCE_PASS" if source_pass else "SOURCE_FAIL")
        projection_counts = {
            "r18_expected_ordered_ids": 1374, "r17_expected_ordered_ids": 1363,
            "r16_expected_ordered_ids": 1357, "r15_expected_ordered_ids": 1356,
            "r14_expected_ordered_ids": 1353, "r13_expected_ordered_ids": 1352,
            "r12_expected_ordered_ids": 1342, "required_r11_ordered_projection": 1329,
            "original_r10_r2_ordered_ids": 1319,
        }
        for key, count in projection_counts.items():
            previous = expected[key]
            assert len(previous) == count
            previous_set = set(previous)
            assert [name for name in ids if name in previous_set] == previous
        events_raw = raw("checks/SOURCE-TESTS.events.jsonl")
        events = [parse(line) for line in events_raw.splitlines()]
        assert [(e["event"], e["id"]) for e in events] == [(event, name) for name in ids for event in ("start", "stop")]
        assert result["generation"]["generator_count"] == 139
        assert result["generation"]["real_generation_passes"] == 2
        assert result["generation"]["physical_paths_retired_in_development_tree"] == 55
        assert result["syntax"]["failures"] == 0 and type(result["syntax"]["checked"]) is int
        generations = {}
        for phase in ("generate", "reproduce"):
            found = {}
            for name in archive.namelist():
                if not name.startswith("raw/commands/") or not name.endswith(".json"):
                    continue
                match = re.search(r"-" + phase + r"-(\d+)-", name)
                if not match:
                    continue
                index = int(match.group(1))
                assert index not in found
                receipt = parse(archive.read(name))
                assert type(receipt["returncode"]) is int and receipt["returncode"] == 0
                assert receipt["timed_out"] is False
                for channel in ("stdout", "stderr"):
                    check_pin(raw(receipt[channel]["file"]), receipt[channel])
                found[index] = receipt["argv"]
            assert sorted(found) == list(range(139))
            generations[phase] = found
        assert generations["generate"] == generations["reproduce"]
        inventory = read("sources/candidate-final.json")
        leaves = {row["path"]: row for row in inventory["entries"] if row["type"] != "tree"}
        assert len(leaves) == inventory["files"] == 3175
        actual_tree = inventory["tree"]
        assert actual_tree == result["generation"]["tree"]
        assert tree([(name, row["mode"], row["oid"]) for name, row in leaves.items()]) == actual_tree
        before = read("checks/before-complete-source-tests-raw-worktree.json")
        after = read("checks/after-complete-source-tests-raw-worktree.json")
        assert not before["failures"] and not after["failures"]
        assert before["files"] == after["files"] and len(before["files"]) == 3175
        assert before["frozen_tree"] == after["frozen_tree"] == actual_tree
        for row in before["files"]:
            leaf = leaves[row["path"]]
            assert row["expected_mode"] == row["actual_mode"] == leaf["mode"]
            assert row["expected_blob"] == row["actual_blob"] == leaf["oid"]
        terminal = read("terminal-worktree/INDEX.json")
        assert len(terminal["files"]) == 3175
        restored, changes = {}, []
        for row in terminal["files"]:
            name = str(safe(row["path"]))
            assert name in leaves and name not in restored
            leaf = leaves[name]
            assert row["kind"] == "regular" and row["mode"] in (0o644, 0o755)
            assert leaf["mode"] == ("100755" if row["mode"] == 0o755 else "100644")
            assert row["blob"] == leaf["oid"]
            custody_row = row["content_custody"]
            content = raw(custody_row["file"]) if "file" in custody_row else (LOCAL / name).read_bytes()
            identity = check_pin(content, row)
            local = (LOCAL / name).read_bytes()
            if local != content:
                changes.append({"path": name, "prepared": pin(local), "actual314": identity})
            put("candidate-ci314/" + name, content, row["mode"])
            restored[name] = {**identity, "mode": row["mode"], "git_mode": leaf["mode"]}
        assert tree([(name, row["git_mode"], row["git_blob"]) for name, row in restored.items()]) == actual_tree
        assert result["syntax"]["checked"] == sum(name.endswith(".py") for name in leaves)
        write_json("CANDIDATE-MANIFEST.json", restored)
        write_json("PREPARED-VS-ACTUAL314-DIFF.json", changes)
        proof = {"schema": "hepta.r19-original-complete-source-control-readback.v1",
                 "status": "COMPLETE_SOURCE_EVIDENCE_VERIFIED", "source_outcome": source["status"],
                 "run": config["run"], "job": config["job"], "head": config["head"],
                 "actual_python": result["python"], "source_files": len(restored),
                 "source_tree": actual_tree, "source_expected": 1411, "source_tests_run": source["tests_run"],
                 "source_wall_seconds": source["wall_seconds"], "source_event_count": len(events),
                 "source_report": pin(source_raw), "source_events": pin(events_raw),
                 "complete_ordered_loaded_started_stopped_ids_equal": True,
                 "ordered_previous_projections": projection_counts,
                 "anomalies": {key: source[key] for key in anomaly_keys},
                 "loader_errors": source["loader_errors"],
                 "generators": 139, "complete_generation_passes": 2,
                 "syntax": result["syntax"], "source_before_after_bytes_and_modes_equal": True,
                 "source_complete_files_materialized": True,
                 "complete_raw_directory_materialized": False,
                 "prepared_vs_formal_differences": changes,
                 "only_three_known_generated_metadata_paths_differ": {row["path"] for row in changes} <= {
                     "docs/HIA_NATIVE_REWRITE_INVENTORY.json", "docs/HIA_SELFHOST_CORE_SUPPORT.json",
                     "hepta/hia_checker_identity.py"},
                 "bounded62_qualification": "SEPARATE_ARTIFACT_VERIFICATION_REQUIRED",
                 "current_source_cold_qualification": False, "whole_native": False,
                 "new_product_executions": 0, "seconds_for_evidence_only": time.monotonic() - started}
        write_json("REPORT.json", proof)
        print(json.dumps({key: proof[key] for key in ("status", "source_outcome", "source_files", "source_tree", "source_tests_run", "source_event_count", "seconds_for_evidence_only")}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        if OUT.is_dir() and not (OUT / "VERIFIER-FAILURE.txt").exists():
            put("VERIFIER-FAILURE.txt", traceback.format_exc().encode())
        raise
