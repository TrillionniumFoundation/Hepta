#!/usr/bin/env python3
"""Read the one frozen iteration-33 hosted artifact; execute no archived code."""
from __future__ import annotations
import argparse
import ast
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import warnings
import zipfile

import readback_common as common

REPO = "TrillionniumFoundation/Hepta"
SOURCE = "6a029bf2791c090da295f325d29a4d239e8e8817"
TREE = "defe21c7c92452f2e452e82625cafe4bf9242da7"
RUN = 41771431668
JOB = 126381779928
PREFIX = "qualification/hcsn-iteration33-artifact-readback-20261104"
WORKFLOW = ".github/workflows/hepta-hcsn-iteration33-readback.yml"
ROOT = Path(__file__).resolve().parents[2]
DATA = "hcsn-iteration33-current/"
NAMES = {
    "receipt.json", "current-markov-defective-raw.json",
    "source-before.json", "source-after.json", "strict-gate.json", "test-inventory.json",
    "original-four-modules.stdout", "original-four-modules.stderr",
    "original-evidence.stdout", "original-evidence.stderr",
    "original-empty-bundle-gate.stdout", "original-empty-bundle-gate.stderr",
}
MEMBERS = {DATA + name for name in NAMES} | {"hcsn-iteration33-install.json"}
MODULES = (
    "research.hcsn.test_p2_markov_defective_firsthit",
    "research.hcsn.test_p2_defective_first_hit_clock",
    "research.hcsn.test_p2_first_hit_renewal_falsification",
    "research.hcsn.test_p2_physical_hazard_clock",
)
require, parse, fp = common.require, common.parse_json, common.fingerprint


def git_at(root, *args):
    result = subprocess.run(["git", "--no-replace-objects", "-C", str(root), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    require(result.returncode == 0, "GIT_READ")
    return result.stdout


def bind_reader():
    head = git_at(ROOT, "rev-parse", "HEAD").decode().strip()
    require(head == os.environ.get("GITHUB_SHA"), "READER_SOURCE")
    paths = [PREFIX + "/" + name for name in ("readback.py", "readback_common.py", "inputs.json")] + [WORKFLOW]
    records = []
    for path in paths:
        file = ROOT / path
        require(stat.S_ISREG(file.lstat().st_mode), "READER_REGULAR")
        raw = file.read_bytes()
        require(raw == git_at(ROOT, "show", "HEAD:" + path), "READER_BYTES")
        records.append({"path": path, **fp(raw)})
    require(records[1]["git_blob_sha"] == "d118ccd94f963b402d1adaa362486e1b32c4e78f",
            "SHARED_READER_CHANGED")
    require(not git_at(ROOT, "diff", "--name-only", "HEAD", "--"), "READER_DIRTY")
    return {"commit": head, "tree": git_at(ROOT, "rev-parse", "HEAD^{tree}").decode().strip(),
            "files": records}


def inspect_zip(raw):
    require(len(raw) <= 128 * 1024, "COMPRESSED_CAP")
    data, budget = {}, 1024 * 1024
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        require(len(infos) == len(MEMBERS) and {i.filename for i in infos} == MEMBERS,
                "EXACT_ARTIFACT_MEMBERS")
        require(sum(i.file_size for i in infos) <= budget, "DECLARED_DECODED_CAP")
        for item in infos:
            require(not item.is_dir() and not (item.flag_bits & 1), "REGULAR_MEMBER")
            require(stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG), "MEMBER_TYPE")
            require(item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "MEMBER_COMPRESSION")
            require(0 <= item.file_size <= 512 * 1024, "MEMBER_CAP")
            with archive.open(item) as stream:
                value = stream.read(min(budget, 512 * 1024) + 1)
            budget -= len(value)
            require(budget >= 0 and len(value) == item.file_size, "RETURNED_DECODED_CAP")
            data[item.filename] = value
    return data, budget


def self_test():
    checks = []
    def pack(extra=None, symlink=False, duplicate=False):
        buf = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for index, name in enumerate(sorted(MEMBERS)):
                    if symlink and index == 0:
                        info = zipfile.ZipInfo(name)
                        info.external_attr = (stat.S_IFLNK | 0o777) << 16
                        archive.writestr(info, b"x")
                    else:
                        archive.writestr(name, b"{}")
                if extra:
                    archive.writestr(extra, b"x")
                if duplicate:
                    archive.writestr(sorted(MEMBERS)[0], b"{}")
        return buf.getvalue()
    require(len(inspect_zip(pack())[0]) == 13, "POSITIVE_ZIP_CONTROL")
    checks.append("exact 13 regular members accepted")
    for label, raw, code in [
        ("extra member refused", pack(extra="extra.txt"), "EXACT_ARTIFACT_MEMBERS"),
        ("traversal member refused", pack(extra="../escape"), "EXACT_ARTIFACT_MEMBERS"),
        ("duplicate member refused", pack(duplicate=True), "EXACT_ARTIFACT_MEMBERS"),
        ("symlink member refused", pack(symlink=True), "MEMBER_TYPE"),
    ]:
        try:
            inspect_zip(raw)
        except common.Rejected as error:
            require(str(error) == code, "CONTROL_REJECTION")
        else:
            raise common.Rejected("CONTROL_FALSE_GREEN")
        checks.append(label)
    print("HCSN_ADDITIONAL_READBACK_CONTROLS=" + json.dumps(
        {"passed": len(checks), "failed": 0, "synthetic_only": True, "checks": checks}, sort_keys=True))


def source_binding(source, before_raw, after_raw):
    require(before_raw == after_raw, "BEFORE_AFTER_SOURCE")
    require(git_at(source, "rev-parse", "HEAD").decode().strip() == SOURCE
            and git_at(source, "rev-parse", "HEAD^{tree}").decode().strip() == TREE,
            "ORIGINAL_CHECKOUT")
    before = parse(before_raw)
    listing = git_at(source, "ls-tree", "-rz", "--full-tree", SOURCE, "--",
                     "research/hcsn", "qualification/hcsn-iteration33-current-20261104",
                     ".github/workflows/hepta-hcsn-iteration33-current.yml")
    rows, bytes_checked = {}, 0
    for record in listing.split(b"\0"):
        if not record:
            continue
        meta, name = record.split(b"\t", 1)
        mode, kind, oid = meta.decode("ascii").split()
        path = name.decode("utf-8")
        require(mode in {"100644", "100755"} and kind == "blob", "ORIGINAL_SOURCE_TYPE")
        raw = git_at(source, "cat-file", "blob", oid)
        bytes_checked += len(raw)
        require(bytes_checked <= 4 * 1024 * 1024, "ORIGINAL_SOURCE_BUDGET")
        require(fp(raw)["git_blob_sha"] == oid, "ORIGINAL_SOURCE_GIT_HASH")
        rows[path] = {**fp(raw), "mode": mode}
    require(rows == before, "COMPLETE_SOURCE_SNAPSHOT")
    return {"files": len(rows), "bytes": bytes_checked, "manifest": fp(before_raw),
            "all_snapshot_paths_exact_git_bytes": True}, rows


def numeric_differences(left, right, path=""):
    if type(left) is dict and type(right) is dict:
        require(set(left) == set(right), "NUMERIC_COMPARISON_KEYS")
        return [row for key in sorted(left) for row in numeric_differences(left[key], right[key], path + "/" + key)]
    if type(left) is list and type(right) is list:
        require(len(left) == len(right), "NUMERIC_COMPARISON_LENGTH")
        return [row for index, (a, b) in enumerate(zip(left, right)) for row in numeric_differences(a, b, path + "/" + str(index))]
    if left == right:
        return []
    require(type(left) in (int, float) and type(right) in (int, float), "NONNUMERIC_SCENARIO_DIFFERENCE")
    return [{"path": path, "historical": left, "current": right, "absolute_difference": abs(left - right)}]


def main():
    require(__debug__, "OPTIMIZED_PYTHON")
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    require(args.source is not None and args.out is not None, "ARGUMENTS")
    reader_before = bind_reader()
    spec = parse((Path(__file__).parent / "inputs.json").read_bytes())
    require(spec["artifact_id"] == 13295306776 and spec["source"] == SOURCE
            and spec["run_id"] == RUN and spec["job_id"] == JOB, "FROZEN_INPUT")
    token = os.environ["GH_TOKEN"]
    base = "/repos/" + REPO
    artifact = common.api_json(base + "/actions/artifacts/" + str(spec["artifact_id"]), token)
    require(artifact["id"] == spec["artifact_id"] and artifact["name"] == spec["artifact_name"]
            and artifact["size_in_bytes"] == spec["bytes"] and artifact["expired"] is False
            and artifact["digest"] == "sha256:" + spec["sha256"]
            and artifact["workflow_run"]["id"] == RUN
            and artifact["workflow_run"]["head_sha"] == SOURCE, "ARTIFACT_METADATA")
    run = common.api_json(base + "/actions/runs/" + str(RUN), token)
    require(run["head_sha"] == SOURCE and run["run_attempt"] == 1 and run["conclusion"] == "success"
            and run["event"] == "push"
            and run["path"] == ".github/workflows/hepta-hcsn-iteration33-current.yml"
            and run["repository"]["id"] == common.REPO_ID, "ORIGINAL_RUN")
    jobs = common.api_json(base + "/actions/runs/" + str(RUN) + "/attempts/1/jobs?per_page=100", token)
    require(jobs["total_count"] == len(jobs["jobs"]) == 1, "ORIGINAL_JOB_SET")
    job = jobs["jobs"][0]
    require(job["id"] == JOB and job["name"] == "current-source" and job["conclusion"] == "success",
            "ORIGINAL_JOB")
    for name in ("Source and count reader rejection controls", "Run the unchanged research reproduction commands"):
        selected = [s for s in job["steps"] if s["name"] == name]
        require(len(selected) == 1 and selected[0]["conclusion"] == "success", "ORIGINAL_STEP")
    raw = common.download(spec, token, {"compressed": 128 * 1024})
    members, remaining = inspect_zip(raw)
    receipt = parse(members[DATA + "receipt.json"])
    require(receipt["source_commit"] == SOURCE and receipt["source_tree"] == TREE
            and receipt["run_id"] == str(RUN) and receipt["run_attempt"] == "1"
            and receipt["status"] == "source-bound-research-commands-passed"
            and receipt["source_unchanged"] is True, "ORIGINAL_RECEIPT")
    require(receipt["scientific_admission"] is False and receipt["production_activation"] is False
            and receipt["gates"] == {f"P{i}": "OPEN" for i in range(7)}, "RESEARCH_BOUNDARY")
    require(set(receipt["retained_outputs"]) == NAMES - {"receipt.json"}, "OUTPUT_SET")
    for name, identity in receipt["retained_outputs"].items():
        value = members[DATA + name]
        require(identity == {"bytes": len(value), "sha256": fp(value)["sha256"]}, "OUTPUT_BYTES")
    source_info, source_rows = source_binding(args.source, members[DATA + "source-before.json"], members[DATA + "source-after.json"])
    expected = []
    for module in MODULES:
        source_path = module.replace(".", "/") + ".py"
        expected.extend(common.test_inventory(git_at(args.source, "show", SOURCE + ":" + source_path), module))
    require(len(expected) == len(set(expected)) == 38
            and sorted(expected) == parse(members[DATA + "test-inventory.json"]), "ORIGINAL_CASE_INVENTORY")
    tests = common.parse_tests(members[DATA + "original-four-modules.stderr"], set(expected))
    require(members[DATA + "original-four-modules.stdout"] == b""
            and tests["passed"] == 38 and receipt["tests"]["exact_cases"] == sorted(expected)
            and [receipt["tests"][key] for key in ("passed", "failed", "errors", "skipped")] == [38, 0, 0, 0],
            "ORIGINAL_TEST_RESULT")
    commands = receipt["commands"]
    require([x["name"] for x in commands] == ["original-four-modules", "original-evidence", "original-empty-bundle-gate"]
            and [x["exit_code"] for x in commands] == [0, 0, 2]
            and all(x["timed_out"] is False for x in commands), "ORIGINAL_COMMANDS")
    require(commands[0]["argv"][1:] == ["-m", "unittest", *MODULES, "-v"], "ORIGINAL_TEST_ARGV")
    require(commands[1]["argv"][1:5] == ["-m", "research.hcsn.p2_markov_defective_evidence", "--samples", "45000"]
            and commands[1]["argv"][5] == "--output"
            and commands[2]["argv"][1:4] == ["-m", "research.hcsn.independent_gate", "--bundle"]
            and commands[2]["argv"][5:7] == ["--strict", "--output"], "ORIGINAL_EVIDENCE_ARGV")
    for row in commands:
        for suffix in ("stdout", "stderr"):
            value = members[DATA + row["name"] + "." + suffix]
            require(row[suffix] == {"bytes": len(value), "sha256": fp(value)["sha256"]}, "COMMAND_LOG_BINDING")
    current = parse(members[DATA + "current-markov-defective-raw.json"])
    require(fp(members[DATA + "current-markov-defective-raw.json"])["sha256"] == spec["fresh_raw_sha256"]
            and current["scientific_admission"] is False and current["production_activation"] is False
            and current["gates"] == {f"P{i}": "OPEN" for i in range(7)}, "CURRENT_RAW")
    expected_hashes = {name: source_rows["research/hcsn/" + name]["sha256"] for name in
                       ("p2_markov_defective_firsthit.py", "test_p2_markov_defective_firsthit.py", "p2_markov_defective_evidence.py")}
    require(current["sha256_sources"] == expected_hashes, "CURRENT_SOURCE_DIGESTS")
    require(current["num_samples_per_seed_and_transition"] == 45000 and current["seeds"] == [11, 23, 37],
            "ORIGINAL_SAMPLE_BUDGET")
    gate = parse(members[DATA + "strict-gate.json"])
    require(gate["full_closure"] is False and gate["production_activation"] is False
            and gate["independent_attestation_verified"] is False
            and set(gate["gates"]) == {f"P{i}" for i in range(7)}
            and all(x["status"] == "OPEN" and x["production_ready"] is False for x in gate["gates"].values()),
            "EMPTY_BUNDLE_REFUSAL")
    old_raw = git_at(args.source, "show", SOURCE + ":research/hcsn/gates/2026-11-03-iteration33-markov-defective-raw.json")
    require(fp(old_raw)["sha256"] == "840399acfe262e43450d2f5f0ac2d89a65bc0e87a24156ffc9da7b2443726d99",
            "HISTORICAL_RAW_UNCHANGED")
    old = parse(old_raw)
    changes = numeric_differences(old["scenarios"], current["scenarios"], "/scenarios")
    require(len(changes) <= 128, "NUMERIC_DIFF_CAP")
    installer = parse(members["hcsn-iteration33-install.json"])
    package_versions = {row["metadata"]["name"].lower(): row["metadata"]["version"] for row in installer["install"]}
    require(package_versions == {"numpy": "2.3.5", "scipy": "1.16.3"}
            and len(installer["install"]) == 2
            and receipt["software"] == {"python": "3.13.5", "numpy": "2.3.5", "scipy": "1.16.3"}, "SOFTWARE_BINDING")
    reader_after = bind_reader()
    require(reader_after == reader_before, "READER_CHANGED")
    report = {"schema": "hcsn.iteration33.original-artifact-readback.v1", "readback_passed": True,
              "reader": reader_before, "source": SOURCE, "source_tree": TREE, "original_run": RUN,
              "original_job": JOB, "artifact_id": spec["artifact_id"], "zip": fp(raw),
              "members": {name: fp(value) for name, value in members.items()}, "all_member_crc_verified": True,
              "source_binding": source_info, "original_tests": tests, "original_command_exits": [0, 0, 2],
              "current_source_sha256": expected_hashes, "original_test_source_mismatch_preserved": True,
              "scenario_numeric_differences": changes, "software": receipt["software"],
              "decoded_budget_remaining": remaining, "new_native_tests_executed": 0,
              "archived_source_executed": False, "scientific_admission": False, "production_activation": False,
              "all_P0_P6_accepted": False, "library_clearance": False}
    selected = ["current-markov-defective-raw.json", "receipt.json", "source-before.json", "source-after.json",
                "original-four-modules.stderr", "strict-gate.json", "test-inventory.json"]
    rendered = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    frames = []
    for name in selected:
        value = members[DATA + name]
        encoded = base64.b64encode(value).decode("ascii")
        parts = [encoded[i:i + 16384] for i in range(0, len(encoded), 16384)]
        for index, part in enumerate(parts):
            frames.append("HCSN_READBACK_CHUNK=" + json.dumps(
                {"name": name, "index": index, "parts": len(parts), "identity": fp(value),
                 "data_base64": part}, separators=(",", ":")))
    summary = "HCSN_ARTIFACT_READBACK=" + json.dumps(report, sort_keys=True, allow_nan=False)
    require(sum(len(x.encode()) + 1 for x in [*frames, summary]) <= 256 * 1024, "STDOUT_CAP")
    require(len(raw) + len(rendered) + sum(len(members[DATA + n]) for n in selected) <= 512 * 1024,
            "DERIVED_OUTPUT_CAP")
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "original.zip").write_bytes(raw)
    (args.out / "readback.json").write_bytes(rendered)
    for name in selected:
        (args.out / name).write_bytes(members[DATA + name])
    for line in frames:
        print(line, flush=True)
    print(summary, flush=True)


if __name__ == "__main__":
    try:
        main()
    except common.Rejected as error:
        print("HCSN_READBACK_FAILED=" + json.dumps({"code": str(error), "new_native_tests_executed": 0}))
        raise SystemExit(1) from None
    except Exception as error:
        print("HCSN_READBACK_FAILED=" + json.dumps({"code": type(error).__name__, "new_native_tests_executed": 0}))
        raise SystemExit(1) from None
