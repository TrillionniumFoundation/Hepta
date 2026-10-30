#!/usr/bin/env python3
"""Bounded, offline archive verification; no extraction or archived-code execution."""
from collections import Counter
from hashlib import sha256
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import time

LIMITS = {"compressed_bytes": 16 * 1024 * 1024, "tar_bytes": 32 * 1024 * 1024,
          "member_bytes": 16 * 1024 * 1024, "member_count": 64,
          "manifest_bytes": 1024 * 1024, "xz_decoder_memory_bytes": 64 * 1024 * 1024}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bounded_file(path, maximum):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= maximum, "bounded regular file required: " + str(path))
        data = stream.read(maximum + 1)
    require(len(data) <= maximum, "file byte limit exceeded")
    return data


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def read_json(data):
    return json.loads(data, object_pairs_hook=no_duplicate_keys,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def match(data, identity, name):
    require(type(identity["bytes"]) is int and len(data) == identity["bytes"]
            and sha256(data).hexdigest() == identity["sha256"], "retained bytes differ: " + name)


def verify(folder):
    started = time.monotonic_ns()
    folder = Path(folder)
    manifest = read_json(bounded_file(folder / "MANIFEST.json", LIMITS["manifest_bytes"]))
    require(manifest["schema"] == "hepta.rust-finite-heap.integrated-archive.v1", "wrong archive profile")
    require(manifest["verification_limits"] == LIMITS, "reviewed archive limits changed")
    require(manifest["archive"]["name"] == "execution.tar.xz", "fixed archive member required")
    encoded = bounded_file(folder / "execution.tar.xz", LIMITS["compressed_bytes"])
    match(encoded, manifest["archive"], "execution.tar.xz")
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=LIMITS["xz_decoder_memory_bytes"])
    expanded = decoder.decompress(encoded, max_length=LIMITS["tar_bytes"] + 1)
    require(len(expanded) <= LIMITS["tar_bytes"] and decoder.eof and not decoder.unused_data,
            "incomplete, concatenated or oversized xz stream")
    match(expanded, manifest["decoded_tar"], "decoded tar")
    members = manifest["members"]
    require(type(members) is dict and 0 < len(members) <= LIMITS["member_count"], "member count exceeds limit")
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        for member in archive:
            require(len(files) < LIMITS["member_count"], "archive member count exceeds limit")
            path = PurePosixPath(member.name)
            require(member.isfile() and not member.issym() and not member.islnk() and not member.pax_headers,
                    "only plain regular archive members are accepted")
            require(not path.is_absolute() and str(path) == member.name
                    and all(part not in {"", ".", ".."} for part in path.parts)
                    and member.name in members and member.name not in files, "unsafe, extra or duplicate member")
            require(0 <= member.size <= LIMITS["member_bytes"], "member byte limit exceeded")
            total += member.size
            require(total <= LIMITS["tar_bytes"], "aggregate member bytes exceed limit")
            stream = archive.extractfile(member)
            require(stream is not None, "regular member is unreadable")
            data = stream.read(member.size + 1)
            require(len(data) == member.size, "member size changed")
            match(data, members[member.name], member.name)
            files[member.name] = data
        require(not archive.pax_headers and not any(expanded[archive.offset:]), "nonzero data after final archive member")
    require(set(files) == set(members) and len(files) == manifest["member_count"]
            and total == manifest["uncompressed_member_bytes"], "archive inventory differs")
    original = read_json(files["fresh/MANIFEST.json"])
    require(original["schema"] == "hepta.rust-finite-heap.integrated-focused-files.v1", "wrong original inventory")
    require(set(files) == {"fresh/" + name for name in original["members"]}
            | {"fresh/MANIFEST.json", "review/P1_P2_INDEPENDENT_REVIEW.json"}, "original evidence inventory changed")
    for name, identity in original["members"].items():
        match(files["fresh/" + name], identity, "original " + name)
    require(len(original["members"]) == original["member_count"] == manifest["original_evidence_members"],
            "original member count differs")
    require(sum(row["bytes"] for row in original["members"].values()) == original["member_bytes"],
            "original aggregate bytes differ")
    for name in ("SUMMARY.json", "README.md", "verify.py"):
        limit = LIMITS["member_bytes"] if name == "SUMMARY.json" else LIMITS["manifest_bytes"]
        match(bounded_file(folder / name, limit), manifest["support_files"][name], name)
    require(bounded_file(folder / "SUMMARY.json", LIMITS["member_bytes"]) == files["fresh/SUMMARY.json"],
            "external summary differs from original")
    doc = lambda name: read_json(files["fresh/" + name])
    summary, receipt, plan = doc("SUMMARY.json"), doc("run/RECEIPT.json"), doc("PLAN.json")
    require(receipt["status"] == "completed" and receipt["errors"] == []
            and receipt["new_holdout"] is False and summary["new_holdout"] is False, "attempt scope changed")
    for name in ("plan", "launcher"):
        match(files["fresh/" + ("PLAN.json" if name == "plan" else "launch.py")], receipt[name], name)
    require(plan["launcher_sha256"] == receipt["launcher"]["sha256"], "launcher no longer matches plan")
    require(all(receipt[key] is True for key in ("source_unchanged", "tools_unchanged", "plan_unchanged", "launcher_unchanged")),
            "execution identities changed")
    before, after = doc("run/source-before.json"), doc("run/source-after.json")
    require(before == after and before["status"] == "" and before["head"] == plan["source_head"]
            == summary["source_head"] == manifest["source_head"]
            and before["tree"] == plan["source_tree"] == summary["source_tree"] == manifest["source_tree"],
            "source identity records differ")
    require(receipt["tools_before"] == receipt["tools_after"], "tool identity records differ")
    require(set(receipt["retained_files"]) == {name[len("run/"):] for name in original["members"]
            if name.startswith("run/") and name != "run/RECEIPT.json"}, "execution retained inventory differs")
    for name, identity in receipt["retained_files"].items():
        match(files["fresh/run/" + name], identity, "execution " + name)
    require([row["id"] for row in receipt["stages"]] == ["rust", "focused"], "stage inventory differs")
    for stage, planned in zip(receipt["stages"], plan["stages"]):
        require(stage["argv"] == planned["argv"] and stage["status"] == "completed"
                and stage["returncode"] == 0 and stage["outcome"]["passed"] is True
                and stage["cleanup_errors"] == [] and stage["persistence_errors"] == [], "incomplete stage")
        require(stage == doc("run/" + stage["id"] + "/execution.json"), "inner and outer stage receipt differ")
        require(before == doc("run/" + stage["id"] + "/source-after.json"), "stage source changed")
    rust, focused = receipt["stages"]
    rust_footer_count = sum(map(int, re.findall(rb"test result: ok\. (\d+) passed", files["fresh/run/rust/stdout"])))
    require(rust_footer_count == rust["outcome"]["tests_run"]
            and all(rust["outcome"][key] == 0 for key in ("failures", "filtered_out", "skipped")), "Rust footer differs")
    stderr = files["fresh/run/focused/stderr"].decode()
    methods = sorted(re.findall(r"(?m)^test\w+ \((tests\.[^\s)]+)\) \.\.\. ok$", stderr))
    require(methods == plan["focused_test_methods"] and len(methods) == focused["outcome"]["tests_run"]
            and re.search(r"Ran " + str(len(methods)) + r" tests in [\d.]+s\n\nOK\s*$", stderr), "focused footer/methods differ")
    actual = doc("run/focused/raw/actual.json")
    binary = focused["binary_after"]["sha256"]
    require(binary == rust["binary_after"]["sha256"] == actual["executable_sha256"] == summary["binary"]["sha256"],
            "actual producer binary bindings differ")
    responses = set()
    processes = {wire(row) for row in actual["processes"]}
    for process in actual["processes"]:
        require(process["executable_sha256"] == binary
                and sha256(actual["programs"][process["input_sha256"]].encode()).hexdigest() == process["input_sha256"],
                "actual producer/input binding differs")
        require(type(process["outer_wall_ns"]) is int and process["outer_wall_ns"] > 0, "process cost missing")
        if process["returncode"] == 0:
            require(process["stderr"] == "", "successful producer has stderr")
            responses.add(wire(read_json(process["stdout"])))
    runtime_statuses = Counter()
    stopped_live = 0
    for observation in actual["observations"]:
        report = observation["rust_report"]
        require(observation["matched"] is True and wire(report) in responses, "observation lacks actual producer bytes")
        require(report["heap_bound"]["peak_bound_bytes"] == observation["python_bound"]["peak_bound_bytes"], "bound differs")
        run, oracle = report["runtime"]["execution"], observation["python_execution"]
        require(all(wire(run[key]) == wire(oracle[key]) for key in ("status", "steps", "resources")), "runtime observation differs")
        require(wire(run["values"]) == wire(oracle["values"]) if run["status"] == "returned"
                else run["error"]["code"] == oracle["error"]["code"], "return/trap observation differs")
        require(run["resources"]["peak_bytes"] <= report["heap_bound"]["peak_bound_bytes"], "observed peak exceeds bound")
        runtime_statuses[run["status"]] += 1
        stopped_live += run["status"] != "returned" and run["resources"]["live_bytes"] > 0
    for refused in actual["refusals"]:
        require(wire(refused) in processes and refused["returncode"] == 1 and refused["stdout"] == ""
                and refused["stderr"].startswith("E_HIA_"), "raw refusal lacks actual process")
    counts = summary["actual_heap_corpus"]
    for key, field in (("actual_direct_rust_processes", "processes"), ("matched_bound_and_machine_observations", "observations"),
                       ("raw_refusal_controls", "refusals"), ("isolated_python_child_processes", "isolated_child_processes")):
        require(counts[key] == receipt["finite_heap_observed_counts"][key] == len(actual[field]), "actual count differs")
    exits = dict(Counter(str(row["returncode"]) for row in actual["processes"]))
    require(exits == counts["direct_process_returncodes"] and dict(runtime_statuses) == counts["observed_runtime_statuses"]
            and stopped_live == counts["stopped_observations_with_nonzero_live_payload"], "status/stop denominator differs")
    peer = read_json(files["review/P1_P2_INDEPENDENT_REVIEW.json"])
    require(peer["verifier_exit_code"] == 0 and peer["raw_stderr"] == "" and peer["input_bytes_before_after_same"] is True,
            "independent readback did not complete")
    require(read_json(peer["raw_stdout"]) == peer["verifier_result"] and peer["verifier_result"]["verified"] is True,
            "independent readback stdout differs")
    for name, identity in peer["inputs"].items():
        match(files["fresh/" + name], identity, "peer input " + name)
    require(peer["additional_recomputed_counts"] == {"direct_returncodes": exits,
            "runtime_statuses": dict(runtime_statuses), "stopped_with_live_payload": stopped_live}, "peer recount differs")
    require(summary["historical_source_references"] == plan["historical_source_references"]
            == receipt["historical_source_references"] == manifest["historical_source_references"], "historical references changed")
    return {"verified": True, "archive_members_rehashed": len(files), "original_evidence_members": original["member_count"],
            "retained_execution_files_rehashed": len(receipt["retained_files"]), "peer_input_files_rehashed": len(peer["inputs"]),
            "uncompressed_member_bytes": total, "source_head": before["head"], "source_tree": before["tree"],
            "rust_tests": rust_footer_count, "focused_tests": len(methods), "actual_direct_processes": len(actual["processes"]),
            "matched_observations": len(actual["observations"]), "explicit_raw_refusal_subset": len(actual["refusals"]),
            "direct_process_returncodes": exits, "runtime_statuses": dict(runtime_statuses),
            "stopped_with_live_payload": stopped_live, "recorded_execution_outer_wall_ns": receipt["outer_wall_ns"],
            "verification_wall_ns": time.monotonic_ns() - started, "new_holdout": False,
            "scope": "bounded retained-byte/count/observed-comparison integrity only; no extraction, archived-code execution, target execution, renewed admission, hostile-producer authentication or refinement proof",
            "bounds_scope": "encoded/decoded byte counts, regular member count and xz decoder memory; not a process RSS or CPU theorem"}


if __name__ == "__main__":
    print(json.dumps(verify(Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).resolve().parent), sort_keys=True))
