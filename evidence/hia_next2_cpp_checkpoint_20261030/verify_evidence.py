#!/usr/bin/env python3
"""Bounded offline byte/source/observation audit. Never extract or execute payloads.

Closed checkpoint record checks are a static copy of the reviewed producer's
readback logic; archive IO and original-object binding below use stdlib only.
No imports, exec/eval, native calls or subprocesses come from archive members.
"""
import argparse
import base64
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import time

SCHEMA = "hepta.cpp-json-checkpoint-qualification.v1"
PROFILE = "hepta.cpp-json-checkpoint.v1"
WORKER_SCHEMA = "hepta.cpp-json-checkpoint-worker.v1"
VERSIONS = ("3.11.3", "3.12.0")
SENTINEL = (1 << 63) - 1
ORDINARY = (([1], 0, -1), ([-1000000] * 64, 63, 1000000), ([1000000, 0, -1000000], 1, 7))
CLAIMS = {name: False for name in (
    "foreign_library_rewritten", "foreign_memory_safety_proved",
    "foreign_noexcept_failures_recovered_in_process", "general_foreign_state_migration_qualified",
    "external_side_effects_rolled_back", "foreign_handles_transferred", "automatic_retry_performed",
    "all_descendants_completion_proved", "full_environment_closure_proved",
    "performance_advantage_measured", "complete_development_cost_measured")}
HEAD = "953fa62dee5aa563551d57b1374ab95b6d548b45"
TREE = "aa0683509a02ca97e4e0c1dd723e4047f50d81b3"
SOURCE_PREFIXES = ("hepta", "tools", "examples/cpp/upgrade", "tests/fixtures/cpp_upgrade")
MAX_COMPRESSED = 32 * 1024 * 1024
MAX_MANIFEST = 8 * 1024 * 1024
MAX_TAR = 128 * 1024 * 1024
MAX_MEMBER = 16 * 1024 * 1024
MAX_MEMBERS = 10000
XZ_MEMORY = 64 * 1024 * 1024

def require(ok, message):
    if not ok:
        raise ValueError("E_CPP_JSON_CHECKPOINT_EVIDENCE: " + message)

def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

def same(a, b):
    return wire(a) == wire(b)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def _snapshot(revision, values):
    value = {"revision": revision, "values": values}
    return {**value, "sha256": digest(wire(value))}

def _raw(row, name):
    item = row[name]
    require(type(item) is dict and set(item) == {"base64", "bytes", "sha256"}, "raw stream schema differs")
    data = base64.b64decode(item["base64"], validate=True)
    require(type(item["bytes"]) is int and len(data) <= 4096 and len(data) == item["bytes"]
            and digest(data) == item["sha256"], "raw worker stream identity differs")
    return data

def _validate_call(row, image_sha, build_sha, version):
    fields = {"request", "request_sha256", "worker_sha256", "build_sha256", "before", "status", "committed",
              "returncode", "direct_child_reaped", "all_descendants_completion_proved", "foreign_memory_safety_proved",
              "foreign_failure_recovered_in_process", "stdout", "stderr", "after", "poisoned", "state_preserved", "wall_ns"}
    require(type(row) is dict and set(row) == fields | ({"observation"} if row.get("status") != "foreign_noexcept_termination" else set()),
            "execution record fields differ")
    require(type(row["wall_ns"]) is int and row["wall_ns"] > 0
            and row["worker_sha256"] == image_sha and row["build_sha256"] == build_sha
            and row["direct_child_reaped"] is True and row["poisoned"] is False
            and row["all_descendants_completion_proved"] is False
            and row["foreign_memory_safety_proved"] is False
            and row["foreign_failure_recovered_in_process"] is False, "execution identity or scope differs")
    request = row["request"]
    require(type(request) is dict and set(request) == {"schema", "owner", "nonce", "sequence", "revision", "version", "values", "index", "value", "fault_site"}
            and request["schema"] == PROFILE and request["version"] == version
            and row["request_sha256"] == digest(wire(request)), "request identity differs")
    for key in ("owner", "nonce"):
        require(type(request[key]) is str and re.fullmatch("[0-9a-f]{32}", request[key]), "request token representation differs")
    values, revision = request["values"], request["revision"]
    require(type(values) is list and 1 <= len(values) <= 64
            and all(type(v) is int and -1000000 <= v <= 1000000 for v in values)
            and type(revision) is int and 0 <= revision < 128
            and type(request["sequence"]) is int and 1 <= request["sequence"] <= 128
            and type(request["index"]) is int and 0 <= request["index"] < len(values)
            and type(request["value"]) is int and -1000000 <= request["value"] <= 1000000
            and type(request["fault_site"]) is int and 0 <= request["fault_site"] < 128,
            "exact bounded request operands differ")
    before = _snapshot(revision, values)
    require(same(row["before"], before), "parent snapshot does not bind invocation")
    stdout, stderr = _raw(row, "stdout"), _raw(row, "stderr")
    require(type(row["returncode"]) is int, "exact child wait status required")
    if row["status"] == "foreign_noexcept_termination":
        require(row["returncode"] == -6 and b"std::bad_alloc" in stderr and request["fault_site"] > 0
                and "observation" not in row and row["committed"] is False, "foreign termination was enlarged")
        expected_after = before
    else:
        require(row["returncode"] == 0 and stderr == b"", "normal frame from failed or noisy child")
        def pairs(items):
            result = {}
            for k, v in items:
                require(k not in result, "duplicate raw worker field")
                result[k] = v
            return result
        observed = json.loads(stdout, object_pairs_hook=pairs)
        require(same(observed, row["observation"]), "embedded worker observation differs from raw stream")
        fixed = {"schema": WORKER_SCHEMA, "version": version, "nonce": request["nonce"],
                 "request_sha256": row["request_sha256"], "revision": revision, "sequence": request["sequence"], "live_delta": 0}
        require(set(observed) == set(fixed) | {"status", "result", "allocation_attempts", "failure_injected"}
                and same({k: observed[k] for k in fixed}, fixed)
                and type(observed["allocation_attempts"]) is int and 0 < observed["allocation_attempts"] < 128,
                "worker result binding or actual allocation count differs")
        if row["status"] == "foreign_exception":
            require(same([observed["status"], observed["result"], observed["failure_injected"]], [3, SENTINEL, True])
                    and request["fault_site"] > 0 and observed["allocation_attempts"] >= request["fault_site"]
                    and row["committed"] is False, "catchable fault status or output differs")
            expected_after = before
        else:
            changed = values.copy(); changed[request["index"]] = request["value"]
            require(row["status"] == "committed" and row["committed"] is True and request["fault_site"] == 0
                    and same([observed["status"], observed["result"], observed["failure_injected"]], [0, sum(changed), False]),
                    "committed result differs from independent integer transition")
            expected_after = _snapshot(revision + 1, changed)
    require(same(row["after"], expected_after)
            and row["state_preserved"] is same(expected_after, before), "commit/failure changed the wrong parent state")

def validate_report(report, files, manifest):
    """Default formal readback requires the exact current source; audit is separate."""
    fields = {"schema", "profile", "directory", "ok", "status", "expected_head", "development_only", "claims",
              "versions", "human_effort", "agent_tokens", "cost_scope", "source_before", "source_after", "wall_ns", "retained_files"}
    require(type(report) is dict and set(report) == fields | ({"readback"} if "readback" in report else set()),
            "qualification fields differ")
    require(report["schema"] == SCHEMA and report["profile"] == PROFILE and report["ok"] is True
            and report["status"] == "passed_finite_checkpoint_reconstruction"
            and same(report["claims"], CLAIMS) and report["human_effort"] is None and report["agent_tokens"] is None
            and type(report["wall_ns"]) is int and report["wall_ns"] > 0, "qualification status, scope or cost differs")
    require(same(report["source_before"], report["source_after"]), "source changed during collection")
    expected_head = report["expected_head"]
    require(report["development_only"] is (expected_head is None), "development result was promoted")
    require(expected_head == manifest["implementation_head"] and report["development_only"] is False,
            "formal source qualification required")
    verify_original_source(report, files, manifest)
    artifact_prefix = "formal/run/checkpoint/qualification/"
    paths = {name[len(artifact_prefix):] for name in files if name.startswith(artifact_prefix)
             and name != artifact_prefix + "qualification.json"}
    require(paths == set(report["retained_files"]), "retained member inventory differs")
    for name, item in report["retained_files"].items():
        safe_name(name)
        data = files[artifact_prefix + name]
        require(same(item, {"bytes": len(data), "sha256": digest(data)}), "retained file differs")
    require([v["version"] for v in report["versions"]] == list(VERSIONS), "exact two-version denominator differs")
    totals = {"worker_processes": 0, "foreign_sigabrt": 0, "actual_allocation_sites": 0,
              "parent_checkpoint_preservations": 0, "fresh_request_reconstructions": 0}
    nonces = set()
    for row in report["versions"]:
        require(type(row) is dict and set(row) == {"version", "status", "build", "calls", "faults", "ordinary", "calibration", "counts", "wall_ns"},
                "version record fields differ")
        version, build = row["version"], row["build"]
        require(row["status"] == "passed_finite_checkpoint_observation" and build["status"] == "built"
                and type(row["wall_ns"]) is int and row["wall_ns"] > 0
                and type(build["wall_ns"]) is int and build["wall_ns"] > 0, "version/build terminal cost differs")
        for name, identity in build["artifacts"].items():
            require(report["retained_files"][version + "/build/" + name] == identity, "built artifact binding differs")
        require(build["image_sha256"] == build["artifacts"]["json-checkpoint-worker"]["sha256"]
                and build["source_inputs_before"] == build["source_inputs_after"]
                and build["build_sha256"] == value_digest({"version": version, "sources": build["source_inputs_before"],
                    "artifacts": build["artifacts"], "generated_identity": build["generated_identity"]}), "worker build receipt differs")
        chains = {}
        for number, call in enumerate(row["calls"]):
            require(call["index"] == number and same(decode(files[artifact_prefix + version + "/calls/" + f"{number:04}.json"]), call),
                    "actual call ledger or retained record differs")
            execution = call["execution"]
            _validate_call(execution, build["image_sha256"], build["build_sha256"], version)
            request = execution["request"]
            require(request["nonce"] not in nonces, "observed request nonce repeated")
            nonces.add(request["nonce"])
            previous = chains.get(request["owner"])
            if previous:
                require(same(previous["after"], execution["before"])
                        and request["sequence"] == previous["request"]["sequence"] + 1, "owner state/request chain differs")
            else:
                require(request["revision"] == 0 and request["sequence"] == 1, "owner did not start at its initial checkpoint")
            chains[request["owner"]] = execution
        used = set()
        def call(index, kind):
            require(type(index) is int and 0 <= index < len(row["calls"]), "call index differs")
            require(index not in used, "one native call was credited to multiple stages")
            used.add(index)
            entry = row["calls"][index]
            require(entry["kind"] == kind, "call stage differs")
            return entry["execution"]
        prefix = call(row["calibration"]["prefix"], "calibration-prefix")
        probe = call(row["calibration"]["probe"], "calibration")
        require(prefix["committed"] is True and probe["committed"] is True
                and same(prefix["before"], _snapshot(0, [1, 2, 3]))
                and same(prefix["after"], _snapshot(1, [7, 2, 3]))
                and same(probe["before"], prefix["after"])
                and same(probe["after"], _snapshot(2, [7, 5, 3]))
                and prefix["request"]["owner"] == probe["request"]["owner"], "calibration did not execute the planned state chain")
        sites = probe["observation"]["allocation_attempts"]
        require(row["calibration"]["allocation_sites"] == sites
                and [f["site"] for f in row["faults"]] == list(range(1, sites + 1)), "calibrated fault denominator differs")
        for fault in row["faults"]:
            require(fault["status"] == "parent_checkpoint_preserved_and_reconstructed"
                    and fault["foreign_recovery_qualified"] is False and fault["replay_refused"] is True
                    and fault["parent_reconstruction_observed"] is True, "parent reconstruction scope enlarged")
            initial = call(fault["prefix"], "prefix")
            failed = call(fault["fault"], "fault")
            recovery = call(fault["recovery"], "explicit-recovery")
            continuation = call(fault["continuation"], "continuation")
            require(same(initial["before"], _snapshot(0, [1, 2, 3]))
                    and same(initial["after"], _snapshot(1, [7, 2, 3]))
                    and failed["request"]["fault_site"] == fault["site"]
                    and failed["status"] == fault["foreign_outcome"]
                    and failed["status"] in {"foreign_exception", "foreign_noexcept_termination"}
                    and failed["state_preserved"] is True
                    and same(failed["before"], initial["after"])
                    and recovery["committed"] is True and same(recovery["after"], _snapshot(2, [7, 5, 3]))
                    and continuation["committed"] is True and same(continuation["after"], _snapshot(3, [7, 5, -9]))
                    and len({r["request"]["owner"] for r in (initial, failed, recovery, continuation)}) == 1,
                    "actual failure/preserved checkpoint/fresh recovery chain differs")
        require(len(row["ordinary"]) == len(ORDINARY), "ordinary input denominator differs")
        for index, (values, at, value) in zip(row["ordinary"], ORDINARY):
            observed = call(index, "ordinary")
            require(same([observed["request"][k] for k in ("values", "index", "value")], [values, at, value])
                    and observed["committed"] is True, "ordinary bounded state input differs")
        counts = {"actual_allocation_sites": sites, "worker_processes": len(row["calls"]),
                  "foreign_caught_exceptions": sum(f["foreign_outcome"] == "foreign_exception" for f in row["faults"]),
                  "foreign_sigabrt": sum(f["foreign_outcome"] == "foreign_noexcept_termination" for f in row["faults"]),
                  "parent_checkpoint_preservations": sites, "fresh_request_reconstructions": sites,
                  "post_reconstruction_continuations": sites, "ordinary_cases": len(ORDINARY)}
        require(same(row["counts"], counts) and counts["foreign_sigabrt"] > 0, "actual failure counters differ")
        require(len(used) == len(row["calls"]) == 2 + 4 * sites + len(ORDINARY)
                and row["wall_ns"] >= build["wall_ns"] + sum(c["execution"]["wall_ns"] for c in row["calls"]),
                "stage denominator or sequential measured cost differs")
        for key in totals:
            totals[key] += counts[key]
    require(report["wall_ns"] >= sum(row["wall_ns"] for row in report["versions"]), "outer measured cost excludes version work")
    result = {"verified": True, "retained_files": len(paths), **totals,
              "scope": "local finite observations and byte consistency; no archived execution or past-execution authentication"}
    if "readback" in report:
        require(same(report["readback"], result), "embedded readback counters differ")
    return result


def value_digest(value):
    return digest(wire(value))


def safe_name(name):
    require(type(name) is str and name and "\\" not in name and "\0" not in name,
            "unsafe archive member name")
    path = PurePosixPath(name)
    require(not path.is_absolute() and path.as_posix() == name
            and all(part not in {"", ".", ".."} for part in name.split("/")), "unsafe archive path")


def decode(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON member")
            result[key] = value
        return result
    def nonfinite(value):
        raise ValueError("nonfinite JSON number")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=nonfinite)


def regular_bytes(path, maximum):
    path = Path(path).absolute()
    require(all(not p.is_symlink() for p in (path, *path.parents)), "symlink input refused")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum,
                "bounded regular file required")
        chunks, count = [], 0
        while True:
            block = os.read(fd, min(65536, maximum + 1 - count))
            if not block:
                break
            chunks.append(block); count += len(block)
            require(count <= maximum, "input grew beyond limit")
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "input changed during read")
        data = b"".join(chunks)
        require(len(data) == before.st_size, "input length changed")
        return data
    finally:
        os.close(fd)


def archive_members(compressed, manifest):
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=XZ_MEMORY)
    tar_bytes = decoder.decompress(compressed, max_length=MAX_TAR + 1)
    while not decoder.eof and not decoder.needs_input:
        require(len(tar_bytes) <= MAX_TAR, "decoded stream exceeds limit")
        tar_bytes += decoder.decompress(b"", max_length=MAX_TAR + 1 - len(tar_bytes))
    require(decoder.eof and decoder.unused_data == b"" and len(tar_bytes) <= MAX_TAR,
            "incomplete, trailing or oversized XZ stream")
    files = {}
    end = 0
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
        for item in archive:
            require(len(files) < MAX_MEMBERS and item.isreg() and not item.pax_headers,
                    "nonregular archive member or count overflow")
            safe_name(item.name)
            require(item.name not in files and 0 <= item.size <= MAX_MEMBER,
                    "duplicate or oversized archive member")
            stream = archive.extractfile(item)
            require(stream is not None, "missing regular payload")
            data = stream.read(MAX_MEMBER + 1)
            require(len(data) == item.size, "member length differs")
            expected = manifest["members"].get(item.name)
            require(expected == {"bytes": len(data), "sha256": digest(data)}, "member hash differs")
            files[item.name] = data
            end = max(end, item.offset_data + ((item.size + 511) // 512) * 512)
    require(len(tar_bytes) % 512 == 0 and len(tar_bytes) - end >= 1024
            and not any(tar_bytes[end:]), "nonzero or incomplete trailing tar bytes")
    require(set(files) == set(manifest["members"])
            and sum(map(len, files.values())) == manifest["uncompressed_member_bytes"], "member inventory differs")
    return files


def raw_tree_files(objects, root):
    result, used = {}, set()
    def visit(object_id, prefix, ancestors):
        require(object_id not in ancestors and len(ancestors) < 64, "cyclic or deep tree")
        used.add(object_id)
        data = objects[object_id]
        offset = 0
        while offset < len(data):
            space = data.index(b" ", offset); zero = data.index(b"\0", space)
            mode = data[offset:space].decode()
            name = data[space + 1:zero].decode()
            require("/" not in name and name not in {"", ".", "..", ".git"}, "unsafe original tree name")
            offset = zero + 1
            object_bytes = data[offset:offset + 20]; offset += 20
            require(len(object_bytes) == 20, "short original tree reference")
            child = object_bytes.hex(); path = prefix + name
            safe_name(path)
            if mode == "40000":
                visit(child, path + "/", ancestors | {object_id})
            else:
                require(mode in {"100644", "100755", "120000", "160000"}
                        and path not in result and len(result) < 100000, "original leaf mode/path differs")
                result[path] = {"mode": mode, "blob": child}
        require(offset == len(data), "original tree has trailing bytes")
    visit(root, "", set())
    return result, used


def verify_original_source(report, files, manifest):
    before = report["source_before"]
    require(manifest["implementation_head"] == before["head"] == HEAD
            and manifest["implementation_tree"] == before["tree"] == TREE
            and before["status"] == "" and before["raw_tree_binding_checked"] is True
            and before["scope"] == list(SOURCE_PREFIXES), "original formal source differs")
    kinds = manifest["source_objects"]
    objects = {}
    for object_id, kind in kinds.items():
        require(re.fullmatch(r"[0-9a-f]{40}", object_id) and kind in {"commit", "tree", "blob"}, "invalid object inventory")
        data = files["source/git-objects/" + object_id]
        require(hashlib.sha1((kind + " " + str(len(data))).encode() + b"\0" + data).hexdigest() == object_id,
                "raw Git object hash differs")
        objects[object_id] = data
    require(kinds[HEAD] == "commit" and kinds[TREE] == "tree"
            and objects[HEAD].split(b"\n", 1)[0] == ("tree " + TREE).encode(), "original commit/tree binding differs")
    inventory, trees = raw_tree_files(objects, TREE)
    closure = {name: row for name, row in inventory.items()
               if any(name == prefix or name.startswith(prefix + "/") for prefix in SOURCE_PREFIXES)}
    require(closure == manifest["source_closure"] and set(closure) == set(before["files"]), "complete source closure differs")
    for name, item in closure.items():
        require(item["mode"] in {"100644", "100755"} and kinds[item["blob"]] == "blob"
                and digest(objects[item["blob"]]) == before["files"][name], "original source blob differs")
    require(all(kinds[tree] == "tree" for tree in trees)
            and set(kinds) == {HEAD} | trees | {item["blob"] for item in closure.values()}, "extra or missing source objects")
    require(manifest["full_repository_blob_payload_packaged"] is False
            and manifest["profile_source_blob_closure_packaged"] is True, "source payload scope enlarged")
    return {"profile_source_files": len(closure), "original_tree_files": len(inventory),
            "original_objects": len(objects), "inventory": inventory}


def check_identity(files, path, identity):
    data = files[path]
    require(type(identity["bytes"]) is int and identity["bytes"] == len(data)
            and identity["sha256"] == digest(data), "retained identity differs: " + path)
    return data


def wrapper_consistency(files, report, manifest):
    prefix = "formal/"
    receipt = decode(files[prefix + "run/RECEIPT.json"])
    plan = decode(check_identity(files, prefix + "PLAN.json", receipt["plan"]))
    check_identity(files, prefix + "launch.py", receipt["launcher"])
    require(receipt["status"] == "completed" and receipt["errors"] == []
            and all(receipt[name + "_unchanged"] is True for name in ("source", "tools", "plan", "launcher")),
            "wrapper terminal or identities differ")
    require(plan["source_head"] == HEAD and plan["source_tree"] == TREE
            and plan["launcher_sha256"] == receipt["launcher"]["sha256"]
            and receipt["tools_before"] == receipt["tools_after"] == plan["tools_before"], "frozen plan/tools differ")
    require(receipt["foreign_library_rewritten"] is False
            and receipt["foreign_failure_recovered_in_process"] is False
            and receipt["core_or_native_publication_authority_granted"] is False
            and receipt["automatic_retry_performed"] is False
            and receipt["cpu_performance_qualification"] is False
            and receipt["external_side_effects_rolled_back"] is False, "wrapper scope enlarged")
    inventory = receipt["retained_files"]
    expected = {name[len(prefix + "run/"):] for name in files
                if name.startswith(prefix + "run/") and name != prefix + "run/RECEIPT.json"}
    require(set(inventory) == expected, "complete run inventory differs")
    for name, identity in inventory.items():
        safe_name(name); check_identity(files, prefix + "run/" + name, identity)
    before = decode(files[prefix + "run/source-before.json"])
    require(same(before, decode(files[prefix + "run/source-after.json"]))
            and same(before, decode(files[prefix + "run/checkpoint/source-after.json"]))
            and before["head"] == HEAD and before["tree"] == TREE and before["status"] == "", "whole-repository source record changed")
    source = verify_original_source(report, files, manifest)
    require(set(before["files"]) == set(source["inventory"])
            and all(before["files"][name] == value for name, value in report["source_before"]["files"].items()),
            "whole-repository/profile source ledger disagreement")
    require(len(receipt["stages"]) == len(plan["stages"]) == 1, "extra or missing stage")
    stage, planned = receipt["stages"][0], plan["stages"][0]
    require(stage["id"] == planned["id"] == "checkpoint" and stage["argv"] == planned["argv"]
            and stage["returncode"] == 0 and stage["status"] == "completed"
            and stage["qualified"] is True and stage["raw_capture_complete"] is True
            and stage["raw_streams_persisted_complete"] is True and stage["persistence_errors"] == []
            and same(stage, decode(files[prefix + "run/checkpoint/execution.json"])), "actual stage receipt differs")
    require(stage["argv"][stage["argv"].index("--expected-head") + 1] == HEAD
            and stage["argv"][stage["argv"].index("--output-directory") + 1] == report["directory"], "actual CLI source/output differs")
    for name in ("stdout", "stderr"):
        check_identity(files, prefix + "run/checkpoint/" + name, stage[name])
    check_identity(files, prefix + "run/checkpoint/qualification/qualification.json", stage["qualification_file"])
    require(same(stage["readback"], report["readback"])
            and all(report["readback"][key] == value for key, value in plan["expected_observed_counts"].items()), "actual readback denominator differs")
    outer = decode(files[prefix + "OUTER_EXECUTION.json"])
    require(outer["returncode"] == 0 and outer["status"] == "completed" and outer["cleanup_errors"] == [], "outer execution failed")
    for name in ("stdout", "stderr"):
        check_identity(files, prefix + "launch." + name, outer[name])
    costs = [outer["wall_ns"], receipt["outer_wall_ns"], stage["wall_ns"], report["wall_ns"]]
    require(all(type(value) is int and value > 0 for value in costs) and costs == sorted(costs, reverse=True),
            "nested measured execution costs differ")
    return {"retained_run_files": len(inventory), "recorded_repository_files": len(before["files"]),
            "profile_source_blob_files": source["profile_source_files"], "original_git_objects": source["original_objects"],
            "nested_wall_ns": dict(zip(("outer", "launcher", "stage", "collector"), costs)),
            "nested_costs_must_not_be_added": True}


def verify_prior_delivery(files, directory):
    """Rehash the copied historical package; do not execute its reader or expand it."""
    binding = decode(files["reference/prior-3533-binding.json"])
    delivery_raw = files["reference/prior-3533-delivery.json"]
    require(binding["implementation_head"] == "3533b95c53d23de2d22c91fcc05cb601b8448eb3"
            and binding["relative_directory"] == "prior-3533"
            and binding["old_failed_verifier_retained"] is True
            and binding["old_raw_and_package_modified"] is False
            and binding["old_result_relabelled_as_current"] is False
            and digest(delivery_raw) == binding["delivery_sha256"], "historical delivery binding differs")
    directory = Path(directory)
    require(regular_bytes(directory / "DELIVERY.json", MAX_MANIFEST) == delivery_raw,
            "copied historical delivery changed")
    delivery = decode(delivery_raw)
    require(delivery["implementation_head"] == binding["implementation_head"]
            and 0 < len(delivery["files"]) == binding["files"] <= MAX_MEMBERS,
            "historical file/source inventory differs")
    total = 0
    retained = {}
    for name, item in delivery["files"].items():
        safe_name(name)
        data = regular_bytes(directory / name, MAX_MEMBER)
        require(item == {"bytes": len(data), "sha256": digest(data)}, "copied historical file changed")
        total += len(data)
        require(total <= 64 * 1024 * 1024, "historical package exceeds aggregate bound")
        if name in {"verification-attempt-001/EXECUTION.json", "verification-attempt-002/EXECUTION.json"}:
            retained[name] = decode(data)
    require(total == delivery["bytes"] == binding["payload_bytes"]
            and delivery["files"]["p3-p6-json-checkpoint-3533.tar.xz"]["sha256"] == binding["archive_sha256"]
            and delivery["files"]["MANIFEST.json"]["sha256"] == binding["manifest_sha256"]
            and retained["verification-attempt-001/EXECUTION.json"]["returncode"] == 1
            and retained["verification-attempt-002/EXECUTION.json"]["returncode"] == 0,
            "historical archive or failed/fixed reader attempts differ")
    return {"prior_3533_delivery_sha256": binding["delivery_sha256"],
            "prior_3533_files_rehashed": len(delivery["files"]) + 1,
            "prior_3533_bytes_rehashed": total + len(delivery_raw),
            "prior_3533_semantic_archive_audit_reexecuted": False,
            "prior_3533_failed_reader_retained": True,
            "prior_3533_qualification_relabelled": False}


def verify(archive, manifest_path, archive_sha256, manifest_sha256, prior_directory):
    started = time.monotonic_ns()
    require(re.fullmatch(r"[0-9a-f]{64}", archive_sha256)
            and re.fullmatch(r"[0-9a-f]{64}", manifest_sha256), "external hash pins required")
    raw_manifest = regular_bytes(manifest_path, MAX_MANIFEST)
    require(digest(raw_manifest) == manifest_sha256, "manifest external pin differs")
    manifest = decode(raw_manifest)
    require(manifest["schema"] == "hepta.cpp-json-checkpoint.953fa62-evidence-manifest.v1", "manifest schema differs")
    compressed = regular_bytes(archive, MAX_COMPRESSED)
    require(digest(compressed) == archive_sha256 == manifest["archive"]["sha256"]
            and len(compressed) == manifest["archive"]["bytes"], "archive external pin differs")
    files = archive_members(compressed, manifest)
    report = decode(files["formal/run/checkpoint/qualification/qualification.json"])
    observations = validate_report(report, files, manifest)
    wrapper = wrapper_consistency(files, report, manifest)
    prior = verify_prior_delivery(files, prior_directory)
    for attempt, count in (("002", 23), ("003", 3)):
        prefix = "development/attempt-" + attempt + "/"
        row = decode(files[prefix + "EXECUTION.json"])
        require(row["returncode"] == 0, "development attempt was relabelled")
        for name in ("stdout", "stderr"):
            check_identity(files, prefix + name, row[name])
        require(re.search(r"Ran " + str(count) + r" tests in [0-9.]+s\n\nOK\s*$", files[prefix + "stderr"].decode()),
                "development footer differs")
    return {"verified": True, "implementation_head": HEAD, "implementation_tree": TREE,
            "archive_sha256": archive_sha256, "manifest_sha256": manifest_sha256,
            "members_rehashed": len(files), "uncompressed_member_bytes": sum(map(len, files.values())),
            "observations": observations, **wrapper, **prior,
            "development_method_executions": {"attempt-002": 23, "attempt-003": 3},
            "development_methods_overlap": True,
            "foreign_sigabrt_recovered_in_process": False, "new_source_head_qualified": False,
            "execution_authority_granted": False, "native_or_model_executed": False,
            "archive_extracted": False, "full_environment_closure_proved": False,
            "full_repository_blob_payload_packaged": False,
            "verification_wall_ns": time.monotonic_ns() - started,
            "scope": "bounded byte, original Git profile-source, raw process/state/count consistency; no hostile-producer authentication or whole C++ safety proof"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--prior-directory", required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.archive, args.manifest, args.archive_sha256, args.manifest_sha256,
                            args.prior_directory), sort_keys=True))

