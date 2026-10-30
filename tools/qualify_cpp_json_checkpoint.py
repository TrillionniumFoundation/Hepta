"""Observe finite parent-state survival and explicit fresh-request recovery.

Every ordinary allocation site is calibrated on the actual scoped worker.
Foreign SIGABRT remains a failed foreign invocation. A later independent call
can demonstrate reconstruction from the retained parent checkpoint; it never
retroactively turns the terminating foreign call into a recovered C++ lifetime.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.cpp_json_checkpoint import JsonCheckpoint, CheckpointRejected, PROFILE, WORKER_SCHEMA, SENTINEL
from tools.qualify_cpp_upgrade import build_json_checkpoint_image, VERSIONS, value_digest
from tools.qualify_hia_integrated import _digest_file

SCHEMA = "hepta.cpp-json-checkpoint-qualification.v1"
CLAIMS = {
    "foreign_library_rewritten": False, "foreign_memory_safety_proved": False,
    "foreign_noexcept_failures_recovered_in_process": False,
    "general_foreign_state_migration_qualified": False, "external_side_effects_rolled_back": False,
    "foreign_handles_transferred": False, "automatic_retry_performed": False,
    "all_descendants_completion_proved": False, "full_environment_closure_proved": False,
    "performance_advantage_measured": False, "complete_development_cost_measured": False,
}
SOURCE_PREFIXES = ("hepta", "tools", "examples/cpp/upgrade", "tests/fixtures/cpp_upgrade")
ORDINARY = (([1], 0, -1), ([-1000000] * 64, 63, 1000000), ([1000000, 0, -1000000], 1, 7))


def require(ok, message):
    if not ok:
        raise ValueError("E_CPP_JSON_CHECKPOINT_EVIDENCE: " + message)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def same(a, b):
    return wire(a) == wire(b)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write(path, value):
    path = Path(path)
    path.write_bytes(json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b"\n")


def git(*args, input=None):
    return subprocess.check_output(["git", "--no-replace-objects", *args], cwd=ROOT, input=input,
                                   env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0"})


def source_state(expected_head=None):
    """Reuse the integrated stable raw-blob/mode reader on this source closure."""
    head = git("rev-parse", "HEAD").decode().strip()
    tree = git("rev-parse", head + "^{tree}").decode().strip()
    status = git("status", "--porcelain", "--untracked-files=all").decode()
    paths = sorted({p.relative_to(ROOT).as_posix() for prefix in SOURCE_PREFIXES
                    for p in (ROOT / prefix).rglob("*")
                    if p.is_file() and "__pycache__" not in p.parts})
    entries = {}
    if expected_head is not None:
        require(type(expected_head) is str and re.fullmatch(r"[0-9a-f]{40}", expected_head)
                and head == expected_head and status == "", "exact clean source head required")
        for row in git("ls-tree", "-r", "-z", tree, "--", *SOURCE_PREFIXES).split(b"\0"):
            if not row:
                continue
            metadata, name = row.split(b"\t", 1)
            mode, kind, blob = metadata.decode().split()
            require(mode in ("100644", "100755") and kind == "blob", "nonregular source tree member")
            entries[name.decode()] = (mode, blob)
        require(set(paths) == set(entries), "source closure paths differ from raw tree")
    files = {}
    for name in paths:
        require(all(not (ROOT / Path(*Path(name).parts[:n])).is_symlink()
                    for n in range(1, len(Path(name).parts) + 1)), "source symlink refused")
        mode, blob = entries.get(name, (None, None))
        files[name] = _digest_file(ROOT / name, expected_mode=mode, expected_blob=blob)
    require(git("rev-parse", "HEAD").decode().strip() == head, "source head changed")
    return {"head": head, "tree": tree, "status": status, "files": files,
            "scope": list(SOURCE_PREFIXES), "raw_tree_binding_checked": expected_head is not None}


def _original_source_objects(snapshot, expected_head):
    """Read the named original Git objects, never relabel a docs-child HEAD.

    A source checkout/object store is required. This does not execute archived
    code or prove that recorded observations historically occurred.
    """
    require(type(expected_head) is str and re.fullmatch(r"[0-9a-f]{40}", expected_head)
            and snapshot["head"] == expected_head and snapshot["status"] == ""
            and snapshot["raw_tree_binding_checked"] is True
            and snapshot["scope"] == list(SOURCE_PREFIXES), "formal original-source record required")
    tree = git("rev-parse", expected_head + "^{tree}").decode().strip()
    require(snapshot["tree"] == tree, "recorded tree differs from original commit")
    entries = {}
    for row in git("ls-tree", "-r", "-z", tree, "--", *SOURCE_PREFIXES).split(b"\0"):
        if not row:
            continue
        metadata, name = row.split(b"\t", 1)
        mode, kind, blob = metadata.decode().split()
        name = name.decode()
        require(mode in {"100644", "100755"} and kind == "blob" and name not in entries
                and all(part not in {"", ".", "..", ".git"} for part in name.split("/")),
                "original source closure contains an unsafe member")
        entries[name] = blob
    require(set(entries) == set(snapshot["files"]), "original source closure inventory differs")
    ids = sorted(set(entries.values()))
    raw = git("cat-file", "--batch", input=("\n".join(ids) + "\n").encode())
    identities = {}
    offset = 0
    for object_id in ids:
        end = raw.find(b"\n", offset)
        require(end >= offset, "original source object batch incomplete")
        fields = raw[offset:end].decode().split()
        require(len(fields) == 3 and fields[:2] == [object_id, "blob"], "original source object identity differs")
        size = int(fields[2]); offset = end + 1
        data = raw[offset:offset + size]; offset += size
        require(size >= 0 and len(data) == size and raw[offset:offset + 1] == b"\n"
                and hashlib.sha1(b"blob " + str(size).encode() + b"\0" + data).hexdigest() == object_id,
                "original Git blob bytes differ")
        offset += 1
        identities[object_id] = digest(data)
    require(offset == len(raw) and snapshot["files"] == {name: identities[blob] for name, blob in entries.items()},
            "recorded source bytes differ from original raw tree")
    return {"head": expected_head, "tree": tree, "files": len(entries)}


def _invoke(owner, row, work, kind, index, value, *, fault_site=0):
    request = owner.prepare(index, value, revision=owner.snapshot()["revision"], fault_site=fault_site)
    before = len(owner.history())
    try:
        result = owner.execute(request)
    finally:
        new = owner.history()[before:]
        for observed in new:
            number = len(row["calls"])
            record = {"index": number, "kind": kind, "execution": observed}
            row["calls"].append(record)
            path = work / "calls" / f"{number:04}.json"
            write(path, record)
    return len(row["calls"]) - 1, result, request


def _version(output, version, *, cxx, rustc, row):
    work = output / version
    work.mkdir()
    (work / "calls").mkdir()
    row.update(version=version, status="running", build={}, calls=[], faults=[], ordinary=[])
    started = time.monotonic_ns()
    try:
        image = build_json_checkpoint_image(work / "build", version, cxx=cxx, rustc=rustc, receipt=row["build"])
        with JsonCheckpoint(image, [1, 2, 3]) as owner:
            prefix, first, _ = _invoke(owner, row, work, "calibration-prefix", 0, 7)
            probe, result, _ = _invoke(owner, row, work, "calibration", 1, 5)
            require(first["committed"] and result["committed"], "actual calibration failed")
            sites = result["observation"]["allocation_attempts"]
            require(type(sites) is int and 0 < sites < 128, "invalid actual allocation denominator")
            row["calibration"] = {"prefix": prefix, "probe": probe, "allocation_sites": sites}
        # Predeclare the entire actual denominator; a terminating site cannot
        # erase later rows or select only the catchable part of the allocator.
        row["faults"] = [{"site": n, "status": "not_run"} for n in range(1, sites + 1)]
        for fault in row["faults"]:
            try:
                with JsonCheckpoint(image, [1, 2, 3]) as owner:
                    prefix, result, _ = _invoke(owner, row, work, "prefix", 0, 7)
                    require(result["committed"], "committed prefix failed")
                    fault_index, result, request = _invoke(owner, row, work, "fault", 1, 5, fault_site=fault["site"])
                    fault.update(status="observed", prefix=prefix, fault=fault_index,
                                 foreign_outcome=result["status"], foreign_recovery_qualified=False)
                    require(result["status"] in {"foreign_exception", "foreign_noexcept_termination"}
                            and result["state_preserved"] and result["direct_child_reaped"]
                            and not result["poisoned"], "foreign failure did not preserve a usable parent checkpoint")
                    count = len(owner.history())
                    try:
                        owner.execute(request)
                    except CheckpointRejected:
                        fault["replay_refused"] = True
                    else:
                        raise ValueError("consumed fault request was replayed")
                    require(len(owner.history()) == count, "refused replay launched another invocation")
                    recovery, result, _ = _invoke(owner, row, work, "explicit-recovery", 1, 5)
                    require(result["committed"] and result["after"]["values"] == [7, 5, 3],
                            "fresh independent reconstruction failed")
                    continuation, result, _ = _invoke(owner, row, work, "continuation", 2, -9)
                    require(result["committed"] and result["after"]["values"] == [7, 5, -9],
                            "continued checkpoint state differs")
                    fault.update(status="parent_checkpoint_preserved_and_reconstructed", recovery=recovery,
                                 continuation=continuation, parent_reconstruction_observed=True)
            except Exception as error:
                fault.update(status="failed", error=str(error))
        for values, index, value in ORDINARY:
            with JsonCheckpoint(image, values) as owner:
                number, result, _ = _invoke(owner, row, work, "ordinary", index, value)
                require(result["committed"], "finite ordinary state case failed")
                row["ordinary"].append(number)
        require(all(f["status"] == "parent_checkpoint_preserved_and_reconstructed" for f in row["faults"]),
                "one or more actual fault/reconstruction paths failed")
        require(any(f["foreign_outcome"] == "foreign_noexcept_termination" for f in row["faults"]),
                "no real noexcept termination was observed")
        row["counts"] = {"actual_allocation_sites": sites, "worker_processes": len(row["calls"]),
                         "foreign_caught_exceptions": sum(f["foreign_outcome"] == "foreign_exception" for f in row["faults"]),
                         "foreign_sigabrt": sum(f["foreign_outcome"] == "foreign_noexcept_termination" for f in row["faults"]),
                         "parent_checkpoint_preservations": sites, "fresh_request_reconstructions": sites,
                         "post_reconstruction_continuations": sites, "ordinary_cases": len(ORDINARY)}
        row["status"] = "passed_finite_checkpoint_observation"
    finally:
        row["wall_ns"] = time.monotonic_ns() - started


def qualify(directory, *, cxx="g++", rustc=None, expected_head=None):
    directory = Path(directory).absolute()
    directory.mkdir(parents=True, exist_ok=False)
    report = {"schema": SCHEMA, "profile": PROFILE, "directory": str(directory), "ok": False,
              "status": "running", "expected_head": expected_head, "development_only": expected_head is None,
              "claims": dict(CLAIMS), "versions": [], "human_effort": None, "agent_tokens": None,
              "cost_scope": "actual collection including failed foreign calls, fresh requests, builds and identity checks; development effort unknown"}
    started = time.monotonic_ns()
    try:
        report["source_before"] = source_state(expected_head)
        for version in VERSIONS:
            row = {"version": version, "status": "not_run"}
            report["versions"].append(row)
            try:
                _version(directory, version, cxx=cxx, rustc=rustc, row=row)
            except Exception as error:
                row.update(status="failed", error=str(error))
            write(directory / "qualification.json", report)
        report["source_after"] = source_state(expected_head)
        require(same(report["source_before"], report["source_after"]), "collection source changed")
        require(all(r["status"] == "passed_finite_checkpoint_observation" for r in report["versions"]),
                "a version failed; every attempted stage remains recorded")
        report.update(ok=True, status="passed_finite_checkpoint_reconstruction")
    except BaseException as error:
        report.update(ok=False, status="failed", error=type(error).__name__ + ": " + str(error))
        if not isinstance(error, Exception):
            raise
    finally:
        report["wall_ns"] = time.monotonic_ns() - started
        report["retained_files"] = {p.relative_to(directory).as_posix(): {"bytes": p.stat().st_size, "sha256": digest(p.read_bytes())}
                                    for p in sorted(directory.rglob("*")) if p.is_file() and p.name != "qualification.json"}
        write(directory / "qualification.json", report)
    if report["ok"]:
        try:
            report["readback"] = validate_report(report)
        except (ValueError, OSError, TypeError, KeyError) as error:
            report.update(ok=False, status="readback_failed", error=str(error))
        report["wall_ns"] = time.monotonic_ns() - started
        write(directory / "qualification.json", report)
    return report


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


def validate_report(report, *, retained_directory=None, verify_current_source=True):
    """Default formal readback requires the exact current source; audit is separate."""
    require(type(verify_current_source) is bool, "exact source-check mode required")
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
    if expected_head is not None:
        if verify_current_source:
            require(same(source_state(expected_head), report["source_before"]), "formal raw source binding differs")
        else:
            _original_source_objects(report["source_before"], expected_head)
    else:
        require(verify_current_source, "unqualified development records have no original formal source binding")
    root = Path(report["directory"] if retained_directory is None else retained_directory)
    require(root.is_dir() and not root.is_symlink(), "retained qualification directory missing")
    paths = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and p.name != "qualification.json"}
    require(paths == set(report["retained_files"]), "retained member inventory differs")
    for name, item in report["retained_files"].items():
        require(name and not Path(name).is_absolute() and ".." not in Path(name).parts
                and all(not (root / Path(*Path(name).parts[:n])).is_symlink() for n in range(1, len(Path(name).parts) + 1)),
                "unsafe retained path")
        data = (root / name).read_bytes()
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
            require(call["index"] == number and same(json.loads((root / version / "calls" / f"{number:04}.json").read_bytes()), call),
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


def audit_report(report, *, retained_directory=None):
    """Historical/relocated data consistency only; never current-head qualification."""
    observed = validate_report(report, retained_directory=retained_directory, verify_current_source=False)
    return {"schema": "hepta.cpp-json-checkpoint-offline-audit.v1", "verified": True,
            "implementation_head": report["source_before"]["head"],
            "implementation_tree": report["source_before"]["tree"],
            "recorded_directory": report["directory"],
            "retained_directory": str(Path(retained_directory or report["directory"]).absolute()),
            "execution_authority": False, "qualified_current_head": False,
            "native_or_model_reexecuted": False, "observation_readback": observed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output-directory", type=Path)
    action.add_argument("--audit-report", type=Path)
    parser.add_argument("--retained-directory", type=Path)
    parser.add_argument("--cxx", default="g++")
    parser.add_argument("--rustc")
    parser.add_argument("--expected-head")
    args = parser.parse_args()
    if args.audit_report is not None:
        require(args.expected_head is None, "offline audit cannot assign another implementation head")
        result = audit_report(json.loads(args.audit_report.read_bytes()), retained_directory=args.retained_directory)
        print(json.dumps(result, sort_keys=True))
        return 0
    require(args.retained_directory is None, "retained relocation is an audit-only option")
    result = qualify(args.output_directory, cxx=args.cxx, rustc=args.rustc, expected_head=args.expected_head)
    print(json.dumps({"ok": result["ok"], "status": result["status"], "readback": result.get("readback"),
                      "error": result.get("error"), "wall_ns": result["wall_ns"]}, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
