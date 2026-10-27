#!/usr/bin/env python3
"""Offline report/source/retention review; all inputs are already retained bytes."""
import ast
import base64
from collections import Counter, defaultdict
from hashlib import sha1
from pathlib import PurePosixPath
import re

from performance_audit import (CANDIDATE, COMPILER, audit_performance, require, parse, same, sha, wire)

TREE = "ad5dcb9118c392ef35cc8621916580eed474621c"
FULL = "artifacts/candidate/"
HIA = "artifacts/hia-unified/"
PERFORMANCES = {"scalar": FULL + "llvm_native.json", "owned": FULL + "llvm_owned.json", "hia": HIA + "performance.json"}


def digest(raw, expected, label):
    require(sha(raw) == expected["sha256"] and ("bytes" not in expected or len(raw) == expected["bytes"]),
            "retained identity differs: " + label)


def terminal_unit(raw, returncode):
    text = raw.decode()
    match = re.search(r"(?m)^Ran ([0-9]+) tests? in ([0-9.]+)s\s+"
                      r"(OK|FAILED)(?: \(([^\n]*)\))?\s*\Z", text)
    result = {"terminal_report_present": match is not None, "returncode": returncode,
              "tests_run": None, "terminal_seconds": None, "skipped": None, "failures": None, "errors": None,
              "terminal_status": None, "zero_skip_gate_pass": False}
    if match is None:
        return result
    result.update(tests_run=int(match[1]), terminal_seconds=float(match[2]), terminal_status=match[3],
                  skipped=0, failures=0, errors=0)
    if match[4]:
        for item in match[4].split(", "):
            field = re.fullmatch(r"(skipped|failures|errors)=([0-9]+)", item)
            require(field is not None, "unrecognized unittest terminal field")
            result[field[1]] = int(field[2])
    result["zero_skip_gate_pass"] = (returncode == 0 and result["tests_run"] > 0 and match[3] == "OK"
        and result["skipped"] == result["failures"] == result["errors"] == 0)
    result["named_skip_rows"] = [{"line": text[:m.start()].count("\n") + 1, "display_name": m[1],
                                  "test_id": m[2], "reason_literal": m[3], "original_line": m[0]}
                                 for m in re.finditer(r"(?m)^(.*?) \((.*?)\) \.\.\. skipped (.*)$", text)]
    return result


def source_tree_binding(sidecars, snapshot):
    recorded = parse(sidecars["source-snapshot-git-audit.json"])
    proof = parse(sidecars["source-tree-proof.json"])
    require(recorded["source_commit"] == proof["source_commit"] == CANDIDATE
            and recorded["source_tree"] == proof["root_tree"] == TREE, "source tree identity")
    require(recorded["all_match"] is True and recorded["files_checked"] == len(recorded["files"])
            == len(snapshot["files"]), "source audit denominator")
    require({row["path"]: row["sha256"] for row in recorded["files"]} == snapshot["files"]
            and recorded["source_snapshot_sha256"] == snapshot["sha256"] == sha(wire(snapshot["files"])),
            "source snapshot correspondence")
    require(recorded["compiler_sha256"] == COMPILER, "source compiler capture identity")
    raw_commit = base64.b64decode(proof["commit_object_base64"], validate=True)
    require(sha1(b"commit " + str(len(raw_commit)).encode() + b"\0" + raw_commit).hexdigest() == CANDIDATE
            and raw_commit.splitlines()[0] == ("tree " + TREE).encode(), "Git commit/root tree object")
    trees = {}
    for oid, encoded in proof["tree_objects_base64"].items():
        raw = base64.b64decode(encoded, validate=True)
        require(sha1(b"tree " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == oid, "Git tree object digest")
        entries, offset = {}, 0
        while offset < len(raw):
            zero = raw.index(b"\0", offset)
            mode, name = raw[offset:zero].split(b" ", 1)
            require(zero + 21 <= len(raw), "Git tree truncation")
            name = name.decode()
            require(name not in entries and name not in (".", "..") and "/" not in name, "Git tree entry name")
            entries[name] = (mode.decode(), raw[zero + 1:zero + 21].hex())
            offset = zero + 21
        trees[oid] = entries
    require(set(proof["source_blobs"]) == set(snapshot["files"]), "Git source path denominator")
    used = set()
    records = {row["path"]: row for row in recorded["files"]}
    for name, blob in proof["source_blobs"].items():
        parts = PurePosixPath(name).parts
        require(parts and not name.startswith("/") and ".." not in parts, "Git source path")
        tree = TREE
        for part in parts[:-1]:
            used.add(tree)
            mode, tree = trees[tree][part]
            require(mode == "40000", "Git source ancestor mode")
        used.add(tree)
        mode, actual = trees[tree][parts[-1]]
        require(mode in ("100644", "100755") and actual == blob == records[name]["git_blob_sha1"],
                "Git source blob identity")
    require(used == set(trees), "source proof tree inventory")
    selected = parse(sidecars["source-identities.json"])
    require(selected["source_commit"] == CANDIDATE, "selected source capture identity")
    sources = {}
    for row in selected["files"]:
        raw = sidecars[row["archived_path"]]
        digest(raw, row, row["git_path"])
        require(sha(raw) == snapshot["files"][row["git_path"]]
                and sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
                == row["git_blob_sha1"] == proof["source_blobs"][row["git_path"]], "selected source bytes/Git binding")
        require(row["git_path"] not in sources, "duplicate selected source")
        sources[row["git_path"]] = raw
    return sources, {"source_commit": CANDIDATE, "source_tree": TREE, "files_checked_at_capture": len(records),
        "source_snapshot_sha256": snapshot["sha256"], "retained_source_files": len(sources), "tree_objects": len(trees),
        "source_path_to_git_blob_proof_verified": True,
        "scope": "selected source bytes verified offline; every source SHA-256 was compared with immutable Git blobs at capture, full source bytes are not duplicated here"}


def assignment(source, name):
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            return node.value
    raise ValueError("source assignment missing: " + name)


def literal(node, context=None):
    context = context or {}
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return context[node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        values = [literal(value, context) for value in node.elts]
        return tuple(values) if isinstance(node, ast.Tuple) else values
    if isinstance(node, ast.Dict):
        result = {}
        for key, value in zip(node.keys, node.values):
            if key is None:
                result.update(literal(value, context))
            else:
                result[literal(key, context)] = literal(value, context)
        return result
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"str", "Path"}
            and len(node.args) == 1 and not node.keywords):
        value = literal(node.args[0], context)
        require(type(value) is str, "nonliteral protocol path")
        return value
    raise ValueError("unsupported data-only protocol expression")


def source_protocols(sources):
    scalar = sources["tools/qualify_llvm_native.py"]
    owned = sources["tools/qualify_llvm_owned.py"]
    hia = sources["tools/qualify_hia_program_perf.py"]
    context = {name: literal(assignment(owned, name)) for name in ("CALLS", "SIZES")}
    context["PROFILE"] = literal(assignment(sources["hepta/llvm_owned_backend.py"], "PROFILE"))
    own_protocol = literal(assignment(owned, "PROTOCOL"), context)
    context = {"ORIGINAL_PROTOCOL": own_protocol}
    for name in ("BUILD_ROOT", "BUILD_PREFIX", "BUILD_SUFFIX_CHARACTERS", "BUILD_LAYOUT"):
        context[name] = literal(assignment(hia, name), context)
    return {"scalar": literal(assignment(scalar, "PROTOCOL")), "owned": own_protocol,
            "hia": literal(assignment(hia, "PROTOCOL"), context)}


def verify_performance_inputs(report, kind, sources):
    require(kind in {"owned", "hia"}, "non-owned input inventory")
    if kind == "hia":
        names = literal(assignment(sources["tools/qualify_hia_program_perf.py"], "INPUTS"))
        source = sources["examples/hia_program/benchmarks.hepta"]
    else:
        # Exact frozen owned INPUTS tuple, including its expanded generator.
        names = ("tools/qualify_llvm_owned.py", "tools/evidence_checks.py", "tools/performance_observation.py",
                 *("examples/llvm_owned/" + name for name in
                   ("owned.hepta", "qualification.hepta", "reference.rs", "driver.c", "observe.c")))
        source = sources["examples/llvm_owned/owned.hepta"] + b"\n" + sources["examples/llvm_owned/qualification.hepta"]
        for field, name in (("handwritten_rust_sha256", "reference.rs"), ("driver_source_sha256", "driver.c"),
                            ("observer_source_sha256", "observe.c")):
            require(report[field] == sha(sources["examples/llvm_owned/" + name]), "owned auxiliary source identity")
    require(same(report["inputs"], {name: sha(sources[name]) for name in names}),
            "owned/HIA frozen input inventory mismatch")
    require(report["source_sha256"] == sha(source), "owned/HIA frozen source identity mismatch")


def hia_retention(report, members):
    retention = report.get("artifact_retention", {})
    if retention.get("retained") is not True:
        return {"retained": False, "reported_status": retention.get("status"),
                "reported_files": len(retention.get("files", {}))}
    prefix = HIA + "performance-artifacts/"
    raw = members[prefix + "artifact-retention.json"]
    require(sha(raw) == retention["manifest_sha256"], "HIA retention manifest identity")
    manifest = parse(raw)
    require(manifest["files"] == retention["files"] and manifest["path_mapping"] == retention["path_mapping"]
            and manifest["build_layout"] == report["build_layout"], "HIA retention correspondence")
    names = {name[len(prefix):] for name in members if name.startswith(prefix)}
    require(names == set(retention["files"]) | {"artifact-retention.json"}, "HIA retained file inventory")
    for name, row in retention["files"].items():
        digest(members[prefix + name], row, name)
        mapping = retention["path_mapping"][name]
        require(mapping == {**row, "original": report["build_layout"]["directory"] + "/" + name,
                "retained": retention["directory"] + "/" + name, "source_and_copy_hashes_verified": True},
                "HIA retained original/copy path mapping")
    identities = {}
    for section in (report.get("artifacts", {}), report.get("resource_observation", {}).get("artifacts", {})):
        for label, row in section.items():
            name = PurePosixPath(row["path"]).name
            digest(members[prefix + name], row, label)
            identities[label] = {"archive_member": prefix + name, **row}
    return {"retained": True, "reported_status": retention["status"], "files": len(retention["files"]),
            "all_bytes_match": True, "measured_and_observed_artifacts": identities,
            "manifest_sha256": retention["manifest_sha256"]}


def artifact_availability(report, inventory):
    by_identity = defaultdict(list)
    for row in inventory:
        if row.get("sha256"):
            by_identity[row["sha256"], row["bytes"]].append(row["path"])
    result = {}
    for label, section in (("artifacts", report.get("artifacts", {})),
                           ("resource_observation", report.get("resource_observation", {}).get("artifacts", {}))):
        for name, identity in section.items():
            result[label + "/" + name] = {"recorded_path": identity.get("path"), "sha256": identity["sha256"],
                "bytes": identity["bytes"], "matching_provider_members": by_identity[identity["sha256"], identity["bytes"]]}
    return result


def review_reports(members, sidecars, inventory):
    full = parse(members[FULL + "release-validation.json"])
    hia = parse(members[HIA + "qualification.json"])
    require(full["schema"] == "hepta.release.v2" and full["source_git_commit"] == CANDIDATE
            and full["compiler_sha256"] == COMPILER, "full report source identity")
    require(hia["schema"] == "hepta.hia.unified-qualification.v1" and hia["git_commit"] == CANDIDATE
            and hia["compiler_tree_sha256"] == COMPILER, "HIA report source identity")
    snapshot = full["source_snapshot"]
    require(snapshot == hia["source_snapshot_before"] == hia["source_snapshot_after"]
            and full["snapshot_unchanged"] is hia["unchanged_source"] is True, "three unchanged source snapshots")
    sources, source_review = source_tree_binding(sidecars, snapshot)
    require(full["whole_project_blockers_closed"] is hia["full_six_deliverables_complete"]
            is hia["full_seven_deliverables_complete"] is False, "whole-project closure claim enlarged")
    workflow = parse(members["artifacts/workflow-source.json"])
    require(workflow["expected_head_sha"] == workflow["checkout_head_sha"] == CANDIDATE, "actual workflow checkout identity")
    require([row["name"] for row in full["gates"]] == full["planned_gates"]
            and len(set(full["planned_gates"])) == len(full["gates"]) == 50, "full gate denominator/order")
    for gate in full["gates"]:
        require(sha(members[gate["log"]]) == gate["log_sha256"], "full gate log identity")
        if gate["status"] == "passed":
            require(gate["exit_code"] == 0, "passing full gate has nonzero process exit")
    for path, row in full["evidence"].items():
        digest(members[path], row, path)
        require(row["fresh"] is True, "stale retained gate evidence")
    full_passed = sum(row["status"] == "passed" for row in full["gates"])
    require(full["status"] == ("passed" if full_passed == 50 else "failed"), "full aggregate status differs")
    unit_gate = full["gates"][0]
    full_unit = terminal_unit(members[unit_gate["log"]], unit_gate.get("exit_code"))
    require(unit_gate["name"] == "unit_and_integration"
            and (unit_gate["status"] == "passed") is full_unit["zero_skip_gate_pass"], "full unit zero-skip rule")
    require(unit_gate["test_count"] == (full_unit["tests_run"] if full_unit["zero_skip_gate_pass"] else 0),
            "strict accepted unit denominator versus actual terminal count")
    full_unit["collector_test_count"] = unit_gate["test_count"]
    full_unit["collector_skipped"] = unit_gate["skipped"]
    require([row["name"] for row in hia["gates"]] == hia["planned_gates"]
            and len(set(hia["planned_gates"])) == len(hia["gates"]) == hia["completed_gates"] == 15,
            "HIA gate denominator/order")
    linked = sizes = 0
    for gate in hia["gates"]:
        for field in ("evidence", "stdout", "stderr"):
            if field in gate:
                row = gate[field]
                digest(members[HIA + row["path"]], row, row["path"])
                linked += 1
                sizes += "bytes" in row
        if gate["name"] != "unit_regression" and "evidence" in gate:
            payload = parse(members[HIA + gate["evidence"]["path"]])
            require(gate["evidence"]["status"] == payload.get("status")
                    and gate["evidence"]["ok"] is payload.get("ok"), "HIA producer status linkage")
            expected = gate["returncode"] == 0 and (payload.get("ok") is True
                or (gate["name"] == "legacy_cortex_m4_qemu" and payload.get("status") == "passed"))
            require(gate["passed"] is expected, "HIA producer acceptance differs")
    hia_unit_gate = hia["gates"][0]
    hia_unit = terminal_unit(members[HIA + hia_unit_gate["stderr"]["path"]], hia_unit_gate["returncode"])
    require(hia_unit_gate["name"] == "unit_regression" and hia_unit_gate["passed"] is hia_unit["zero_skip_gate_pass"]
            and all(hia_unit_gate[key] == hia_unit[key] for key in ("tests_run", "skipped", "failures", "errors")),
            "HIA unit terminal/collector denominator")
    hia_passed = sum(gate["passed"] for gate in hia["gates"])
    require(hia["passed_gates"] == hia_passed and hia["ok"] is (hia_passed == 15)
            and hia["status"] == ("all_scoped_gates_passed" if hia_passed == 15 else "scoped_gates_not_all_qualified"),
            "HIA aggregate status differs")
    protocols = source_protocols(sources)
    performance = {}
    for kind, path in PERFORMANCES.items():
        if path not in members:
            performance[kind] = {"report_present": False, "observed_raw_samples": None,
                "independent_review": {"applicable": False, "reason": "no original report was retained; no sample count or result is inferred"}}
            continue
        report = parse(members[path])
        require(report.get("git_commit") in (None, "", CANDIDATE), "performance report belongs to another candidate")
        state = {"report_present": True, "phase": report.get("phase"), "status": report.get("status"), "ok": report.get("ok"),
                 "observed_raw_samples": len(report["raw_samples"]) if "raw_samples" in report else None,
                 "report_sha256": sha(members[path])}
        if report.get("phase") == "complete":
            require(report["git_commit"] == CANDIDATE and report["compiler_tree_sha256"] == COMPILER
                    and same(protocols[kind], report["protocol"]), "performance source/protocol mismatch")
            if kind == "scalar":
                require(report["qualifier_sha256"] == sha(sources["tools/qualify_llvm_native.py"])
                        and report["process_observer_sha256"] == sha(sources["tools/performance_observation.py"]),
                        "scalar qualifier/observer input mismatch")
                for field, name in (("source_sha256", "SOURCE"), ("driver_source_sha256", "DRIVER")):
                    require(report[field] == sha(literal(assignment(sources["tools/qualify_llvm_native.py"], name)).encode()),
                            "scalar frozen source input mismatch")
            else:
                verify_performance_inputs(report, kind, sources)
            state["independent_review"] = audit_performance(report, kind)
        else:
            state["independent_review"] = {"applicable": False, "reason": "original attempt is incomplete; no complete inventory is inferred"}
        state["artifact_availability"] = artifact_availability(report, inventory)
        if kind == "hia":
            state["artifact_retention"] = hia_retention(report, members)
        performance[kind] = state
    sandbox = parse(members[FULL + "sandbox.json"])
    return {"schema": "hepta.ci-independent-report-review.v1", "source_commit": CANDIDATE,
        "source_identity": source_review,
        "full_source": {"status": full["status"], "planned_gates": 50, "completed_gates": len(full["gates"]),
            "passed_gates": full_passed, "failed_gates": [row["name"] for row in full["gates"] if row["status"] != "passed"],
            "linked_gate_logs": len(full["gates"]), "linked_evidence_files": len(full["evidence"]), "unit": full_unit,
            "sandbox": {key: sandbox.get(key) for key in ("status", "qualified", "error", "checks")}},
        "hia": {"status": hia["status"], "planned_gates": 15, "completed_gates": len(hia["gates"]),
            "passed_gates": hia_passed, "failed_gates": [row["name"] for row in hia["gates"] if not row["passed"]],
            "linked_evidence_or_log_files": linked, "linked_log_byte_counts": sizes, "unit": hia_unit},
        "performance": performance, "native_execution_repeated": False, "performance_remeasured": False,
        "source_current_checkout_used_as_tested_tree": False, "whole_project_blockers_closed": False,
        "scope": "fixed candidate report identity, source/Git capture, arithmetic and retained outputs; no general language or arbitrary-producer execution authentication"}
