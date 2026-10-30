#!/usr/bin/env python3
"""Offline, read-only verification. Never extract or execute archive contents."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

HEAD = "50c4067399989e7194028576c38c0e783b78cf06"
OLD_HEAD = "ba267bf824a0f978f86b2003c8e4f0e9f70935ce"
CONTRACT = "591573c769ad36061b00ac91b3ab780daa448074909d559c78f23eac32776cb5"
MAX_TOTAL = 2 * 1024**3
MAX_FILE = 256 * 1024**2
MAX_JSON = 16 * 1024**2
MAX_MEMBERS = 20000
GATES = ["actual_tools_and_linux_seals", "ranking_bridge_identity",
         "recursive_bridge_identity", "finite_bridge_identity", "stream_bridge_identity",
         "rust_resource_crate", "full_regression", "merge_and_profile_coverage"]
RUNS = ["integrated-final-20261030", "integrated-run02-20261030",
        "integrated-run03-20261030", "integrated-run04-20261030"]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest_file(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse_json(raw):
    require(len(raw) <= MAX_JSON, "JSON size limit")
    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def safe_name(name):
    require(type(name) is str and name and len(name) <= 255, "bounded member name required")
    require(not name.startswith("/") and "\\" not in name and ":" not in name,
            "absolute/platform-specific member name refused")
    require(str(PurePosixPath(name)) == name and all(x not in ("", ".", "..") for x in name.split("/")),
            "noncanonical member path refused")
    require(all(ord(x) >= 32 for x in name), "control character in member name")


def member(relative):
    return "workspace/" + relative


def check_full_methods(execution, count):
    stderr = execution["stderr"]
    matches = list(re.finditer(r"(?m)^test\w+ \(((?:tests\.)?test_[^\s)]+)\)", stderr))
    identifiers = {m.group(1).removeprefix("tests.") for m in matches}
    require(len(matches) == len(identifiers) == count, "full-regression method denominator mismatch")
    for i, match in enumerate(matches):
        block = stderr[match.start():matches[i + 1].start() if i + 1 < len(matches) else len(stderr)]
        block = re.split(r"(?m)^(?:setUpClass|tearDownClass|setUpModule|tearDownModule) \(|^={20,}|^-{20,}",
                         block, maxsplit=1)[0].rstrip()
        require(block.endswith("ok"), "executed method did not finish ok: " + match.group(1))
    return identifiers


def core_checks(manifest, records, raw):
    def data(relative):
        key = member(relative)
        require(key in raw, "required report missing: " + relative)
        return parse_json(raw[key])

    reports = []
    for i, name in enumerate(RUNS):
        report = data(name + "/qualification.json")
        execution = data(name + "/full_regression-execution.json")
        require(report["source_before"] == report["source_after"] and report["source_unchanged"] is True,
                "source drift in " + name)
        require(report["source_before"]["head"] == (OLD_HEAD if i == 0 else HEAD), "wrong measured source")
        require(report["external_inventory_before"] == report["external_inventory_after"]
                and report["external_inputs_unchanged"] is True, "external inventory drift")
        require([gate["name"] for gate in report["gates"]] == GATES, "gate order differs")
        require(report["gates"][6] == execution, "standalone/embedded full result differs")
        if i < 2:
            stop = data(name + "/intentional-interruption.json")
            require(report["ok"] is False and report["status"] == "integration_qualification_failed",
                    "interrupted run relabelled")
            require(execution["tests_run"] is None and execution["passed"] is False
                    and execution["execution"]["returncode"] == -2 and stop["qualified"] is False,
                    "interrupted run received a completed denominator")
        elif i == 2:
            require(report["ok"] is False and execution["tests_run"] == 4178
                    and execution["errors"] == 1 and execution["failures"] == execution["skipped"] == 0,
                    "run03 failure/denominator changed")
            require("ERROR: setUpClass (test_system_board.SystemBoardTests)" in execution["execution"]["stderr"],
                    "original board setup failure missing")
            check_full_methods(execution["execution"], 4178)
        else:
            require(report["ok"] is True and report["status"] == "bounded_integrated_contracts_passed"
                    and all(g["passed"] is True for g in report["gates"]), "run04 did not pass every gate")
            require(execution["tests_run"] == 4183 and execution["errors"] == execution["failures"] == execution["skipped"] == 0
                    and execution["execution"]["returncode"] == 0, "run04 outcome differs")
            require(re.search(r"\nRan 4183 tests in [0-9.]+s\n\nOK\n\Z", execution["execution"]["stderr"]),
                    "run04 raw footer differs")
            identifiers = check_full_methods(execution["execution"], 4183)
            require(sum(x.startswith("test_system_board.SystemBoardTests.") for x in identifiers) == 5,
                    "board class methods missing")
            rust = report["gates"][5]
            require(rust["tests_run"] == 109 and rust["failures"] == rust["skipped"] == rust["filtered_out"] == 0,
                    "Rust denominator differs")
            rust_text = rust["execution"]["stdout"] + rust["execution"]["stderr"]
            summaries = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", rust_text)
            require(sum(int(x[0]) for x in summaries) == 109
                    and all(all(int(v) == 0 for v in x[1:]) for x in summaries), "Rust raw summaries differ")
            coverage = report["gates"][7]
            modules = {m for group in coverage["groups"].values() for m in group}
            selected = {s for group in coverage["groups"].values() for values in group.values() for s in values}
            require(len(coverage["groups"]) == 72 and len(modules) == 179 and len(selected) == 1763
                    and not coverage["missing_modules"] and selected <= identifiers, "critical coverage differs")
        reports.append(report)

    full = reports[-1]
    matrix = data("integrated-safety-50c40673/qualification.json")
    launch = data("integrated-safety-50c40673/MATRIX_LAUNCH.json")
    outer = data("integrated-safety-50c40673/OUTER_CAPTURE_PARTIAL.json")
    external = data("integrated-safety-50c40673/EXTERNALS_AFTER_MATRIX.json")
    require(matrix["status"] == "passed" and matrix["tests_run"] == matrix["expected_tests"] == 364,
            "matrix outcome/denominator differs")
    require(len(matrix["tests"]) == 364 and all(x["status"] == "passed" for x in matrix["tests"].values()),
            "matrix selected method did not pass")
    contract_wire = json.dumps(matrix["contract"], sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    require(hashlib.sha256(contract_wire).hexdigest() == matrix["contract_sha256"] == matrix["reviewed_contract_sha256"] == CONTRACT,
            "reviewed contract pin differs")
    selectors = {s for row in matrix["contract"]["capabilities"] for s in row["regression_selectors"]}
    require(set(matrix["tests"]) == selectors and len(matrix["capabilities"]) == 39
            and len({c["id"] for c in matrix["capabilities"]}) == 39
            and all(c["regression_evidence_passed"] is True and c["soundness_or_refinement_proof_established_by_this_run"] is False
                    for c in matrix["capabilities"]), "matrix capability coverage differs")
    require(re.search(r"\nRan 364 tests in [0-9.]+s\n\nOK\n\Z", matrix["log"]), "matrix raw footer differs")
    require(matrix["source_before"] == matrix["source_after"] and matrix["source_stable"] is True
            and matrix["head_before"]["stdout"].strip() == matrix["head_after"]["stdout"].strip() == HEAD,
            "matrix source drift")
    full_sha = records[member(RUNS[-1] + "/qualification.json")]["sha256"]
    matrix_sha = records[member("integrated-safety-50c40673/qualification.json")]["sha256"]
    require(launch["integration_qualification_sha256"] == full_sha
            and launch["configured_environment"] == full["configured_environment"]
            and launch["inherited_tool_environment"] == full["inherited_tool_environment"]
            and launch["test_denominators_must_not_be_added"] is True, "matrix launch binding differs")
    require(outer["outer_diagnostic_stream_complete"] is False
            and outer["authoritative_report_and_unittest_log_complete"] is True
            and manifest["matrix_outer_diagnostic_capture_complete"] is False,
            "partial diagnostic outer capture was promoted to complete")
    require(external["same_observed_inputs"] is True and external["actual"] == external["expected"] == full["external_inventory_after"]
            and external["integration_qualification_sha256"] == full_sha
            and external["matrix_qualification_sha256"] == matrix_sha, "matrix external after-snapshot differs")
    for directory, expected in (("p0-ci-dependencies-20261030", 16076), ("p0-qemu-board-20261030", 396)):
        before = data(directory + "/run04-before.json")
        for filename in ("run04-after.json", "matrix-after.json"):
            after = data(directory + "/" + filename)
            require(before["files"] == after["files"] and len(after["files"]) == expected
                    and after["same_observed_dependencies"] is True, "additional dependency drift")
    pins = {"ranking": "d3c2d760eca5065fc966820379c35c6e8d56e855",
            "recursive": "2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b",
            "finite": "4b6391e116949af0c7e59776baead67271856bdb",
            "stream": "c4a1bbed3a39beba43a6abf1a18b6f75c5725c21"}
    for profile in manifest["bridge_profiles"]:
        receipt = parse_json(raw[profile["receipt"]])
        require(records[profile["binary"]]["sha256"] == receipt["binary_sha256"], "bridge binary differs")
        label = profile["profile"]
        require((receipt["upstream"]["commit"] if label == "ranking" else receipt["identity"]["source_commit"]) == pins[label],
                "bridge source pin differs")
        for binding in profile["source_sets"]:
            for relative, expected in receipt[binding["receipt_key"]].items():
                require(records[binding["member_prefix"] + relative]["sha256"] == expected, "bridge source byte differs")
    require({p["profile"] for p in manifest["bridge_profiles"]} == set(pins), "missing bridge profile")
    return {"full_regression": 4183, "rust_resource_crate": 109, "matrix_selectors": 364,
            "matrix_capabilities": 39, "denominators_are_separate": True,
            "historical_failed_runs_preserved": True, "matrix_outer_diagnostic_capture_complete": False,
            "core_reports_consistent": True, "tool_or_environment_closure_proved": False}


def verify(archive, manifest_path, archive_sha256, manifest_sha256):
    for value in (archive_sha256, manifest_sha256):
        require(re.fullmatch(r"[0-9a-f]{64}", value) is not None, "external SHA256 pin required")
    require(digest_file(archive) == archive_sha256, "archive SHA256 mismatch")
    require(digest_file(manifest_path) == manifest_sha256, "manifest SHA256 mismatch")
    manifest = parse_json(Path(manifest_path).read_bytes())
    require(manifest["schema"] == "hepta.offline-evidence-manifest.v1"
            and manifest["frozen_source_head"] == HEAD, "manifest scope differs")
    rows = manifest["members"]
    require(type(rows) is list and 0 < len(rows) <= MAX_MEMBERS, "member count bound")
    records = {}
    for row in rows:
        safe_name(row["name"])
        require(row["name"] not in records, "duplicate manifest member")
        require(type(row["bytes"]) is int and 0 <= row["bytes"] <= MAX_FILE, "member size bound")
        require(re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None, "member digest required")
        records[row["name"]] = row
    total = sum(r["bytes"] for r in rows)
    require(total <= MAX_TOTAL and len(rows) == manifest["member_count"]
            and total == manifest["total_member_bytes"], "aggregate denominator bound")
    core_names = set(manifest.get("core_json_members", []))
    require(core_names <= records.keys() and sum(records[n]["bytes"] for n in core_names) <= 128 * 1024**2,
            "core report memory bound")
    seen, raw = set(), {}
    with tarfile.open(archive, "r|xz") as tf:
        for item in tf:
            safe_name(item.name)
            require(item.isfile() and not item.pax_headers and item.name in records and item.name not in seen,
                    "unexpected, duplicated, linked or special archive member")
            row = records[item.name]
            require(item.size == row["bytes"] and item.mode == row["mode"], "member metadata differs")
            digest, count, retained = hashlib.sha256(), 0, bytearray()
            stream = tf.extractfile(item)  # File-like read only; never extracts to the filesystem.
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                count += len(chunk); digest.update(chunk)
                require(count <= row["bytes"], "oversized member")
                if item.name in core_names:
                    require(count <= MAX_JSON, "core JSON size bound")
                    retained.extend(chunk)
            require(count == row["bytes"] and digest.hexdigest() == row["sha256"], "member SHA256 mismatch")
            if item.name in core_names:
                raw[item.name] = bytes(retained)
            seen.add(item.name)
    require(seen == records.keys(), "missing archive member")
    result = {"members_verified": len(seen), "bytes_verified": total, "all_member_sha256_match": True,
              "archive_sha256": archive_sha256, "manifest_sha256": manifest_sha256,
              "no_extraction_performed": True, "no_archive_code_or_binary_executed": True}
    if manifest["bundle_kind"] == "p0":
        result.update(core_checks(manifest, records, raw))
    else:
        require(manifest["bundle_kind"] == "apt_lists", "unknown bundle kind")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    try:
        result = verify(args.archive, args.manifest, args.archive_sha256, args.manifest_sha256)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(json.dumps({"verified": False, "error": str(error)}))
        return 1
    print(json.dumps({"verified": True, **result}, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
