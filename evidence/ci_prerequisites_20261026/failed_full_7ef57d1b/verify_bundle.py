#!/usr/bin/env python3
"""Check this immutable CI archive as data; never extract, import, or run its code."""
import argparse
import base64
from collections import Counter
import hashlib
import io
import json
import math
from pathlib import Path, PurePosixPath
import re
import statistics
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parent
COMMIT = "7ef57d1b380e73269f592fa26fe95f9636c88586"
PREFIX = "artifacts/hia-unified/"
BACKENDS = ("rust", "llvm", "handwritten_rust")
KERNELS = ("full_lifecycle", "constructor_error", "two_stage")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def safe(name):
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and ".." not in path.parts
            and "\\" not in name and str(path) == name, "unsafe path: " + name)
    return name


def local(name):
    path = ROOT / safe(name)
    require(path.is_file() and not path.is_symlink(), "missing ordinary sidecar: " + name)
    return path.read_bytes()


def read(name):
    return json.loads(local(name))


def identity(raw, record, label):
    require(sha(raw) == record["sha256"], "SHA-256 mismatch: " + label)
    if "bytes" in record:
        require(len(raw) == record["bytes"], "byte count mismatch: " + label)


def near(actual, expected, label):
    require(math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-15), label)


def processes(value):
    if isinstance(value, dict):
        fields = {"command", "returncode", "stdout", "stderr", "stdout_sha256", "stderr_sha256"}
        if fields <= value.keys():
            yield value
        for child in value.values():
            yield from processes(child)
    elif isinstance(value, list):
        for child in value:
            yield from processes(child)


def verify_archive(original_zip=None):
    manifest = read("MANIFEST.json")
    require(manifest["source_commit"] == COMMIT, "wrong source commit")
    for item in manifest["sidecar_files"]:
        identity(local(item["path"]), item, item["path"])
    archive = manifest["archive"]
    pieces = []
    for part in archive["parts"]:
        raw = local(part["path"])
        require(len(raw) <= 3_500_000 and raw.isascii(), "part exceeds ASCII limit")
        identity(raw, part, part["path"])
        pieces.append(raw)
    encoded = b"".join(pieces)
    require(len(encoded) == archive["encoded_bytes"] <= 16_000_000, "encoded bound")
    require(sha(encoded) == archive["encoded_sha256"], "encoded identity")
    packed = base64.b64decode(b"".join(encoded.split()), validate=True)
    require(len(packed) == archive["decoded_bytes"] and sha(packed) == archive["sha256"],
            "archive identity")
    expected = {item["path"]: item for item in manifest["members"]}
    require(len(expected) == len(manifest["members"]) == 1306, "manifest member count")
    members = {}
    with tarfile.open(fileobj=io.BytesIO(packed), mode="r|xz") as stream:
        total = 0
        for item in stream:
            name = safe(item.name)
            require(item.isfile() and name.startswith("artifacts/") and name not in members,
                    "nonordinary or duplicate archive member")
            require(name in expected and 0 <= item.size <= 32_000_000, "member bound")
            total += item.size
            require(total <= 256_000_000 and len(members) < 1400, "archive total bound")
            raw = stream.extractfile(item).read()
            identity(raw, expected[name], name)
            require(item.mode == expected[name]["mode"], "archive mode mismatch")
            members[name] = raw
    require(set(members) == set(expected) and total == manifest["uncompressed_member_bytes"],
            "incomplete archive")
    native = {name: raw for name, raw in members.items() if raw.startswith(b"\x7fELF")}
    require(len(native) == 176 and sum(map(len, native.values())) == 110_401_880, "ELF inventory")
    for name, item in expected.items():
        require((item.get("native_format") == "ELF") == (name in native), "ELF label")

    inventory = read("zip-inventory.json")
    require(inventory["source_commit"] == COMMIT, "ZIP inventory source")
    entries = {item["path"]: item for item in inventory["members"]}
    require(len(entries) == len(inventory["members"]) == 3394, "ZIP member count")
    counts = Counter((v["kind"], v.get("classification")) for v in entries.values())
    require(counts == {("artifacts", "added_by_run"): 1306,
                       ("artifacts", "unchanged_from_source"): 89,
                       ("evidence", None): 1999}, "ZIP selection counts")
    selected = {name for name, item in entries.items() if item.get("classification") == "added_by_run"}
    require(selected == set(members), "selected ZIP inventory mismatch")
    for name, raw in members.items():
        identity(raw, entries[name], name)
        require(expected[name]["origin"] == {"artifact_id": 12704884741,
                "classification": "added_by_run", "zip_member": name}, "member provenance")

    provider = read("provider-observation.json")
    zip_identity = read("zip-identity.json")
    require(zip_identity == manifest["original_zip"], "ZIP manifest identity")
    artifact = provider["artifact_metadata"]["artifacts"][0]
    require(artifact["id"] == 12704884741 and artifact["workflow_run"]["head_sha"] == COMMIT
            and artifact["workflow_run"]["id"] == 40435880235, "provider artifact identity")
    require(artifact["digest"] == "sha256:" + zip_identity["sha256"]
            and artifact["size_in_bytes"] == zip_identity["bytes"] == 76_482_230, "provider ZIP digest")
    job = provider["job_metadata"]["jobs"][0]
    require(job["id"] == 121964313186 and job["run_id"] == 40435880235
            and job["status"] == "completed" and job["conclusion"] == "failure", "provider job")
    steps = {step["number"]: step["conclusion"] for step in job["steps"]}
    require(all(steps[n] == "success" for n in (7, 8, 9, 10, 11, 14))
            and (steps[12], steps[13]) == ("failure", "failure"), "provider steps")
    if original_zip:
        zipped = Path(original_zip).read_bytes()
        identity(zipped, zip_identity, "provider ZIP")
        with zipfile.ZipFile(io.BytesIO(zipped)) as stream:
            files = [item for item in stream.infolist() if not item.is_dir()]
            require(len(files) == len(entries) and {i.filename for i in files} == set(entries), "ZIP contents")
            for item in files:
                meta = entries[item.filename]
                require(item.file_size == meta["bytes"] and item.external_attr == meta["zip_external_attr"],
                        "ZIP metadata mismatch")
                if meta["kind"] == "artifacts":
                    raw = stream.read(item)
                    identity(raw, meta, item.filename)
                    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
                    require(blob == meta["git_blob_sha1"], "ZIP Git blob mismatch")
                    if item.filename in members:
                        require(raw == members[item.filename], "ZIP retained bytes mismatch")
                    else:
                        require(blob == meta["source_git_blob_sha1"], "unchanged tracked artifact identity")
    for item in read("original-copies.json"):
        raw = local(item["path"])
        identity(raw, item, item["path"])
        require(raw == members[item["archive_member"]], "raw convenience copy differs")

    return manifest, members, entries, provider


def dictionaries(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from dictionaries(child)
    elif isinstance(value, list):
        for child in value:
            yield from dictionaries(child)


def verify_performance(perf, name, members):
    scalar = name == "scalar_native"
    hia = name == "hia"
    kernels = ("signed_walk", "unsigned_walk", "branch_accumulate") if scalar else KERNELS
    backends = ("rust", "llvm") if scalar else BACKENDS
    sample_count = 42 if scalar else 63
    require(perf["git_commit"] == COMMIT and perf["phase"] == "complete"
            and perf["status"] == "passed" and perf["ok"] is True, name + " terminal identity")
    protocol, evaluation = perf["protocol"], perf["evaluation"]
    require(sha(wire(protocol)) == perf["protocol_sha256"], name + " protocol hash")
    require(evaluation["ok"] is True and evaluation["status"] == "passed"
            and evaluation["measurement_quality_failures"] == []
            and evaluation["performance_threshold_failures"] == [], name + " evaluation")
    require(protocol["paired_groups"] == 7 and protocol["maximum_relative_mad"] == 0.05
            and protocol["maximum_kernel_paired_time_ratio"] == 1.2
            and protocol["maximum_geometric_mean_paired_time_ratio"] == 1.1
            and protocol["minimum_sample_seconds"] == 0.05, name + " fixed thresholds")
    samples = perf["raw_samples"]
    require(len(samples) == sample_count and [s["sample_index"] for s in samples] == list(range(sample_count)),
            name + " sample inventory")
    cells = {(s["group"], s["kernel"], s["backend"]): s for s in samples}
    require(len(cells) == sample_count and set(cells) ==
            {(g, k, b) for g in range(7) for k in kernels for b in backends}, name + " paired inventory")
    for sample in samples:
        duration = sample["elapsed_ns"] / 1e9
        require(duration >= protocol["minimum_sample_seconds"], name + " minimum duration")
        if "maximum_sample_seconds" in protocol:
            require(duration <= protocol["maximum_sample_seconds"], name + " maximum duration")
        if not scalar:
            require(sample["execution"]["returncode"] == 0, name + " timed process")
            for key, value in json.loads(sample["execution"]["stdout"]).items():
                require(sample[key] == value, name + " original stdout correspondence")
            library = sample["backend"] if hia else sample["backend"] + "_library"
            driver = "driver" if hia else "driver_binary"
            require(sample["library_sha256"] == perf["artifacts"][library]["sha256"]
                    and sample["driver_sha256"] == perf["artifacts"][driver]["sha256"], name + " measured identities")
    baselines = ("rust",) if scalar else ("rust", "handwritten_rust")
    ratios_by_baseline = {baseline: [] for baseline in baselines}
    max_mad = 0.0
    for kernel in kernels:
        summary = evaluation["summary"][kernel]
        for backend in backends:
            times = [cells[g, kernel, backend]["elapsed_ns"] for g in range(7)]
            median = statistics.median(times)
            mad = statistics.median(abs(t - median) for t in times) / median
            row = summary["implementations"][backend]
            require(row["samples_ns"] == times and row["median_ns"] == median
                    and row["minimum_ns"] == min(times) and row["maximum_ns"] == max(times), name + " sample statistics")
            near(mad, row["relative_mad"], name + " MAD")
            require(mad <= protocol["maximum_relative_mad"], name + " MAD limit")
            denominator = protocol["native_calls_per_sample"] * protocol["kernel_iterations"] if scalar else protocol["native_calls_per_sample"][kernel]
            field = "median_ns_per_kernel_iteration" if scalar else "median_ns_per_native_call"
            near(median / denominator, row[field], name + " timing denominator")
            max_mad = max(max_mad, mad)
        for baseline in baselines:
            paired = [cells[g, kernel, "llvm"]["elapsed_ns"] / cells[g, kernel, baseline]["elapsed_ns"] for g in range(7)]
            row = summary if scalar else summary["comparisons"][baseline]
            require(paired == row["paired_time_ratios"], name + " paired ratios")
            median = statistics.median(paired)
            near(median, row["median_paired_time_ratio"], name + " paired median")
            require(median <= protocol["maximum_kernel_paired_time_ratio"], name + " kernel threshold")
            ratios_by_baseline[baseline].append(median)
    geomeans = {}
    for baseline, ratios in ratios_by_baseline.items():
        value = math.exp(statistics.mean(math.log(r) for r in ratios))
        expected = evaluation["geometric_mean_paired_time_ratio"] if scalar else evaluation["geometric_mean_paired_time_ratios"][baseline]
        near(value, expected, name + " geometric mean")
        require(value <= protocol["maximum_geometric_mean_paired_time_ratio"], name + " geometric threshold")
        geomeans[baseline] = value
    correctness = perf["correctness"]
    require(correctness["status"] == "passed_finite_domain", name + " correctness status")
    if hia:
        observations = correctness["observations"]
        require(len(observations) == correctness["native_calls"] == 588
                and correctness["process"]["returncode"] == 0, "HIA correctness terminal")
        require(observations == [json.loads(line) for line in correctness["process"]["stdout"].splitlines()]
                and all(x["actual"] == x["expected"] for x in observations)
                and sha(wire(observations)) == correctness["observations_sha256"], "HIA actual observations")
    else:
        count, calls = (186, 372) if scalar else (196, 784)
        require(len(correctness["cases"]) == correctness["case_count"] == count
                and correctness["native_calls"] == calls and "observations" not in correctness,
                name + " reported correctness domain and limited retention")
    process_rows = list(processes(perf))
    expected_processes = 0 if scalar else 71 if hia else 70
    require(len(process_rows) == expected_processes, name + " complete process inventory")
    for row in process_rows:
        for field in ("stdout", "stderr"):
            require(sha(row[field].encode()) == row[field + "_sha256"], name + " process stream hash")
    if not scalar:
        require(Counter(row["returncode"] for row in process_rows) == {0: expected_processes - 1, 1: 1},
                name + " process returncodes")
        observer = perf["resource_observation"]
        require(observer["positive"]["returncode"] == 0 and observer["negative"]["returncode"] == 1
                and json.loads(observer["positive"]["stdout"]) == {"allocations": 7, "frees": 7, "live": 0, "refusals": 1}
                and json.loads(observer["negative"]["stdout"]) == {"allocations": 7, "frees": 0, "live": 7, "refusals": 1},
                name + " expected positive/negative resource controls")
    telemetry = perf.get("process_observations", [])
    require(len(telemetry) == (0 if hia else sample_count)
            and all(row["state"] == "complete" and row["capture_exception"] is None for row in telemetry),
            name + " telemetry terminal")
    raw_telemetry = [row for row in dictionaries(telemetry) if {"raw", "raw_sha256"} <= row.keys()]
    require(len(raw_telemetry) == (0 if hia else sample_count * 6), name + " raw telemetry count")
    for row in raw_telemetry:
        require(sha(row["raw"].encode()) == row["raw_sha256"], name + " raw telemetry hash")
    if hia:
        retention = perf["artifact_retention"]
        require(retention["status"] == "complete" and retention["retained"] is True
                and len(retention["files"]) == 16, "HIA retained outputs")
        prefix = PREFIX + "performance-artifacts/"
        raw = members[prefix + "artifact-retention.json"]
        require(sha(raw) == retention["manifest_sha256"], "HIA retention manifest hash")
        retained = json.loads(raw)
        require(retained["files"] == retention["files"] and retained["path_mapping"] == retention["path_mapping"],
                "HIA retention mapping")
        for path, item in retention["files"].items():
            identity(members[prefix + safe(path)], item, "retained " + path)
        for section in (perf["artifacts"], perf["resource_observation"]["artifacts"]):
            for item in section.values():
                identity(members[prefix + PurePosixPath(item["path"]).name], item, "measured HIA binary")
        require(perf["interference_observations"]["samples_excluded"] == 0
                and perf["interference_observations"]["acceptance_thresholds_adjusted"] is False,
                "HIA unadjusted protocol")
    else:
        require("artifact_retention" not in perf, name + " retention scope unchanged")
    return {"raw_samples": sample_count, "reported_correctness_calls": correctness["native_calls"],
            "actual_correctness_observations_retained": hia, "complete_process_records": len(process_rows),
            "stream_hashes": len(process_rows) * 2, "raw_telemetry_hashes": len(raw_telemetry),
            "maximum_observed_relative_mad": max_mad, "geometric_mean_paired_ratios": geomeans,
            "complete_binary_retention": hia}


def verify(original_zip=None):
    manifest, members, entries, provider = verify_archive(original_zip)
    diagnosis = read("diagnosis.json")
    log = local("job-121964313186.log")
    identity(log, diagnosis["job_log"], "complete job log")
    require(len(log.decode().splitlines()) == diagnosis["job_log"]["lines"] == 1378, "job log lines")
    full = json.loads(members["artifacts/candidate/release-validation.json"])
    hia = json.loads(members[PREFIX + "qualification.json"])
    require(full["source_git_commit"] == hia["git_commit"] == COMMIT, "aggregate source commit")
    require(full["status"] == "failed" and len(full["planned_gates"]) == len(full["gates"]) == 50
            and sum(g["status"] == "passed" for g in full["gates"]) == 48, "full gate terminal")
    require([g["name"] for g in full["gates"] if g["status"] != "passed"]
            == ["unit_and_integration", "strict_namespace_execution"], "full failure names")
    for gate in full["gates"]:
        require(sha(members[safe(gate["log"])]) == gate["log_sha256"], "full gate log hash")
    require(len(full["evidence"]) == 43, "full linked reports")
    for name, row in full["evidence"].items():
        identity(members[safe(name)], row, name)
    unit = members["artifacts/candidate/unit_and_integration.log"].decode()
    require(re.search(r"Ran 2099 tests in 582\.709s\n\nOK \(skipped=15\)\n*\Z", unit), "full unit terminal")
    require(full["gates"][0]["exit_code"] == 0 and full["gates"][0]["test_count"] == 0
            and full["gates"][0]["skipped"] == 15, "strict unit acceptance differs from executed test count")
    named = read("named-source-unit-skips.json")
    actual = []
    for number, line in enumerate(unit.splitlines(), 1):
        match = re.match(r"^(.*?) \((.*?)\) \.\.\. skipped (.*)$", line)
        if match:
            actual.append({"line": number, "display_name": match[1], "test_id": match[2],
                           "reason_literal": match[3], "original_line": line})
    require(actual == named["named_skip_rows"] and len(actual) == 15
            and sha(unit.encode()) == named["original_log_sha256"], "exact named source skips")
    sandbox = json.loads(members["artifacts/candidate/sandbox.json"])
    require(sandbox["qualified"] is False and sandbox["error"]["type"] == "PermissionError"
            and sandbox["error"] == diagnosis["full_source"]["sandbox"]["error"]
            and sandbox["checks"]["startup"]["status"] == "passed"
            and sum(v["status"] == "not_run" for v in sandbox["checks"].values()) == 9,
            "sandbox qualification error and reported states")
    require(hia["completed_gates"] == len(hia["gates"]) == len(hia["planned_gates"]) == 15
            and hia["passed_gates"] == sum(g["passed"] for g in hia["gates"]) == 14
            and hia["ok"] is False and [g["name"] for g in hia["gates"] if not g["passed"]] == ["unit_regression"],
            "HIA gate terminal")
    hu = hia["gates"][0]
    require((hu["tests_run"], hu["failures"], hu["errors"], hu["skipped"], hu["returncode"])
            == (2102, 0, 0, 2, 0), "HIA unit acceptance")
    require(re.search(rb"Ran 2102 tests in 586\.083s\n\nOK \(skipped=2\)\n?\Z",
                      members[PREFIX + "unit_regression.stderr.log"]), "HIA quiet unit terminal")
    linked = sized = 0
    for gate in hia["gates"]:
        for field in ("evidence", "stdout", "stderr"):
            if field in gate:
                row = gate[field]
                identity(members[PREFIX + safe(row["path"])], row, row["path"])
                linked += 1
                sized += "bytes" in row
    require((linked, sized) == (44, 30), "HIA links and log sizes")
    snapshot = full["source_snapshot"]
    require(snapshot == hia["source_snapshot_before"] == hia["source_snapshot_after"]
            and full["snapshot_unchanged"] is True and hia["unchanged_source"] is True
            and len(snapshot["files"]) == 922 and sha(wire(snapshot["files"])) == snapshot["sha256"],
            "three exact source snapshots")
    audit = read("source-snapshot-git-audit.json")
    require(audit["source_commit"] == COMMIT and audit["all_match"] is True
            and audit["files_checked"] == len(audit["files"]) == 922
            and {r["path"]: r["sha256"] for r in audit["files"]} == snapshot["files"], "recorded Git blob audit")
    source = read("source-identities.json")
    require(source["source_commit"] == COMMIT, "selected source commit")
    for row in source["files"]:
        raw = local(row["archived_path"])
        identity(raw, row, row["git_path"])
        require(sha(raw) == snapshot["files"][row["git_path"]]
                and hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
                == row["git_blob_sha1"], "selected immutable source bytes")
    performance = {}
    byhash = {}
    for name, entry in entries.items():
        if "sha256" in entry:
            byhash.setdefault(entry["sha256"], []).append(name)
    paths = {"scalar_native": "artifacts/candidate/llvm_native.json",
             "owned": "artifacts/candidate/llvm_owned.json", "hia": PREFIX + "performance.json"}
    for name, path in paths.items():
        perf = json.loads(members[path])
        require(perf["compiler_tree_sha256"] == hia["compiler_tree_sha256"] == full["compiler_sha256"],
                name + " compiler identity")
        performance[name] = verify_performance(perf, name, members)
        derived = diagnosis["performance"][path]
        require(derived["raw_samples"] == performance[name]["raw_samples"], "diagnosis sample count")
        for field, section in [("recorded_artifact_availability", perf["artifacts"]),
                               ("observer_artifact_availability", perf.get("resource_observation", {}).get("artifacts", {}))]:
            require(set(derived[field]) == set(section), "artifact availability inventory")
            for artifact, item in section.items():
                require(derived[field][artifact]["sha256"] == item["sha256"]
                        and derived[field][artifact]["matching_provider_artifact_members"] == byhash.get(item["sha256"], []),
                        "actual binary availability in provider ZIP")
    return {"verified": True, "source_commit": COMMIT, "original_zip_rechecked": original_zip is not None,
            "new_original_files": len(members), "new_original_bytes": manifest["uncompressed_member_bytes"],
            "elf_files": 176, "full_gates": {"completed": 50, "passed": 48},
            "hia_gates": {"completed": 15, "passed": 14}, "named_source_skips": len(actual),
            "source_test_count": 2099, "source_skips": 15, "hia_test_count": 2102, "hia_skips": 2,
            "source_snapshot_files": 922, "full_linked_files": 93, "hia_linked_files": linked,
            "performance": performance, "native_execution_repeated": False,
            "scope": "Archive identity and arithmetic replay; actual native observations are not regenerated."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-zip", type=Path, help="optionally recheck the separately downloaded provider ZIP")
    args = parser.parse_args()
    print(json.dumps(verify(args.original_zip), indent=2, sort_keys=True))
