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
COMMIT = "8dcb0d0d8aabfa6bd260305c57344ce15ef72eca"
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


def verify(original_zip=None):
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
    require(len(expected) == len(manifest["members"]) == 570, "manifest member count")
    members = {}
    with tarfile.open(fileobj=io.BytesIO(packed), mode="r|xz") as stream:
        total = 0
        for item in stream:
            name = safe(item.name)
            require(item.isfile() and name.startswith("artifacts/") and name not in members,
                    "nonordinary or duplicate archive member")
            require(name in expected and 0 <= item.size <= 16_000_000, "member bound")
            total += item.size
            require(total <= 64_000_000 and len(members) < 600, "archive total bound")
            raw = stream.extractfile(item).read()
            identity(raw, expected[name], name)
            require(item.mode == expected[name]["mode"], "archive mode mismatch")
            members[name] = raw
    require(set(members) == set(expected) and total == manifest["uncompressed_member_bytes"],
            "incomplete archive")
    native = {name: raw for name, raw in members.items() if raw.startswith(b"\x7fELF")}
    require(len(native) == 58 and sum(map(len, native.values())) == 8_208_592, "ELF inventory")
    for name, item in expected.items():
        require((item.get("native_format") == "ELF") == (name in native), "ELF label")

    inventory = read("zip-inventory.json")
    require(inventory["source_commit"] == COMMIT, "ZIP inventory source")
    entries = {item["path"]: item for item in inventory["members"]}
    require(len(entries) == len(inventory["members"]) == 2647, "ZIP member count")
    counts = Counter((v["kind"], v.get("classification")) for v in entries.values())
    require(counts == {("artifacts", "added_by_run"): 570,
                       ("artifacts", "unchanged_from_source"): 89,
                       ("evidence", None): 1988}, "ZIP selection counts")
    selected = {name for name, item in entries.items() if item.get("classification") == "added_by_run"}
    require(selected == set(members), "selected ZIP inventory mismatch")
    for name, raw in members.items():
        identity(raw, entries[name], name)
        require(expected[name]["origin"] == {"artifact_id": 12704417329,
                "classification": "added_by_run", "zip_member": name}, "member provenance")

    provider = read("provider-observation.json")
    zip_identity = read("zip-identity.json")
    require(zip_identity == manifest["original_zip"], "ZIP manifest identity")
    artifact = provider["artifact_metadata"]["artifacts"][0]
    require(artifact["id"] == 12704417329 and artifact["workflow_run"]["head_sha"] == COMMIT
            and artifact["workflow_run"]["id"] == 40435070810, "provider artifact identity")
    require(artifact["digest"] == "sha256:" + zip_identity["sha256"]
            and artifact["size_in_bytes"] == zip_identity["bytes"] == 32_688_285, "provider ZIP digest")
    job = provider["job_metadata"]["jobs"][0]
    require(job["id"] == 121961684415 and job["run_id"] == 40435070810
            and job["status"] == "completed" and job["conclusion"] == "failure", "provider job")
    steps = {step["number"]: step["conclusion"] for step in job["steps"]}
    require(all(steps[n] == "success" for n in (7, 8, 9, 10, 14))
            and (steps[11], steps[12], steps[13]) == ("failure", "skipped", "failure"), "provider steps")
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

    diagnosis = read("diagnosis.json")
    log = local("job-121961684415.log")
    identity(log, diagnosis["job_log"], "complete job log")
    lines = log.decode().splitlines()
    require(len(lines) == diagnosis["job_log"]["lines"] == 1363, "job line count")
    events = []
    for number, line in enumerate(lines, 1):
        timestamp, _, text = line.partition(" ")
        if text.startswith("{"):
            try:
                record = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict) and record.get("event") in ("download_attempt", "download_transient_failure"):
                events.append({"line": number, "timestamp": timestamp, "record": record})
    require(events == diagnosis["bootstrap"]["events"], "download event sequence")
    attempts = [e["record"] for e in events if e["record"].get("component") == "qemu"
                and e["record"].get("event") == "download_attempt"]
    failures = [e["record"] for e in events if e["record"].get("component") == "qemu"
                and e["record"].get("event") == "download_transient_failure"]
    require([e["attempt"] for e in attempts] == [1, 2, 3, 4], "four QEMU attempts")
    require([e["http_status"] for e in failures] == [500, 503, 503, 503]
            and [e["retry_after_seconds"] for e in failures] == [1, 2, 4, None]
            and [e["exhausted"] for e in failures] == [False, False, False, True], "retry exhaustion")
    require("urllib.error.HTTPError: HTTP Error 503: Service Unavailable" in log.decode(), "final HTTP exception")
    require(read("source/qemu-toolchain-lock.json")["source"] == diagnosis["bootstrap"]["locked_qemu_source"],
            "bootstrap locked URL")

    qualification = json.loads(members[PREFIX + "qualification.json"])
    require(qualification["git_commit"] == COMMIT and qualification["ok"] is False,
            "HIA source/result")
    gates = qualification["gates"]
    require(len(gates) == len(qualification["planned_gates"]) == qualification["completed_gates"] == 15,
            "HIA completion count")
    require(sum(g["passed"] for g in gates) == qualification["passed_gates"] == 12, "HIA passed count")
    require([g["name"] for g in gates if not g["passed"]] ==
            ["unit_regression", "composite_bulk_targets", "standalone_aarch64_qemu"], "HIA rejected gates")
    linked = log_counts = 0
    for gate in gates:
        for field in ("evidence", "stdout", "stderr"):
            if field in gate:
                row = gate[field]
                identity(members[PREFIX + safe(row["path"])], row, row["path"])
                linked += 1
                log_counts += "bytes" in row
    require((linked, log_counts) == (44, 30), "aggregate linked evidence")
    unit = gates[0]
    require((unit["tests_run"], unit["failures"], unit["errors"], unit["skipped"], unit["returncode"])
            == (2102, 0, 0, 3, 0), "unit result")
    require(re.search(rb"Ran 2102 tests in 559\.735s\n\nOK \(skipped=3\)\n?\Z",
                      members[PREFIX + "unit_regression.stderr.log"]), "unit terminal log")
    aarch64 = json.loads(members[PREFIX + "aarch64.json"])
    bulk = json.loads(members[PREFIX + "composite-bulk/qualification.json"])
    require(len(aarch64["reference_cases"]) == diagnosis["aarch64"]["standalone_reference_cases"] == 17,
            "reference case count")
    require(aarch64["error"]["message"] == "E_HIA_PROGRAM_AARCH64: QEMU AArch64 unavailable"
            and bulk["error"]["type"] == "ToolIdentityRejected"
            and "FileNotFoundError" in bulk["error"]["traceback"] and bulk["processes"] == [], "QEMU prerequisites")

    before = qualification["source_snapshot_before"]
    require(before == qualification["source_snapshot_after"] and qualification["unchanged_source"] is True,
            "source snapshots changed")
    require(sha(wire(before["files"])) == before["sha256"] and len(before["files"]) == 922, "source snapshot hash")
    audit = read("source-snapshot-git-audit.json")
    require(audit["source_commit"] == COMMIT and audit["files_checked"] == 922 and audit["all_match"] is True,
            "immutable Git source audit")
    require({i["path"]: i["sha256"] for i in audit["files"]} == before["files"], "source audit correspondence")
    source = read("source-identities.json")
    require(source["source_commit"] == COMMIT, "tool source commit")
    for item in source["files"]:
        raw = local(item["archived_path"])
        identity(raw, item, item["git_path"])
        require(sha(raw) == before["files"][item["git_path"]], "tool source snapshot")
        require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
                == item["git_blob_sha1"], "tool Git blob")

    perf = json.loads(members[PREFIX + "performance.json"])
    require(perf["git_commit"] == COMMIT and perf["compiler_tree_sha256"] == qualification["compiler_tree_sha256"],
            "performance source identity")
    require(perf["phase"] == "complete" and perf["status"] == "passed" and perf["ok"] is True,
            "performance terminal state")
    evaluation = perf["evaluation"]
    require(evaluation["ok"] is True and evaluation["status"] == "passed"
            and evaluation["measurement_quality_failures"] == []
            and evaluation["performance_threshold_failures"] == [], "performance evaluation")
    require(sha(wire(perf["protocol"])) == perf["protocol_sha256"], "protocol hash")
    samples = perf["raw_samples"]
    require(len(samples) == 63 and [s["sample_index"] for s in samples] == list(range(63)), "raw sample count/order")
    cells = {(s["group"], s["kernel"], s["backend"]): s for s in samples}
    require(len(cells) == 63 and set(cells) == {(g, k, b) for g in range(7) for k in KERNELS for b in BACKENDS},
            "paired sample inventory")
    for sample in samples:
        require(sample["execution"]["returncode"] == 0, "timing process failed")
        for key, value in json.loads(sample["execution"]["stdout"]).items():
            require(sample[key] == value, "raw process/summary difference")
        require(sample["driver_sha256"] == perf["artifacts"]["driver"]["sha256"]
                and sample["library_sha256"] == perf["artifacts"][sample["backend"]]["sha256"], "measured binary identity")
    max_mad = 0.0
    medians = {backend: [] for backend in ("rust", "handwritten_rust")}
    for kernel in KERNELS:
        summary = evaluation["summary"][kernel]
        for backend in BACKENDS:
            values = [cells[g, kernel, backend]["elapsed_ns"] for g in range(7)]
            median = statistics.median(values)
            mad = statistics.median(abs(n - median) for n in values) / median
            expected_stats = summary["implementations"][backend]
            require(expected_stats["samples_ns"] == values and expected_stats["median_ns"] == median
                    and expected_stats["minimum_ns"] == min(values) and expected_stats["maximum_ns"] == max(values),
                    "recomputed timing summary")
            near(mad, expected_stats["relative_mad"], "recomputed MAD")
            require(mad <= perf["protocol"]["maximum_relative_mad"], "MAD limit")
            max_mad = max(max_mad, mad)
        for backend in medians:
            ratios = [cells[g, kernel, "llvm"]["elapsed_ns"] / cells[g, kernel, backend]["elapsed_ns"] for g in range(7)]
            claimed = summary["comparisons"][backend]
            require(ratios == claimed["paired_time_ratios"], "paired ratios")
            median = statistics.median(ratios)
            near(median, claimed["median_paired_time_ratio"], "paired median")
            require(median <= perf["protocol"]["maximum_kernel_paired_time_ratio"], "kernel limit")
            medians[backend].append(median)
    for backend, values in medians.items():
        mean = math.exp(sum(math.log(v) for v in values) / len(values))
        near(mean, evaluation["geometric_mean_paired_time_ratios"][backend], "geometric mean")
        require(mean <= perf["protocol"]["maximum_geometric_mean_paired_time_ratio"], "geometric mean limit")
    for sample in samples:
        require(perf["protocol"]["minimum_sample_seconds"] <= sample["elapsed_ns"] / 1e9
                <= perf["protocol"]["maximum_sample_seconds"], "sample duration")

    correctness = perf["correctness"]
    observations = correctness["observations"]
    require(correctness["native_calls"] == len(observations) == 588 and correctness["process"]["returncode"] == 0,
            "correctness completion")
    require(observations == [json.loads(line) for line in correctness["process"]["stdout"].splitlines()]
            and all(row["actual"] == row["expected"] for row in observations)
            and sha(wire(observations)) == correctness["observations_sha256"], "correctness observations")
    process_rows = list(processes(perf))
    require(len(process_rows) == 71 and Counter(row["returncode"] for row in process_rows) == {0: 70, 1: 1},
            "process inventory")
    for row in process_rows:
        for field in ("stdout", "stderr"):
            require(sha(row[field].encode()) == row[field + "_sha256"], "process stream identity")
    observer = perf["resource_observation"]
    positive = json.loads(observer["positive"]["stdout"])
    negative = json.loads(observer["negative"]["stdout"])
    require(positive == {"allocations": 7, "frees": 7, "live": 0, "refusals": 1}
            and negative == {"allocations": 7, "frees": 0, "live": 7, "refusals": 1}
            and observer["positive"]["returncode"] == 0 and observer["negative"]["returncode"] == 1
            and observer["rehashed_llvm_rejected"] is True, "resource positive/negative controls")
    retention = perf["artifact_retention"]
    require(retention["retained"] is True and retention["status"] == "complete"
            and len(retention["files"]) == 16, "performance retention")
    retention_prefix = PREFIX + "performance-artifacts/"
    raw = members[retention_prefix + "artifact-retention.json"]
    require(sha(raw) == retention["manifest_sha256"], "retention manifest hash")
    retained_manifest = json.loads(raw)
    require(retained_manifest["files"] == retention["files"]
            and retained_manifest["path_mapping"] == retention["path_mapping"], "retention mapping")
    for name, item in retention["files"].items():
        identity(members[retention_prefix + safe(name)], item, name)
    for section in (perf["artifacts"], observer["artifacts"]):
        for item in section.values():
            identity(members[retention_prefix + PurePosixPath(item["path"]).name], item, item["path"])
    interference = perf["interference_observations"]
    require(interference["samples_excluded"] == 0 and interference["acceptance_thresholds_adjusted"] is False,
            "unaltered acceptance")
    return {"verified": True, "source_commit": COMMIT, "original_zip_rechecked": original_zip is not None,
            "new_original_files": len(members), "new_original_bytes": total, "elf_files": len(native),
            "source_snapshot_files": 922, "aggregate_file_hashes": linked, "aggregate_log_sizes": log_counts,
            "qemu_http_statuses": [e["http_status"] for e in failures], "hia_completed": 15, "hia_passed": 12,
            "unit_tests": 2102, "unit_failures": 0, "unit_errors": 0, "unit_skips": 3,
            "performance_raw_samples": len(samples), "correctness_observations": len(observations),
            "performance_processes": len(process_rows), "retained_performance_files": 16,
            "maximum_relative_mad": max_mad, "native_execution_repeated": False,
            "scope": "Archive identity and arithmetic replay; no native execution or service root-cause inference."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-zip", type=Path, help="optionally recheck a separately downloaded provider ZIP")
    args = parser.parse_args()
    print(json.dumps(verify(args.original_zip), indent=2, sort_keys=True))
