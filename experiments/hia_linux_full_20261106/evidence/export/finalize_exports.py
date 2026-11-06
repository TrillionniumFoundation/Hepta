#!/usr/bin/env python3
"""Postprocess a completed campaign; never executes a benchmark or changes inputs."""
from __future__ import annotations
import argparse
from collections import Counter
from fractions import Fraction
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import time

sys.dont_write_bytecode = True
EXPECTED = {
    "EVALUATION.json": (283090, "27fb22c9cc12b6852efd2515730401c1094c1e90b174e756fde04a103d95b582"),
    "HELDOUT_OBSERVATIONS.json": (911497, "542948cfcecc8d3328b9d47c2b1bc355d8ac046e5a319a2b0d579c9d2b262481"),
}
JOB = "1a1b222835d-fc05-7c8b"
ARMS = ("stock", "hia-static", "best-fixed", "greedy", "ordinary-mpc",
        "independent-same-objective", "fixed-ndu", "dynamic-ndu")
PHASES = ("syscall_process_pipe", "anonymous_memory", "tmpfs_files", "unix_tcp")
NATIVE = {"independent-same-objective", "fixed-ndu", "dynamic-ndu"}
INPUT_DIRS = ("comparison-campaign-r1", "comparison-calibration-r1",
              "comparison-supervisor-r1", "comparison-campaign-input-r1")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def binding(path):
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": file_sha(path)}


def wire(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True,
                       allow_nan=False) + "\n").encode()


def write_new(path, data):
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return binding(path)


def number(value):
    q = Fraction(value)
    return {"value": float(q), "exact": {"numerator": q.numerator,
                                          "denominator": q.denominator}}


def mean(values):
    values = list(values)
    require(bool(values), "empty mean")
    return number(sum(Fraction(x) for x in values) / len(values))


def compact_stat(value):
    return {key: value[key] for key in (
        "arm_mean", "baseline_mean", "relative_change_percent",
        "relative_change_ci95_percent", "difference", "difference_ci95",
        "independent_block_clusters", "bootstrap_replicates", "lower_is_better")}


def derive(evaluation, rows, driver):
    require(evaluation["status"] == "PASS", "evaluation not PASS")
    require(evaluation["heldout_boots"] == evaluation["correct_boots"] == 160,
            "wrong successful boot count")
    require(evaluation["failed_boots"] == evaluation["excluded_outliers"] == 0,
            "failure or exclusion found")
    require(len(rows) == 160 and all(row["correctness"] for row in rows),
            "raw row count/correctness")
    by_arm = {arm: sorted((r for r in rows if r["arm"] == arm),
                          key=lambda r: r["case_index"]) for arm in ARMS}
    for arm, arm_rows in by_arm.items():
        require([r["case_index"] for r in arm_rows] == list(range(20)),
                "noncomplete cases for " + arm)
        require(all(r["net_delivery_wall_ns"] == r["qemu_wall_ns"] +
                    r["planning"]["standalone_planning_wall_ns"] for r in arm_rows),
                "primary net cost equation changed")
    calls = {arm: [] for arm in NATIVE}
    for call in evaluation["actual_controller_native_calls"]:
        arm = Path(call["request"]["path"]).parent.name
        require(arm in calls, "unrecognized native call owner")
        calls[arm].append(call)
    require(all(len(v) == 20 for v in calls.values()), "native call counts")
    stats = evaluation["statistics"]
    arm_summary = {}
    for arm, arm_rows in by_arm.items():
        obj = {
            "independent_boots": 20,
            "action_counts": dict(sorted(Counter(r["image_id"] for r in arm_rows).items())),
            "abstentions": sum(r["abstain"] for r in arm_rows),
            "mean_guest_within_boot_median_ns": mean(r["median_ns"] for r in arm_rows),
            "mean_qemu_wall_ns": mean(r["qemu_wall_ns"] for r in arm_rows),
            "mean_standalone_planning_wall_ns": mean(r["planning"]["standalone_planning_wall_ns"] for r in arm_rows),
            "mean_standalone_planning_cpu_ns": mean(r["planning"]["standalone_planning_cpu_ns"] for r in arm_rows),
            "mean_independent_numerical_audit_wall_ns": mean(r["planning"]["audit_wall_ns"] for r in arm_rows),
            "mean_common_construction_charged_wall_ns": mean(r["planning"]["common_construction_charged_wall_ns"] for r in arm_rows),
            "mean_net_delivery_wall_ns": mean(r["net_delivery_wall_ns"] for r in arm_rows),
            "mean_image_bytes": mean(r["image_bytes"] for r in arm_rows),
            "four_phase_block_statistics_vs_stock": {
                key: compact_stat(value)
                for key, value in stats["four_phase_block_cycles"][arm].items()},
            "per_phase_statistics_vs_stock": {
                phase: {key: compact_stat(value) for key, value in
                        stats["per_phase"][arm][phase].items()} for phase in PHASES},
            "public_objective_block_statistics_vs_stock": compact_stat(
                stats["public_objective_block_statistics"][arm]),
            "native_process_calls": len(calls.get(arm, [])),
            "native_costs": None,
        }
        if arm in calls:
            obj["native_costs"] = {
                "scope": calls[arm][0]["cost_scope"],
                **{"mean_" + key: mean(c[key] for c in calls[arm]) for key in
                   ("wall_ns", "parent_cpu_ns", "child_cpu_ns",
                    "cold_process_io_wall_ns", "service_ns")},
            }
        arm_summary[arm] = obj
    sequences = {arm: [(r["case_index"], r["phase"], r["seed"], r["image_id"],
                        r["abstain"]) for r in arm_rows]
                 for arm, arm_rows in by_arm.items()}
    groups = []
    unseen = list(ARMS)
    while unseen:
        first = unseen.pop(0)
        same = [a for a in unseen if sequences[a] == sequences[first]]
        unseen = [a for a in unseen if a not in same]
        groups.append({"arms": [first] + same, "cases": len(sequences[first])})
    expected_group = {"greedy", "ordinary-mpc", "independent-same-objective", "dynamic-ndu"}
    require(any(set(g["arms"]) == expected_group and g["cases"] == 20 for g in groups),
            "reported exact action group changed")
    direct = {}
    for metric in ("median_ns", "qemu_wall_ns", "net_delivery_wall_ns"):
        pairs = []
        for block in range(5):
            pairs.append(tuple(sum(r[metric] for r in by_arm[arm] if r["block"] == block)
                               for arm in ("independent-same-objective", "dynamic-ndu")))
        direct[metric] = driver.paired_cluster_bootstrap(pairs)
    action_comparisons = {
        "complete_action_sequence_equivalence_groups": groups,
        "same_objective_vs_dynamic_matching_cases": sum(
            a == b for a, b in zip(sequences["independent-same-objective"],
                                  sequences["dynamic-ndu"])),
        "fixed_vs_dynamic_matching_cases": sum(
            a == b for a, b in zip(sequences["fixed-ndu"], sequences["dynamic-ndu"])),
        "case_actions": [{"case_index": i, "phase": by_arm["stock"][i]["phase"],
                          "seed": by_arm["stock"][i]["seed"],
                          "images": {a: by_arm[a][i]["image_id"] for a in ARMS}}
                         for i in range(20)],
    }
    return {
        "schema": "hepta.hia.kernel-comparison.derived-summary.v1",
        "status": "PASS",
        "kind": "derived postprocessing, no new measurement",
        "campaign_id": "full-linux-hia-ndu-20261106-r1",
        "durable_campaign_job_id": JOB,
        "successful_driver_calls": 183,
        "calibration_independent_boots": 12,
        "heldout_independent_boots": 160,
        "failed_boots": 0,
        "excluded_outliers": 0,
        "cells_with_active_prediction_budget": evaluation["cells_with_active_prediction_budget"],
        "scope": evaluation["scope"],
        "primary_cost": {
            "formula": "QEMU whole wall ns + standalone controller planning wall ns",
            "planning_includes": "common model/candidate construction charged to the arm; request/state preparation; binary binding; JSON serialization/parsing; durable request/response/command logs; cold process I/O",
            "independent_numerical_audit_is_separate": True,
            "admission_and_final_closure_audits_are_separate": True,
            "native_service": "inside-process service_before_output_ns; not total standalone controller latency",
        },
        "statistical_unit": {
            "independent_block_clusters": 5,
            "phases_per_block": 4,
            "within_boot_warmups": 2,
            "within_boot_measured_samples": 5,
            "within_boot_statistic": "median of five measured samples",
            "within_boot_repeats_are_independent": False,
            "twenty_phase_cells_are_independent_clusters": False,
            "bootstrap": "exhaustive paired five-block resampling, 3125 replicates, percentile 95% CI",
            "guest_ns_mean_scope": "mean of twenty different phase-boot medians; per-phase ns/op is reported separately",
        },
        "arms": arm_summary,
        "actions": action_comparisons,
        "dynamic_vs_independent_same_objective_direct_paired": {
            "baseline": "independent-same-objective",
            "treatment": "dynamic-ndu",
            "statistics": direct,
            "computed_after_campaign": True,
            "method": "same frozen paired_cluster_bootstrap helper; five whole four-phase block sums",
        },
        "artifact_equivalence_groups": evaluation["artifact_equivalence_groups"],
        "setup_costs": stats["setup_costs"],
        "amortization": stats["amortization"],
        "campaign_accounting_ns": {key: evaluation[key] for key in (
            "actual_campaign_planning_wall_ns", "actual_heldout_qemu_wall_ns",
            "calibration_pipeline_wall_ns", "registration_wall_ns",
            "statistics_wall_ns", "validation_wall_ns", "final_whole_build_audit_wall_ns")},
        "interpretation": [
            "Greedy, ordinary MPC, independent Rust same-objective control and dynamic NDU chose exactly the same images in all twenty cases: fourteen original, four Os and two O3.",
            "Differences in observed guest time or public utility among those four arms do not demonstrate different image-selection policies: image and seed choices coincide, and each observation is a separate boot subject to execution/environment variation.",
            "Dynamic NDU versus the independent same-objective Rust control has a direct paired net-wall confidence interval crossing zero; this experiment does not establish an NDU-specific decision or end-to-end advantage.",
            "Stock and the original HIA image are byte-identical. Their separate-boot timing differences are not evidence that HIA made execution faster.",
            "The prediction resource budget excluded some candidate paths in all twenty cells; it is a past-only predicted budget, not a guaranteed real-time deadline.",
            "Compressed image bytes are not runtime RAM. This measures cold-boot image selection, not seamless online replacement.",
            "Build costs are observed nonexclusive pipeline costs; preserve observed window, active union, parallel sums and CPU time as distinct quantities.",
            "Files and hashes preserve evidence consistency but are not cryptographic attestation of execution; the separate observed HeptaRuntime terminal receipt binds the durable campaign job.",
        ],
    }


def same_bytes(left, right):
    with left.open("rb") as a, right.open("rb") as b:
        while True:
            x, y = a.read(1024 * 1024), b.read(1024 * 1024)
            if x != y:
                return False
            if not x:
                return True


def signature(st):
    return (st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
            st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_nlink)


def cas_bundle(root, out):
    entries, objects, snapshots = [], {}, {}
    total = 0
    for dirname in INPUT_DIRS:
        start = root / dirname
        require(start.is_dir() and not start.is_symlink(), "missing input directory")
        paths = [start]
        for parent, dirnames, filenames in os.walk(start, followlinks=False):
            dirnames.sort()
            filenames.sort()
            paths.extend(Path(parent) / n for n in dirnames)
            paths.extend(Path(parent) / n for n in filenames)
        for path in sorted(set(paths)):
            st = path.lstat()
            rel = path.relative_to(root).as_posix()
            snapshots[rel] = signature(st)
            entry = {"path": rel, "mode": stat.S_IMODE(st.st_mode),
                     "uid": st.st_uid, "gid": st.st_gid, "mtime_ns": st.st_mtime_ns}
            if stat.S_ISDIR(st.st_mode):
                entry["kind"] = "directory"
            elif stat.S_ISLNK(st.st_mode):
                entry.update(kind="symlink", target=os.readlink(path))
            elif stat.S_ISREG(st.st_mode):
                digest = file_sha(path)
                total += st.st_size
                entry.update(kind="file", bytes=st.st_size, sha256=digest,
                             object="objects/" + digest)
                if st.st_nlink > 1:
                    entry["original_hardlink_identity"] = [st.st_dev, st.st_ino]
                if digest in objects:
                    require(st.st_size == objects[digest]["bytes"] and
                            same_bytes(path, objects[digest]["source"]),
                            "hash match without exact-byte identity")
                    objects[digest]["paths"] += 1
                else:
                    objects[digest] = {"source": path, "bytes": st.st_size, "paths": 1}
            else:
                raise ValueError("unsupported special file: " + rel)
            require(signature(path.lstat()) == snapshots[rel], "input changed while hashing")
            entries.append(entry)
    file_count = sum(e["kind"] == "file" for e in entries)
    manifest = {
        "schema": "hepta.content-addressed-file-tree.v1",
        "source_root": str(root), "included_trees": list(INPUT_DIRS),
        "entries": entries,
        "regular_file_count": file_count,
        "unique_payload_count": len(objects),
        "total_regular_file_bytes": total,
        "unique_payload_bytes": sum(o["bytes"] for o in objects.values()),
        "deduplicated_bytes": total - sum(o["bytes"] for o in objects.values()),
        "deduplication": "SHA256 and size, followed by actual byte-for-byte equality for every duplicate",
        "restoration": "For every file entry, restore exact object bytes at its path and apply mode/mtime. Restore recorded symlinks without following them. Apply directory modes/mtime last. uid/gid and hardlink identity are recorded; ownership restoration requires corresponding privileges.",
        "omissions": [],
        "object_metadata": {digest: {"bytes": o["bytes"], "referencing_files": o["paths"]}
                            for digest, o in sorted(objects.items())},
    }
    manifest_bytes = wire(manifest)
    manifest_binding = write_new(out / "EVIDENCE_TREE.json", manifest_bytes)
    archive = out / "CAMPAIGN_EVIDENCE.cas.tar.gz"
    with archive.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as gz:
            with tarfile.open(mode="w|", fileobj=gz, format=tarfile.PAX_FORMAT) as tar:
                info = tarfile.TarInfo("manifest.json")
                info.size, info.mode, info.mtime = len(manifest_bytes), 0o644, 0
                tar.addfile(info, io.BytesIO(manifest_bytes))
                for digest, obj in sorted(objects.items()):
                    info = tarfile.TarInfo("objects/" + digest)
                    info.size, info.mode, info.mtime = obj["bytes"], 0o644, 0
                    with obj["source"].open("rb") as stream:
                        tar.addfile(info, stream)
        raw.flush()
        os.fsync(raw.fileno())
    seen = set()
    with tarfile.open(archive, "r|gz") as tar:
        for member in tar:
            require(member.isfile(), "nonregular archive payload")
            stream = tar.extractfile(member)
            if member.name == "manifest.json":
                require(stream.read() == manifest_bytes, "archive manifest differs")
                continue
            require(member.name.startswith("objects/"), "unexpected archive member")
            digest = member.name.split("/", 1)[1]
            require(digest in objects and digest not in seen, "unexpected/repeated object")
            h, n = hashlib.sha256(), 0
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(chunk)
                n += len(chunk)
            require(h.hexdigest() == digest and n == objects[digest]["bytes"],
                    "archive object not exact original bytes")
            seen.add(digest)
    require(seen == set(objects), "archive omitted a payload")
    for entry in entries:
        path = root / entry["path"]
        require(signature(path.lstat()) == snapshots[entry["path"]], "input mutated after snapshot")
        if entry["kind"] == "file":
            require(file_sha(path) == entry["sha256"], "source payload changed")
        elif entry["kind"] == "symlink":
            require(os.readlink(path) == entry["target"], "symlink changed")
    require(len(entries) == len({e["path"] for e in entries}), "duplicate manifest path")
    return {
        "manifest": manifest_binding, "archive": binding(archive),
        "included_trees": list(INPUT_DIRS), "entries": len(entries),
        "regular_files": file_count, "unique_payloads": len(objects),
        "original_regular_file_bytes": total,
        "unique_payload_bytes": manifest["unique_payload_bytes"],
        "deduplicated_bytes": manifest["deduplicated_bytes"],
        "lossless_archive_verification": "all payload hashes/sizes verified by streaming decompression; every input path represented; duplicate byte equality verified; final source signatures and hashes unchanged",
        "omitted_raw_files": 0,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime-attestation", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    campaign = root / "comparison-campaign-r1"
    out = args.output.resolve()
    require(not out.is_relative_to(root), "export must not modify the frozen ROOT tree")
    started = time.time_ns()
    out.mkdir(exist_ok=False)
    source = write_new(out / "finalize_exports.py", Path(__file__).read_bytes())
    write_new(out / "STARTED.json", wire({"schema": "hepta.comparison-export.started.v1",
              "started_unix_ns": started, "source": source, "campaign_job_id": JOB,
              "no_benchmark_execution": True}))
    raw = {}
    for name, (size, digest) in EXPECTED.items():
        data = (campaign / name).read_bytes()
        require((len(data), sha(data)) == (size, digest), "frozen raw identity changed: " + name)
        raw[name] = data
    supervisor_path = root / "comparison-supervisor-r1/RESULT.json"
    supervisor_bytes = supervisor_path.read_bytes()
    require(sha(supervisor_bytes) == "e798e4b738b7eade3e26163ec3dfda2a08c347313b4cb23bbec33f7255e11bb6",
            "supervisor result binding changed")
    supervisor = json.loads(supervisor_bytes)
    require(supervisor["status"] == "PASS", "supervisor did not pass")
    runtime_bytes = args.runtime_attestation.read_bytes()
    runtime = json.loads(runtime_bytes)
    terminal = runtime["runtime_terminal"]
    require(runtime["job_id"] == JOB and terminal["state"] == "succeeded" and
            terminal["exit_code"] == 0 and terminal["output_complete"] and
            terminal["output_durable"], "runtime attestation not successful durable job")
    require(runtime["evaluation"]["sha256"] == EXPECTED["EVALUATION.json"][1] and
            runtime["heldout_observations"]["sha256"] == EXPECTED["HELDOUT_OBSERVATIONS.json"][1],
            "runtime attestation binds different measurements")
    runtime_binding = write_new(out / "RUNTIME_ATTESTATION.json", runtime_bytes)
    driver_path = root / "comparison-code-r1-frozen/tools/qualify_hia_kernel_comparison.py"
    driver_bytes = driver_path.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(driver_bytes)).encode() + b"\0" + driver_bytes).hexdigest()
    require(blob == "259bd665f245f7640fdeb91f75c538408f7bf3e7", "frozen statistical helper changed")
    spec = importlib.util.spec_from_file_location("frozen_comparison_postprocess", driver_path)
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    evaluation = json.loads(raw["EVALUATION.json"])
    rows = json.loads(raw["HELDOUT_OBSERVATIONS.json"])
    summary = derive(evaluation, rows, driver)
    summary["inputs"] = {name: binding(campaign / name) for name in EXPECTED}
    summary["inputs"].update(supervisor=binding(supervisor_path),
                             runtime_attestation=runtime_binding,
                             frozen_statistical_helper=binding(driver_path),
                             postprocessor=source)
    summary_binding = write_new(out / "SUMMARY.json", wire(summary))
    gz_bindings = {}
    for name, data in raw.items():
        compressed = gzip.compress(data, compresslevel=9, mtime=0)
        require(gzip.decompress(compressed) == data, "raw gzip differs")
        gz_bindings[name] = {"compressed": write_new(out / (name + ".gz"), compressed),
                             "uncompressed": binding(campaign / name),
                             "exact_byte_roundtrip": True}
    print(json.dumps({"stage": "summary-and-raw-gzip", "status": "PASS",
                      "summary": summary_binding, "gzip": gz_bindings}), flush=True)
    archive = cas_bundle(root, out)
    finalized = {
        "schema": "hepta.hia.kernel-comparison.export-finalized.v1", "status": "PASS",
        "started_unix_ns": started, "completed_unix_ns": time.time_ns(),
        "campaign_job_id": JOB, "output_directory": str(out),
        "source": source, "summary": summary_binding, "raw_gzip": gz_bindings,
        "runtime_attestation": runtime_binding, "evidence_bundle": archive,
        "no_tests_or_benchmarks_run": True,
        "frozen_sources_and_measurements_modified": False,
        "finalized_directory_entries": [binding(p) for p in sorted(out.iterdir()) if p.is_file()],
        "write_boundary": "All export data complete. This postprocessor never writes the frozen ROOT tree and makes no further output writes after FINALIZED.json.",
    }
    final_binding = write_new(out / "FINALIZED.json", wire(finalized))
    print(json.dumps({"stage": "finalized", "status": "PASS", "marker": final_binding,
                      "evidence_bundle": archive}), flush=True)


if __name__ == "__main__":
    main()
