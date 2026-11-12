#!/usr/bin/env python3
"""Publish exact receipts/streams and generated text without large executables.

Every retained file is checked against the completed run's manifest first.
Omitted binaries remain named and hash-bound in the archive manifest and full
report; deterministic input traces can be regenerated from the frozen protocol.
"""
import argparse
import gzip
from hashlib import sha256
import io
import json
from pathlib import Path
import tarfile


def export(report_path, archive_path, summary_path):
    report_path, archive_path, summary_path = map(Path, (report_path, archive_path, summary_path))
    raw_report = report_path.read_bytes()
    report = json.loads(raw_report)
    if report.get("ok") is not True or report.get("stage") != "complete":
        raise ValueError("Only a completed qualification can be published")
    base = report_path.parent.resolve()
    included, omitted = {}, {}
    files = {"qualification.json": raw_report}
    binary_suffixes = {".so", ".o", ".bin", ".profraw", ".profdata", ".bc", ".a"}
    for name, expected in sorted(report["evidence"]["artifacts"].items()):
        path = base / name
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(base):
            raise ValueError("Retained artifact is not a regular file within the run: " + name)
        data = path.read_bytes()
        if len(data) != expected["bytes"] or sha256(data).hexdigest() != expected["sha256"]:
            raise ValueError("Retained artifact changed: " + name)
        is_stream = path.name in {"stdout", "stderr"}
        binary = not is_stream and (path.suffix in binary_suffixes or data.startswith(b"\x7fELF"))
        if binary:
            omitted[name] = {**expected, "reason": "native or replayable binary; identity retained, bytes omitted"}
        else:
            files["evidence/" + name] = data
            included[name] = expected
    manifest = {"schema": "hepta.ring-text-evidence.v1", "report_sha256": sha256(raw_report).hexdigest(),
        "source_head": report["git"]["head"], "included": included, "omitted_binary_artifacts": omitted,
        "scope": "Complete original report, actual command records, exact stdout/stderr bytes, state/resource observations and generated source text; native binaries/traces/profiles are hash-inventoried"}
    files["MANIFEST.json"] = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with archive_path.open("xb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(data), 0o644, 0
                archive.addfile(info, io.BytesIO(data))
    keys = ("schema", "ok", "stage", "git", "protocol", "protocol_sha256", "claims", "host", "tools",
            "cost", "maintenance", "abi", "original_header_layout", "fault_recovery", "host_summary",
            "summary", "ledger", "conclusion", "fresh_migration_wall_ns", "profile_counters", "source_bindings", "committed_source_inventory")
    summary = {key: report[key] for key in keys if key in report}
    if "versions" in report:
        summary["versions"] = {name: {"upstream_commit": version["upstream"]["commit"],
            "automatic_migration_wall_ns": version["automatic_migration_wall_ns"],
            "migration_disposition": version["migration_disposition"], "api_sequences": version["api_sequences"],
            "original_simple_calls": len(version["original_clients"]["simple"]),
            "tail_cases_per_route": version["original_clients"]["tail_case_count"],
            "upstream_sources_and_modes_unchanged_after_build": version["upstream_sources_and_modes_unchanged_after_build"]}
            for name, version in report["versions"].items()}
    if "owned_client_faults" in report:
        summary["owned_client_fault_calls"] = report["owned_client_faults"]["calls"]
    summary["published_evidence"] = {"archive": archive_path.name, "bytes": archive_path.stat().st_size,
        "sha256": sha256(archive_path.read_bytes()).hexdigest(), "full_report_sha256": sha256(raw_report).hexdigest(),
        "included_files": len(included), "omitted_binary_files": len(omitted),
        "binary_omission_scope": manifest["scope"]}
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with summary_path.open("x") as stream:
        stream.write(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    return summary["published_evidence"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(export(args.report, args.archive, args.summary), indent=2))
