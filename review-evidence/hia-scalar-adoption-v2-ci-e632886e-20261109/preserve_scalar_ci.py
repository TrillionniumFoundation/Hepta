#!/usr/bin/env python3
"""Copy and verify original scalar CI evidence using only the standard library.

No native image, HIA service, compiler, emitter, linker, solver, or proof
generator is invoked. Original selected ZIP paths and file bytes are unchanged.
"""
from __future__ import annotations
import argparse
from collections import Counter
from hashlib import sha1, sha256
import gzip
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from zipfile import ZipFile

COMMIT = "e632886e3ae63365b509aa29529d0968a228346d"
TREE = "3fc34baf1710a99093e181a7d6c87bb373c4204f"
ZIP_SHA256 = "321d17dab979ceb0378d7b078446432c77e408d13b82821175ca1715a9e5c421"
ZIP_BYTES = 38898072
PREFIXES = ("scalar-adoption-chain/", "scalar-adoption-replay.json.recomputed/")
EXACT_FILES = {"source.txt", "dependencies.txt", "scalar-adoption-chain.log",
               "scalar-adoption-replay.json", "scalar-adoption-replay.log",
               "scalar-adoption-tests.log"}
ARCHIVE_NAME = "scalar-adoption-v2-e632886e.tar.gz"
TYPES = ["u8", "u32", "u64", "usize"]

def require(condition, message):
    if not condition:
        raise ValueError(message)

def digest(data):
    return sha256(data).hexdigest()

def canonical(name):
    path = PurePosixPath(name)
    return (type(name) is str and name == str(path) and path.parts
            and not path.is_absolute() and all(part not in {".", ".."} for part in path.parts))

def selected(name):
    return name.startswith(PREFIXES) or name in EXACT_FILES

def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()

def check_originals(files):
    """Check bytes and preserved CI results; never rerun a proof."""
    require(len(files) == 372 and all(selected(name) for name in files), "selected inventory differs")
    require(all(name in files for name in EXACT_FILES), "missing CI logs/source/replay result")
    packet = "scalar-adoption-chain/"
    fresh = "scalar-adoption-replay.json.recomputed/"
    manifest_name = packet + "original-files.json"
    manifest = json.loads(files[manifest_name])
    require(type(manifest) is list and len(manifest) == 249, "original manifest count differs")
    manifest_names = set()
    for row in manifest:
        name = row["path"]
        require(canonical(name) and name not in manifest_names, "invalid original manifest path")
        manifest_names.add(name)
        data = files[packet + name]
        require(len(data) == row["bytes"] and digest(data) == row["sha256"], "original bytes differ: " + name)
    require({packet + name for name in manifest_names} | {manifest_name}
            == {name for name in files if name.startswith(packet)}, "packet omission or extra member")
    report_bytes = files[packet + "report.json"]
    report = json.loads(report_bytes)
    replay = json.loads(files["scalar-adoption-replay.json"])
    require(report["schema"] == "hepta.hia.scalar-adoption-chain.v2"
            and report["status"] == "passed" and report["types"] == TYPES, "incomplete original qualification")
    require(report["source"]["commit"] == COMMIT and report["source"]["tree"] == TREE
            and report["source"]["worktree_status"] == "", "source identity differs")
    require(files["source.txt"] == (COMMIT + "\n" + TREE + "\n").encode(), "source.txt differs")
    require(all(value is False for value in report["claims"].values()), "scope was promoted")
    require(replay["schema"] == "hepta.hia.scalar-adoption-chain-replay.v2"
            and replay["status"] == "passed" and replay["complete_artifact_chain_checked"] is True
            and replay["types"] == TYPES and replay["source"] == report["source"]
            and replay["original_manifest_sha256"] == digest(files[manifest_name])
            and replay["source_report_sha256"] == digest(report_bytes)
            and replay["files_verified"] == 249, "strict CI replay is not bound to this packet")
    for name in ("fresh_native_execution", "kernel_checked_isa_proof",
                 "execution_authority_granted", "recorded_execution_independently_authenticated"):
        require(replay[name] is False, "strict replay scope changed: " + name)
    require([f["type"] for f in report["families"]] == TYPES
            and [f["type"] for f in replay["families"]] == TYPES
            and [f["type"] for f in replay["recomputed"]] == TYPES, "type matrix differs")
    query_records = []
    export_count = owner_calls = native_workload_calls = 0
    for family, checked, recomputed in zip(report["families"], replay["families"], replay["recomputed"]):
        typ = family["type"]
        require(family["status"] == "passed" and family["phase"] == "complete", "incomplete family")
        require(len(family["exports"]) == 52, "original export inventory differs")
        for name, reference in family["exports"].items():
            require(PurePosixPath(name).name == name and set(reference) == {"id", "sha256", "uri"},
                    "incomplete exported reference")
            require(digest(files[packet + typ + "/" + name]) == reference["sha256"],
                    "exported reference bytes differ: " + typ + "/" + name)
            export_count += 1
        require(family["native_workload_vectors"] == 125 and family["observed_owner_calls"] == 10,
                "recorded workload/owner inventory differs")
        require(checked["status"] == "consistent" and checked["identity_chain"] == family["identity_chain"]
                and checked["original_artifacts_checked"] == 52
                and checked["recorded_owner_calls_checked"] == 10, "CI chain reconstruction differs")
        require(recomputed["fresh_queries_checked"] == 13
                and recomputed["saved_queries_reencoded_identically"] is True
                and recomputed["producer_reemission_used"] is False
                and recomputed["native_image_loaded"] is False, "CI fresh model scope differs")
        owner_calls += family["observed_owner_calls"]
        native_workload_calls += family["native_workload_vectors"] * 2
        specification = json.loads(files[packet + typ + "/specification/specification.json"])
        require(specification == family["specification"], "specification receipt differs")
        rows = [(typ + "/specification/" + q["query_file"],
                 fresh + typ + "/specification/" + q["query_file"], q)
                for q in specification["obligations"]]
        for mode in ("canonical", "planned"):
            evidence = json.loads(files[packet + typ + "/" + mode + "-machine-evidence.json"])
            rows.extend((typ + "/" + mode + "-" + q["query_file"],
                         fresh + typ + "/" + mode + "/" + q["query_file"], q)
                        for q in evidence["validation"]["obligations"])
        require(len(rows) == 13, "per-type original query inventory differs")
        for original_name, fresh_name, obligation in rows:
            original = files[packet + original_name]
            require(digest(original) == obligation["query_sha256"]
                    and obligation["result"] == obligation["expected"], "original query result differs")
            require(files[fresh_name] == original, "original CI regenerated query differs: " + fresh_name)
            query_records.append({"path": original_name, "query_sha256": obligation["query_sha256"],
                                  "expected": obligation["expected"], "result": obligation["result"]})
    require(len(query_records) == 52 and replay["queries"] == query_records, "strict saved-query results differ")
    require(sum(r["fresh_queries_checked"] for r in replay["recomputed"]) == 52, "fresh CI query inventory differs")
    test_log = files["scalar-adoption-tests.log"].decode()
    match = re.search(r"Ran 16 tests in ([0-9.]+)s", test_log)
    require(match is not None and re.search(r"\nOK\n", test_log) is not None, "focused test completion missing")
    require("skipped=" not in test_log and "expected failures=" not in test_log, "focused completion contains skips")
    return {"original_manifest_sha256": digest(files[manifest_name]), "original_manifest_members": 249,
            "packet_members_including_manifest": 250, "selected_original_members": len(files),
            "selected_original_bytes": sum(map(len, files.values())),
            "original_export_references_checked": export_count,
            "original_queries_checked": len(query_records),
            "ci_regenerated_queries_compared_byte_for_byte": len(query_records),
            "recorded_native_workload_calls": native_workload_calls, "recorded_owner_calls": owner_calls,
            "focused_test_methods": 16, "focused_test_elapsed_seconds": match.group(1),
            "qualification_source_sha256": report["source"]["qualification_source_sha256"],
            "ci_replayer_sha256": replay["replayer_sha256"], "source": report["source"],
            "scope_flags": report["claims"], "new_native_execution": False,
            "new_solver_execution": False, "new_proof_generation": False}

def verify_package(directory):
    metadata = json.loads((directory / "preservation.json").read_bytes())
    index_bytes = (directory / "selected-files.json").read_bytes()
    require(digest(index_bytes) == metadata["selected_files_sha256"], "selected index identity differs")
    index = json.loads(index_bytes)
    archive = (directory / ARCHIVE_NAME).read_bytes()
    require(len(archive) == metadata["archive_bytes"] and digest(archive) == metadata["archive_sha256"],
            "preserved archive differs")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
        for member in source:
            require(member.isfile() and canonical(member.name) and member.name not in files,
                    "unsafe or repeated archive member")
            require(member.size <= 8 * 1024**2, "oversized evidence member")
            files[member.name] = source.extractfile(member).read()
    require(set(files) == {row["path"] for row in index}, "archive and selected index differ")
    for row in index:
        require(len(files[row["path"]]) == row["bytes"] and digest(files[row["path"]]) == row["sha256"],
                "selected member differs: " + row["path"])
    checked = check_originals(files)
    require(checked == metadata["offline_checks"], "offline check result differs")
    return checked

def preserve(source_zip, output):
    require(source_zip.stat().st_size == ZIP_BYTES, "original ZIP size differs")
    archive_bytes = source_zip.read_bytes()
    require(digest(archive_bytes) == ZIP_SHA256, "original ZIP identity differs")
    output.mkdir(exist_ok=False)
    with ZipFile(io.BytesIO(archive_bytes)) as source:
        entries = source.infolist()
        require(len({entry.filename for entry in entries}) == len(entries), "duplicate ZIP path")
        for entry in entries:
            require(canonical(entry.filename.rstrip("/")), "noncanonical original ZIP path")
        chosen = [entry for entry in entries if not entry.is_dir() and selected(entry.filename)]
        require(len(chosen) == 372 and sum(entry.file_size for entry in chosen) <= 16 * 1024**2,
                "selected evidence boundary differs")
        files, index = {}, []
        for entry in sorted(chosen, key=lambda item: item.filename):
            require(stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG),
                    "selected original is not a regular file")
            data = source.read(entry)
            require(len(data) == entry.file_size, "ZIP member size differs")
            files[entry.filename] = data
            index.append({"path": entry.filename, "bytes": len(data), "sha256": digest(data),
                          "original_zip_crc32": format(entry.CRC, "08x"),
                          "original_zip_compressed_bytes": entry.compress_size,
                          "original_zip_header_offset": entry.header_offset,
                          "original_zip_date_time": list(entry.date_time),
                          "original_zip_external_attr": entry.external_attr})
        checked = check_originals(files)
        excluded = Counter(PurePosixPath(e.filename).parts[0] for e in entries if e.filename not in files)
        original_entry_count = len(entries)
        original_uncompressed_bytes = sum(e.file_size for e in entries)
    with (output / ARCHIVE_NAME).open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as target:
                for name, data in sorted(files.items()):
                    member = tarfile.TarInfo(name)
                    member.size, member.mode, member.mtime = len(data), 0o644, 0
                    member.uid = member.gid = 0
                    member.uname = member.gname = ""
                    target.addfile(member, io.BytesIO(data))
    index_bytes = json_bytes(index)
    (output / "selected-files.json").write_bytes(index_bytes)
    compressed = (output / ARCHIVE_NAME).read_bytes()
    metadata = {"schema": "hepta.hia.original-ci-evidence-preservation.v1",
        "status": "original_bytes_verified_and_preserved",
        "qualified_source_commit": COMMIT, "qualified_source_tree": TREE,
        "github_repository": "TrillionniumFoundation/Hepta",
        "github_run_id": 42629363155, "github_job_id": 129201346180, "github_artifact_id": 13682147300,
        "original_zip_bytes": ZIP_BYTES, "original_zip_sha256": ZIP_SHA256,
        "original_zip_entries": original_entry_count,
        "original_zip_total_uncompressed_bytes": original_uncompressed_bytes,
        "selection": {"complete_prefixes": list(PREFIXES), "exact_files": sorted(EXACT_FILES),
                      "members_not_selected": original_entry_count - len(files),
                      "excluded_top_level_member_counts": dict(sorted(excluded.items()))},
        "preservation": "Selected ZIP paths and uncompressed bytes are unchanged; tar metadata is normalized.",
        "archive_name": ARCHIVE_NAME, "archive_bytes": len(compressed), "archive_sha256": digest(compressed),
        "archive_git_blob_sha1": sha1(b"blob " + str(len(compressed)).encode() + b"\0" + compressed).hexdigest(),
        "selected_files_sha256": digest(index_bytes), "packager_sha256": digest(Path(__file__).read_bytes()),
        "offline_checks": checked,
        "verification_scope": "Hashes, references, original query identities, preserved CI results and source binding only; no new proof or native execution."}
    (output / "preservation.json").write_bytes(json_bytes(metadata))
    require(verify_package(output) == checked, "archive readback verification differs")
    print(json.dumps({"archive": str(output / ARCHIVE_NAME), "archive_bytes": metadata["archive_bytes"],
                      "archive_sha256": metadata["archive_sha256"],
                      "archive_git_blob_sha1": metadata["archive_git_blob_sha1"],
                      "offline_checks": checked}, indent=2))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("preserve")
    create.add_argument("--source-zip", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "preserve":
        preserve(args.source_zip, args.output)
    else:
        print(json.dumps(verify_package(args.directory), indent=2))

if __name__ == "__main__":
    main()

