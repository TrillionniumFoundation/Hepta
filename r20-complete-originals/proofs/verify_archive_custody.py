"""Verify retained R20 artifact bytes without executing or importing product code.

The ZIPs remain the complete originals. Only small diagnostic records are copied
out. Every outer member and every inner tar member is nevertheless streamed to
EOF and checked. This is not a claim that the entire raw directory was restored.
"""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import tarfile
import time
import traceback
import zipfile


ROOT = Path(__file__).resolve().parent
OUT = ROOT / "custody-stream-r1"
CONFIG = ROOT / "ARTIFACT-PINS.json"


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(("duplicate JSON key", key))
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)


def safe(name, *, directory=False):
    assert isinstance(name, str) and name and "\0" not in name and "\\" not in name
    if directory and name.endswith("/"):
        name = name[:-1]
    path = PurePosixPath(name)
    assert name and not path.is_absolute() and str(path) == name
    assert all(part not in ("", ".", "..") for part in path.parts)
    return path


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def stream_pin(stream, size):
    assert type(size) is int and size >= 0
    sha = hashlib.sha256()
    git = hashlib.sha1(b"blob " + str(size).encode() + b"\0")
    count = 0
    for block in iter(lambda: stream.read(1 << 20), b""):
        count += len(block)
        assert count <= size
        sha.update(block)
        git.update(block)
    assert count == size
    return {"bytes": count, "sha256": sha.hexdigest(), "git_blob": git.hexdigest()}


def same_pin(actual, expected):
    assert actual["bytes"] == expected["bytes"]
    assert actual["sha256"] == expected["sha256"]
    expected_git = expected.get("git_blob", expected.get("blob"))
    if expected_git is not None:
        assert actual["git_blob"] == expected_git


def put(relative, raw, mode=0o644):
    relative = safe(relative)
    assert type(mode) is int and 0 <= mode <= 0o777
    path = OUT.joinpath(*relative.parts)
    parent = OUT
    for part in relative.parts[:-1]:
        parent = parent / part
        if parent.exists() or parent.is_symlink():
            assert stat.S_ISDIR(parent.lstat().st_mode) and not parent.is_symlink()
        else:
            parent.mkdir()
    assert not path.exists() and not path.is_symlink()
    with path.open("xb") as stream:
        stream.write(raw)
    path.chmod(mode)
    assert stat.S_IMODE(path.stat().st_mode) == mode


def write_json(relative, value):
    put(relative, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def selected_outer(label, name):
    if "/" not in name:
        return name.endswith((".json", ".jsonl", ".log", ".txt"))
    if label == "combined-source":
        if name.startswith("raw/commands/"):
            return name.endswith((".json", ".stdout", ".stderr"))
        return name in {
            "raw/RESULT.json", "raw/checks/SOURCE-TESTS.json",
            "raw/checks/SOURCE-TESTS.events.jsonl",
            "raw/checks/before-complete-source-tests-raw-worktree.json",
            "raw/checks/after-complete-source-tests-raw-worktree.json",
            "raw/sources/candidate-final.json", "raw/terminal-worktree/INDEX.json",
            "raw/harness/INPUTS.json", "raw/harness/DRIVER.py",
            "raw/harness/tools/run_source_gate.py",
            "raw/harness/inputs/ORIGINAL-SOURCE-IDS.json",
        }
    groups = ("source10", "original43", "native9", "build", "fresh5")
    return any(name == "evidence/" + group + suffix
               for group in groups for suffix in ("/REPORT.json", "-owner/owner.json"))


def verify_outer(label, expected):
    path = ROOT / expected["file"]
    safe(expected["file"])
    assert path.is_file() and not path.is_symlink()
    with path.open("rb") as stream:
        actual = stream_pin(stream, expected["bytes"])
    same_pin(actual, expected)
    rows = []
    restored = []
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        assert len(infos) == len({item.filename for item in infos})
        if "members" in expected:
            assert len(infos) == expected["members"]
        normalized = set()
        for item in infos:
            relative = safe(item.filename, directory=item.is_dir())
            assert str(relative) not in normalized
            normalized.add(str(relative))
            mode = (item.external_attr >> 16) & 0xffff
            assert not item.flag_bits & 1
            if item.is_dir():
                assert stat.S_IFMT(mode) in (0, stat.S_IFDIR)
                assert item.file_size == 0
            else:
                assert stat.S_ISREG(mode), (label, item.filename, oct(mode))
            with archive.open(item) as stream:
                member_pin = stream_pin(stream, item.file_size)
            row = {"path": item.filename, **member_pin, "crc32": item.CRC,
                   "is_directory": item.is_dir(), "external_attr": item.external_attr,
                   "create_system": item.create_system, "zip_unix_mode": mode,
                   "permission_mode": stat.S_IMODE(mode)}
            rows.append(row)
            if not item.is_dir() and selected_outer(label, item.filename):
                raw = archive.read(item)
                same_pin(pin(raw), row)
                put(label + "/" + item.filename, raw, stat.S_IMODE(mode))
                restored.append(item.filename)
    write_json(label + "-OUTER-MEMBERS.json", rows)
    with path.open("rb") as stream:
        same_pin(stream_pin(stream, expected["bytes"]), actual)
    return {row["path"]: row for row in rows}, {
        "original": {"file": expected["file"], **actual},
        "members": len(rows), "regular_files": sum(not r["is_directory"] for r in rows),
        "directory_entries": sum(r["is_directory"] for r in rows),
        "raw_bytes": sum(r["bytes"] for r in rows),
        "actual_zip_modes": sorted({r["zip_unix_mode"] for r in rows}),
        "selected_regular_files_materialized": restored,
        "all_members_crc_and_complete_bytes_hashes_verified": True,
        "original_outer_unchanged": True,
        "unrecorded_directory_modes": "Not inferred from extraction-created directories",
    }


def verify_inner(source_config, outer):
    with zipfile.ZipFile(ROOT / source_config["file"]) as archive:
        raw_manifest = archive.read("EVIDENCE-MANIFEST.json")
        manifest = parse(raw_manifest)
        assert manifest["schema"] == "hepta.combined-source-build-evidence.v2"
        evidence_pin = parse(archive.read("EVIDENCE-PIN.json"))
        assert evidence_pin["full_readback_equal"] is True
        packed_name = "FROZEN-SOURCE-EVIDENCE.tar.gz"
        assert outer[packed_name]["bytes"] == manifest["bytes"]
        assert outer[packed_name]["sha256"] == manifest["sha256"]
        chunks = []
        offset = 0
        with archive.open(packed_name) as stream:
            for index, chunk in enumerate(manifest["chunks"]):
                assert chunk["index"] == index and chunk["offset"] == offset
                raw = stream.read(chunk["bytes"])
                actual = pin(raw)
                same_pin(actual, chunk)
                assert chunk["full_readback_equal"] is True
                receipt_name = "raw/upload-readbacks/" + chunk["blob"] + ".json"
                receipt = parse(archive.read(receipt_name))
                same_pin(actual, receipt)
                assert receipt["full_readback_equal"] is True
                chunks.append({"index": index, "offset": offset, **actual,
                               "producer_receipt": receipt_name, "producer_full_get": True})
                offset += len(raw)
            assert offset == manifest["bytes"] and stream.read() == b""
        files = {row["path"]: row for row in manifest["members"]}
        directories = {row["path"]: row for row in manifest["directories"]}
        assert len(files) == len(manifest["members"])
        assert len(directories) == len(manifest["directories"])
        assert not files.keys() & directories.keys()
        for name in files.keys() | directories.keys():
            safe(name)
        seen_files, seen_directories = set(), set()
        with archive.open(packed_name) as source, gzip.GzipFile(fileobj=source) as inflated:
            with tarfile.open(fileobj=inflated, mode="r|") as packed:
                for member in packed:
                    name = str(safe(member.name))
                    if member.isdir():
                        assert name in directories and name not in seen_directories
                        assert member.mode == directories[name]["mode"]
                        seen_directories.add(name)
                        continue
                    assert member.isfile() and name in files and name not in seen_files
                    assert member.mode == files[name]["mode"]
                    extracted = packed.extractfile(member)
                    assert extracted is not None
                    with extracted:
                        actual = stream_pin(extracted, member.size)
                    same_pin(actual, files[name])
                    same_pin(actual, outer["raw/" + name])
                    seen_files.add(name)
            while inflated.read(1 << 20):
                pass
        assert seen_files == set(files) and seen_directories == set(directories)
        result = parse(archive.read("raw/RESULT.json"))
        assert result == manifest["result"]
        write_json("INNER-CHUNKS-READBACK.json", chunks)
        return {
            "manifest": pin(raw_manifest), "packed_archive": outer[packed_name],
            "members": len(seen_files), "directories": len(seen_directories),
            "recorded_root_mode": manifest["root_mode"], "transport_chunks": len(chunks),
            "complete_gzip_crc": True, "all_inner_bytes_git_sha_modes_verified": True,
            "all_inner_files_match_outer_raw_members": True,
            "producer_git_transport_receipts_verified_against_original_chunk_bytes": True,
            "original_execution_status": result["status"],
            "execution_status_does_not_change_custody_verdict": True,
            "complete_raw_directory_materialized": False,
        }


def main():
    started = time.monotonic()
    config = parse(CONFIG.read_bytes())
    assert config["run"] == 43553551892 and config["job"] == 132321186937
    assert config["head"] == "28b8e6f5b44022f9d6e90d561573d41f0f7e8633"
    assert config["terminal"] is True
    assert not OUT.exists()
    OUT.mkdir()
    outer_summaries = {}
    outer_maps = {}
    for label, entry in config["artifacts"].items():
        assert label in ("combined-source", "parser-bounded")
        outer_maps[label], outer_summaries[label] = verify_outer(label, entry)
    assert "combined-source" in outer_maps
    inner = verify_inner(config["artifacts"]["combined-source"], outer_maps["combined-source"])
    report = {"schema": "hepta.r20.complete-artifact-stream-custody.v1",
              "status": "CUSTODY_PASS_EXECUTION_STATUS_RECORDED_SEPARATELY",
              "run": config["run"], "job": config["job"], "head": config["head"],
              "outer_artifacts": outer_summaries, "inner_source": inner,
              "source_and_bounded_execution_qualification": "NOT_INFERRED_BY_THIS_BYTE_CUSTODY_STAGE",
              "new_product_executions": 0, "originals_deleted": 0,
              "complete_raw_directory_materialized": False,
              "seconds_for_evidence_only": time.monotonic() - started}
    write_json("REPORT.json", report)
    print(json.dumps({"status": report["status"], "inner_members": inner["members"],
                      "outer_counts": {k: v["members"] for k, v in outer_summaries.items()},
                      "seconds": report["seconds_for_evidence_only"]}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        if OUT.is_dir() and not (OUT / "VERIFIER-FAILURE.txt").exists():
            put("VERIFIER-FAILURE.txt", traceback.format_exc().encode())
        raise
