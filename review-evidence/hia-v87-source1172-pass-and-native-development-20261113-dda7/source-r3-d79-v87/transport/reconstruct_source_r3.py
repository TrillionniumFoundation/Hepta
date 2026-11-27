"""Reconstruct Source R3's unchanged evidence from 74 binaries and one wrapper.

Run from any location with --root pointing to source-r3-d79-v87 in the audit
checkout. No product, generator or test is imported or executed. The optional
archive output is the original gzip bytes, not a recompression.
"""
from pathlib import Path, PurePosixPath
import argparse
import base64
import gzip
import hashlib
import io
import json
import stat
import tarfile
import zipfile

MANIFEST_BLOB = "97e52715891c1c498fd765cf009abb3247277d0a"
WRAPPER_BLOB = "8c43200601b343faab093975604091635f67ef91"
ARCHIVE_BYTES = 38854610
ARCHIVE_SHA256 = "22a8029c4ecbb161a1b1c44dc5e05f0b042a5a53fbaf48605256217758104fb8"
ARTIFACT_BYTES = 120474423
ARTIFACT_SHA256 = "c35fe52511aa48ed187011bd531bdd2adf57838cdf4965af00e38b4866d32886"


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)


def read(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o644,
            "nonordinary or changed mode: " + str(path))
    return path.read_bytes()


def check_chunk(raw, row):
    require(type(row["bytes"]) is int and len(raw) == row["bytes"], "chunk size")
    require(digest(raw) == row["sha256"] and blob(raw) == row["blob"], "chunk identity")


def verify(root, original_zip=None, output=None):
    manifest_raw = read(root / "EVIDENCE-MANIFEST.json")
    require(blob(manifest_raw) == MANIFEST_BLOB, "original manifest identity")
    manifest = parse(manifest_raw)
    require(manifest["schema"] == "hepta.combined-source-build-evidence.v1" and
            manifest["encoding"] == "ordered-gzip-tar-chunks", "original manifest schema")
    require(len(manifest["chunks"]) == 75, "original chunk count")
    chunks = []
    wrapper_raw = None
    position = 0
    for index, row in enumerate(manifest["chunks"]):
        require(type(row["index"]) is int and row["index"] == index and
                type(row["offset"]) is int and row["offset"] == position,
                "chunk index or contiguous offset")
        require(row["full_readback_equal"] is True, "original full-readback record")
        if index < 74:
            raw = read(root / "archive" / ("chunk-" + str(index).zfill(3) + ".bin"))
        else:
            wrapper_raw = read(root / "archive/chunk-074.base64.json")
            require(blob(wrapper_raw) == WRAPPER_BLOB and len(wrapper_raw) == 76695,
                    "transport wrapper identity")
            wrapper = parse(wrapper_raw)
            require(set(wrapper) == {"schema", "encoding", "index", "offset", "bytes",
                                     "sha256", "original_git_blob", "data"}, "wrapper fields")
            require(wrapper["schema"] == "hia.binary-chunk.base64-transport.v1" and
                    wrapper["encoding"] == "base64", "wrapper schema")
            for name in ("index", "offset", "bytes"):
                require(type(wrapper[name]) is int and wrapper[name] == row[name], "wrapper " + name)
            require(wrapper["sha256"] == row["sha256"] and wrapper["original_git_blob"] == row["blob"],
                    "wrapper decoded identities")
            require(type(wrapper["data"]) is str, "wrapper data type")
            raw = base64.b64decode(wrapper["data"], validate=True)
            require(base64.b64encode(raw).decode("ascii") == wrapper["data"], "canonical base64")
        check_chunk(raw, row)
        position += len(raw)
        chunks.append(raw)
    compressed = b"".join(chunks)
    require(position == len(compressed) == manifest["bytes"] == ARCHIVE_BYTES, "archive length")
    require(digest(compressed) == manifest["sha256"] == ARCHIVE_SHA256, "archive SHA256")
    zip_archive = None
    original_zip_compared = False
    if original_zip is not None:
        raw_zip = original_zip.read_bytes()
        require(len(raw_zip) == ARTIFACT_BYTES and digest(raw_zip) == ARTIFACT_SHA256,
                "original outer ZIP identity")
        zip_archive = zipfile.ZipFile(io.BytesIO(raw_zip))
        require(len(zip_archive.namelist()) == len(set(zip_archive.namelist())) == 3939,
                "original outer member names")
        require(zip_archive.read("EVIDENCE-MANIFEST.json") == manifest_raw, "original manifest bytes")
        require(zip_archive.read("FROZEN-SOURCE-EVIDENCE.tar.gz") == compressed,
                "mixed transport changed original gzip")
        original_zip_compared = True
    tar_raw = gzip.decompress(compressed)
    member_rows = {row["path"]: row for row in manifest["members"]}
    require(len(member_rows) == len(manifest["members"]) == 3554, "complete original member count")
    seen, logical_bytes = set(), 0
    with tarfile.open(fileobj=io.BytesIO(tar_raw), mode="r:") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and ".." not in path.parts and str(path) == member.name,
                    "unsafe tar path")
            require(member.isfile() and member.mode == 0o644 and member.name not in seen,
                    "nonordinary, wrong-mode or repeated member")
            require(member.name in member_rows, "unexpected member")
            row = member_rows[member.name]
            raw = archive.extractfile(member).read()
            require(type(row["bytes"]) is int and len(raw) == member.size == row["bytes"], "member size")
            require(digest(raw) == row["sha256"] and blob(raw) == row["blob"], "member identity")
            if zip_archive is not None:
                require(raw == zip_archive.read("raw/" + member.name), "original raw member differs")
            seen.add(member.name)
            logical_bytes += len(raw)
    require(seen == set(member_rows), "missing member")
    if zip_archive is not None:
        zip_archive.close()
    if output is not None:
        with output.open("xb") as stream:
            stream.write(compressed)
        require(output.read_bytes() == compressed, "archive output readback")
    return {
        "schema": "hepta.source-r3-mixed-transport-readback.v1",
        "status": "COMPLETE_BYTES_AND_MEMBERS_EQUAL",
        "manifest_blob": MANIFEST_BLOB,
        "representation": {"binary_files": 74, "terminal_utf8_wrappers": 1,
                           "logical_chunks": 75, "wrapper_blob": WRAPPER_BLOB,
                           "wrapper_bytes": len(wrapper_raw), "wrapper_sha256": digest(wrapper_raw)},
        "archive": {"bytes": len(compressed), "sha256": digest(compressed), "git_blob": blob(compressed)},
        "tar": {"bytes": len(tar_raw), "sha256": digest(tar_raw)},
        "logical_members": len(seen), "logical_bytes": logical_bytes,
        "all_member_modes": "0644", "all_member_bytes_sha256_git_verified": True,
        "gzip_crc_isize_verified": True,
        "original_outer_zip_compared": original_zip_compared,
        "original_archive_and_manifest_unchanged": True,
        "original_3554_raw_zip_members_compared": 3554 if original_zip_compared else 0,
        "raw_chunk_git_readback": "Original CI/full-root receipts retained; this offline check validates exact bytes against all original chunk identities.",
        "fresh_binary_connector_get_claimed": False,
        "product_executions": 0, "qualification_transferred": False, "whole_native": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--compare-zip", type=Path)
    parser.add_argument("--archive-output", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    report = verify(args.root, args.compare_zip, args.archive_output)
    if args.report is not None:
        with args.report.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, sort_keys=True, indent=2)
            stream.write("\n")
    print(json.dumps(report, sort_keys=True, indent=2))
