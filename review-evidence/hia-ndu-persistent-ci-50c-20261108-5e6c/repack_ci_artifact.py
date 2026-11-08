"""Repack and independently hash every member of one retained public CI ZIP.

No original member is extracted to the filesystem or executed. Container
ownership, timestamp and member order are normalized; payload bytes are exact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
from pathlib import Path, PurePosixPath
import stat
import tarfile
import zipfile

SOURCE = "50c1578b4d4597e3070a9abc3700c9aacbf99851"
TREE = "87b106d1e76337e02bda5e7a9132c4854c601b00"
ZIP_SHA = "4b13273fc3dd4208e312803f369075603435e9f0e17cccb74099f727d9248ed2"
ZIP_BYTES = 8087371
REGISTRATION_SHA = "e57aaa35b1484b60cb0492481909a5971a9c70df1f9a7bb5499837c3fda93151"
RUN = 42516119809
ARTIFACT = 13631367936


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest_file(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def write_new(path, raw):
    with path.open("xb") as f:
        f.write(raw)


def write_json(path, value):
    write_new(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


class HashedInput:
    def __init__(self, stream):
        self.stream = stream
        self.digest = hashlib.sha256()
        self.count = 0

    def read(self, size=-1):
        value = self.stream.read(size)
        self.digest.update(value)
        self.count += len(value)
        return value


def verify_archive(directory):
    inventory = json.loads((directory / "inventory.json").read_text())
    archive = directory / inventory["raw_archive"]["path"]
    require(archive.stat().st_size == inventory["raw_archive"]["bytes"], "archive size")
    require(digest_file(archive) == inventory["raw_archive"]["sha256"], "archive SHA256")
    expected = {row["path"]: row for row in inventory["files"]}
    require(len(expected) == 475 == len(inventory["files"]), "exact member count")
    seen = set()
    total = 0
    with tarfile.open(archive, mode="r|xz") as tar:
        for member in tar:
            require(member.isfile() and member.name in expected and member.name not in seen,
                    "unexpected, duplicate or non-file archive member")
            row = expected[member.name]
            require(member.size == row["bytes"], "member size: " + member.name)
            stream = tar.extractfile(member)
            require(stream is not None, "missing member stream")
            value = hashlib.file_digest(stream, "sha256").hexdigest()
            require(value == row["sha256"], "member SHA256: " + member.name)
            seen.add(member.name)
            total += member.size
    require(seen == set(expected), "missing archive member")
    return {"members": len(seen), "uncompressed_bytes": total,
            "all_member_payloads_match_original_zip_hashes": True,
            "filesystem_extraction_used": False, "native_execution_used": False}


def repack(zip_path, root_summary_path, output):
    require(zip_path.stat().st_size == ZIP_BYTES and digest_file(zip_path) == ZIP_SHA,
            "original CI ZIP identity")
    output.mkdir(parents=True, exist_ok=True)
    summary_raw = root_summary_path.read_bytes()
    summary = json.loads(summary_raw)
    require(summary["source_sha"] == SOURCE, "root summary source")
    require(summary["tests_run"] == 164 and not any(summary[x] for x in ("failures", "errors", "skipped")),
            "root summary controls")
    copies = {"persistent-mechanism/registration.json": "registration.json",
              "persistent-mechanism/result.json": "persistent-result.json",
              "persistent-replay.json": "ci-replay.json",
              "integration-result.json": "integration-result.json",
              "stream-rust-tests.json": "stream-rust-tests.json"}
    targets = ["raw.tar.xz", "inventory.json", "archive-verification.json", "root-summary.json", *copies.values()]
    require(all(not (output / name).exists() for name in targets), "create-only output already exists")
    rows = []
    with zipfile.ZipFile(zip_path) as z:
        members = sorted(z.infolist(), key=lambda member: member.filename)
        names = [member.filename for member in members]
        require(len(members) == len(set(names)) == 475, "exact original member count")
        for member in members:
            path = PurePosixPath(member.filename)
            require(not member.is_dir() and not path.is_absolute() and ".." not in path.parts
                    and path.as_posix() == member.filename, "unsafe/non-file original member")
            mode = member.external_attr >> 16
            require(not stat.S_ISLNK(mode) and stat.S_IFMT(mode) in (0, stat.S_IFREG), "non-regular original member")
        require(z.read("source-before.txt") == z.read("source-after.txt") == (SOURCE + "\n" + TREE + "\n").encode(),
                "original source boundary identity")
        registration_raw = z.read("persistent-mechanism/registration.json")
        require(hashlib.sha256(registration_raw).hexdigest() == REGISTRATION_SHA, "original registration SHA256")
        result = json.loads(z.read("persistent-mechanism/result.json"))
        replay = json.loads(z.read("persistent-replay.json"))
        require(summary["ndu"] == {key: result[key] for key in summary["ndu"]}, "root summary result differs")
        require(summary["replay"] == replay, "root summary replay differs")
        require(result["p2_acceptance"] == "HOLD" and result["completed_cells"] == 72
                and result["failed_cells"] == result["automatic_retries"] == 0, "original experiment scope")
        with (output / "raw.tar.xz").open("xb") as raw:
            with lzma.LZMAFile(raw, "w", format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, preset=6) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as tar:
                    for member in members:
                        entry = tarfile.TarInfo(member.filename)
                        entry.size = member.file_size
                        entry.mode = 0o755 if (member.external_attr >> 16) & 0o111 else 0o644
                        entry.uid = entry.gid = entry.mtime = 0
                        entry.uname = entry.gname = ""
                        with z.open(member) as stream:
                            hashed = HashedInput(stream)
                            tar.addfile(entry, hashed)
                            require(hashed.read(1) == b"" and hashed.count == member.file_size,
                                    "original member length or EOF")
                        rows.append({"path": member.filename, "bytes": member.file_size,
                                     "sha256": hashed.digest.hexdigest()})
        for source, destination in copies.items():
            write_new(output / destination, z.read(source))
    require(digest_file(zip_path) == ZIP_SHA, "original ZIP changed during repack")
    write_new(output / "root-summary.json", summary_raw)
    archive = output / "raw.tar.xz"
    inventory = {"schema": "hepta.hia.ndu-ci-evidence-inventory.v1", "workflow_run": RUN,
                 "artifact_id": ARTIFACT, "source_sha": SOURCE, "source_tree": TREE,
                 "original_zip_bytes": ZIP_BYTES, "original_zip_sha256": ZIP_SHA,
                 "raw_archive": {"path": archive.name, "bytes": archive.stat().st_size,
                                 "sha256": digest_file(archive)}, "files": rows}
    write_json(output / "inventory.json", inventory)
    verified = verify_archive(output)
    verified.update({"schema": "hepta.hia.ndu-ci-lossless-repack-verification.v1",
                     "status": "PASS_ALL_ORIGINAL_MEMBERS", "source_sha": SOURCE,
                     "original_zip_sha256": ZIP_SHA, "raw_archive": inventory["raw_archive"],
                     "inventory_sha256": digest_file(output / "inventory.json"),
                     "repack_script_sha256": digest_file(Path(__file__)),
                     "timings_independently_authenticated": False,
                     "economic_benefit_established": False, "p2_acceptance": "HOLD",
                     "container_metadata_normalized": "sorted path order; uid/gid/mtime zero; executable bit preserved"})
    write_json(output / "archive-verification.json", verified)
    print(json.dumps(verified, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--zip", type=Path)
    parser.add_argument("--root-summary", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    if args.verify_only:
        require(args.zip is None and args.root_summary is None, "verify-only takes no original input paths")
        print(json.dumps(verify_archive(args.output_directory), sort_keys=True))
    else:
        require(args.zip is not None and args.root_summary is not None, "both original inputs are required")
        repack(args.zip, args.root_summary, args.output_directory)


if __name__ == "__main__":
    main()
