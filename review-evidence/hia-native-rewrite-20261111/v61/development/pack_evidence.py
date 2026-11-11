"""Package the explicitly selected v61 development evidence without altering it.

Every tar member is an original ordinary file. Custody is external to the tar,
so every member can be compared byte-for-byte with its original after packing.
This records observations; it grants no qualification or production authority.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile

SOURCE = Path("/workspace/scratch/9acdfa9f5639")
OUTPUT = Path(__file__).resolve().parent
BASELINE = "c80eb2ecc5d08421a3d124c879edb33cefff2267"
FOLDERS = (
    "hia-structure-performance", "structure-independent-review",
    "native-origins-development", "hia-origins-independent-audit",
    "hia-json-independent-audit", "hia-ci-c80eb2",
    "hia-archive-stored-experiment",
)
EXCLUDED = {
    "hia-json-independent-audit/outcomes.jsonl.gz":
        (14779166, "4bab6b4732699fcd09610b95c2d9e8d1b85d95fb412a4439be126a970fcd1585"),
    "hia-ci-c80eb2/c80eb2-native-attempt1.zip":
        (41214916, "c1d137bf8f54afaff613e725c152e84ecb19cab20fd03f94531e8392ffef11ec"),
}
INTEGRATION = (
    "v61-focused-source.json", "v61-focused-source.log",
    "v61-integration-incomplete-first.json", "v61-integration-incomplete-first.log",
    "v61-integration-custody.json", "v61-regeneration.log", "json-span-regressions.log",
)
READABLE = (
    "hia-structure-performance/comparison.json",
    "hia-structure-performance/tests.json",
    "hia-structure-performance/guarded/SUMMARY.json",
    "hia-structure-performance/guarded/comparison.json",
    "hia-structure-performance/guarded/components.json",
    "hia-structure-performance/guarded/tests.json",
    "structure-independent-review/results.json",
    "native-origins-development/review-evidence.json",
    "native-origins-development/scope.json",
    "native-origins-development/initial-assertion-failure-tool-output.log",
    "hia-origins-independent-audit/summary.json",
    "hia-json-independent-audit/summary.json",
    "hia-json-independent-audit/double-preflight-counts.json",
    "hia-ci-c80eb2/cold-failure-analysis.json",
    "hia-ci-c80eb2/archive-candidate-disposition.json",
    "hia-archive-stored-experiment/disposition.json",
)


def digest(data):
    return sha256(data).hexdigest()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_uid, info.st_nlink)


def capture(path, expected=None, maximum=10 * 1024 * 1024):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= maximum:
        raise ValueError("not an admitted ordinary evidence file: " + str(path))
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        held = os.fstat(descriptor)
        if identity(held) != identity(before):
            raise ValueError("evidence pathname changed before read: " + str(path))
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            raw = stream.read(maximum + 1)
        if (identity(os.fstat(descriptor)) != identity(before)
                or identity(path.lstat()) != identity(before) or len(raw) != before.st_size):
            raise ValueError("evidence changed while reading: " + str(path))
    finally:
        os.close(descriptor)
    row = {"source": str(path), "bytes": len(raw), "sha256": digest(raw),
           "mode": stat.S_IMODE(before.st_mode), "source_identity": list(identity(before))}
    if expected is not None and row != expected:
        raise ValueError("evidence bytes/identity changed after capture: " + str(path))
    return raw, row


def folder_files(name):
    base = SOURCE / name
    result = {}
    for path in sorted(base.rglob("*")):
        if path.is_symlink():
            raise ValueError("symbolic link in evidence inventory: " + str(path))
        if path.is_file():
            relative = path.relative_to(SOURCE).as_posix()
            if relative not in EXCLUDED:
                result[relative] = path
    return result


def package(name, files):
    destination = OUTPUT / (name + ".tar.xz")
    inventory = {}
    with destination.open("xb") as stream:
        with tarfile.open(fileobj=stream, mode="w:xz", format=tarfile.PAX_FORMAT, preset=6) as archive:
            for member, original in sorted(files.items()):
                raw, row = capture(original)
                inventory[member] = row
                info = tarfile.TarInfo(member)
                info.size, info.mode = len(raw), row["mode"]
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                archive.addfile(info, io.BytesIO(raw))
        stream.flush(); os.fsync(stream.fileno())
    # Replay every member against a second real read of its unchanged source.
    with tarfile.open(destination, "r:xz") as archive:
        members = archive.getmembers()
        if (len(members) != len(inventory)
                or {member.name for member in members} != set(inventory)):
            raise ValueError("tar member inventory differs")
        for member in members:
            expected = inventory[member.name]
            if not member.isfile() or member.size != expected["bytes"] or member.mode != expected["mode"]:
                raise ValueError("tar member metadata differs: " + member.name)
            restored = archive.extractfile(member).read()
            original, _ = capture(Path(expected["source"]), expected)
            if restored != original or digest(restored) != expected["sha256"]:
                raise ValueError("tar member bytes differ: " + member.name)
    packed = destination.read_bytes()
    return {"archive": destination.name, "bytes": len(packed), "sha256": digest(packed),
            "members": inventory, "member_count": len(inventory),
            "original_bytes": sum(row["bytes"] for row in inventory.values()),
            "every_member_replayed_byte_equal": True,
            "every_member_sha256_matches_original": True,
            "original_metadata_and_bytes_read_back_unchanged": True,
            "tar_metadata": "Paths and permission bits retained; archive uid/gid/mtime normalized to zero. Original stat identity is recorded here."}


def write_exact_copy(relative, destination, expected):
    raw, row = capture(SOURCE / relative, expected)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(raw)
    if destination.read_bytes() != raw:
        raise ValueError("readable copy differs")
    return {"path": destination.relative_to(OUTPUT).as_posix(), "source": row["source"],
            "bytes": len(raw), "sha256": digest(raw), "byte_equal": True}


def main():
    plans = {name: folder_files(name) for name in FOLDERS}
    plans["root-integration"] = {"integration/" + name: SOURCE / name for name in INTEGRATION}
    exclusions = []
    for relative, (size, expected_sha) in EXCLUDED.items():
        raw, row = capture(SOURCE / relative, maximum=64 * 1024 * 1024)
        if (len(raw), digest(raw)) != (size, expected_sha):
            raise ValueError("excluded externally retained file differs: " + relative)
        external = {"filename": Path(relative).name, "bytes": len(raw), "sha256": digest(raw),
                    "included_in_repository_package": False,
                    "reason": "Parent confirmed separate durable retention with matching size/SHA-256. The large original is excluded from this small repository package; private access identifiers and signed URLs are intentionally absent."}
        if relative.startswith("hia-ci-c80eb2/"):
            external["original_GitHub_artifact_id"] = 13824752138
        exclusions.append(external)
    packages = {name: package(name, files) for name, files in plans.items()}
    original_rows = {row["source"]: row for value in packages.values() for row in value["members"].values()}
    readable = [write_exact_copy(relative, OUTPUT / "readable" / relative,
                                original_rows[str(SOURCE / relative)]) for relative in READABLE]
    integration = [write_exact_copy(name, OUTPUT / "integration" / name,
                                   original_rows[str(SOURCE / name)]) for name in INTEGRATION]
    for name in FOLDERS:
        if set(folder_files(name)) != set(plans[name]):
            raise ValueError("source inventory changed during packaging: " + name)
    for path, row in original_rows.items():
        capture(Path(path), row)
    baseline_archive = subprocess.check_output(
        ["git", "show", BASELINE + ":tools/hia_evidence_archive.py"], cwd=SOURCE / "Hepta")
    integrated_archive = (SOURCE / "Hepta/tools/hia_evidence_archive.py").read_bytes()
    custody = {"schema": "hepta.hia.v61.development-evidence-custody.v1",
               "captured_at_utc": datetime.now(timezone.utc).isoformat(),
               "baseline_commit": BASELINE, "source_root": str(SOURCE),
               "packages": packages, "excluded_large_originals": exclusions,
               "readable_exact_copies": readable, "integration_exact_copies": integration,
               "package_count": len(packages),
               "original_member_count": sum(value["member_count"] for value in packages.values()),
               "original_member_bytes": sum(value["original_bytes"] for value in packages.values()),
               "compressed_package_bytes": sum(value["bytes"] for value in packages.values()),
               "archive_experiments_integrated": False,
               "integrated_archive_source_matches_c80": integrated_archive == baseline_archive,
               "integrated_archive_source_sha256": digest(integrated_archive),
               "evidence_only": True, "cold_qualification": False,
               "whole_language_self_hosted": False, "whole_native_stack_complete": False,
               "production_docs_support_modified_by_packager": False,
               "packager_source_sha256": digest(Path(__file__).read_bytes())}
    with (OUTPUT / "CUSTODY.json").open("x") as stream:
        json.dump(custody, stream, indent=2, sort_keys=True); stream.write("\n")
    print(json.dumps({key: custody[key] for key in (
        "package_count", "original_member_count", "original_member_bytes", "compressed_package_bytes",
        "integrated_archive_source_matches_c80")}, sort_keys=True))
    print(json.dumps({name: {key: value[key] for key in ("bytes", "sha256", "member_count", "original_bytes")}
                      for name, value in packages.items()}, indent=2))


if __name__ == "__main__":
    main()
