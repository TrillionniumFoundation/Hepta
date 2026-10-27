#!/usr/bin/env python3
"""Verify retained CI failure evidence without importing or executing its source."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import zipfile


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(root, original_zip=None):
    root = Path(root)
    read = lambda name: json.loads((root / name).read_text())
    manifest = read("MANIFEST.json")
    require(manifest["schema"] == "hepta.ci-failure-appendix.v1", "manifest schema")
    files = manifest["files"]
    require(len({row["path"] for row in files}) == len(files) <= 64, "file inventory")
    for row in files:
        relative = PurePosixPath(row["path"])
        require(not relative.is_absolute() and ".." not in relative.parts, "file path")
        path = root / row["path"]
        require(path.is_file() and not path.is_symlink(), "regular evidence file")
        raw = path.read_bytes()
        require(len(raw) == row["bytes"] and sha(raw) == row["sha256"], "file identity")
    parent_manifest = json.loads((root.parent / "MANIFEST.json").read_text())
    parent = manifest["parent_archive"]
    require(parent["decoded_sha256"] == parent_manifest["archive"]["sha256"], "parent identity")
    require(parent_manifest["archive"]["path"] == "ci-records.tar.xz.base64", "parent path")
    require(sha((root.parent / "ci-records.tar.xz.base64").read_bytes())
            == parent["encoded_sha256"] == parent_manifest["archive"]["encoded_sha256"],
            "parent sealed archive changed")

    provider = read("provider-observation.json")
    diagnosis = read("diagnosis.json")
    inventory = read("zip-inventory.json")["members"]
    source = read("source-identities.json")
    artifact = provider["artifact_metadata"]["artifacts"][0]
    job = provider["job_metadata"]["jobs"][0]
    require(source["source_commit"] == diagnosis["source_commit"]
            == provider["source_commit"] == manifest["source_commit"]
            == artifact["workflow_run"]["head_sha"], "source commit linkage")
    require(artifact["id"] == diagnosis["zip"]["artifact_id"] == 12702707920, "artifact ID")
    require(artifact["size_in_bytes"] == diagnosis["zip"]["bytes"] == 25322286, "ZIP size")
    require(artifact["digest"] == diagnosis["zip"]["provider_digest"]
            == "sha256:" + diagnosis["zip"]["sha256"], "provider ZIP digest")
    require(job["id"] == 121952281854 and job["run_id"] == 40432186614, "job identity")
    require(job["status"] == "completed" and job["conclusion"] == "failure", "job conclusion")
    require(job["steps"] == diagnosis["steps"], "step linkage")
    steps = {row["number"]: row for row in job["steps"]}
    require(all(steps[n]["conclusion"] == "success" for n in (7, 8, 9, 10)), "prerequisites")
    require(steps[11]["conclusion"] == steps[13]["conclusion"] == "failure"
            and steps[12]["conclusion"] == "skipped", "qualification step outcomes")

    log = (root / diagnosis["log"]["path"]).read_bytes()
    lines = log.decode("utf-8").splitlines()
    require(sha(log) == diagnosis["log"]["sha256"]
            and len(log) == diagnosis["log"]["bytes"]
            and len(lines) == diagnosis["log"]["line_count"], "full job log identity")
    for anchors in diagnosis["log"]["anchors"].values():
        require(bool(anchors), "missing diagnostic anchor")
        for anchor in anchors:
            require(lines[anchor["line"] - 1] == anchor["text"], "diagnostic anchor")
    for row in source["files"]:
        raw = (root / row["archived_path"]).read_bytes()
        require(sha(raw) == row["sha256"] and git_blob(raw) == row["git_blob_sha1"],
                "exact source bytes")

    require(len(inventory) == len({row["path"] for row in inventory}) == 1791, "ZIP inventory")
    added = [row for row in inventory if row.get("classification") == "added_by_run"]
    unchanged = [row for row in inventory if row.get("classification") == "unchanged_from_source"]
    history = [row for row in inventory if row["kind"] == "evidence"]
    require(len(added) == 4 and len(unchanged) == 89 and len(history) == 1698, "selection counts")
    require(len(added) + len(unchanged) + len(history) == len(inventory), "unclassified files")
    require([row["path"] for row in added] == diagnosis["new_artifacts"], "new artifact list")
    for row in added:
        raw = (root / row["path"]).read_bytes()
        require(len(raw) == row["bytes"] and sha(raw) == row["sha256"]
                and git_blob(raw) == row["git_blob_sha1"], "new artifact identity")
    for row in unchanged:
        require(row["git_blob_sha1"] == row["source_git_blob_sha1"], "tracked-file exclusion")
    require(not any(row["path"].startswith(("artifacts/candidate/", "artifacts/hia-unified/"))
                    for row in inventory), "unexpected qualification artifact")
    require(read("artifacts/sandbox-startup.json")["available"] is True, "startup receipt")
    require(read("artifacts/selected-rustc.json")["version"].startswith("rustc 1.90.0 "),
            "selected Rust receipt")

    if original_zip is not None:
        path = Path(original_zip)
        require(path.stat().st_size == artifact["size_in_bytes"], "original ZIP size")
        require(sha(path.read_bytes()) == diagnosis["zip"]["sha256"], "original ZIP hash")
        with zipfile.ZipFile(path) as archive:
            entries = [entry for entry in archive.infolist() if not entry.is_dir()]
            require(len(entries) == len(inventory), "original ZIP member count")
            expected = {row["path"]: row for row in inventory}
            require(len({entry.filename for entry in entries}) == len(entries), "duplicate ZIP path")
            for entry in entries:
                require(entry.filename in expected, "unknown ZIP path")
                row = expected[entry.filename]
                require(entry.file_size == row["bytes"], "original ZIP member size")
                if row["kind"] == "artifacts":
                    require(entry.file_size <= 16 * 1024 * 1024, "member size bound")
                    raw = archive.read(entry)
                    require(sha(raw) == row["sha256"] and git_blob(raw) == row["git_blob_sha1"],
                            "original ZIP artifact bytes")
    return {"verified": True, "retained_files": len(files), "new_artifacts": len(added),
            "job_log_bytes": len(log), "original_zip_revalidated": original_zip is not None,
            "omitted_tracked_artifacts": len(unchanged), "omitted_historical_evidence": len(history),
            "parent_archive_unchanged": True, "native_execution_repeated": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-zip", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(Path(__file__).resolve().parent, args.original_zip), sort_keys=True))
