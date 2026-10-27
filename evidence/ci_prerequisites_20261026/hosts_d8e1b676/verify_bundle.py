#!/usr/bin/env python3
"""Verify new host receipts and their byte-identical prior source archive."""
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import zipfile


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def read_bundle(directory, schema, filename):
    manifest = json.loads((directory / "MANIFEST.json").read_text())
    require(manifest["schema"] == schema and manifest["archive"]["path"] == filename,
            "archive schema/path")
    encoded = (directory / filename).read_bytes()
    require(len(encoded) <= 16 * 1024 * 1024
            and sha(encoded) == manifest["archive"]["encoded_sha256"], "encoded archive")
    packed = base64.b64decode(b"".join(encoded.split()), validate=True)
    require(len(packed) == manifest["archive"]["decoded_bytes"]
            and sha(packed) == manifest["archive"]["sha256"], "decoded archive")
    expected = {row["path"]: row for row in manifest["members"]}
    require(len(expected) == len(manifest["members"]) == manifest["member_count"] <= 512,
            "manifest member inventory")
    contents = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(packed), mode="r|gz") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            require(member.isfile() and not path.is_absolute() and ".." not in path.parts,
                    "member path/type")
            require(member.name in expected and member.name not in contents, "member identity")
            row = expected[member.name]
            require(type(row["bytes"]) is int and 0 <= row["bytes"] <= 16 * 1024 * 1024,
                    "member size bound")
            require(member.size == row["bytes"], "member size")
            total += member.size
            require(total <= 64 * 1024 * 1024, "total size bound")
            stream = archive.extractfile(member)
            require(stream is not None, "member stream")
            raw = stream.read(member.size + 1)
            require(len(raw) == row["bytes"] and sha(raw) == row["sha256"], "member digest")
            contents[member.name] = raw
    require(set(contents) == set(expected), "missing members")
    return manifest, contents


def verify(directory):
    directory = Path(directory)
    manifest, contents = read_bundle(directory, "hepta.shared-source-host-archive.v1",
                                     "host-zips.tar.gz.base64")
    reference = manifest["source_archive_reference"]
    require(reference["directory"] == "../hosts_8dcb0d0d", "source archive location")
    prior = directory.parent / "hosts_8dcb0d0d"
    require(sha((prior / "MANIFEST.json").read_bytes()) == reference["manifest_sha256"],
            "prior source manifest changed")
    prior_manifest, prior_contents = read_bundle(prior, "hepta.host-source-archive.v1",
                                                "host-records.tar.gz.base64")
    require(prior_manifest["archive"]["sha256"] == reference["archive_sha256"]
            and prior_manifest["archive"]["encoded_sha256"] == reference["encoded_sha256"],
            "prior source archive changed")
    relation = json.loads((directory / "source-relationship.json").read_text())
    replay = json.loads((directory / "source-replay.json").read_text())
    require(relation["source_commit"] == manifest["source_commit"]
            and relation["prior_source_commit"] == prior_manifest["source_commit"]
            and relation["source_archive_reference"] == reference, "source relation identity")
    require(relation["intermediate_source_commit"] == "7ef57d1b380e73269f592fa26fe95f9636c88586"
            and relation["all_intermediate_python_git_objects_identical"] is True,
            "intermediate source relationship")
    source_rows = {row["git_path"]: row for row in relation["python_files"]}
    require(len(source_rows) == len(relation["python_files"]) == relation["python_file_count"] == 183,
            "Python source count")
    prefix = "source/" + prior_manifest["source_commit"][:8] + "/"
    require({name[len(prefix):] for name in prior_contents if name.startswith(prefix)}
            == set(source_rows), "complete shared source set")
    for path, row in source_rows.items():
        require(row["source_archive_member"] == prefix + path, "source member mapping")
        raw = prior_contents[row["source_archive_member"]]
        require(len(raw) == row["bytes"] and sha(raw) == row["sha256"]
                and blob(raw) == row["prior_git_blob_sha1"] == row["source_git_blob_sha1"]
                == row["intermediate_git_blob_sha1"],
                "shared Git/source bytes")
    workflow = relation["host_workflow"]
    raw = prior_contents[workflow["source_archive_member"]]
    require(len(raw) == workflow["bytes"] and sha(raw) == workflow["sha256"]
            and blob(raw) == workflow["prior_git_blob_sha1"] == workflow["source_git_blob_sha1"]
            == workflow["intermediate_git_blob_sha1"],
            "shared host workflow")
    require(len(replay["profiles"]) == 2 and replay["native_commands_executed"] is False,
            "replay profiles/scope")
    for profile in replay["profiles"].values():
        require(profile["commit"] == manifest["source_commit"]
                and profile["tree"] == relation["source_tree"]
                and set(profile["source_files"]) == set(source_rows), "profile identity")
        for path, digest in profile["source_files"].items():
            raw = prior_contents[source_rows[path]["source_archive_member"]]
            if profile["newline_policy"] == "crlf":
                raw = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            else:
                require(profile["newline_policy"] == "lf", "newline policy")
            require(sha(raw) == digest, "replayed source inventory")

    provider = json.loads((directory / "provider-observation.json").read_text())
    identities = json.loads((directory / "zip-identities.json").read_text())
    by_id = {row["artifact_id"]: row for row in identities}
    artifacts = {row["id"]: row for row in provider["artifact_metadata"]["artifacts"]}
    jobs = provider["job_metadata"]["jobs"]
    require(len(jobs) == 4 and all(row["status"] == "completed" and row["conclusion"] == "success"
            and row["run_id"] == 40438827770 for row in jobs), "provider host jobs")
    require(len(by_id) == len(identities) == len(artifacts) == len(replay["reports"]) == 4
            and set(by_id) == set(artifacts), "receipt inventory")
    require(set(contents) == {f"host-zips/{aid}.zip" for aid in by_id}, "only new host ZIPs retained")
    seen = set()
    for row in replay["reports"]:
        aid = row["artifact_id"]
        require(aid in by_id and aid not in seen, "unique report")
        seen.add(aid)
        identity, artifact = by_id[aid], artifacts[aid]
        require(artifact["workflow_run"]["id"] == 40438827770, "provider artifact run")
        require(identity["source_commit"] == artifact["workflow_run"]["head_sha"]
                == manifest["source_commit"] == row["commit_binding"]["source_commit"],
                "actual provider source binding")
        require(row["commit_binding"]["kind"] == "provider_workflow_run_head_sha", "binding kind")
        zipped = contents[f"host-zips/{aid}.zip"]
        require(sha(zipped) == identity["sha256"] and len(zipped) == identity["bytes"]
                == artifact["size_in_bytes"] and artifact["digest"]
                == identity["provider_digest"] == "sha256:" + identity["sha256"], "ZIP identity")
        require(row["archived_report"] == f"hosts/{aid}.json", "report location")
        raw = (directory / row["archived_report"]).read_bytes()
        require(sha(raw) == row["input_sha256"], "raw report digest")
        with zipfile.ZipFile(io.BytesIO(zipped)) as archive:
            require(archive.namelist() == ["native-host.json"]
                    and archive.read("native-host.json") == raw, "original report bytes")
        report = json.loads(raw)
        require({k: report[k] for k in ("git_commit", "gitcommit", "source_git_commit") if k in report}
                == row["original_report_commit_fields"], "original commit-field observation")
        profile = replay["profiles"][row["source_profile"]]
        require(report["compiler_sha256"] == row["reported_compiler_sha256"]
                == row["actual_compiler_sha256"] == profile["actual_compiler_sha256"],
                "compiler identity linkage")
        require(row["validated"] is True and row["error"] is None and row["returncode"] == 0
                and row["native_commands_executed"] is False, "recorded replay result")
    return {"verified": True, "host_reports": len(seen), "new_archive_members": len(contents),
            "shared_python_files": len(source_rows), "host_workflow_shared": True,
            "source_commit": manifest["source_commit"], "source_profiles": len(replay["profiles"]),
            "prior_source_archive_unchanged": True, "native_execution_repeated": False}


if __name__ == "__main__":
    print(json.dumps(verify(Path(__file__).resolve().parent), sort_keys=True))
