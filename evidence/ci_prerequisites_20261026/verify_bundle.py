#!/usr/bin/env python3
"""Verify archived bytes and receipt linkage without extraction or execution."""
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import zipfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def safe_relative(name):
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts


def verify(directory):
    directory = Path(directory)
    manifest = json.loads((directory / "MANIFEST.json").read_text())
    require(manifest["schema"] == "hepta.ci-prerequisite-archive.v1", "schema")
    identity = manifest["archive"]
    require(identity["path"] == "ci-records.tar.xz.base64", "archive path")
    encoded = (directory / identity["path"]).read_bytes()
    require(len(encoded) <= 16 * 1024 * 1024, "encoded size bound")
    require(sha(encoded) == identity["encoded_sha256"], "encoded digest")
    packed = base64.b64decode(b"".join(encoded.split()), validate=True)
    require(len(packed) == identity["decoded_bytes"], "archive size")
    require(sha(packed) == identity["sha256"], "archive digest")
    expected = {row["path"]: row for row in manifest["members"]}
    require(len(expected) == len(manifest["members"]) == manifest["member_count"] <= 1024,
            "member count or duplicate manifest path")
    contents = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(packed), mode="r|xz") as archive:
        for member in archive:
            require(member.isfile() and safe_relative(member.name), "member type/path")
            require(member.name in expected and member.name not in contents,
                    "unexpected or duplicate member")
            row = expected[member.name]
            require(type(row["bytes"]) is int and 0 <= row["bytes"] <= 16 * 1024 * 1024,
                    "member size bound")
            require(member.size == row["bytes"], "member size")
            total += member.size
            require(total <= 128 * 1024 * 1024, "total size bound")
            stream = archive.extractfile(member)
            require(stream is not None, "member stream")
            data = stream.read(member.size + 1)
            require(len(data) == row["bytes"] and sha(data) == row["sha256"], "member digest")
            contents[member.name] = data
    require(set(contents) == set(expected), "missing members")

    replay = json.loads((directory / "source-replay.json").read_text())
    identities = json.loads((directory / "zip-identities.json").read_text())
    zip_ids = {row["artifact_id"]: row for row in identities}
    require(len(zip_ids) == len(identities) == 9, "ZIP identity count")
    for row in identities:
        require(row["provider_digest"] == "sha256:" + row["sha256"]
                and row["digest_matches"] is True, "provider digest linkage")
        require(row["public_url"].startswith(
            "https://github.com/TrillionniumFoundation/Hepta/actions/runs/")
                and "?" not in row["public_url"], "public provider URL")
    require(zip_ids[12618342700] == manifest["old_zip_identity"], "old ZIP identity")
    for profile in replay["profiles"].values():
        prefix = "source/" + profile["commit"][:8] + "/"
        files = {name[len(prefix):]: data for name, data in contents.items()
                 if name.startswith(prefix)}
        require(set(files) == set(profile["source_files"]), "source inventory")
        for name, data in files.items():
            if profile["newline_policy"] == "crlf":
                data = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            else:
                require(profile["newline_policy"] == "lf", "newline policy")
            require(sha(data) == profile["source_files"][name], "source profile digest")
    require(len(replay["reports"]) == 8 and replay["native_commands_executed"] is False,
            "receipt count or replay scope")
    seen_ids = set()
    for row in replay["reports"]:
        artifact = zip_ids[row["artifact_id"]]
        profile = replay["profiles"][row["source_profile"]]
        require(artifact["source_commit"] == profile["commit"], "receipt/source commit")
        require(row["artifact_id"] not in seen_ids, "duplicate receipt")
        seen_ids.add(row["artifact_id"])
        require(safe_relative(row["archived_report"]), "receipt path")
        raw = (directory / row["archived_report"]).read_bytes()
        require(sha(raw) == row["input_sha256"], "receipt digest")
        zipped = contents[f"host-zips/{row['artifact_id']}.zip"]
        require(len(zipped) == artifact["bytes"] and sha(zipped) == artifact["sha256"],
                "host ZIP identity")
        with zipfile.ZipFile(io.BytesIO(zipped)) as archive:
            require(archive.namelist() == ["native-host.json"], "host ZIP members")
            require(archive.read("native-host.json") == raw, "original receipt bytes")
        report = json.loads(raw)
        require(row["validated"] is True and row["error"] is None
                and row["returncode"] == 0 and row["native_commands_executed"] is False,
                "recorded replay result")
        require(report["compiler_sha256"] == row["reported_compiler_sha256"]
                == row["actual_compiler_sha256"] == profile["actual_compiler_sha256"],
                "compiler identity linkage")

    original_paths = {
        "release-validation.json": "artifacts/candidate/release-validation.json",
        "sandbox.json": "artifacts/candidate/sandbox.json",
        "workflow-source.json": "artifacts/workflow-source.json",
    }
    for name, member in original_paths.items():
        require((directory / "old-full-original" / name).read_bytes()
                == contents["old-full/" + member], "old original copy")
    release = json.loads(contents["old-full/artifacts/candidate/release-validation.json"])
    diagnosis = json.loads((directory / "old-full-diagnosis.json").read_text())
    gates = release["gates"]
    require(len(release["planned_gates"]) == diagnosis["planned_gate_count"] == 46,
            "old planned denominator")
    require(len(gates) == diagnosis["completed_gate_count"] == 46, "old completed denominator")
    for status, key in (("passed", "passed_gates"), ("failed", "failed_gates")):
        require([row["name"] for row in gates if row["status"] == status] == diagnosis[key],
                "old gate outcomes")
    unit_log = contents["old-full/artifacts/candidate/unit_and_integration.log"].decode()
    count = re.search(r"Ran (\d+) tests in ([\d.]+)s", unit_log)
    failed = re.search(r"FAILED \(failures=(\d+), errors=(\d+)\)", unit_log)
    require(count is not None and failed is not None, "old terminal unittest record")
    require(diagnosis["unit"] == {"tests_run": int(count[1]), "seconds": float(count[2]),
            "failures": int(failed[1]), "errors": int(failed[2]), "skipped": 0}, "unit counts")
    require(unit_log.count("E_TOOLCHAIN_IDENTITY")
            == diagnosis["toolchain_identity_error_occurrences_in_unit_log"], "identity errors")
    return {"verified": True, "members": len(contents), "uncompressed_bytes": total,
            "host_reports": len(seen_ids), "source_profiles": len(replay["profiles"]),
            "old_full_passed": len(diagnosis["passed_gates"]),
            "old_full_failed": len(diagnosis["failed_gates"]),
            "native_execution_repeated": False}


if __name__ == "__main__":
    print(json.dumps(verify(Path(__file__).resolve().parent), sort_keys=True))
