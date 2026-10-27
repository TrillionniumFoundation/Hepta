#!/usr/bin/env python3
"""Verify this self-contained host archive without Git, extraction, or execution.

Only standard-library parsing, hashing and data comparisons are performed. The
recorded exact-source replay is checked as evidence, not rerun by this verifier.
The manifest preserves an observation; it cannot authenticate arbitrary authors.
"""
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import zipfile

COMMIT = "4ac39e626acd7f78e2f66708be741e78308b4e6a"
LOCAL = "8c88308eb9b6a8acf612ae9e8f7d9a7d89f5a776"
PRIOR = "44cb32576f0ee8b0d9f01aa5a4fa44ea0848c314"
TREE = "99a2273d45a333a1a9cc87110742399e7413d512"
RUN = 40445065374
WORKFLOW = ".github/workflows/hepta-native-hosts.yml"
HOSTS = {
    12707109574: (121994260948, "windows-2025", "Windows", "x86_64", "crlf"),
    12707772859: (121994261088, "ubuntu-24.04-arm", "Linux", "aarch64", "lf"),
    12707981204: (121994261134, "ubuntu-24.04", "Linux", "x86_64", "lf"),
    12708355394: (121994260804, "macos-15", "Darwin", "aarch64", "lf"),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def object_sha(kind, raw):
    return hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def safe_path(name):
    path = PurePosixPath(name)
    require(type(name) is str and bool(name) and not path.is_absolute()
            and ".." not in path.parts and str(path) == name and "\\" not in name,
            "unsafe/noncanonical archive path")
    return path


def load(root, name):
    return json.loads((root / name).read_bytes())


def archive(root, manifest):
    metadata = manifest["archive"]
    require(metadata["path"] == "host-records.tar.gz.base64", "archive filename")
    encoded = (root / metadata["path"]).read_bytes()
    require(len(encoded) == metadata["encoded_bytes"] <= 3_500_000
            and sha(encoded) == metadata["encoded_sha256"], "encoded archive identity")
    packed = base64.b64decode(b"".join(encoded.split()), validate=True)
    require(len(packed) == metadata["decoded_bytes"] and sha(packed) == metadata["sha256"],
            "compressed archive identity")
    with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
        raw_tar = stream.read(8 * 1024 * 1024 + 1)
    require(len(raw_tar) == metadata["tar_bytes"] <= 8 * 1024 * 1024
            and sha(raw_tar) == metadata["tar_sha256"], "bounded tar identity")
    expected = {row["path"]: row for row in manifest["members"]}
    require(len(expected) == len(manifest["members"]) == manifest["member_count"] == 188,
            "archive member denominator")
    contents = {}
    with tarfile.open(fileobj=io.BytesIO(raw_tar), mode="r:") as stream:
        for member in stream:
            safe_path(member.name)
            require(member.isfile() and member.name in expected and member.name not in contents,
                    "archive member type/inventory")
            row = expected[member.name]
            require(type(row["bytes"]) is int and member.size == row["bytes"] <= 4 * 1024 * 1024,
                    "archive member size")
            data = stream.extractfile(member).read(member.size + 1)
            require(len(data) == row["bytes"] and sha(data) == row["sha256"], "archive member digest")
            contents[member.name] = data
    require(set(contents) == set(expected), "complete archive inventory")
    return contents


def verify_sources(root, contents):
    proof, relation = load(root, "source-proof.json"), load(root, "source-relationship.json")
    require(set(proof["snapshots"]) == {COMMIT, LOCAL, PRIOR}, "source proof commit denominator")
    trees = {}
    for oid, encoded in proof["tree_objects_base64"].items():
        raw = base64.b64decode(encoded, validate=True)
        require(object_sha("tree", raw) == oid, "immutable tree hash")
        entries, position = [], 0
        while position < len(raw):
            end = raw.index(b"\0", position)
            mode, name = raw[position:end].split(b" ", 1)
            child = raw[end + 1:end + 21]
            require(len(child) == 20 and b"/" not in name and name not in {b"", b".", b".."}, "Git tree entry")
            entries.append((mode.decode(), name.decode(), child.hex()))
            position = end + 21
        require(len({name for _, name, _ in entries}) == len(entries), "duplicate Git entry")
        trees[oid] = entries
    leaves, roots, used = {}, {}, set()
    for commit, snapshot in proof["snapshots"].items():
        raw = base64.b64decode(snapshot["commit_object_base64"], validate=True)
        require(object_sha("commit", raw) == commit, "immutable commit hash")
        first = raw.splitlines()[0]
        require(first.startswith(b"tree "), "commit tree line")
        tree = first[5:].decode()
        require(tree == snapshot["tree"], "commit/root tree binding")
        roots[commit], leaves[commit] = tree, {}

        def walk(oid, prefix=""):
            require(oid in trees, "selected source tree missing")
            used.add(oid)
            for mode, name, child in trees[oid]:
                path = prefix + name
                if mode == "40000":
                    if path in {"hepta", "tools", ".github", ".github/workflows"} or path.startswith(("hepta/", "tools/")):
                        walk(child, path + "/")
                elif path == WORKFLOW or (path.startswith(("hepta/", "tools/")) and path.endswith(".py")):
                    require(mode in {"100644", "100755"}, "selected source must be a regular Git blob")
                    leaves[commit][path] = {"mode": mode, "oid": child}

        walk(tree)
    require(used == set(trees) and roots[COMMIT] == roots[LOCAL] == TREE, "complete captured tree identity")
    require(leaves[COMMIT] == leaves[LOCAL] and set(leaves[COMMIT]) == set(leaves[PRIOR]), "selected source path relation")
    require(relation["source_commit"] == COMMIT and relation["source_tree"] == TREE
            and relation["local_source_commit"] == LOCAL and relation["local_tree_identical"] is True
            and relation["prior_source_commit"] == PRIOR and relation["prior_source_tree"] == roots[PRIOR]
            and relation["whole_repository_identity_claimed"] is False, "source relation scope")
    rows = {row["git_path"]: row for row in relation["files"]}
    require(len(rows) == len(relation["files"]) == relation["source_file_count"] == 184
            and set(rows) == set(leaves[COMMIT]) == set(proof["selected_paths"]), "complete selected source inventory")
    source, changed = {}, []
    for path, row in rows.items():
        require(row["archive_member"] == "source/4ac39e62/" + path, "source/archive mapping")
        raw = contents[row["archive_member"]]
        require(b"\r\n" not in raw and len(raw) == row["bytes"] and sha(raw) == row["sha256"], "LF source bytes")
        require(object_sha("blob", raw) == row["source_git_blob_sha1"] == leaves[COMMIT][path]["oid"]
                and row["mode"] == leaves[COMMIT][path]["mode"]
                and row["prior_git_blob_sha1"] == leaves[PRIOR][path]["oid"], "source blob/commit binding")
        require(sha(raw.replace(b"\n", b"\r\n")) == row["crlf_sha256"], "CRLF source bytes")
        if row["source_git_blob_sha1"] != row["prior_git_blob_sha1"]:
            changed.append(path)
        source[path] = raw
    expected_changes = ["tools/qualify_cpp_composed_llvm.py", "tools/qualify_cpp_owned_llvm.py"]
    require(sorted(changed) == relation["selected_paths_changed_since_prior"] == expected_changes,
            "precise selected-source change boundary")
    require(sum(name.endswith(".py") for name in source) == relation["python_file_count"] == 183,
            "Python source denominator")
    return source, relation, len(trees)


def compiler_hash(source, policy):
    digest = hashlib.sha256()
    for path, raw in sorted(source.items()):
        if path.startswith("hepta/") and path.count("/") == 1 and path.endswith(".py"):
            if policy == "crlf":
                raw = raw.replace(b"\n", b"\r\n")
            digest.update(PurePosixPath(path).name.encode() + b"\0" + raw + b"\0")
    return digest.hexdigest()


def verify(root):
    root = Path(root)
    manifest = load(root, "MANIFEST.json")
    require(manifest["schema"] == "hepta.self-contained-host-archive.v2"
            and manifest["source_commit"] == COMMIT and manifest["source_tree"] == TREE,
            "manifest identity")
    sidecars = manifest["sidecar_files"]
    names = {row["path"] for row in sidecars}
    require(len(names) == len(sidecars), "unique sidecar list")
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    require(actual - {"MANIFEST.json", "archive-verification.json", manifest["archive"]["path"]} == names,
            "complete sidecar file inventory")
    for row in sidecars:
        path = root / safe_path(row["path"])
        require(path.is_file() and not path.is_symlink(), "ordinary sidecar")
        raw = path.read_bytes()
        require(len(raw) == row["bytes"] and sha(raw) == row["sha256"], "sidecar digest")
    contents = archive(root, manifest)
    source, relation, tree_count = verify_sources(root, contents)
    require(set(contents) == {"source/4ac39e62/" + p for p in source}
            | {f"host-zips/{aid}.zip" for aid in HOSTS}, "archive contains only exact sources and provider ZIPs")
    provider = load(root, "provider-observation.json")
    run, jobs_data, artifacts_data = provider["run_metadata"], provider["job_metadata"], provider["artifact_metadata"]
    require(load(root, "provider-originals/run.json") == run
            and load(root, "provider-originals/jobs.json") == jobs_data
            and load(root, "provider-originals/artifacts.json") == artifacts_data, "provider original metadata")
    require(run["id"] == RUN and run["run_number"] == 21 and run["run_attempt"] == 1
            and run["status"] == "completed" and run["conclusion"] == "success"
            and run["head_sha"] == COMMIT and run["head_commit"]["id"] == COMMIT
            and run["head_commit"]["tree_id"] == TREE and run["path"] == WORKFLOW,
            "exact provider run/source identity")
    jobs = {row["id"]: row for row in jobs_data["jobs"]}
    artifacts = {row["id"]: row for row in artifacts_data["artifacts"]}
    require(len(jobs_data["jobs"]) == jobs_data["total_count"] == len(jobs) == 4
            and set(jobs) == {v[0] for v in HOSTS.values()} and len(artifacts) == 4 and set(artifacts) == set(HOSTS),
            "provider host job/artifact denominator")
    identities = load(root, "zip-identities.json")
    zips = {row["artifact_id"]: row for row in identities}
    require(len(zips) == len(identities) == 4 and set(zips) == set(HOSTS), "unique ZIP identity inventory")
    replay = load(root, "source-replay.json")
    require(replay["native_commands_executed"] is False and replay["network_access_performed"] is False
            and set(replay["profiles"]) == {"lf", "crlf"}, "replay scope/profiles")
    for policy, profile in replay["profiles"].items():
        expected = {p: sha(raw if policy == "lf" else raw.replace(b"\n", b"\r\n"))
                    for p, raw in source.items() if p.endswith(".py")}
        require(profile["commit"] == COMMIT and profile["tree"] == TREE and profile["newline_policy"] == policy
                and profile["source_files"] == expected and profile["actual_compiler_sha256"] == compiler_hash(source, policy),
                "exact LF/CRLF source and compiler replay inventory")
    records = {row["artifact_id"]: row for row in replay["reports"]}
    require(len(records) == len(replay["reports"]) == 4 and set(records) == set(HOSTS), "four new report replays")
    summaries, log_bytes, report_bytes = [], 0, 0
    for aid, (jid, runner, system, machine, policy) in HOSTS.items():
        job, artifact, row, identity = jobs[jid], artifacts[aid], records[aid], zips[aid]
        require(job["run_id"] == RUN and job["head_sha"] == COMMIT and job["name"] == runner + " / " + machine
                and job["status"] == "completed" and job["conclusion"] == "success"
                and all(s["status"] == "completed" and s["conclusion"] == "success" for s in job["steps"]),
                "successful exact-head provider job")
        require(artifact["workflow_run"]["id"] == RUN and artifact["workflow_run"]["head_sha"] == COMMIT
                and artifact["name"] == "native-" + runner + "-" + COMMIT
                and identity["source_commit"] == COMMIT and identity["run_id"] == RUN,
                "provider artifact source/host binding")
        zipped = contents[f"host-zips/{aid}.zip"]
        require(len(zipped) == identity["bytes"] == artifact["size_in_bytes"]
                and sha(zipped) == identity["sha256"]
                and artifact["digest"] == identity["provider_digest"] == "sha256:" + sha(zipped), "original ZIP identity")
        require(row["archived_report"] == f"hosts/{aid}.json", "original report path")
        raw = (root / row["archived_report"]).read_bytes()
        with zipfile.ZipFile(io.BytesIO(zipped)) as stream:
            require(stream.namelist() == ["native-host.json"] and stream.read("native-host.json") == raw,
                    "single byte-identical original report; no archived binary")
        require(identity["members"] == [{"name": "native-host.json", "bytes": len(raw), "sha256": sha(raw)}], "ZIP member inventory")
        report = json.loads(raw)
        require(report["schema"] == "hepta.native-host.v1" and report["status"] == "passed"
                and (report["host"]["system"], report["host"]["machine"]) == (system, machine)
                and report["host"]["execution"] == "native_host_process", "native host observation")
        require(row["provider_job_id"] == jid and row["provider_job_name"] == job["name"]
                and row["commit_binding"] == {"kind": "provider_workflow_run_head_sha", "source_commit": COMMIT}
                and row["original_report_commit_fields"] == {k: report[k] for k in ("git_commit", "gitcommit", "source_git_commit") if k in report}
                and row["source_profile"] == policy and row["input_sha256"] == sha(raw), "original report identity/replay mapping")
        original_replay = load(root, row["replay_output"])
        require(not (root / row["replay_stderr"]).read_bytes(), "replay stderr must be retained and empty")
        for key, value in original_replay.items():
            require(value == (replay["profiles"][policy]["source_files"] if key == "source_files" else row[key]),
                    "raw replay/aggregate agreement")
        require(row["validated"] is True and row["error"] is None and type(row["returncode"]) is int and row["returncode"] == 0
                and row["native_commands_executed"] is False and row["network_access_performed"] is False
                and row["blocked_audit_events"] == [] and row["source_and_report_unchanged"] is True,
                "successful pure-data replay")
        require(report["compiler_sha256"] == row["actual_compiler_sha256"] == row["reported_compiler_sha256"]
                == compiler_hash(source, policy), "compiler byte identity")
        require(report["matrix"]["expected_foreign_calls_per_run"] == 181
                and report["matrix"]["aggregate_shapes"] == 36 and report["matrix"]["seed"] == 20261025
                and report["matrix"]["values_per_shape"] == 3, "finite ABI denominator")
        commands = report["commands"]
        require(len(commands) == 8 and all(type(c["returncode"]) is int for c in commands), "complete recorded command trace")
        expected_runs = [{"optimization": flag, "layout_checked": True, "returncode": 0,
                          "observed": {"status": "passed", "foreign_calls": 181}} for flag in ("-O0", "-O2")]
        require(report["executions"] == row["observed_executions"] == expected_runs, "two successful ABI executions")
        require(all(c["returncode"] == 0 for c in commands[:7]), "compiler and positive commands succeeded")
        for i in (3, 5):
            require(json.loads(commands[i]["stdout"]) == {"status": "passed", "foreign_calls": 181}, "actual positive stdout")
        negative = report["negative_control"]
        require(negative == row["negative_control"] and negative["name"] == "compiled_wrong_c_echo"
                and negative["status"] == "rejected_as_expected" and type(negative["returncode"]) is int
                and negative["returncode"] == commands[7]["returncode"] != 0
                and "v_scalar0_0" in commands[7]["stderr"], "actual compiled negative assertion")
        claims = report["claims"]
        require(claims == {"actual_reported_host_executed": True, "cross_host_results_inferred": False,
                           "physical_board_executed": False, "gpu_device_executed": False,
                           "all_abi_features_qualified": False}, "finite host qualification scope")
        log = (root / f"provider-logs/{jid}.log").read_bytes()
        text = log.decode("utf-8")
        require(re.search(r"^\S+Z " + COMMIT + r"\r?$", text, re.M) is not None
                and '"status": "passed"' in text and str(aid) in text
                and "HEPTA_QUALIFICATION_HEAD_SHA: " + COMMIT in text,
                "provider job log exact-head/result/upload observations")
        log_bytes += len(log)
        report_bytes += len(raw)
        summaries.append({"artifact_id": aid, "job_id": jid, "system": system, "machine": machine,
                          "source_profile": policy, "foreign_calls_per_positive_run": 181,
                          "positive_runs": 2, "negative_returncode": negative["returncode"],
                          "original_report_sha256": sha(raw), "original_report_bytes": len(raw),
                          "original_report_crlf_count": raw.count(b"\r\n"),
                          "provider_decoded_log_sha256": sha(log), "provider_decoded_log_bytes": len(log)})
    return {"verified": True, "source_commit": COMMIT, "source_tree": TREE, "local_same_tree_commit": LOCAL,
            "provider_run_id": RUN, "host_jobs": 4, "host_reports": 4, "original_zip_bytes": sum(v["bytes"] for v in zips.values()),
            "original_report_bytes": report_bytes, "provider_decoded_log_bytes": log_bytes,
            "source_python_files": 183, "source_workflow_files": 1, "captured_git_tree_objects": tree_count,
            "archive_members": len(contents), "sidecar_files_verified": len(sidecars), "source_profiles": 2,
            "positive_runs": 8, "foreign_calls_across_positive_runs": 1448, "compiled_wrong_controls_rejected": 4,
            "archived_native_binary_members": 0, "native_execution_repeated": False,
            "archived_source_executed_by_portable_verifier": False, "network_access_performed": False,
            "whole_project_blockers_closed": False, "hosts": summaries}


if __name__ == "__main__":
    print(json.dumps(verify(Path(__file__).resolve().parent), indent=2, sort_keys=True))
