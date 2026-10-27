#!/usr/bin/env python3
"""Read-only identity verification; never extract, import or execute bundle code.

Git object identities bind the retained source bytes to the tested commit.
They do not attest that a hostile producer executed the reported experiments.
"""
import ast
import base64
import collections
import hashlib
import io
import json
import lzma
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

COMMIT = "3a424e427b378400802c9e3c2fef558c0a352756"
SNAPSHOT = "339ed18eafd41c41e6b1e84f18bec100db5122cf60983c948aa721f54249c10b"
COMPILER = "baa9c71bf65c590b23598635012989ac2f07242803b1a876b13a28eec2848bd7"
REPORT_SHA256 = "248a5aa6041e90e87e1528bf78ea35f97316caf8fe99b686b19156e55cf2ad8f"
RUN = "artifacts/composition-candidate-20261026-run1"
MAX_ENCODED = 64 * 1024 * 1024
MAX_TAR = 256 * 1024 * 1024
MAX_FILE = 32 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode_json(data):
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def safe_path(value):
    require(isinstance(value, str) and value and "\\" not in value and "\0" not in value,
            "unsafe path text")
    path = PurePosixPath(value)
    require(not path.is_absolute() and ".." not in path.parts and str(path) == value
            and value != ".", "unsafe relative path")
    return path


def read_regular(directory, name, maximum=MAX_ENCODED):
    path = safe_path(name)
    current = Path(directory)
    for component in path.parts:
        current = current / component
        require(not current.is_symlink(), "symlink in retained file path")
    before = current.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "nonregular or oversized file")
    data = current.read_bytes()
    after = current.stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(identity(before) == identity(after) and len(data) == before.st_size, "file changed during read")
    return data


def unpack_archive(directory, manifest, retain):
    require(manifest["schema"] == "hepta.source-candidate.archive.v1", "archive schema")
    require(manifest["encoding"] == "base64" and manifest["compression"] in
            ("xz-preset-1", "xz-preset-6-dict-64MiB"), "archive encoding")
    require(0 < manifest["encoded_bytes"] <= MAX_ENCODED, "encoded archive size")
    require(0 < manifest["decoded_bytes"] <= MAX_ENCODED, "compressed archive size")
    require(0 < manifest["member_count"] <= 2000, "archive member count")
    require(0 <= manifest["uncompressed_bytes"] <= MAX_TAR, "archive uncompressed size")
    logical_name = str(safe_path(manifest["archive"]))
    parts = manifest["parts"]
    require(isinstance(parts, list) and 1 <= len(parts) <= 32, "archive part count")
    expected_names = [logical_name] if len(parts) == 1 else [logical_name + ".part%02d" % (i + 1) for i in range(len(parts))]
    require([p["path"] for p in parts] == expected_names, "archive part order")
    encoded = bytearray()
    for part in parts:
        data = read_regular(directory, part["path"], 3_500_000)
        require(len(data) == part["bytes"] and sha(data) == part["sha256"], "archive part identity")
        encoded.extend(data)
        require(len(encoded) <= MAX_ENCODED, "encoded archive bound")
    require(len(encoded) == manifest["encoded_bytes"] and sha(encoded) == manifest["encoded_sha256"], "encoded archive identity")
    packed = base64.b64decode(b"".join(encoded.split()), validate=True)
    require(len(packed) == manifest["decoded_bytes"] and sha(packed) == manifest["decoded_sha256"], "compressed archive identity")
    decoder = lzma.LZMADecompressor(memlimit=96 * 1024 * 1024)
    tar_bytes = decoder.decompress(packed, max_length=MAX_TAR + 1)
    require(len(tar_bytes) <= MAX_TAR and decoder.eof and not decoder.unused_data,
            "xz expansion bound, truncation or concatenated stream")
    if "tar_sha256" in manifest:
        require(len(tar_bytes) == manifest["tar_bytes"] and sha(tar_bytes) == manifest["tar_sha256"],
                "uncompressed tar container identity")
    expected = {}
    for row in manifest["members"]:
        name = str(safe_path(row["path"]))
        require(name not in expected, "duplicate manifest member")
        require(type(row["bytes"]) is int and 0 <= row["bytes"] <= MAX_FILE, "member size bound")
        require(type(row["mode"]) is int and 0 <= row["mode"] <= 0o777, "member permissions")
        expected[name] = row
    require(len(expected) == manifest["member_count"], "manifest member denominator")
    found = set()
    retained = {}
    total = last = 0
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
        for member in archive:
            name = str(safe_path(member.name))
            require(member.isfile() and not member.pax_headers, "archive member must be a regular USTAR file")
            require(name in expected and name not in found, "unlisted or duplicate tar member")
            row = expected[name]
            require(member.size == row["bytes"] and member.mode == row["mode"], "tar member identity metadata")
            total += member.size
            require(total <= MAX_TAR, "archive member byte bound")
            with archive.extractfile(member) as stream:
                data = stream.read(member.size + 1)
            require(len(data) == member.size and sha(data) == row["sha256"], "tar member digest")
            if retain(name):
                retained[name] = data
            found.add(name)
            last = member.offset_data + (member.size + 511) // 512 * 512
    require(found == set(expected) and total == manifest["uncompressed_bytes"], "archive inventory denominator")
    require(len(tar_bytes) >= last + 1024 and not any(tar_bytes[last:]), "unexpected tar trailing data")
    return retained, expected


def git_sha(kind, data):
    return hashlib.sha1(kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest()


def verify_source(sources, snapshot, proof):
    require(len(sources) == len(snapshot["files"]) == 920 and set(sources) == set(snapshot["files"]), "source denominator")
    require(snapshot["sha256"] == SNAPSHOT and sha(wire(snapshot["files"])) == SNAPSHOT, "snapshot identity")
    require(proof["schema"] == "hepta.source-candidate.git-proof.v1" and proof["commit"] == COMMIT, "Git proof scope")
    raw = base64.b64decode(proof["commit_object_base64"], validate=True)
    require(git_sha("commit", raw) == COMMIT, "Git commit object identity")
    require(raw.splitlines()[0] == ("tree " + proof["root_tree"]).encode(), "Git root tree identity")
    trees = {}
    for oid, value in proof["tree_objects_base64"].items():
        require(re.fullmatch(r"[0-9a-f]{40}", oid) is not None, "Git tree object name")
        raw = base64.b64decode(value, validate=True)
        require(git_sha("tree", raw) == oid, "Git tree object identity")
        entries = {}
        offset = 0
        while offset < len(raw):
            zero = raw.index(b"\0", offset)
            mode, name = raw[offset:zero].split(b" ", 1)
            require(zero + 21 <= len(raw), "Git tree entry truncation")
            text = name.decode()
            require("/" not in text and text not in (".", "..") and text not in entries, "Git tree entry path")
            entries[text] = (mode.decode(), raw[zero + 1:zero + 21].hex())
            offset = zero + 21
        trees[oid] = entries
    require(set(proof["source_blobs"]) == set(sources), "Git source denominator")
    used = set()
    compiler = hashlib.sha256()
    for name, data in sorted(sources.items()):
        require(sha(data) == snapshot["files"][name], "snapshot file digest")
        parts = safe_path(name).parts
        tree = proof["root_tree"]
        for component in parts[:-1]:
            used.add(tree)
            mode, tree = trees[tree][component]
            require(mode == "40000", "Git source ancestor type")
        used.add(tree)
        mode, oid = trees[tree][parts[-1]]
        require(mode in ("100644", "100755") and git_sha("blob", data) == oid == proof["source_blobs"][name], "Git source blob identity")
        if len(parts) == 2 and parts[0] == "hepta" and name.endswith(".py"):
            compiler.update(parts[-1].encode() + b"\0" + data + b"\0")
    require(used == set(trees), "unnecessary or missing Git tree objects")
    require(compiler.hexdigest() == COMPILER, "compiler source tree digest")


def literal_assignment(source, name):
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError("missing literal assignment: " + name)


def verify_reports(report_data, artifacts, identities, sources, snapshot):
    require(sha(report_data) == REPORT_SHA256, "original release report digest")
    report = decode_json(report_data)
    require(report["schema"] == "hepta.release.v2" and report["status"] == "failed", "release result changed")
    require(report["source_git_commit"] == COMMIT and report["source_snapshot"] == snapshot
            and report["compiler_sha256"] == COMPILER and report["snapshot_unchanged"] is True, "release source binding")
    require(report["whole_project_blockers_closed"] is False, "unsupported whole-project closure")
    gates = report["gates"]
    require(len(gates) == len(report["planned_gates"]) == 50
            and [g["name"] for g in gates] == report["planned_gates"]
            and len(set(report["planned_gates"])) == 50, "release gate denominator or order")
    require(collections.Counter(g["status"] for g in gates) == {"passed": 48, "failed": 2}, "release result denominator")
    require({g["name"] for g in gates if g["status"] == "failed"} == {"llvm_native_performance", "llvm_owned_performance"}, "failed gates changed")
    require(len({g["log"] for g in gates}) == 50, "gate log denominator")
    for gate in gates:
        require(identities[gate["log"]]["sha256"] == gate["log_sha256"], "gate log hash")
        require(gate["exit_code"] == (0 if gate["status"] == "passed" else 1), "gate exit result")
    require(len(report["evidence"]) == 43 and {g["evidence"] for g in gates if "evidence" in g} == set(report["evidence"]), "evidence denominator")
    for path, value in report["evidence"].items():
        require(identities[path]["sha256"] == value["sha256"] and identities[path]["bytes"] == value["bytes"], "evidence file identity")
    unit = gates[0]
    require(unit["name"] == "unit_and_integration" and unit["test_count"] == 2093
            and unit["skipped"] == 0 and unit["seconds"] == 615.644, "unit result denominator")
    require(re.search(rb"\nRan 2093 tests in 614\.471s\n\nOK\n?\Z", artifacts[unit["log"]]) is not None, "terminal unittest result")
    counts = {}
    for name, count in (("llvm_native.json", 42), ("llvm_owned.json", 63)):
        data = decode_json(artifacts[RUN + "/" + name])
        require(data["git_commit"] == COMMIT and data["compiler_tree_sha256"] == COMPILER, "performance source binding")
        require(data["status"] == "measurement_inconclusive" and data["ok"] is False
                and data["evaluation"]["status"] == "measurement_inconclusive", "retained inconclusive result changed")
        samples, observations = data["raw_samples"], data["process_observations"]
        require(len(samples) == len(observations) == count, "performance sample or observation denominator")
        require([s["sample_index"] for s in samples] == list(range(count)), "performance sample sequence")
        for sample, observation in zip(samples, observations):
            require(observation["sample"] == {key: sample[key] for key in ("backend", "group", "kernel", "sample_index")}, "observation/sample order")
            require(all(observation["scope"][key] is False for key in ("exclusive_cpu_access_proved", "measurement_cause_proved", "native_elapsed_replaced", "sample_selection_or_threshold_adjustment")), "observation scope changed")
        require(sha(wire(data["protocol"])) == data["protocol_sha256"], "performance protocol identity")
        if name == "llvm_native.json":
            source = sources["tools/qualify_llvm_native.py"]
            require(sha(source) == data["qualifier_sha256"], "native qualifier input")
            require(sha(sources["tools/performance_observation.py"]) == data["process_observer_sha256"], "native observer input")
            require(literal_assignment(source, "PROTOCOL") == data["protocol"], "native protocol source")
            require(sha(literal_assignment(source, "SOURCE").encode()) == data["source_sha256"], "native workload source")
            require(sha(literal_assignment(source, "DRIVER").encode()) == data["driver_source_sha256"], "native driver source")
        else:
            for path, digest in data["inputs"].items():
                require(sha(sources[path]) == digest, "owned qualifier input")
            workload = sources["examples/llvm_owned/owned.hepta"] + b"\n" + sources["examples/llvm_owned/qualification.hepta"]
            require(sha(workload) == data["source_sha256"], "owned workload source")
            require(sha(sources["examples/llvm_owned/driver.c"]) == data["driver_source_sha256"], "owned driver source")
        counts[name] = {"samples": count, "observations": count, "status": data["status"]}
    return report, counts


def verify(directory):
    directory = Path(directory)
    manifest = decode_json(read_regular(directory, "MANIFEST.json", 1024 * 1024))
    require(manifest["schema"] == "hepta.source-candidate.bundle.v1", "bundle schema")
    require(manifest["tested_source_commit"] == COMMIT and manifest["source_snapshot_sha256"] == SNAPSHOT
            and manifest["compiler_sha256"] == COMPILER, "bundle source binding")
    for name, row in manifest["files"].items():
        data = read_regular(directory, name)
        require(len(data) == row["bytes"] and sha(data) == row["sha256"], "retained loose file digest: " + name)
    source_manifest = decode_json(read_regular(directory, "source-files.manifest.json"))
    artifact_manifest = decode_json(read_regular(directory, "run-artifacts.manifest.json"))
    sources, source_ids = unpack_archive(directory, source_manifest, lambda _: True)
    retain = {RUN + "/" + n for n in ("release-validation.json", "llvm_native.json", "llvm_owned.json", "unit_and_integration.log")}
    artifacts, artifact_ids = unpack_archive(directory, artifact_manifest, lambda p: p in retain)
    require(len(source_ids) == 920 and len(artifact_ids) == 585, "bundle inventory denominator")
    snapshot = decode_json(read_regular(directory, "source-snapshot.json"))
    proof = decode_json(read_regular(directory, "source-git-identity.json"))
    verify_source(sources, snapshot, proof)
    for name in ("release-validation.json", "llvm_native.json", "llvm_owned.json"):
        require(read_regular(directory, name) == artifacts[RUN + "/" + name], "loose report differs from archive")
    report, counts = verify_reports(artifacts[RUN + "/release-validation.json"], artifacts, artifact_ids, sources, snapshot)
    scope = decode_json(read_regular(directory, "archive-scope.json"))
    require(scope["all_native_artifact_bytes_retained"] is False and scope["all_toolchains_retained"] is False
            and scope["native_execution_repeated"] is False, "archive scope overstated")
    expected_dirs = [RUN] + [g["command"][g["command"].index("--workdir") + 1] for g in report["gates"] if "--workdir" in g["command"]]
    require([d["path"] for d in scope["directory_inventory"]] == expected_dirs and len(expected_dirs) == 7, "retained workdir scope")
    covered = {scope["driver_log_member"]}
    for row in scope["directory_inventory"]:
        members = {name for name in artifact_ids if name.startswith(row["path"] + "/")}
        require(len(members) == row["files"] and sum(artifact_ids[n]["bytes"] for n in members) == row["bytes"], "retained workdir inventory")
        covered.update(members)
    require(covered == set(artifact_ids), "unrelated or missing artifact scope")
    require(sha(read_regular(directory, "driver.log")) == artifact_ids[scope["driver_log_member"]]["sha256"], "driver log identity")
    return {"verified": True, "source_commit": COMMIT, "source_snapshot_sha256": SNAPSHOT,
            "compiler_sha256": COMPILER, "source_files": len(source_ids), "git_tree_objects": len(proof["tree_objects_base64"]),
            "artifact_files": len(artifact_ids), "gate_logs": 50, "evidence_hashes": 43,
            "archives": {label: {key: item[key] for key in ("compression", "encoded_sha256", "decoded_sha256", "encoded_bytes", "decoded_bytes")}
                         for label, item in (("source", source_manifest), ("artifacts", artifact_manifest))},
            "gate_results": {"passed": 48, "failed": 2}, "unit_tests": 2093, "unit_skips": 0,
            "retained_performance": counts, "native_execution_repeated": False,
            "all_native_artifact_bytes_retained": False,
            "scope": "retained bytes and internally consistent identities; no fresh execution, hostile-producer attestation or whole-language proof"}


if __name__ == "__main__":
    print(json.dumps(verify(Path(__file__).resolve().parent), sort_keys=True, indent=2))
