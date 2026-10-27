#!/usr/bin/env python3
"""Read immutable Git objects for a retained CI snapshot; never import source."""
import argparse
import base64
from hashlib import sha1, sha256
import json
from pathlib import Path, PurePosixPath
import subprocess

COMMIT = "44cb32576f0ee8b0d9f01aa5a4fa44ea0848c314"


def git(repository, *args, data=None):
    return subprocess.run(["git", "-C", str(repository), *args], input=data,
                          check=True, capture_output=True).stdout


def objects(repository, identifiers, kind):
    ordered = sorted(set(identifiers))
    data = git(repository, "cat-file", "--batch", data=("\n".join(ordered) + "\n").encode())
    result, offset = {}, 0
    for identifier in ordered:
        end = data.index(b"\n", offset)
        oid, actual_kind, size = data[offset:end].decode().split()
        assert oid == identifier and actual_kind == kind
        length = int(size)
        body = data[end + 1:end + 1 + length]
        assert len(body) == length and data[end + 1 + length:end + 2 + length] == b"\n"
        assert sha1(kind.encode() + b" " + str(length).encode() + b"\0" + body).hexdigest() == identifier
        result[identifier] = body
        offset = end + length + 2
    assert offset == len(data)
    return result


def prepare(repository, snapshot, directory):
    assert snapshot["sha256"] == sha256(json.dumps(snapshot["files"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    entries = {}
    for raw in git(repository, "ls-tree", "-r", "-z", COMMIT).split(b"\0"):
        if raw:
            header, name = raw.split(b"\t", 1)
            mode, kind, oid = header.decode().split()
            entries[name.decode()] = (mode, kind, oid)
    selected = {}
    for name in snapshot["files"]:
        mode, kind, oid = entries[name]
        assert mode in {"100644", "100755"} and kind == "blob"
        selected[name] = oid
    blobs = objects(repository, selected.values(), "blob")
    rows = []
    compiler = sha256()
    for name, oid in sorted(selected.items()):
        raw = blobs[oid]
        digest = sha256(raw).hexdigest()
        assert digest == snapshot["files"][name], name
        rows.append({"path": name, "bytes": len(raw), "sha256": digest, "git_blob_sha1": oid})
        parts = PurePosixPath(name).parts
        if len(parts) == 2 and parts[0] == "hepta" and name.endswith(".py"):
            compiler.update(parts[-1].encode() + b"\0" + raw + b"\0")
    commit_object = git(repository, "cat-file", "commit", COMMIT)
    assert sha1(b"commit " + str(len(commit_object)).encode() + b"\0" + commit_object).hexdigest() == COMMIT
    root_tree = commit_object.splitlines()[0].decode().split()[1]
    trees = {"": root_tree}
    for raw in git(repository, "ls-tree", "-d", "-r", "-z", COMMIT).split(b"\0"):
        if raw:
            header, name = raw.split(b"\t", 1)
            mode, kind, oid = header.decode().split()
            assert mode == "040000" and kind == "tree"
            trees[name.decode()] = oid
    ancestors = {""}
    for name in selected:
        path = PurePosixPath(name).parent
        while path.as_posix() != ".":
            ancestors.add(path.as_posix())
            path = path.parent
    raw_trees = objects(repository, [trees[path] for path in ancestors], "tree")
    audit = {"schema": "hepta.ci-source-snapshot-git-audit.v1", "source_commit": COMMIT,
        "source_tree": root_tree, "source_snapshot_sha256": snapshot["sha256"],
        "compiler_sha256": compiler.hexdigest(), "files_checked": len(rows), "all_match": True, "files": rows,
        "scope": "every retained source-snapshot SHA-256 compared with exact immutable Git blob bytes during capture"}
    proof = {"schema": "hepta.ci-source-tree-proof.v1", "source_commit": COMMIT,
        "root_tree": root_tree, "commit_object_base64": base64.b64encode(commit_object).decode(),
        "tree_objects_base64": {oid: base64.b64encode(raw).decode() for oid, raw in sorted(raw_trees.items())},
        "source_blobs": selected,
        "scope": "commit/tree proof binds source paths to Git blob IDs; full-source SHA-256 comparison was performed at capture and selected source bytes are retained separately"}
    directory.mkdir(exist_ok=True, parents=True)
    for name, value in (("source-snapshot-git-audit.json", audit), ("source-tree-proof.json", proof)):
        with (directory / name).open("x") as stream:
            stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
    inputs = [".github/workflows/hepta-qualification.yml", "tools/release_check.py", "tools/bootstrap_verification.py",
              "experiments/agent_eval/sandbox_qualification.py", "formal/qemu-toolchain-lock.json",
              "tools/qualify_hia_unified.py", "tools/qualify_hia_program_perf.py", "tools/qualify_llvm_native.py",
              "tools/qualify_llvm_owned.py", "tools/performance_observation.py", "hepta/llvm_owned_backend.py",
              "examples/hia_program/benchmarks.hepta", "examples/hia_program/perf_driver.c",
              "examples/llvm_owned/owned.hepta", "examples/llvm_owned/qualification.hepta",
              "examples/llvm_owned/reference.rs", "examples/llvm_owned/driver.c", "examples/llvm_owned/observe.c",
              "tools/evidence_checks.py", "tests/test_qualification_environment.py",
              "experiments/agent_eval/sandbox.py", "tools/qualify_cpp_composed_llvm.py",
              "tools/validate_cpp_composed.py", "examples/cpp/composed_migration/harness.c",
              "tools/qualify_cpp_owned_llvm.py", "tools/validate_cpp_owned.py",
              "examples/cpp/owned_migration/harness.c"]
    selected_sources = []
    for name in inputs:
        raw = blobs[selected[name]]
        archive_path = "source/" + name
        output = directory / archive_path
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("xb") as stream:
            stream.write(raw)
        selected_sources.append({"git_path": name, "archived_path": archive_path, "bytes": len(raw),
                                 "sha256": sha256(raw).hexdigest(), "git_blob_sha1": selected[name]})
    with (directory / "source-identities.json").open("x") as stream:
        stream.write(json.dumps({"source_commit": COMMIT, "files": selected_sources}, indent=2, sort_keys=True) + "\n")
    return {"source_commit": COMMIT, "source_tree": root_tree, "files": len(rows),
            "snapshot_sha256": snapshot["sha256"], "compiler_sha256": compiler.hexdigest(),
            "selected_sources": len(selected_sources), "retained_tree_objects": len(raw_trees)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_bytes())
    assert report["source_git_commit"] == COMMIT
    print(json.dumps(prepare(args.repo, report["source_snapshot"], args.output), indent=2, sort_keys=True))
