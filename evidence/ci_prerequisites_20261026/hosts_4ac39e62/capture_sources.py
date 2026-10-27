#!/usr/bin/env python3
"""Export immutable Git source bytes for evidence replay; execute only Git reads.

This preparation helper does not run a compiler, native program, or qualifier.
The portable verifier separately checks the captured commit/tree/blob proof.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess

COMMIT = "4ac39e626acd7f78e2f66708be741e78308b4e6a"
LOCAL = "8c88308eb9b6a8acf612ae9e8f7d9a7d89f5a776"
PRIOR = "44cb32576f0ee8b0d9f01aa5a4fa44ea0848c314"
TREE = "99a2273d45a333a1a9cc87110742399e7413d512"
WORKFLOW = ".github/workflows/hepta-native-hosts.yml"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def object_sha(kind, raw):
    return hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def entries(raw):
    result = []
    position = 0
    while position < len(raw):
        end = raw.index(b"\0", position)
        mode, name = raw[position:end].split(b" ", 1)
        digest = raw[end + 1:end + 21]
        assert len(digest) == 20
        result.append((mode.decode(), name.decode(), digest.hex()))
        position = end + 21
    return result


def capture(repo, staging, output):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args])

    trees = {}
    snapshots = {}
    source_maps = {}
    for commit in (COMMIT, LOCAL, PRIOR):
        raw = git("cat-file", "commit", commit)
        assert object_sha("commit", raw) == commit
        root = raw.splitlines()[0].decode().removeprefix("tree ")
        snapshots[commit] = {"commit_object_base64": base64.b64encode(raw).decode(), "tree": root}
        leaves = {}

        def visit(oid, prefix=""):
            raw_tree = git("cat-file", "tree", oid)
            assert object_sha("tree", raw_tree) == oid
            trees[oid] = base64.b64encode(raw_tree).decode()
            for mode, name, child in entries(raw_tree):
                path = prefix + name
                if mode == "40000":
                    if path in {"hepta", "tools", ".github", ".github/workflows"} or path.startswith(("hepta/", "tools/")):
                        visit(child, path + "/")
                elif path == WORKFLOW or (path.startswith(("hepta/", "tools/")) and path.endswith(".py")):
                    assert mode in {"100644", "100755"}
                    leaves[path] = {"mode": mode, "git_blob_sha1": child}

        visit(root)
        source_maps[commit] = leaves
    assert snapshots[COMMIT]["tree"] == snapshots[LOCAL]["tree"] == TREE
    assert source_maps[COMMIT] == source_maps[LOCAL]
    current, prior = source_maps[COMMIT], source_maps[PRIOR]
    assert set(current) == set(prior)
    rows = []
    for path, entry in sorted(current.items()):
        raw = git("cat-file", "blob", entry["git_blob_sha1"])
        assert object_sha("blob", raw) == entry["git_blob_sha1"]
        assert b"\r\n" not in raw, "Git source unexpectedly contains CRLF"
        for policy, data in (("lf", raw), ("crlf", raw.replace(b"\n", b"\r\n"))):
            target = staging / policy / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        rows.append({"git_path": path, "mode": entry["mode"], "source_git_blob_sha1": entry["git_blob_sha1"],
                     "prior_git_blob_sha1": prior[path]["git_blob_sha1"], "bytes": len(raw), "sha256": sha(raw),
                     "crlf_sha256": sha(raw.replace(b"\n", b"\r\n")),
                     "archive_member": "source/4ac39e62/" + path})
    python = [row for row in rows if row["git_path"].endswith(".py")]
    changed = [row["git_path"] for row in rows if row["source_git_blob_sha1"] != row["prior_git_blob_sha1"]]
    relation = {"schema": "hepta.host-source-capture.v2", "source_commit": COMMIT, "source_tree": TREE,
                "local_source_commit": LOCAL, "local_tree_identical": True,
                "prior_source_commit": PRIOR, "prior_source_tree": snapshots[PRIOR]["tree"],
                "source_file_count": len(rows), "python_file_count": len(python), "files": rows,
                "selected_paths_changed_since_prior": changed,
                "whole_repository_identity_claimed": False,
                "export_method": "git cat-file immutable commit/tree/blob objects; independent LF and LF-to-CRLF exports"}
    proof = {"schema": "hepta.selected-git-source-proof.v1", "snapshots": snapshots, "tree_objects_base64": trees,
             "selected_paths": [row["git_path"] for row in rows], "native_execution_performed": False}
    for name, value in (("source-relationship.json", relation), ("source-proof.json", proof)):
        (output / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"source_commit": COMMIT, "source_tree": TREE, "python_files": len(python),
                      "workflow_files": 1, "total_bytes": sum(row["bytes"] for row in rows),
                      "captured_tree_objects": len(trees), "changed_since_44": changed}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    capture(args.repo, args.staging, args.output)
