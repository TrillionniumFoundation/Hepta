#!/usr/bin/env python3
"""Capture immutable Git directory objects for every ZIP deduplication decision."""
import argparse
import base64
import json
from pathlib import Path

from source_git_audit import COMMIT, git, objects


def capture(repository, inventory, output):
    assert inventory["source_commit"] == COMMIT
    commit = git(repository, "cat-file", "commit", COMMIT)
    root = commit.splitlines()[0].decode().split()[1]
    trees = {"": root}
    blobs = {}
    for raw in git(repository, "ls-tree", "-r", "-t", "-z", COMMIT, "--", "artifacts/", "evidence/").split(b"\0"):
        if not raw:
            continue
        header, name = raw.split(b"\t", 1)
        mode, kind, oid = header.decode().split()
        if kind == "tree":
            assert mode == "040000"
            trees[name.decode()] = oid
        else:
            assert kind == "blob" and mode in {"100644", "100755"}
            blobs[name.decode()] = oid
    for row in inventory["members"]:
        assert blobs.get(row["path"]) == row["source_git_blob_sha1"]
    raw_trees = objects(repository, trees.values(), "tree")
    proof = {"schema": "hepta.ci-zip-source-tree-proof.v1", "source_commit": COMMIT,
        "root_tree": root, "commit_object_base64": base64.b64encode(commit).decode(),
        "tree_objects_base64": {oid: base64.b64encode(raw).decode() for oid, raw in sorted(raw_trees.items())},
        "scope": "complete artifacts/evidence directory subtrees prove existing blob identity or path absence for every provider ZIP file"}
    with output.open("x") as stream:
        stream.write(json.dumps(proof, indent=2, sort_keys=True) + "\n")
    return {"source_commit": COMMIT, "source_tree": root, "tree_objects": len(raw_trees),
            "zip_paths_checked": len(inventory["members"]), "tracked_artifact_and_evidence_blobs": len(blobs)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(capture(args.repo, json.loads(args.inventory.read_bytes()), args.output), indent=2, sort_keys=True))
