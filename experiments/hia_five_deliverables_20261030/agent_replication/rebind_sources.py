#!/usr/bin/env python3
"""Compare the registered study closure to current source without rescoring.

Sparse, unmaterialized tracked files may be read from HEAD only when Git marks
them skip-worktree. A deleted or modified working-tree file cannot silently use
the committed version. This is a source identity report, not a model rerun.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True).stdout


def rebind(registration, snapshot_manifest, current_root, output):
    started = time.monotonic_ns()
    registration, snapshot_manifest, root = map(lambda p: Path(p).resolve(), (registration, snapshot_manifest, current_root))
    registered_bytes = registration.read_bytes()
    registered = json.loads(registered_bytes)
    frozen = json.loads(snapshot_manifest.read_bytes())
    head = git(root, "rev-parse", "HEAD").decode().strip()
    states = {entry[2:].decode(): entry[:1].decode()
              for entry in git(root, "ls-files", "-v", "-z").split(b"\0") if entry}

    def current(name):
        path = root / name
        if path.is_file():
            return {"mode": "working_tree", "sha256": sha(path.read_bytes())}
        if states.get(name) == "S":
            return {"mode": "sparse_skip_worktree_HEAD_blob", "head_commit": head,
                    "sha256": sha(git(root, "show", head + ":" + name))}
        return {"mode": "missing", "sha256": None}

    rows = []
    for name, expected in sorted(registered["sources"].items()):
        actual = current(name)
        rows.append({"path": name, "registered_sha256": expected, **actual,
                     "matches": actual["sha256"] == expected})
    differences = []
    for name, identity in sorted(frozen["files"].items()):
        actual = current(name)
        if actual["sha256"] != identity["sha256"]:
            differences.append({"path": name, "snapshot_sha256": identity["sha256"], **actual,
                                "in_registered_study_closure": name in registered["sources"]})
    current_python = {str(path.relative_to(root)) for directory in ("hepta", "tools", "tests", "experiments")
                      for path in (root / directory).rglob("*.py") if "__pycache__" not in path.parts}
    added = [{"path": name, **current(name), "in_registered_study_closure": name in registered["sources"]}
             for name in sorted(current_python - set(frozen["files"]))]
    stable = all(current(row["path"])["sha256"] == row["sha256"] for row in rows)
    head_stable = git(root, "rev-parse", "HEAD").decode().strip() == head
    result = {"schema": "hepta.agent-replication.registered-source-rebind.v1",
              "checked_unix_ns": time.time_ns(), "current_root": str(root), "current_HEAD": head,
              "registration_sha256": sha(registered_bytes), "snapshot_content_sha256": frozen["content_sha256"],
              "registered_source_count": len(rows),
              "registered_sources_match": stable and head_stable and all(row["matches"] for row in rows),
              "registered_sources_unchanged_during_rebind": stable, "HEAD_unchanged_during_rebind": head_stable,
              "registered_sources": rows, "frozen_source_inventory_differences": differences,
              "new_python_files_outside_snapshot": added,
              "full_source_snapshot_equals_current_inventory": not differences and not added,
              "model_rerun_or_rescoring": False, "original_registration_modified": False,
              "interpretation": "Matching registered sources rebind only the primitive/assembly/Core/native study paths. New or changed unregistered modules are not exercised by this Agent comparison. Python inventory comparison is not a complete repository, OS, compiler, or dynamic-library dependency closure.",
              "wall_ns": time.monotonic_ns() - started}
    with Path(output).open("x") as stream:
        json.dump(result, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    print(json.dumps({key: result[key] for key in ("registered_source_count", "registered_sources_match", "full_source_snapshot_equals_current_inventory", "wall_ns")}), flush=True)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("registration", "snapshot-manifest", "current-root", "output"):
        parser.add_argument("--" + name, required=True)
    result = rebind(**vars(parser.parse_args()))
    raise SystemExit(not result["registered_sources_match"])
