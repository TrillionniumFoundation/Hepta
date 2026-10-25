#!/usr/bin/env python3
"""Fail-closed, exact-SHA audit of parallel Hepta integration candidates.

Usage:
  python tools/audit_parallel_prs.py --base SHA \
    --candidate pr14=SHA --candidate pr36=SHA --candidate pr37=SHA \
    --output audit.json

Requires a locally available git object database containing every specified
commit. This command never fetches, merges, changes HEAD, or edits source.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SHA = re.compile(r"^[0-9a-fA-F]{40}$")
SEMANTIC_PATHS = (
    "hepta/ast.py", "hepta/parser.py", "hepta/checker.py",
    "hepta/backend.py", "hepta/c_backend.py", "hepta/cli.py",
    "hepta/semantic_ir.py", "hepta/hsir.py", "hepta/hmir.py",
    "hepta/migration_ir.py", "hepta/flow_ir.py", "hepta/resource_ir.py",
    "hepta/resource_lowering.py", "hepta/c_migrate.py",
    "hepta/c2hepta.py", "hepta/cpp2hepta.py", "hepta/cpp_bridge.py",
    "hepta/llvm_scalar_backend.py", "hepta/llvm_ssa_backend.py",
    "hepta/llvm_ssa_target.py", "hepta/protocol.py",
    "hepta/protocol_v3.py", "hepta/workspace.py",
)

def git(*args):
    proc = subprocess.run(
        ["git", "--no-pager", *args], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=60,
    )
    if proc.returncode:
        raise RuntimeError("git " + " ".join(args[:2]) + " failed: " +
                           proc.stderr.decode("utf-8", "replace")[:500])
    return proc.stdout

def check_commit(sha):
    if not SHA.fullmatch(sha):
        raise ValueError("Require a full 40-character commit SHA")
    git("cat-file", "-e", sha + "^{commit}")
    return git("rev-parse", sha + "^{commit}").decode().strip()

def changed_files(base, head):
    # Null-separated paths: safely handles whitespace/newline in filenames.
    raw = git("diff", "--name-only", "-z", base, head)
    return sorted(os.fsdecode(p) for p in raw.split(b"\0") if p)

def audit(base, candidates):
    base = check_commit(base)
    heads = {label: check_commit(sha) for label, sha in candidates.items()}
    changed = {}
    ancestry = {}
    for label, head in sorted(heads.items()):
        merge_base = git("merge-base", base, head).decode().strip()
        if merge_base != base:
            raise ValueError(label + ": base is not an ancestor of candidate")
        changed[label] = changed_files(base, head)
    labels = sorted(heads)
    overlaps = []
    for i, left in enumerate(labels):
        for right in labels[i + 1:]:
            common = sorted(set(changed[left]) & set(changed[right]))
            left_ancestor = (git("merge-base", heads[left], heads[right])
                             .decode().strip() == heads[left])
            right_ancestor = (git("merge-base", heads[right], heads[left])
                              .decode().strip() == heads[right])
            ancestry[left + ":" + right] = {
                "left_ancestor_of_right": left_ancestor,
                "right_ancestor_of_left": right_ancestor,
            }
            overlaps.append({
                "left": left, "right": right, "shared_paths": common,
                "shared_semantic_paths": sorted(set(common) & set(SEMANTIC_PATHS)),
            })
    semantic_owners = {}
    for label, paths in changed.items():
        for path in paths:
            if path in SEMANTIC_PATHS:
                semantic_owners.setdefault(path, []).append(label)
    conflicting = {p: names for p, names in sorted(semantic_owners.items())
                   if len(names) > 1}
    # Disjoint files can STILL implement competing semantic authorities.
    # Manual semantic/IR mapping and end-to-end native gates are mandatory.
    return {
        "schema": "hepta.integration-audit.v1",
        "base": base, "candidates": heads, "changed_files": changed,
        "ancestry": ancestry, "overlaps": overlaps,
        "duplicate_semantic_path_owners": conflicting,
        "automatic_merge_approved": False,
        "whole_project_blockers_closed": False,
        "limitations": [
            "File/path audit cannot detect duplicated concepts under distinct filenames",
            "No content merge, native compilation, test execution or safety proof",
            "Passing this audit cannot authorize a production merge",
        ],
    }

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", action="append", required=True,
                        help="label=40-character-SHA")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    candidates = {}
    try:
        for item in args.candidate:
            label, sha = item.split("=", 1)
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", label):
                raise ValueError("invalid candidate label")
            if label in candidates:
                raise ValueError("duplicate candidate label")
            candidates[label] = sha
        if len(candidates) < 2:
            raise ValueError("need at least two candidates")
        report = audit(args.base, candidates)
        payload = json.dumps(report, sort_keys=True, indent=2) + "\n"
        # Protect previously published evidence from accidental overwrite.
        with open(args.output, "x", encoding="utf-8") as output:
            output.write(payload)
        print(payload, end="")
        return 0
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print("E_INTEGRATION_AUDIT: " + str(error), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
