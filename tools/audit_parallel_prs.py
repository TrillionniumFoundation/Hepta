#!/usr/bin/env python3
"""Exact-commit Hepta branch integration audit; always manual-review-only.

No checkout, fetch, merge or source modification is performed. Commit objects
must already be present in the current repository. Paths are interpreted from
NUL-delimited Git tree entries, not a rename-detecting textual diff.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading

_MAX_GIT_TREE_BYTES = 32_000_000
_MAX_GIT_SMALL_BYTES = 4096
_MAX_GIT_STDERR_BYTES = 4096

SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
LABEL = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")

# Multiple paths may represent complementary implementations, not necessarily
# a bug; every multi-candidate family requires source-level reconciliation.
SEMANTIC_FAMILIES = {
    "typed_hsir": ("hepta/semantic_ir.py", "hepta/hsir.py"),
    "control_flow_ssa": ("hepta/hmir.py", "hepta/cfg.py", "hepta/ssa.py"),
    "ownership_resources": ("hepta/resource_ir.py", "hepta/resource_lowering.py",
                            "hepta/concurrent_ir.py", "hepta/flow_ir.py"),
    "c_source_migration": ("hepta/c_migrate.py", "hepta/c_migration_project.py",
                           "hepta/c2hepta.py", "hepta/migration_ir.py"),
    "cpp_interop_migration": ("hepta/cpp_bridge.py", "hepta/cpp_contracts.py",
                              "hepta/cpp2hepta.py"),
    "agent_transactions": ("hepta/workspace.py", "hepta/protocol_v3.py",
                           "hepta/agent_preview.py"),
    "llvm_codegen": ("hepta/llvm_scalar_backend.py", "hepta/llvm_ssa_backend.py",
                     "hepta/llvm_ssa_target.py"),
}
DIRECT_SEMANTIC_PATHS = frozenset({
    "hepta/ast.py", "hepta/parser.py", "hepta/checker.py", "hepta/backend.py",
    "hepta/c_backend.py", "hepta/cli.py", "hepta/protocol.py",
    *(path for group in SEMANTIC_FAMILIES.values() for path in group),
})


def git(*args: str) -> bytes:
    """Bound stdout/stderr *while* Git runs, before loading a tree into RAM.

    A post-subprocess 32 MB check is too late: capture_output=True can
    allocate arbitrary memory when a tree is unexpectedly large. Limit even
    diagnostic output, kill the producer on overflow, and retain the existing
    60-second execution deadline. Short Git metadata commands need only 4 KiB.
    """
    env = {**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"}
    cap = _MAX_GIT_TREE_BYTES if args and args[0] == "ls-tree" else _MAX_GIT_SMALL_BYTES
    with subprocess.Popen(["git", "--no-pager", *args], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=env) as proc:
        stdout = bytearray()
        stderr = bytearray()
        over_budget: list[str] = []
        stream_errors: list[Exception] = []

        def kill() -> None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass

        def drain(pipe, buffer: bytearray, limit: int, label: str) -> None:
            try:
                with pipe:
                    # read1 does not wait for EOF or for an entire 64-KiB
                    # buffer before reporting an over-budget producer.
                    while chunk := pipe.read1(65_536):
                        remaining = max(0, limit - len(buffer))
                        buffer.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            over_budget.append(label)
                            kill()
                            return
            except (OSError, ValueError) as exc:
                stream_errors.append(exc)
                kill()

        readers = (
            threading.Thread(target=drain,
                             args=(proc.stdout, stdout, cap, "stdout"), daemon=True),
            threading.Thread(target=drain,
                             args=(proc.stderr, stderr, _MAX_GIT_STDERR_BYTES, "stderr"),
                             daemon=True),
        )
        for reader in readers:
            reader.start()
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            kill()
            proc.wait()
            raise
        finally:
            for reader in readers:
                reader.join(timeout=1)
        if over_budget:
            raise ValueError("git output exceeds bounded capture budget: " +
                             ",".join(over_budget))
        if stream_errors or any(reader.is_alive() for reader in readers):
            kill()
            raise RuntimeError("git output capture failed")
        if proc.returncode:
            raise RuntimeError("git " + " ".join(args[:2]) + " failed: " +
                               bytes(stderr).decode("utf-8", "replace")[:500])
        return bytes(stdout)


def check_commit(sha: str) -> str:
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise ValueError("Require an exact 40-character commit SHA")
    git("cat-file", "-e", sha + "^{commit}")
    committed = git("rev-parse", sha + "^{commit}").decode("ascii").strip()
    if not SHA.fullmatch(committed):
        raise ValueError("Git returned an unexpected commit identity")
    return committed.lower()


def tree_entries(commit: str) -> dict[str, dict[str, str]]:
    raw = git("ls-tree", "-r", "-z", "--full-tree", commit)
    if len(raw) > 32_000_000:
        raise ValueError("Tree listing exceeds bounded input")
    result: dict[str, dict[str, str]] = {}
    if raw and not raw.endswith(b"\0"):
        raise ValueError("Git returned a truncated NUL-delimited tree")
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        header, sep, path_bytes = entry.partition(b"\t")
        parts = header.split(b" ")
        if not sep or len(parts) != 3 or not path_bytes:
            raise ValueError("Malformed Git tree entry")
        mode, kind, oid = parts
        if kind not in (b"blob", b"commit") or not SHA.fullmatch(oid.decode("ascii")):
            raise ValueError("Unsupported Git tree entry")
        path = os.fsdecode(path_bytes)
        if path in result:
            raise ValueError("Duplicate path in Git tree")
        result[path] = {"mode": mode.decode("ascii"),
                        "kind": kind.decode("ascii"), "oid": oid.decode("ascii").lower()}
        if len(result) > 100_000:
            raise ValueError("Tree has too many entries")
    return result


def audit(base: str, candidates: dict[str, str]) -> dict:
    if len(candidates) < 2 or len(candidates) > 16:
        raise ValueError("Require between 2 and 16 distinct candidates")
    if any(not LABEL.fullmatch(label) or label == "base" for label in candidates):
        raise ValueError("Invalid candidate label")
    base = check_commit(base)
    heads = {label: check_commit(sha) for label, sha in sorted(candidates.items())}
    if len(set(heads.values())) != len(heads):
        raise ValueError("Duplicate candidate commit")
    for label, head in heads.items():
        ancestor = git("merge-base", base, head).decode("ascii").strip()
        if ancestor != base:
            raise ValueError(label + ": expected base is not a candidate ancestor")
    trees = {"base": tree_entries(base)}
    trees.update((label, tree_entries(head)) for label, head in heads.items())
    changes: dict[str, dict] = {}
    for label in heads:
        old, new = trees["base"], trees[label]
        changes[label] = {path: {"base": old.get(path), "candidate": new.get(path)}
                          for path in sorted(old.keys() | new.keys())
                          if old.get(path) != new.get(path)}
    ancestry = {}
    overlaps = []
    labels = sorted(heads)
    for index, left in enumerate(labels):
        for right in labels[index + 1:]:
            common = sorted(changes[left].keys() & changes[right].keys())
            same = [path for path in common if trees[left].get(path) == trees[right].get(path)]
            different = [path for path in common if trees[left].get(path) != trees[right].get(path)]
            mergebase = git("merge-base", heads[left], heads[right]).decode("ascii").strip()
            ancestry[left + ":" + right] = {
                "merge_base": mergebase,
                "left_ancestor_of_right": mergebase == heads[left],
                "right_ancestor_of_left": mergebase == heads[right],
            }
            overlaps.append({"left": left, "right": right,
                             "shared_paths": common,
                             "identical_final_paths": same,
                             "different_final_paths": different,
                             "different_semantic_paths": sorted(set(different) & DIRECT_SEMANTIC_PATHS)})
    semantic_families = {}
    for family, paths in SEMANTIC_FAMILIES.items():
        owners = {label: sorted(set(paths) & changes[label].keys())
                  for label in labels if set(paths) & changes[label].keys()}
        if len(owners) >= 2:
            semantic_families[family] = {"candidate_paths": owners,
                                         "classification": "requires_source_level_review"}
    duplicated = {}
    for path in sorted(DIRECT_SEMANTIC_PATHS):
        owners = [label for label in labels if path in changes[label]]
        if len(owners) > 1:
            duplicated[path] = owners
    return {
        "schema": "hepta.integration-audit.v2", "base": base, "candidates": heads,
        "changes": changes, "ancestry": ancestry, "overlaps": overlaps,
        "semantic_family_review": semantic_families,
        "duplicate_semantic_path_owners": duplicated,
        "automatic_merge_approved": False,
        "whole_project_blockers_closed": False,
        "limitations": [
            "Equal blob content or path lists do not prove semantic compatibility",
            "Cross-file semantic authority and FFI assumptions require manual review",
            "No native test, whole-language soundness proof or production qualification was run",
        ],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", action="append", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    candidates = {}
    try:
        for item in args.candidate:
            label, sep, sha = item.partition("=")
            if not sep or not LABEL.fullmatch(label) or label == "base" or label in candidates:
                raise ValueError("Invalid or duplicate candidate label")
            candidates[label] = sha
        report = audit(args.base, candidates)
        payload = json.dumps(report, sort_keys=True, indent=2) + "\n"
        # O_CREAT|O_EXCL refuses existing outputs including dangling symlinks.
        with open(args.output, "x", encoding="utf-8") as stream:
            stream.write(payload)
        print(payload, end="")
        return 0
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print("E_INTEGRATION_AUDIT: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
