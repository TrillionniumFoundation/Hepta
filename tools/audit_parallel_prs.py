#!/usr/bin/env python3
"""Exact-commit Hepta branch integration audit; always manual-review-only.

No checkout, fetch, merge or source modification is performed. Commit objects
must already be present in the current repository. Paths are interpreted from
NUL-delimited Git tree entries, not a rename-detecting textual diff.
"""
from __future__ import annotations

import argparse
import json
import io
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
import tempfile

_MAX_GIT_TREE_BYTES = 32_000_000
_MAX_GIT_SMALL_BYTES = 4096
_MAX_GIT_STDERR_BYTES = 4096
_MAX_REPORT_BYTES = 32_000_000
# Aggregate limits bound expansion *before* any serialized-report rejection.
# These are operational audit limits, not evidence of full-process RSS isolation.
_MAX_AUDIT_TREE_ENTRIES = 200_000
_MAX_AUDIT_TREE_PATH_BYTES = 32_000_000
_MAX_AUDIT_CHANGE_ENTRIES = 200_000
_MAX_AUDIT_OVERLAP_ENTRIES = 200_000

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
                          stderr=subprocess.PIPE, env=env,
                          start_new_session=(os.name == "posix")) as proc:
        stdout = bytearray()
        stderr = bytearray()
        over_budget: list[str] = []
        stream_errors: list[Exception] = []

        def kill() -> None:
            # Git wrappers may leave inherited-pipe children after their leader
            # exits. Own a private POSIX group and reap all same-group workers.
            try:
                if os.name == "posix":
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
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
            for reader in readers:
                reader.join(timeout=1)
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
    # A per-Git-command 32-MB cap is not a per-audit cap: up to 16 heads
    # can each be retained in memory. Account for every retained tree and
    # its path bytes before constructing any repeated comparison structures.
    trees: dict[str, dict] = {}
    total_tree_entries = 0
    total_tree_path_bytes = 0
    for label, commit in [("base", base), *heads.items()]:
        listing = tree_entries(commit)
        total_tree_entries += len(listing)
        total_tree_path_bytes += sum(len(os.fsencode(path)) + 64 for path in listing)
        if (total_tree_entries > _MAX_AUDIT_TREE_ENTRIES or
                total_tree_path_bytes > _MAX_AUDIT_TREE_PATH_BYTES):
            raise ValueError("aggregate tree input budget exceeded")
        trees[label] = listing

    changes: dict[str, dict] = {}
    total_changes = 0
    for label in heads:
        old, new = trees["base"], trees[label]
        changed = {path: {"base": old.get(path), "candidate": new.get(path)}
                   for path in sorted(old.keys() | new.keys())
                   if old.get(path) != new.get(path)}
        total_changes += len(changed)
        if total_changes > _MAX_AUDIT_CHANGE_ENTRIES:
            raise ValueError("aggregate changes budget exceeded")
        changes[label] = changed

    ancestry = {}
    overlaps = []
    total_overlap_entries = 0
    labels = sorted(heads)
    for index, left in enumerate(labels):
        for right in labels[index + 1:]:
            common = sorted(changes[left].keys() & changes[right].keys())
            total_overlap_entries += len(common)
            if total_overlap_entries > _MAX_AUDIT_OVERLAP_ENTRIES:
                raise ValueError("aggregate overlaps budget exceeded")
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



# Snapshot capability support before a test/adversary can replace os.link.
_POSIX_REPORT_DIRFD = (
    os.name == "posix"
    and all(operation in os.supports_dir_fd
            for operation in (os.open, os.link, os.unlink))
)



def encode_report(report: dict) -> str:
    """Bound serialized JSON bytes before any report/stdout publication.

    Git tree capture is bounded per candidate, but comparing up to 16 heads
    expands into repeated change, overlap and ancestry lists. A single
    json.dumps(report) would allocate the entire expanded string first.
    Stream encoder chunks into a capped in-memory buffer and reserve one byte
    for the terminating newline. This does not bound audit()'s in-memory
    comparison structures; those require an independent complexity budget.
    """
    remaining = _MAX_REPORT_BYTES - 1
    if remaining < 0:
        raise ValueError("Integration audit JSON exceeds serialized byte budget")
    buffer = io.StringIO()
    for chunk in json.JSONEncoder(sort_keys=True, indent=2).iterencode(report):
        chunk_bytes = len(chunk.encode("utf-8"))
        if chunk_bytes > remaining:
            raise ValueError("Integration audit JSON exceeds serialized byte budget")
        buffer.write(chunk)
        remaining -= chunk_bytes
    buffer.write("\n")
    return buffer.getvalue()


def publish_report(output: str, payload: str) -> None:
    """Publish only complete evidence, bound to one admitted directory inode.

    Source staging and destination publication use the same directory handle.
    Re-resolving both pathnames through an attacker-swapped parent symlink
    previously allowed a forged same-named temp file to become the report.
    A changed directory binding refuses after removing any pinned publication.
    This is not a security boundary against a writer *inside* that directory.
    """
    if output.endswith(os.sep) or os.path.basename(output) in ("", ".", ".."):
        raise ValueError("Invalid report destination")
    absolute = os.path.abspath(output)
    directory = os.path.dirname(absolute)
    filename = os.path.basename(absolute)
    if os.name != "posix":
        # Windows directory handles need a separate native implementation.
        # Keep the old no-overwrite publication, without claiming pinning.
        fd, staging = tempfile.mkstemp(prefix=".hepta-integration-audit-",
                                       suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(staging, absolute)
        finally:
            os.unlink(staging)
        return

    if not _POSIX_REPORT_DIRFD:
        raise OSError("POSIX directory-fd report publication unavailable")

    directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        admitted = os.fstat(directory_fd)
        staging_name = None
        for _ in range(16):
            name = ".hepta-integration-audit-" + secrets.token_hex(16) + ".tmp"
            try:
                staging_fd = os.open(
                    name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0), 0o600,
                    dir_fd=directory_fd)
                staging_name = name
                break
            except FileExistsError:
                continue
        if staging_name is None:
            raise OSError("Could not allocate unique audit report staging")

        published = False
        try:
            with os.fdopen(staging_fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())

            def require_admitted_directory() -> None:
                current = os.stat(directory)
                if ((current.st_dev, current.st_ino) !=
                        (admitted.st_dev, admitted.st_ino)):
                    raise ValueError("Report output directory rebound during publication")

            require_admitted_directory()
            os.link(staging_name, filename, src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd, follow_symlinks=False)
            published = True
            require_admitted_directory()
            os.fsync(directory_fd)
        except BaseException:
            if published:
                os.unlink(filename, dir_fd=directory_fd)
            raise
        finally:
            os.unlink(staging_name, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)


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
        payload = encode_report(report)
        publish_report(args.output, payload)
        print(payload, end="")
        return 0
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print("E_INTEGRATION_AUDIT: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
