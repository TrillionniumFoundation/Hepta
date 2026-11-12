#!/usr/bin/env python3
"""Verify the frozen evidence bytes through an explicitly pinned path migration.

The original manifest and VERIFY.py are immutable inputs. No archived program
is executed, and a moved file must still match its original size and hash.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
INDEX = "evidence/hia_five_deliverables_20261030/EVIDENCE_FILES.json"
INDEX_SHA256 = "29b643df0c6a2c6982e9b40b745b52a297b168b28a7b03dc091d66bd280bb24b"
MIGRATIONS = "docs/HIA_ARCHIVE_PATH_MIGRATIONS.json"
MIGRATIONS_SHA256 = "b7dd8dc3e435d3fb1c9c69f24ec111b3c4f2ac356078e68f2123d851e527f1f0"
MAX_GIT_MEMBERS = 4096
MAX_GIT_MEMBER_BYTES = 16 * 1024 * 1024
MAX_GIT_TOTAL_BYTES = 64 * 1024 * 1024
MAX_GIT_PATH_BYTES = 512 * 1024
GIT_COMMAND_SECONDS = 30


def relative_name(value):
    if (type(value) is not str or not value or len(value) > 4096
            or any(c in value for c in ("\\", ":", "\0"))
            or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise ValueError("A canonical relative evidence path is required")
    return value


def regular_path(root, name):
    root = Path(root).resolve()
    path = root
    for part in relative_name(name).split("/"):
        path = path / part
        if path.is_symlink():
            raise ValueError("Symlink in retained evidence path: " + name)
    if not path.resolve().is_relative_to(root) or not path.is_file():
        raise ValueError("Missing or nonregular evidence file: " + name)
    return path


def evidence_rows(rows):
    if type(rows) is not list or not rows:
        raise ValueError("Complete nonempty evidence row inventory is required")
    indexed = {}
    for row in rows:
        if (type(row) is not dict or set(row) != {"path", "bytes", "sha256"}
                or type(row["bytes"]) is not int or row["bytes"] < 0
                or type(row["sha256"]) is not str
                or not re.fullmatch("[0-9a-f]{64}", row["sha256"])):
            raise ValueError("Malformed original evidence identity")
        name = relative_name(row["path"])
        if name in indexed:
            raise ValueError("Duplicate logical evidence path: " + name)
        indexed[name] = row
    return indexed


def migration_aliases(rows, migration):
    indexed = evidence_rows(rows)
    fields = {"schema", "original_source_commit", "reason", "historical_snapshots_edited",
              "new_native_execution_claimed", "migrations"}
    if (type(migration) is not dict or set(migration) != fields
            or migration["schema"] != "hepta.archive-path-migrations.v1"
            or type(migration["original_source_commit"]) is not str
            or not re.fullmatch("[0-9a-f]{40}", migration["original_source_commit"])
            or type(migration["reason"]) is not str
            or migration["historical_snapshots_edited"] is not False
            or migration["new_native_execution_claimed"] is not False
            or type(migration["migrations"]) is not list):
        raise ValueError("Exact retained-byte path migration contract is required")
    aliases = {}
    for row in migration["migrations"]:
        if type(row) is not dict or set(row) != {"original_path", "current_path", "bytes", "sha256", "unchanged_receipt"}:
            raise ValueError("Malformed path migration")
        old, new = relative_name(row["original_path"]), relative_name(row["current_path"])
        if old in aliases or old == new or old not in indexed:
            raise ValueError("Duplicate, unknown or unchanged migration path")
        if (type(row["bytes"]) is not int or row["bytes"] != indexed[old]["bytes"]
                or row["sha256"] != indexed[old]["sha256"]):
            raise ValueError("Migration does not preserve the original evidence identity")
        receipt = row["unchanged_receipt"]
        receipt_rows = evidence_rows([receipt])
        if receipt != indexed.get(next(iter(receipt_rows))):
            raise ValueError("Original unchanged receipt identity differs")
        aliases[old] = new
    seen = {}
    for old in indexed:
        target = aliases.get(old, old)
        folded = target.casefold()
        if folded in seen:
            raise ValueError("Mapped evidence paths collide: " + target)
        seen[folded] = old
    return aliases


def load_contract(root=ROOT):
    documents = []
    for name, expected in ((INDEX, INDEX_SHA256), (MIGRATIONS, MIGRATIONS_SHA256)):
        with regular_path(root, name).open("rb") as stream:
            data = stream.read(1_000_001)
        if len(data) > 1_000_000:
            raise ValueError("Pinned evidence contract exceeds its input bound")
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("Pinned evidence contract bytes changed: " + name)
        documents.append(json.loads(data))
    index, migration = documents
    if (set(index) != {"schema", "implementation_commit", "scope", "files"}
            or index["schema"] != "hepta.five-deliverables.evidence-files.v1"):
        raise ValueError("Unknown frozen evidence manifest")
    aliases = migration_aliases(index["files"], migration)
    return index["files"], aliases


def verify_rows(root, rows, aliases):
    indexed = evidence_rows(rows)
    if type(aliases) is not dict or not set(aliases) <= set(indexed):
        raise ValueError("Unknown evidence path alias")
    targets = [relative_name(aliases.get(name, name)) for name in indexed]
    if len({name.casefold() for name in targets}) != len(targets):
        raise ValueError("Evidence physical identities must remain distinct")
    failures, checked_bytes = [], 0
    for (name, row), target in zip(indexed.items(), targets):
        try:
            path = regular_path(root, target)
            digest, size = hashlib.sha256(), 0
            with path.open("rb") as stream:
                while True:
                    block = stream.read(min(1024 * 1024, row["bytes"] - size + 1))
                    if not block:
                        break
                    size += len(block)
                    digest.update(block)
                    if size > row["bytes"]:
                        break
            checked_bytes += size
            if size != row["bytes"] or digest.hexdigest() != row["sha256"]:
                raise ValueError("Original size or hash mismatch")
        except (OSError, ValueError) as error:
            failures.append({"path": name, "materialized_path": target, "reason": str(error)})
    return {"schema": "hepta.five-deliverables.evidence-integrity.v2",
            "files_checked": len(indexed), "bytes_checked": checked_bytes,
            "path_migrations": dict(aliases), "failures": failures, "passed": not failures,
            "scope": "retained original bytes only; not a new experiment or safety proof"}


def _git_output(root, args, limit, input_bytes=None):
    """Read bounded output from an owned, local Git process without filters.

    No shell, checkout, automatic fetch or replacement objects. A temporary
    stdin file avoids pipe deadlock for a batch while stdout remains bounded.
    The timer applies to this owned command, including its output read.
    """
    expired = threading.Event()
    with tempfile.TemporaryFile() as source:
        if input_bytes is not None:
            source.write(input_bytes)
            source.seek(0)
        process = subprocess.Popen(
            ["git", "--no-replace-objects", "--literal-pathspecs", "-C", str(root), *args],
            stdin=source, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "",
                 "GIT_TERMINAL_PROMPT": "0"},
        )

        def expire():
            expired.set()
            try:
                process.kill()
            except ProcessLookupError:
                pass

        timer = threading.Timer(GIT_COMMAND_SECONDS, expire)
        timer.daemon = True
        timer.start()
        try:
            raw = process.stdout.read(limit + 1)
            if len(raw) > limit:
                raise ValueError("Git evidence output exceeds its admitted byte bound")
            returncode = process.wait(timeout=GIT_COMMAND_SECONDS)
            if expired.is_set():
                raise ValueError("Git evidence command exceeded its deadline")
            if returncode != 0:
                raise ValueError("Git evidence command failed; revision or object is unavailable")
            return raw
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
            process.wait(timeout=GIT_COMMAND_SECONDS)
            process.stdout.close()


def _object_id(value):
    return re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is not None


def verify_git_rows(root, rows, revision):
    """Verify original manifest paths from one explicitly resolved Git commit.

    Relocation aliases describe later working-tree paths. They must not rename
    historical Git entries or cause a fallback from a missing current file.
    The caller must opt into this mode; every original size/hash still applies.
    """
    indexed = evidence_rows(rows)
    if (type(revision) is not str or not revision or len(revision) > 512
            or any(ord(c) < 32 or ord(c) == 127 for c in revision)):
        raise ValueError("An explicit bounded Git revision is required")
    if (len(indexed) > MAX_GIT_MEMBERS
            or any(row["bytes"] > MAX_GIT_MEMBER_BYTES for row in indexed.values())
            or sum(row["bytes"] for row in indexed.values()) > MAX_GIT_TOTAL_BYTES
            or sum(len(name.encode("utf-8")) for name in indexed) > MAX_GIT_PATH_BYTES):
        raise ValueError("Historical Git evidence exceeds its member or total byte bounds")
    root = Path(root).resolve()
    commit = _git_output(
        root, ["rev-parse", "--verify", "--end-of-options", revision + "^{commit}"], 128,
    ).decode("ascii").strip()
    if not _object_id(commit):
        raise ValueError("Git evidence revision did not resolve to one full commit identity")

    tree_bytes = _git_output(
        root, ["ls-tree", "-z", "--full-tree", commit, "--", *indexed],
        MAX_GIT_PATH_BYTES + MAX_GIT_MEMBERS * 128,
    )
    entries = {}
    for record in tree_bytes.split(b"\0"):
        if not record:
            continue
        metadata, path = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        name = path.decode("utf-8")
        if name not in indexed or name in entries or not _object_id(oid):
            raise ValueError("Unexpected or duplicate historical Git tree entry")
        entries[name] = (mode, kind, oid)

    failures, candidates, checked_bytes = [], [], 0
    for name, row in indexed.items():
        entry = entries.get(name)
        if entry is None:
            failures.append({"path": name, "reason": "Original path is absent from selected Git commit"})
        elif entry[0] not in {"100644", "100755"} or entry[1] != "blob":
            failures.append({"path": name, "reason": "Original path is not an ordinary Git file blob"})
        else:
            candidates.append((name, row, entry[2]))

    # Query sizes before requesting any payload. A tree, symlink, larger blob
    # or unrelated path cannot make a historical byte oracle read other data.
    admitted = []
    if candidates:
        request = "".join(oid + "\n" for _, _, oid in candidates).encode("ascii")
        info = _git_output(root, ["cat-file", "--batch-check"], len(candidates) * 128, request)
        lines = info.splitlines()
        if len(lines) != len(candidates):
            raise ValueError("Incomplete historical Git object metadata")
        for (name, row, oid), line in zip(candidates, lines):
            parts = line.decode("ascii").split()
            if (len(parts) != 3 or parts[0] != oid or parts[1] != "blob"
                    or not parts[2].isdigit()):
                failures.append({"path": name, "reason": "Historical Git blob metadata is unavailable"})
            elif int(parts[2]) != row["bytes"]:
                failures.append({"path": name, "reason": "Original size mismatch in selected Git commit"})
            else:
                admitted.append((name, row, oid))

    if admitted:
        request = "".join(oid + "\n" for _, _, oid in admitted).encode("ascii")
        limit = sum(row["bytes"] for _, row, _ in admitted) + len(admitted) * 128
        raw = _git_output(root, ["cat-file", "--batch"], limit, request)
        offset = 0
        for name, row, oid in admitted:
            end = raw.find(b"\n", offset, offset + 128)
            expected = f"{oid} blob {row['bytes']}".encode("ascii")
            if end < 0 or raw[offset:end] != expected:
                raise ValueError("Historical Git payload header differs from admitted metadata")
            start, stop = end + 1, end + 1 + row["bytes"]
            if stop >= len(raw) or raw[stop:stop + 1] != b"\n":
                raise ValueError("Historical Git blob is truncated")
            data = memoryview(raw)[start:stop]
            checked_bytes += len(data)
            if hashlib.sha256(data).hexdigest() != row["sha256"]:
                failures.append({"path": name, "reason": "Original hash mismatch in selected Git commit"})
            offset = stop + 1
        if offset != len(raw):
            raise ValueError("Unexpected bytes after historical Git evidence batch")

    return {"schema": "hepta.five-deliverables.evidence-integrity.v3",
            "source_mode": "explicit_git_revision", "requested_revision": revision,
            "resolved_commit": commit, "replacement_objects_allowed": False,
            "paths": "original manifest paths; working-tree relocation aliases do not apply",
            "files_checked": len(indexed), "bytes_checked": checked_bytes,
            "failures": failures, "passed": not failures,
            "scope": "retained original bytes only; not a new experiment or safety proof"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--git-revision", metavar="REVISION",
        help="explicitly verify original manifest paths from a local Git commit; never fetch or restore files",
    )
    args = parser.parse_args()
    try:
        rows, aliases = load_contract()
        result = (verify_git_rows(ROOT, rows, args.git_revision) if args.git_revision is not None
                  else verify_rows(ROOT, rows, aliases))
        result.update(original_manifest_sha256=INDEX_SHA256, path_migrations_sha256=MIGRATIONS_SHA256)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result = {"schema": "hepta.five-deliverables.evidence-integrity.v2",
                  "passed": False, "failures": [{"reason": str(error)}]}
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
