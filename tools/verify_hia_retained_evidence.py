#!/usr/bin/env python3
"""Verify the frozen evidence bytes through an explicitly pinned path migration.

The original manifest and VERIFY.py are immutable inputs. No archived program
is executed, and a moved file must still match its original size and hash.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
INDEX = "evidence/hia_five_deliverables_20261030/EVIDENCE_FILES.json"
INDEX_SHA256 = "29b643df0c6a2c6982e9b40b745b52a297b168b28a7b03dc091d66bd280bb24b"
MIGRATIONS = "docs/HIA_ARCHIVE_PATH_MIGRATIONS.json"
MIGRATIONS_SHA256 = "b7dd8dc3e435d3fb1c9c69f24ec111b3c4f2ac356078e68f2123d851e527f1f0"


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


def main():
    try:
        rows, aliases = load_contract()
        result = verify_rows(ROOT, rows, aliases)
        result.update(original_manifest_sha256=INDEX_SHA256, path_migrations_sha256=MIGRATIONS_SHA256)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result = {"schema": "hepta.five-deliverables.evidence-integrity.v2",
                  "passed": False, "failures": [{"reason": str(error)}]}
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
