#!/usr/bin/env python3
"""Verify frozen evidence through explicit, digest-preserving path migrations.

The original verifier and inventory remain historical bytes. No artifact runs.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
INDEX = 'evidence/hia_five_deliverables_20261030/EVIDENCE_FILES.json'
MIGRATIONS = 'docs/HIA_ARCHIVE_PATH_MIGRATIONS.json'


def safe_path(root, name):
    if not isinstance(name, str) or '\\' in name:
        raise ValueError('invalid archive path')
    parts = PurePosixPath(name)
    if parts.is_absolute() or '..' in parts.parts or str(parts) != name or name == '.':
        raise ValueError('invalid archive path')
    root = root.resolve()
    path = root / name
    if any((root.joinpath(*parts.parts[:i])).is_symlink()
           for i in range(1, len(parts.parts) + 1)):
        raise ValueError('symlink archive path')
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('archive path escapes root')
    return path


def verify(root, index, manifest):
    root = Path(root)
    rows = index['files']
    by_name = {row['path']: row for row in rows}
    if len(by_name) != len(rows):
        raise ValueError('duplicate inventory path')
    if (manifest.get('schema') != 'hepta.archive-path-migrations.v1' or
            manifest.get('historical_snapshots_edited') is not False or
            manifest.get('new_native_execution_claimed') is not False):
        raise ValueError('invalid migration scope')
    mappings = {}
    targets = set()
    for migration in manifest['migrations']:
        old, new = migration['original_path'], migration['current_path']
        safe_path(root, old)
        safe_path(root, new)
        if old in mappings or new in targets or new in by_name or old not in by_name:
            raise ValueError('duplicate or unbound migration')
        original = by_name[old]
        if any(migration[key] != original[key] for key in ('bytes', 'sha256')):
            raise ValueError('migration changes frozen identity')
        receipt = migration['unchanged_receipt']
        if receipt != by_name.get(receipt['path']):
            raise ValueError('migration changes receipt identity')
        mappings[old] = new
        targets.add(new)
    failures, checked_bytes, applied = [], 0, []
    for row in rows:
        name = row['path']
        current = mappings.get(name, name)
        try:
            path = safe_path(root, current)
            if not path.is_file():
                raise ValueError('missing file')
            raw = path.read_bytes()
            checked_bytes += len(raw)
            if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
                raise ValueError('size or hash mismatch')
            if current != name:
                applied.append({'original_path': name, 'current_path': current})
        except (OSError, ValueError) as error:
            failures.append({'path': name, 'current_path': current, 'reason': str(error)})
    return {'schema': 'hepta.five-deliverables.migrated-evidence-integrity.v1',
            'files_checked': len(rows), 'bytes_checked': checked_bytes,
            'applied_migrations': applied, 'failures': failures, 'passed': not failures,
            'scope': 'retained bytes only; not a new experiment or safety proof'}


def main():
    result = verify(ROOT, json.loads((ROOT / INDEX).read_text()),
                    json.loads((ROOT / MIGRATIONS).read_text()))
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
