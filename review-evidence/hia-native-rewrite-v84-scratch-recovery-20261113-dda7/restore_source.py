"""Restore exactly one explicitly partial source export from its retained base."""
from __future__ import annotations
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
WORK = HERE.parent
sys.path.insert(0, str(WORK/'v81-service-requests-development-r1'))
from package_source import manifest, tree_hash


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: restore_source.py EXACT_SOURCE_PATH')
    plan = json.loads((HERE/'PLAN.json').read_bytes())
    source = Path(sys.argv[1]).resolve(strict=True)
    rows = [row for row in plan['targets'] if Path(row['source']) == source]
    if len(rows) != 1:
        raise ValueError('source is not an exact recorded inactive target')
    row = rows[0]
    base = Path(plan['base_source'])
    base_manifest = manifest(base)
    if len(base_manifest) != 3153 or tree_hash(base_manifest) != plan['base_git_tree']:
        raise ValueError('retained complete Git base differs')
    if manifest(source) != row['retained']:
        raise ValueError('retained changes differ; no source file may be overwritten')
    for name, expected in sorted(row['recoverable'].items()):
        if base_manifest.get(name) != expected:
            raise ValueError('one original base file differs')
        out = source/name
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open('xb') as stream:
            stream.write((base/name).read_bytes())
        out.chmod(0o755 if expected['mode'] == '100755' else 0o644)
    complete = manifest(source)
    if complete != {**row['retained'], **row['recoverable']} or tree_hash(complete) != row['original_tree']:
        raise ValueError('full restored source identity differs')
    marker = source.parent/'PARTIAL-SOURCE-NOT-RUNNABLE.json'
    marker.write_text(json.dumps({'source': str(source), 'status': 'EXACTLY_RESTORED',
        'source_tree': row['original_tree'], 'files': len(complete),
        'actual_git_metadata_created': False, 'whole_native': False}, sort_keys=True, indent=2)+'\n')
    print(json.dumps({'status': 'EXACTLY_RESTORED', 'source': str(source),
                      'source_tree': row['original_tree'], 'files': len(complete)}))


if __name__ == '__main__':
    main()
