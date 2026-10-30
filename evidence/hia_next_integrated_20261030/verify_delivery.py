"""Check the final delivery inventory as inert files; does not rerun native/model code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat


def read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('nonregular or oversized input')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) != info.st_size or len(data) > limit:
            raise ValueError('input changed size')
        return data
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--manifest-sha256')
    args = parser.parse_args()
    root = args.root.resolve()
    manifest_path = root / 'evidence/hia_next_integrated_20261030/DELIVERY_FILES.json'
    raw = read_regular(manifest_path, 1024 * 1024)
    digest = hashlib.sha256(raw).hexdigest()
    if args.manifest_sha256 and digest != args.manifest_sha256:
        raise ValueError('manifest identity differs')
    manifest = json.loads(raw)
    if manifest['schema'] != 'hepta.hia.next.delivery-files.v1' or len(manifest['files']) > 1000:
        raise ValueError('unsupported manifest')
    seen = set()
    total = 0
    for row in manifest['files']:
        rel = Path(row['path'])
        if rel.is_absolute() or '..' in rel.parts or row['path'] in seen:
            raise ValueError('unsafe or duplicate member')
        seen.add(row['path'])
        path = root / rel
        if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != root.parent):
            raise ValueError('symlink member or ancestor')
        data = read_regular(path, 16 * 1024 * 1024)
        if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('delivery member differs: ' + row['path'])
        total += len(data)
        if total > 64 * 1024 * 1024:
            raise ValueError('aggregate input limit')
    if total != manifest['total_bytes']:
        raise ValueError('aggregate bytes differ')
    result = json.loads(read_regular(root / 'evidence/hia_next_integrated_20261030/RESULT.json', 1024 * 1024))
    if result['all_P0_P7_strict_conditions_met'] is not False or any(result['unproved_claims'].values()):
        raise ValueError('unproved claim changed')
    if result['implementation']['commit'] != '44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304':
        raise ValueError('implementation identity differs')
    print(json.dumps({'passed': True, 'files': len(seen), 'bytes': total,
        'manifest_sha256': digest, 'actual_new_native_or_model_executions': 0,
        'scope': 'delivery byte inventory and explicit claim flags; nested package verifiers are separate'}, sort_keys=True))


if __name__ == '__main__':
    main()
