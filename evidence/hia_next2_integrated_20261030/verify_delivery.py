"""Bounded byte inventory and claim audit of the additive delivery; no execution."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import stat
import time

HEAD = '953fa62dee5aa563551d57b1374ab95b6d548b45'
MANIFEST = 'evidence/hia_next2_integrated_20261030/DELIVERY_FILES.json'


def read_regular(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= maximum:
            raise ValueError('bounded regular input required')
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if len(raw) != before.st_size or any(getattr(before, k) != getattr(after, k) for k in fields):
        raise ValueError('input changed during bounded read')
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    args = parser.parse_args()
    started = time.monotonic_ns()
    root = args.root.resolve()
    raw = read_regular(root / MANIFEST, 1024 * 1024)
    sha = hashlib.sha256(raw).hexdigest()
    if sha != args.manifest_sha256:
        raise ValueError('external manifest digest differs')
    manifest = json.loads(raw)
    if (manifest['schema'] != 'hepta.hia.next2.delivery-files.v1'
            or manifest['implementation'] != HEAD or not 0 < len(manifest['files']) <= 1000):
        raise ValueError('unsupported delivery identity or count')
    seen, total = set(), 0
    for row in manifest['files']:
        name = row['path']
        relative = PurePosixPath(name)
        if (relative.is_absolute() or str(relative) != name or '..' in relative.parts
                or '\\' in name or name in seen or not (name.startswith('evidence/hia_next2_')
                or name == 'docs/HIA_NEXT2_STRICT_RESULTS_20261030.md')):
            raise ValueError('unsafe or duplicate delivery path')
        seen.add(name)
        path = root / name
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
            raise ValueError('symlink input or ancestor')
        data = read_regular(path, 16 * 1024 * 1024)
        if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('delivery byte identity differs: ' + name)
        total += len(data)
        if total > 64 * 1024 * 1024:
            raise ValueError('delivery aggregate limit')
    if total != manifest['total_bytes']:
        raise ValueError('delivery byte denominator differs')
    result = json.loads(read_regular(root / 'evidence/hia_next2_integrated_20261030/RESULT.json', 1024 * 1024))
    if (result['implementation']['commit'] != HEAD or result['all_P0_P7_strict_conditions_met'] is not False
            or any(result['unproved_claims'].values()) or result['stages']['P4']['counts_and_costs']['complete_cost_cold_gate_passed'] is not False
            or result['stages']['P5']['current_NDU_decisions'] != 0 or result['stages']['P7']['calibration']['correct'] != 0
            or result['stages']['P7']['main']['generation_requests'] != 0
            or result['delivery']['qualified_as_new_execution_commit'] is not False):
        raise ValueError('unproved or failed outcome was promoted')
    print(json.dumps({'schema': 'hepta.hia.next2.delivery-verification.v1', 'passed': True,
        'files': len(seen), 'bytes': total, 'manifest_sha256': sha,
        'actual_new_native_or_model_executions': 0, 'wall_ns': time.monotonic_ns() - started,
        'scope': 'additive byte inventory and explicit claim boundaries; nested archive readers are independent retained checks'}, sort_keys=True))


if __name__ == '__main__':
    main()
