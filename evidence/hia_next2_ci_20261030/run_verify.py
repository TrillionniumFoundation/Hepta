#!/usr/bin/env python3
"""Capture the unchanged CI reader's stdout, stderr, status and outer cost."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
READER_SHA = 'e2ab3be7afd0e2b47feb5a0d5a465cc9cc8c2a37426b002a89ec341d58e16437'


def identity(path):
    data = path.read_bytes()
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def main():
    start = time.monotonic_ns()
    inputs = [ROOT / name for name in ('verify_ci.py', 'CI_PINS.json', 'MANIFEST.json', 'raw/ci-953fa62.zip')]
    before = {str(path.relative_to(ROOT)): identity(path) for path in inputs}
    assert before['verify_ci.py']['sha256'] == READER_SHA
    argv = [sys.executable, str(ROOT / 'verify_ci.py'), '--root', str(ROOT),
            '--pins', str(ROOT / 'CI_PINS.json'), '--pins-sha256', before['CI_PINS.json']['sha256'],
            '--manifest', str(ROOT / 'MANIFEST.json'), '--manifest-sha256', before['MANIFEST.json']['sha256'],
            '--output', str(ROOT / 'VERIFY.json')]
    with (ROOT / 'VERIFY.stdout').open('xb') as out, (ROOT / 'VERIFY.stderr').open('xb') as err:
        invoked = time.monotonic_ns()
        child = subprocess.run(argv, cwd=ROOT, stdout=out, stderr=err, timeout=60, check=False)
        process_ns = time.monotonic_ns() - invoked
    after = {str(path.relative_to(ROOT)): identity(path) for path in inputs}
    record = {'schema': 'hepta.ci.offline-verification-execution.v1', 'argv': argv,
              'returncode': child.returncode, 'reader_process_wall_ns': process_ns,
              'inputs_before': before, 'inputs_after': after, 'inputs_unchanged': before == after,
              'stdout': identity(ROOT / 'VERIFY.stdout'), 'stderr': identity(ROOT / 'VERIFY.stderr'),
              'new_test_or_model_runs': 0, 'payload_extracted_or_executed': False,
              'outer_wall_ns_before_encoding': time.monotonic_ns() - start}
    if (ROOT / 'VERIFY.json').exists():
        record['verification'] = identity(ROOT / 'VERIFY.json')
    with (ROOT / 'VERIFY_EXECUTION.json').open('x') as f:
        json.dump(record, f, sort_keys=True, indent=2); f.write('\n')
    print(json.dumps(record, sort_keys=True))
    raise SystemExit(child.returncode or (0 if before == after else 2))


if __name__ == '__main__':
    main()
