"""Issue exactly one reviewed eight-method source-only request."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import time

ROOT = Path('/tmp/hia-full32-rust195-source-eight-plan-r2-20261112-e26e')
REVIEW = Path('/workspace/scratch/e26ed3e2edcf/root/full32-rust195-source8-r2-review/ROOT-REVIEW.json')
OUT = Path('/workspace/scratch/e26ed3e2edcf/root/full32-rust195-source8-r2-invocation')


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())


def main():
    assert not OUT.exists()
    review = json.loads(REVIEW.read_bytes())
    assert review['status'] == 'ROOT_REVIEW_PASS_FOR_ONE_SOURCE_ONLY_REQUEST'
    assert pin(REVIEW)['sha256'] == 'c0e5754bca76e36e688d35d132d89255ccb6863902bb6bbea987a9b090ddee43'
    request_path = ROOT / 'REQUEST.json'
    request_pin = pin(request_path)
    assert request_pin['sha256'] == '2818142cea6592022bb0d54fc7d3de93c8c19a548834e82c244869f2c55389a3'
    request = json.loads(request_path.read_bytes())
    assert not os.path.lexists(request['operation_root'])
    launch = json.loads((ROOT / 'LAUNCH.json').read_bytes())
    command = launch['command']
    assert command == [request['runtime']['path'], '-I', '-S', '-B', str(ROOT / 'control/launch.py')]
    OUT.mkdir(mode=0o700)
    save(OUT / 'INTENT.json', {'status': 'ISSUED_ONCE_NO_REPLAY', 'canonical_request': review['canonical'],
        'request': request_pin, 'review': pin(REVIEW), 'command': command, 'cwd': str(ROOT),
        'environment': request['environment'], 'operation_root': request['operation_root'],
        'qualification_seconds': 180, 'cleanup_seconds': 3, 'source_controls_only': True,
        'supplier_or_product_qualification_permitted': False, 'started_ns': time.time_ns()})
    began = time.monotonic_ns()
    with (OUT / 'launcher.stdout.log').open('xb') as stdout, (OUT / 'launcher.stderr.log').open('xb') as stderr:
        process = subprocess.Popen(command, cwd=ROOT, env=request['environment'], stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr)
        save(OUT / 'SPAWN.json', {'pid': process.pid, 'intent': pin(OUT / 'INTENT.json')})
        returncode = process.wait()
    result = {'status': 'LAUNCHER_RETURNED', 'returncode': returncode, 'elapsed_ns': time.monotonic_ns() - began,
        'stdout': pin(OUT / 'launcher.stdout.log'), 'stderr': pin(OUT / 'launcher.stderr.log'),
        'request_unchanged': pin(request_path) == request_pin, 'actual_qualification_not_inferred_from_exit_code': True}
    save(OUT / 'RETURNED.json', result)
    print(json.dumps(result, sort_keys=True))
    return returncode


if __name__ == '__main__':
    raise SystemExit(main())
