"""Issue the single reviewed finite CLI request; preserve the invocation itself."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import time

ROOT = Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r1-20261112-e26e')
REVIEW = Path('/workspace/scratch/e26ed3e2edcf/root/cli-c-runtime-lifetime-review-r1/ROOT-REVIEW.json')
OUT = Path('/workspace/scratch/e26ed3e2edcf/root/cli-c-runtime-lifetime-invocation-r1')
PYTHON = '/opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python3.12'


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def save(path, data):
    raw = (json.dumps(data, indent=2, sort_keys=True) + '\n').encode()
    with path.open('xb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())


def main():
    assert not OUT.exists()
    review = json.loads(REVIEW.read_bytes())
    assert review['status'] == 'ROOT_STATIC_AND_INPUT_READBACK_PASS'
    request = ROOT / 'REQUEST.json'
    request_pin = pin(request)
    assert request_pin['sha256'] == '7aa2713a05537355eb844b81d92ad5cfad8401d582c9c1add6d1362926b6498a'
    policy = json.loads(request.read_bytes())
    assert not os.path.lexists(policy['operation_root'])
    command = [PYTHON, '-I', '-S', '-B', str(ROOT / 'control/launch.py'),
               '--request', str(request), '--sha256', request_pin['sha256']]
    environment = {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PATH': ''}
    OUT.mkdir(mode=0o700)
    intent = {'schema': 'hia.root.cli-finite-unique-invocation.v1', 'status': 'ISSUED_ONCE_NO_REPLAY',
        'request': request_pin, 'review': pin(REVIEW), 'command': command, 'cwd': str(ROOT),
        'environment': environment, 'operation_root': policy['operation_root'],
        'canonical_request': '30d2cf56eb346db37a1da41dffbffa0cfefc6c44',
        'qualification_seconds': 180, 'cleanup_seconds': 3, 'started_ns': time.time_ns()}
    save(OUT / 'INTENT.json', intent)
    started = time.monotonic_ns()
    with (OUT / 'launcher.stdout.log').open('xb') as stdout, (OUT / 'launcher.stderr.log').open('xb') as stderr:
        process = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=stdout, stderr=stderr)
        save(OUT / 'SPAWN.json', {'pid': process.pid, 'intent': pin(OUT / 'INTENT.json')})
        result = process.wait()
    returned = {'status': 'LAUNCHER_RETURNED', 'returncode': result,
        'elapsed_ns': time.monotonic_ns() - started, 'stdout': pin(OUT / 'launcher.stdout.log'),
        'stderr': pin(OUT / 'launcher.stderr.log'), 'request_unchanged': pin(request) == request_pin,
        'result_is_not_inferred_from_exit_code': True}
    save(OUT / 'RETURNED.json', returned)
    print(json.dumps(returned, sort_keys=True))
    return result


if __name__ == '__main__':
    raise SystemExit(main())
