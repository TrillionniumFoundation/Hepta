"""Issue the single reviewed finite CLI request; preserve the invocation itself."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import time

ROOT = Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r3-20261112-e26e')
REVIEW = Path('/workspace/scratch/e26ed3e2edcf/root/cli-c-runtime-lifetime-review-r3/ROOT-REVIEW.json')
OUT = Path('/workspace/scratch/e26ed3e2edcf/root/cli-c-runtime-lifetime-invocation-r3')
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
    assert review['status'] == 'ROOT_STATIC_AND_COMPLETE_INPUT_READBACK_PASS'
    assert pin(REVIEW)['sha256'] == '4db6881f4846c6a72d12ba1f04336ecb37d490ac85cee56f1fccd8649f74410b'
    assert review['canonical'] == '7e2d37f425987c827a09f5cd0207595fd86e2e56'
    request = ROOT / 'REQUEST.json'
    request_pin = pin(request)
    assert request_pin['sha256'] == '29e590a10fe3d32ef911aa19db6b73eb3cc2a0681d004c45b3bd653fb12d4849'
    policy = json.loads(request.read_bytes())
    assert not os.path.lexists(policy['operation_root'])
    command = [PYTHON, '-I', '-S', '-B', str(ROOT / 'control/launch.py'),
               '--request', str(request), '--sha256', request_pin['sha256']]
    environment = {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PATH': ''}
    OUT.mkdir(mode=0o700)
    intent = {'schema': 'hia.root.cli-finite-unique-invocation.v1', 'status': 'ISSUED_ONCE_NO_REPLAY',
        'request': request_pin, 'review': pin(REVIEW), 'command': command, 'cwd': str(ROOT),
        'environment': environment, 'operation_root': policy['operation_root'],
        'canonical_request': '7e2d37f425987c827a09f5cd0207595fd86e2e56',
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
