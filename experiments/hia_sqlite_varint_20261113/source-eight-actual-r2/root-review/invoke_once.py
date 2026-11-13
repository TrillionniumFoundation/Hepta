"""Issue the independently reviewed first source8 r2 request exactly once."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import time

ROOT = Path(__file__).resolve().parent
REQUEST_ROOT = Path('/home/agent/hia-sqlite-source8-r2-recovery-20261113-e26e')
OUT = Path('/workspace/scratch/e26ed3e2edcf/root/sqlite-varint-source8-r2-invocation')

def checked(path, expected):
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected, str(path)
    return raw

def write(name, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(OUT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())

review_raw = checked(ROOT / 'ROOT-REVIEW.json', 'cfef6a2209c140f3bcbae376d748ca977d58362985a03df021cafde4af6b1fd7')
review = json.loads(review_raw)
assert review['status'] == 'COMPLETE_REVIEW_FOR_ONE_FIRST_SOURCE8_R2_EXECUTION'
request_raw = checked(REQUEST_ROOT / 'REQUEST.json', '7edf8b146dec5aa0acdfe75fa3dbd69aaae4916436de40736c237d2817fffcb7')
launch_raw = checked(REQUEST_ROOT / 'LAUNCH.json', 'a786a75d340513f81dea1fde83b05d499e80b9412f91948872bdd9aac212ad1c')
request, launch = json.loads(request_raw), json.loads(launch_raw)
assert not os.path.lexists(request['operation_root'])
assert launch['command'] == [request['runtime']['path'], '-I', '-S', '-B', str(REQUEST_ROOT / 'control/launch.py')]
assert launch['environment'] == request['environment'] and launch['cwd'] == str(REQUEST_ROOT)
for name, pin in request['inputs'].items():
    body = checked(REQUEST_ROOT / name, pin['sha256'])
    assert len(body) == pin['bytes']
checked(Path(request['runtime']['path']), request['runtime']['sha256'])
OUT.mkdir(mode=0o700, exist_ok=False)
write('INTENT.json', {'operation': 'FIRST_SOURCE8_R2_WRAPPER_CALL_ONCE',
      'canonical_request_commit': '045f1ae1e88f9be6680f618bf220857c42a4cbbb',
      'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
      'review_sha256': hashlib.sha256(review_raw).hexdigest(),
      'request_sha256': hashlib.sha256(request_raw).hexdigest(),
      'launch_sha256': hashlib.sha256(launch_raw).hexdigest(),
      'launch': launch, 'unchanged_original_owner_seconds': 180, 'cleanup_seconds': 3,
      'additional_wrapper_timeout': None, 'retries': 0, 'source_or_native_pass_claimed': False})
started = time.monotonic_ns()
with (OUT / 'stdout.log').open('xb') as stdout, (OUT / 'stderr.log').open('xb') as stderr:
    completed = subprocess.run(launch['command'], cwd=launch['cwd'], env=launch['environment'],
                               stdout=stdout, stderr=stderr, check=False)
    stdout.flush(); os.fsync(stdout.fileno()); stderr.flush(); os.fsync(stderr.fileno())
returned = {'wrapper_returncode': completed.returncode, 'elapsed_ns': time.monotonic_ns() - started,
            'request_sha256': hashlib.sha256(request_raw).hexdigest(),
            'raw_outputs': {name: {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                            for name in ('stdout.log', 'stderr.log')
                            for raw in [(OUT / name).read_bytes()]},
            'child_owner_or_qualification_not_inferred_from_wrapper_return': True}
write('RETURN.json', returned)
print(json.dumps(returned))
raise SystemExit(completed.returncode)
