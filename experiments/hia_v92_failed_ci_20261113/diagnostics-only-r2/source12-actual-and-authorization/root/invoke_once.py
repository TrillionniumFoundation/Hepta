"""Execute the independently reviewed source12 r2b launch exactly once."""
from pathlib import Path
import hashlib
import json
import os
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parent
REQUEST_ROOT = Path('/home/agent/hia-v92-diagnostics-only-remote-r2-20261113-e26e')
OUT = Path('/workspace/scratch/e26ed3e2edcf/root/v92-diagnostics-only-source12-r2b-invocation')

def checked(path, expected, identity=None):
    path = Path(path)
    ident = lambda s: [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode)
    if identity is not None:
        assert ident(before) == identity, str(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        assert ident(os.fstat(stream.fileno())) == ident(before)
        raw = stream.read()
        assert ident(os.fstat(stream.fileno())) == ident(before)
    assert ident(path.lstat()) == ident(before)
    assert hashlib.sha256(raw).hexdigest() == expected, str(path)
    return raw

def write(name, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(OUT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())

review_raw = checked(ROOT / 'ROOT-REVIEW.json', '923dc22488c1610326115cd3963c2cb6327e49cf9e6c43a393bda612513e9035')
review = json.loads(review_raw)
assert review['status'] == 'COMPLETE_REVIEW_FOR_ONE_SOURCE12_R2B_EXECUTION'
request_raw = checked(REQUEST_ROOT / 'CONTROL-REQUEST-r2b.json', review['request']['sha256'], review['request']['identity'])
launch_raw = checked(REQUEST_ROOT / 'CONTROL-LAUNCH-r2b.json', review['launch']['sha256'], review['launch']['identity'])
request, launch = json.loads(request_raw), json.loads(launch_raw)
assert not os.path.lexists(request['output_root'])
assert launch['automatic_retry'] is False and launch['network'] is False and launch['product'] is False
assert launch['command'] == [request['runtime']['executable'], '-I', '-S', '-B', str(REQUEST_ROOT / 'controls/source_launch.py'), '--request', str(REQUEST_ROOT / 'CONTROL-REQUEST-r2b.json'), '--request-sha256', review['request']['sha256']]
assert launch['environment'] == request['environment'] and launch['cwd'] == str(REQUEST_ROOT)
assert request['qualification_seconds'] == 20 and request['cleanup_seconds'] == 3
for pin in request['inputs']:
    assert len(checked(pin['path'], pin['sha256'], pin['identity'])) == pin['bytes']
OUT.mkdir(mode=0o700, exist_ok=False)
write('INTENT.json', {'operation': 'FIRST_SOURCE12_R2B_WRAPPER_CALL_ONCE',
      'canonical_request_commit': 'e72669c33591bd73f5f3feb1c70425263855d34a',
      'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
      'review_sha256': hashlib.sha256(review_raw).hexdigest(),
      'request_sha256': hashlib.sha256(request_raw).hexdigest(),
      'launch_sha256': hashlib.sha256(launch_raw).hexdigest(),
      'launch': launch, 'unchanged_original_owner_seconds': 20, 'cleanup_seconds': 3,
      'additional_wrapper_timeout': None, 'retries': 0,
      'synthetic_only': True, 'network_requests': 0, 'product_executed': False})
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
