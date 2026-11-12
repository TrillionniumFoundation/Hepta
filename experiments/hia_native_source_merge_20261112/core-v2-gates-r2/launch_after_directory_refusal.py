"""Preserve the known pre-owner directory refusal, then use a fresh private guard."""
from pathlib import Path
from hashlib import sha256
import json
import os
import stat
import sys

OUT = Path(__file__).resolve().parent
CONTROL = Path('/workspace/scratch/e26ed3e2edcf/core/native116-freeze-r1')
old = OUT / 'guard'
stderr = (OUT / 'supervisor.stderr.log').read_bytes()
assert b'guardian requires its existing private directory' in stderr
assert sorted(p.name for p in old.iterdir()) == ['request.json']
assert not (OUT / 'TEST-RESULT.json').exists()
request = (old / 'request.json').read_bytes()
failure = {
    'schema': 'hia.local-source-gate-pre-owner-launch-refusal.v1',
    'status': 'FAILED_BEFORE_OWNER_OR_TEST_EXECUTION',
    'reason': 'fresh guard directory was created with default 0755 instead of private 0700',
    'observed_guard_mode': oct(stat.S_IMODE(old.stat().st_mode)),
    'original_stdout_sha256': sha256((OUT / 'supervisor.stdout.log').read_bytes()).hexdigest(),
    'original_stderr_sha256': sha256(stderr).hexdigest(),
    'original_request_sha256': sha256(request).hexdigest(),
    'owner_or_test_result_present': False,
    'old_control_directory_preserved': True,
}
with (OUT / 'INITIAL-LAUNCH-REFUSAL.json').open('x') as stream:
    json.dump(failure, stream, indent=2, sort_keys=True)
    stream.write('\n')
fresh = OUT / 'guard-private-r2'
fresh.mkdir(mode=0o700, exist_ok=False)
assert stat.S_IMODE(fresh.stat().st_mode) == 0o700
config = fresh / 'request.json'
with config.open('xb') as stream:
    stream.write(request)
assert sha256((CONTROL / 'guardian.py').read_bytes()).hexdigest() == 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023'
assert sha256((CONTROL / 'process_owner_impl.py').read_bytes()).hexdigest() == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
for descriptor, name in ((1, 'supervisor-r2.stdout.log'), (2, 'supervisor-r2.stderr.log')):
    fd = os.open(OUT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.dup2(fd, descriptor)
    os.close(fd)
python = str(Path(sys.executable).resolve())
os.execv(python, [python, '-I', '-S', '-B', str(CONTROL / 'guardian.py'),
                 '--config', str(config), '--config-sha256', sha256(request).hexdigest(),
                 '--implementation', str(CONTROL / 'process_owner_impl.py')])
