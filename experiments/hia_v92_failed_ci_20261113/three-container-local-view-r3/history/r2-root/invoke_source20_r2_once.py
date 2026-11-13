"""Unique invocation of the frozen20/3 tiny-file source controls."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, '/workspace/scratch/e26ed3e2edcf/root')
from audit_cli_r2b_actual_publication import read, pin, js, save

PLAN = Path('/home/agent/hia-v92-three-view-plan-r2-20261113-e26e')
OUT = Path('/home/agent/hia-root-v92-three-view-r2-20261113-e26e/source20-r2-invocation')
REVIEW = OUT.parent / 'request-review/ROOT-REVIEW.json'


def main():
    review = js(REVIEW)
    assert pin(REVIEW)['sha256'] == '82b6337bf16904e02c76fa6f8b6ed1a7d087983fd9c22e1dc7a22900a7350fb6'
    assert review['status'] == 'FULL48_REMOTE_BODIES_AND_EXACT_STORAGE_REVISION_PASS_SOURCE20_PENDING'
    launch = js(PLAN / 'CONTROL-LAUNCH.json')
    request = js(PLAN / 'CONTROL-REQUEST.json')
    assert pin(PLAN / 'CONTROL-LAUNCH.json') == review['control_launch']
    assert pin(PLAN / 'CONTROL-REQUEST.json') == review['control_request']
    assert (launch['owner_seconds'], launch['cleanup_seconds']) == (20, 3)
    assert len(request['expected_ids']) == 20
    assert launch['command'] == [request['runtime']['path'], '-I', '-S', '-B', str(PLAN / 'controls/launch_controls.py')]
    assert launch['cwd'] == str(PLAN) and launch['environment'] == request['environment']
    assert not os.path.lexists(OUT) and not os.path.lexists(request['operation_root'])
    for name, expected in request['inputs'].items():
        actual = pin(PLAN / name)
        assert all(actual[k] == expected[k] for k in ('bytes', 'sha256'))
    ref = js(OUT.parent / 'request-review/REF-GET.provider.json')
    assert json.loads(ref['structuredContent']['content'])['object']['sha'] == review['canonical']
    OUT.mkdir(mode=0o700)
    save(OUT / 'INTENT.json', {'schema': 'hia.root.v92-three-view-source20-unique-invocation.v1',
        'status': 'ISSUED_ONCE_NO_REPLAY', 'canonical_request': review['canonical'], 'review': pin(REVIEW),
        'request': pin(PLAN / 'CONTROL-REQUEST.json'), 'launch': pin(PLAN / 'CONTROL-LAUNCH.json'),
        'invoker': pin(Path(__file__)), 'command': launch['command'], 'cwd': launch['cwd'],
        'environment': launch['environment'], 'owner_seconds': 20, 'cleanup_seconds': 3,
        'expected_ids': request['expected_ids'], 'network_product_receiver': False, 'started_time_ns': time.time_ns()})
    start = time.monotonic_ns()
    with (OUT / 'launcher.stdout.log').open('xb') as stdout, (OUT / 'launcher.stderr.log').open('xb') as stderr:
        done = subprocess.run(launch['command'], cwd=launch['cwd'], env=launch['environment'],
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, check=False)
        stdout.flush(); os.fsync(stdout.fileno()); stderr.flush(); os.fsync(stderr.fileno())
    result = {'schema': 'hia.root.v92-source20-launch-return.v1', 'returncode': done.returncode,
        'elapsed_ns': time.monotonic_ns() - start, 'exact_launcher_returned': True,
        'result_or_closed_owner_not_inferred_from_returncode': True,
        'stdout': pin(OUT / 'launcher.stdout.log'), 'stderr': pin(OUT / 'launcher.stderr.log')}
    save(OUT / 'RETURNED.json', result)
    print(json.dumps(result, sort_keys=True))
    return done.returncode


if __name__ == '__main__':
    raise SystemExit(main())
