"""Issue the reviewed finite CLI successor once after source28 actual closure."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, '/workspace/scratch/e26ed3e2edcf/root')
from audit_cli_r2b_actual_publication import pin, js, save

ROOT = Path('/workspace/scratch/e26ed3e2edcf/native-cli-c-runtime-lifetime-plan-r4b')
BASE = Path('/workspace/scratch/e26ed3e2edcf/root')
REVIEW = BASE / 'cli-c-runtime-lifetime-review-r4b/ROOT-REVIEW.json'
SOURCE = BASE / 'cli-runtime-layout-source28-r4b-invocation/READBACK.json'
OUT = BASE / 'cli-c-runtime-lifetime-invocation-r4b'


def main():
    assert not os.path.lexists(OUT)
    assert pin(REVIEW)['sha256'] == 'a527018fbdcafca9efdeb23dbef5d537c239335d7db3c25b56ea3d26c03cf56b'
    assert pin(SOURCE)['sha256'] == 'f37ac4a76e7dfbe369bc0a8d28f598ebba9f70593e8520325e60671663c30847'
    review, source = js(REVIEW), js(SOURCE)
    assert review['status'] == 'ROOT_STATIC_AND_COMPLETE_INPUT_READBACK_PASS'
    assert source['status'] == 'SOURCE28_ACTUAL_PASS_ONLY' and source['population'] == 28
    assert review['canonical'] == source['canonical_request'] == '6e704d8457ebb357fa71e3f0d40fc5064d943da8'
    request_path = ROOT / 'REQUEST.json'
    assert pin(request_path) == review['request']
    assert pin(ROOT / 'POLICY.json') == review['policy']
    request, policy = js(request_path), js(ROOT / 'POLICY.json')
    assert not os.path.lexists(request['operation_root'])
    runtime = pin(Path(policy['python']['path']))
    assert all(runtime[k] == policy['python'][k] for k in ('path', 'bytes', 'sha256', 'git_blob', 'mode'))
    command = [runtime['path'], '-I', '-S', '-B', str(ROOT / 'control/launch.py'),
        '--request', str(request_path), '--sha256', review['request']['sha256']]
    environment = {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PATH': ''}
    OUT.mkdir(mode=0o700)
    intent = {'schema': 'hia.root.cli-finite-r4b-unique-invocation.v1', 'status': 'ISSUED_ONCE_NO_REPLAY',
        'request': pin(request_path), 'policy': pin(ROOT / 'POLICY.json'), 'review': pin(REVIEW),
        'source28_actual': pin(SOURCE), 'invoker': pin(Path(__file__)), 'runtime': runtime,
        'command': command, 'cwd': str(ROOT), 'environment': environment,
        'operation_root': request['operation_root'], 'canonical_request': review['canonical'],
        'qualification_seconds': 180, 'cleanup_seconds': 3, 'inner_seconds': [20, 5, 20, 5],
        'expected_not_actual': [8, 10, 48, 11], 'started_time_ns': time.time_ns()}
    save(OUT / 'INTENT.json', intent)
    started = time.monotonic_ns()
    with (OUT / 'launcher.stdout.log').open('xb') as stdout, (OUT / 'launcher.stderr.log').open('xb') as stderr:
        process = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=stdout, stderr=stderr,
                                   stdin=subprocess.DEVNULL)
        save(OUT / 'SPAWN.json', {'pid': process.pid, 'intent': pin(OUT / 'INTENT.json')})
        returncode = process.wait()
    result = {'schema': 'hia.root.cli-finite-r4b-launcher-return.v1', 'status': 'LAUNCHER_RETURNED',
        'returncode': returncode, 'elapsed_ns': time.monotonic_ns() - started,
        'stdout': pin(OUT / 'launcher.stdout.log'), 'stderr': pin(OUT / 'launcher.stderr.log'),
        'request_unchanged': pin(request_path) == review['request'],
        'actual_qualification_not_inferred_from_exit_code': True}
    save(OUT / 'RETURNED.json', result)
    print(json.dumps(result, sort_keys=True))
    return returncode


if __name__ == '__main__':
    raise SystemExit(main())
