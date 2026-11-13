"""Invoke the separately frozen pure ELF/map population once under 20/3."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, '/workspace/scratch/e26ed3e2edcf/root')
from audit_cli_r2b_actual_publication import pin, js, save

PLAN = Path('/workspace/scratch/e26ed3e2edcf/native-cli-c-runtime-lifetime-plan-r4b')
BASE = Path('/workspace/scratch/e26ed3e2edcf/root')
OUT = BASE / 'cli-runtime-layout-source28-r4b-invocation'
GUARD = BASE / 'cli-runtime-layout-source28-r4b-owner'
REVIEW = BASE / 'cli-c-runtime-lifetime-review-r4b/ROOT-REVIEW.json'


def main():
    assert pin(REVIEW)['sha256'] == 'a527018fbdcafca9efdeb23dbef5d537c239335d7db3c25b56ea3d26c03cf56b'
    review = js(REVIEW)
    assert review['status'] == 'ROOT_STATIC_AND_COMPLETE_INPUT_READBACK_PASS'
    assert review['canonical'] == '6e704d8457ebb357fa71e3f0d40fc5064d943da8'
    request_path = PLAN / 'SOURCE-CONTROL-REQUEST.json'
    assert pin(request_path) == review['source_control_request']
    request = js(request_path)
    assert request['new_source_control_wall_seconds'] == 20
    assert request['expected_ids'] == review['source_control_ids'] and len(request['expected_ids']) == 28
    assert not any(os.path.lexists(p) for p in (OUT, GUARD, request['output']))
    assert request['cwd'] == str(PLAN)
    assert request['environment'] == {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PATH': ''}
    actual_inputs = []
    for expected in review['source_control_inputs']:
        actual = pin(Path(expected['path']))
        assert actual == expected
        actual_inputs.append(actual)
    implementation = PLAN / 'control/process_owner_impl.py'
    assert pin(implementation)['sha256'] == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
    OUT.mkdir(mode=0o700)
    GUARD.mkdir(mode=0o700)
    paths = {'stdout_path': GUARD / 'qualification.stdout.log',
             'stderr_path': GUARD / 'qualification.stderr.log',
             'receipt_path': GUARD / 'process-owner.json'}
    intent = {'schema': 'hia.root.cli-source28-r4b-invocation.v1', 'status': 'ISSUED_ONCE_NO_REPLAY',
        'canonical_request': review['canonical'], 'request': pin(request_path), 'review': pin(REVIEW),
        'invoker': pin(Path(__file__)), 'owner_implementation': pin(implementation),
        'command': request['command'], 'cwd': str(PLAN), 'environment': request['environment'],
        'paths': {k: str(v) for k, v in paths.items()}, 'parent_pid': os.getpid(),
        'qualification_seconds': 20, 'cleanup_seconds': 3, 'expected_ids': request['expected_ids'],
        'source_inputs': actual_inputs, 'native_runtime_or_DSO_or_HIA_execution': False,
        'started_time_ns': time.time_ns()}
    save(OUT / 'INTENT.json', intent)
    spec = importlib.util.spec_from_file_location('root_cli_source28_original_owner', implementation)
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    started = time.monotonic_ns()
    wrapper = owner.run_owned(request['command'], cwd=str(PLAN), env=request['environment'],
        **paths, qualification_seconds=20, cleanup_seconds=3)
    save(OUT / 'WRAPPER.json', wrapper)
    returned = {'schema': 'hia.root.source28-owner-return.v1', 'owner_function_returned': True,
        'elapsed_ns': time.monotonic_ns() - started, 'wrapper': pin(OUT / 'WRAPPER.json'),
        'qualification_returncode': wrapper.get('returncode'),
        'supervisor_returncode': wrapper.get('supervisor_returncode'),
        'qualification_result_not_inferred_from_returncode': True}
    save(OUT / 'RETURNED.json', returned)
    print(json.dumps(returned, sort_keys=True))
    return 0 if wrapper.get('supervisor_returncode') == 0 and wrapper.get('returncode') == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
