"""Create-only launcher for the one frozen finite native development request.

Do not execute before root review. No automatic retry or new operation key is
available. Native execution, trace writing and complete trace readback share
the original single 180-second owner, with its original 3-second cleanup.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import traceback

CONTROL = Path(__file__).resolve().parent
ROOT = CONTROL.parent
sys.path.insert(0, str(CONTROL))
from common import frozen, natural_owner, parent_fd, pin, read_file, require, save


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    raw, _ = read_file(args.request, 262144)
    require(sha256(raw).hexdigest() == args.sha256, 'launch request identity differs')
    request = json.loads(raw)
    require(request['schema'] == 'hepta.hia.numeric-native-development-request.v1'
            and request['operation_key'] == 'hia-e26e-core-compare-native-development-r2',
            'finite development operation differs')
    policy_raw, _ = read_file(ROOT / request['policy_path'], 262144)
    require(sha256(policy_raw).hexdigest() == request['policy_sha256'], 'launch policy differs')
    policy = json.loads(policy_raw)
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
            'isolated launcher runtime required')
    require(str(Path(sys.executable).resolve()) == policy['python']['path']
            and list(sys.version_info[:3]) == policy['python_version'], 'launcher runtime differs')
    before = frozen(ROOT, policy)
    folder = Path(request['operation_root'])
    require(folder == Path('/tmp/hia-core-compare-native-development-r2'), 'fixed operation root differs')
    disk = shutil.disk_usage(folder.parent)
    space = os.statvfs(folder.parent)
    require(disk.free >= policy['development_resources']['minimum_free_bytes']
            and space.f_favail >= policy['development_resources']['minimum_free_inodes'],
            'finite development output space is insufficient')
    with parent_fd(folder) as (parent, name):
        os.mkdir(name, mode=0o700, dir_fd=parent)
    final = {'schema': 'hepta.hia.numeric-native-development-terminal.v1', 'status': 'HOLD',
             'operation_key': request['operation_key'], 'request_sha256': args.sha256,
             'source_evidence_commit': policy['source_evidence_commit'],
             'scope': 'FINITE_LOCAL_NATIVE_DEVELOPMENT_NOT_COLD_OR_CORE116',
             'original18_executed': False, 'original116_executed': False,
             'native_Core39_executed': False, 'matching_source_cold': False,
             'installed_wheel_executed': False, 'default_activated': False}
    save(folder / 'LAUNCH-INPUTS.json', before)
    try:
        owner_path = ROOT / 'compiler-source/tools/hia_selfhost_process_owner.py'
        spec = importlib.util.spec_from_file_location('numeric_finite_original_owner', owner_path)
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        environment = {name: os.environ[name] for name in
                       ('PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TMPDIR', 'TZ') if name in os.environ}
        environment['PYTHONDONTWRITEBYTECODE'] = '1'
        command = [policy['python']['path'], '-I', '-S', '-B', str(CONTROL / 'worker.py'),
                   str(args.request), args.sha256]
        save(folder / 'INTENT.json', {'command': command, 'cwd': str(ROOT),
             'qualification_seconds': 180, 'cleanup_seconds': 3,
             'compile_wall_seconds': 20, 'compile_cpu_seconds': 10,
             'all_native_tests_trace_and_readback_inside_same_owner': True,
             'runtime_scope': 'actual pinned CPython3.12.14 local development; CPython3.14 unexecuted'})
        wrapper = owner.run_owned(command, cwd=str(ROOT), env=environment,
            stdout_path=folder / 'child.stdout.log', stderr_path=folder / 'child.stderr.log',
            receipt_path=folder / 'lifecycle.json', qualification_seconds=180, cleanup_seconds=3)
        save(folder / 'wrapper.json', wrapper)
        life_raw, life_pin = read_file(folder / 'lifecycle.json', 1 << 20)
        life = natural_owner(wrapper, life_raw)
        owner_request_raw, owner_request_pin = read_file(folder / 'lifecycle.json.request.json', 262144)
        owner_request = json.loads(owner_request_raw)
        require(owner_request['command'] == command and owner_request['cwd'] == str(ROOT)
                and owner_request['qualification_seconds'] == 180 and owner_request['cleanup_seconds'] == 3
                and owner_request['env'] == environment
                and life['request_sha256'] == sha256(owner_request_raw).hexdigest()
                and life['implementation_sha256'] == pin(owner_path)['sha256'],
                'actual owner request or implementation binding differs')
        report_raw, report_pin = read_file(folder / 'worker-report.json', 1 << 20)
        report = json.loads(report_raw)
        require(report['status'] == 'FINITE_NATIVE_DEVELOPMENT_PASS'
                and report['compile_attempts'] == report['native_child_attempts'] == 1
                and report['source_before_after_preserved'] is True
                and report['actual_native_test_count'] == 8
                and report['original_VM_matrix_pairs'] == 172 and report['complete_large_pair_count'] == 1
                and report.get('error') is None and report.get('preservation_error') is None,
                'finite development worker did not pass all required observations')
        final.update(status='FINITE_NATIVE_DEVELOPMENT_PASS', owner=life_pin,
                     owner_request=owner_request_pin, worker_report=report_pin,
                     actual_native_test_count=8, actual_image_sha256=report['actual_image_sha256'],
                     actual_trace=report['actual_trace'])
    except BaseException:
        final['status'] = 'HOLD'
        final['error'] = traceback.format_exc()
    finally:
        try:
            after = frozen(ROOT, policy)
            save(folder / 'LAUNCH-INPUTS-AFTER.json', after)
            final['inputs_preserved'] = before == after
            if before != after:
                final['status'] = 'HOLD'
        except BaseException:
            final['status'] = 'HOLD'
            final['preservation_error'] = traceback.format_exc()
        save(folder / 'FINAL.json', final)
    print(json.dumps({'status': final['status'], 'scope': final['scope'], 'output': str(folder)}))
    return 0 if final['status'] == 'FINITE_NATIVE_DEVELOPMENT_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
