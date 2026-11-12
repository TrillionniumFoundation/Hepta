"""One create-only 180/3 source validation. No numeric native launch exists here."""
from __future__ import annotations
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import sys
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, pin, request, require, runtime, save


def main():
    policy = request()
    runtime(policy['runtime'])
    for expected in policy['control_inputs']:
        require(pin(expected['path']) == expected, 'frozen control input changed')
    folder = Path(policy['evidence_root'])
    require(not folder.exists(), 'preserve prior execution; this request is create-only')
    folder.mkdir(mode=0o700)
    space = os.statvfs(folder)
    save(folder / 'RESOURCE-OBSERVATION.json', {'available_bytes': space.f_bavail * space.f_frsize,
        'free_inodes': space.f_favail, 'native_trace_allocation': False})
    require(space.f_bavail * space.f_frsize >= policy['minimum_available_bytes']
            and space.f_favail >= policy['minimum_available_inodes'],
            'fresh source-only resource precondition is not met')
    expected = policy['process_owner']
    require(pin(expected['path']) == expected, 'original process-owner bytes or identity changed')
    spec = importlib.util.spec_from_file_location('core_compare_integration_source_owner', expected['path'])
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    command = [policy['runtime']['path'], '-I', '-S', '-B', str(HERE / 'control/worker.py')]
    environment = {name: os.environ[name] for name in ('PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TMPDIR', 'TZ')
                   if name in os.environ}
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    environment['PYTHONPYCACHEPREFIX'] = str(folder / 'unused-pycache')
    final = {'schema': 'hepta.hia.core-compare-integration-source-final.v1', 'status': 'HOLD',
        'qualification_seconds': 180, 'cleanup_seconds': 3,
        'request': pin(HERE / 'REQUEST.json'), 'command': command,
        'native_executed': False, 'complete18_executed': False, 'complete116_executed': False,
        'cold_executed': False, 'installed_executed': False}
    try:
        returned = owner.run_owned(command, cwd=HERE, env=environment,
            stdout_path=folder / 'child.stdout.log', stderr_path=folder / 'child.stderr.log',
            receipt_path=folder / 'lifecycle.json', qualification_seconds=180, cleanup_seconds=3)
        save(folder / 'wrapper.json', returned)
        life_raw = (folder / 'lifecycle.json').read_bytes()
        life = json.loads(life_raw)
        require(returned['receipt_sha256'] == sha256(life_raw).hexdigest()
                and all(returned.get(key) == value for key, value in life.items())
                and returned['supervisor_returncode'] == 0,
                'original lifecycle/wrapper binding differs')
        cleanup = life['cleanup']
        require(life['schema'] == 'hepta.hia.selfhost-process-owner.v1'
                and life['implementation_sha256'] == expected['sha256']
                and life['status'] == 'OWNED_PROCESS_COMPLETED' and life['returncode'] == 0
                and life['qualification_seconds'] == 180 and life['cleanup_seconds'] == 3
                and life['qualification_started'] is True and life['subreaper_enabled'] is True
                and life['exit_observed_before_deadline'] is True
                and life['event_overflow'] is False and life['interrupted_signals'] == []
                and life.get('owner_error') is None and not life.get('timed_out', False)
                and cleanup['attempted'] is True and cleanup['complete'] is True
                and cleanup['deadline_exceeded'] is False
                and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True
                and cleanup['remaining_direct_children'] == [] and cleanup['errors'] == []
                and [row['kind'] for row in life['events']] == [
                    'qualification_started', 'owned_child_observed',
                    'qualification_exit_observed', 'owned_child_reaped'],
                'source owner did not close naturally with the original ECHILD condition')
        report = json.loads((folder / 'evidence/report.json').read_bytes())
        require(report['status'] == 'SOURCE_INTEGRATION_PASS'
                and report.get('error') is None and report.get('preservation_error') is None,
                'source worker did not qualify')
        tests = report['tests']
        require(tests['expected_ids'] == tests['loaded_ids'] == tests['executed_ids'] == policy['expected_ids']
                and all(tests[key] == [] for key in ('loader_errors', 'errors', 'failures', 'skipped',
                    'expectedFailures', 'unexpectedSuccesses', 'native_or_compiler_or_process_attempts')),
                'source final complete denominator or anomalies differ')
        final['status'] = 'SOURCE_INTEGRATION_PASS'
    except BaseException:
        final['status'] = 'HOLD'
        final['error'] = traceback.format_exc()
    finally:
        final['actual_originals'] = [pin(path) for path in sorted(folder.rglob('*')) if path.is_file()]
        save(folder / 'FINAL.json', final)
    print(json.dumps({key: final[key] for key in ('status', 'native_executed', 'complete116_executed')}))
    return 0 if final['status'] == 'SOURCE_INTEGRATION_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
