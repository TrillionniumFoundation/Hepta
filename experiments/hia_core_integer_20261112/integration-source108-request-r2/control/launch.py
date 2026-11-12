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
    final = {'schema': 'hepta.hia.core-integer-integration-source-final.v1', 'status': 'HOLD',
        'qualification_seconds': 180, 'cleanup_seconds': 3,
        'request': pin(HERE / 'REQUEST.json'), 'command': command,
        'native_executed': False, 'complete18_executed': False, 'complete116_executed': False,
        'cold_executed': False, 'installed_executed': False,
        'source_child_process_policy': policy['source_child_process_policy'],
        'allowed_negative_processes': None, 'forbidden_attempts': None,
        'zero_process_scope_claimed': False}
    closed = False
    parent_pins = [pin(folder / 'RESOURCE-OBSERVATION.json')]
    try:
        returned = owner.run_owned(command, cwd=HERE, env=environment,
            stdout_path=folder / 'child.stdout.log', stderr_path=folder / 'child.stderr.log',
            receipt_path=folder / 'lifecycle.json', qualification_seconds=180, cleanup_seconds=3)
        save(folder / 'wrapper.json', returned)
        parent_pins.append(pin(folder / 'wrapper.json'))
        provisional = returned.get('cleanup', {})
        require(type(returned.get('supervisor_returncode')) is int
                and type(returned.get('receipt_sha256')) is str
                and provisional.get('complete') is True
                and provisional.get('observed_echild') is True
                and provisional.get('leader_reaped') is True
                and provisional.get('deadline_exceeded') is False
                and provisional.get('errors') == []
                and provisional.get('remaining_direct_children') == [],
                'owner closure is unconfirmed; child originals must not be read')
        life_path = folder / 'lifecycle.json'
        life_pin = pin(life_path)
        life_raw = life_path.read_bytes()
        require(sha256(life_raw).hexdigest() == life_pin['sha256']
                and pin(life_path) == life_pin, 'owner receipt changed while binding')
        life = json.loads(life_raw)
        request_path = folder / 'lifecycle.json.request.json'
        request_pin = pin(request_path)
        owner_request_raw = request_path.read_bytes()
        require(sha256(owner_request_raw).hexdigest() == request_pin['sha256']
                and pin(request_path) == request_pin, 'owner request changed while binding')
        owner_request = json.loads(owner_request_raw)
        require(returned['receipt_sha256'] == sha256(life_raw).hexdigest()
                and {key: value for key, value in returned.items()
                     if key not in {'receipt_sha256', 'supervisor_returncode'}} == life,
                'original lifecycle/wrapper binding differs')
        require(owner_request['schema'] == life['schema'] == 'hepta.hia.selfhost-process-owner.v1'
                and life['request_sha256'] == sha256(owner_request_raw).hexdigest()
                and owner_request['command'] == command and owner_request['cwd'] == str(HERE)
                and owner_request['env'] == environment
                and owner_request['stdout_path'] == str(folder / 'child.stdout.log')
                and owner_request['stderr_path'] == str(folder / 'child.stderr.log')
                and owner_request['receipt_path'] == str(life_path)
                and owner_request['qualification_seconds'] == life['qualification_seconds'] == 180
                and owner_request['cleanup_seconds'] == life['cleanup_seconds'] == 3
                and owner_request['implementation_sha256'] == life['implementation_sha256'] == expected['sha256']
                and type(owner_request['started_ns']) is int
                and type(owner_request['deadline_ns']) is int
                and owner_request['deadline_ns'] - owner_request['started_ns'] == 180_000_000_000,
                'original owner command/request/deadline binding differs')
        cleanup = life['cleanup']
        require(life['subreaper_enabled'] is True
                and cleanup.get('attempted') is True and cleanup.get('complete') is True
                and cleanup.get('observed_echild') is True and cleanup.get('leader_reaped') is True
                and cleanup.get('deadline_exceeded') is False
                and cleanup.get('remaining_direct_children') == [] and cleanup.get('errors') == [],
                'bound original owner does not confirm ECHILD closure')
        closed = True
        final['bound_owner_observation'] = {
            'lifecycle': life_pin, 'request': request_pin,
            'status': life['status'], 'returncode': life['returncode'],
            'supervisor_returncode': returned['supervisor_returncode']}
        require(returned['supervisor_returncode'] == 0
                and life['schema'] == 'hepta.hia.selfhost-process-owner.v1'
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
        require(type(tests['allowed_negative_processes']) is int
                and tests['allowed_negative_processes'] == report['allowed_negative_processes'] == 4
                and tests['forbidden_attempts'] == report['forbidden_attempts'] == []
                and tests['forbidden_attempt_count'] == 0
                and tests['zero_process_scope_claimed'] is report['zero_process_scope_claimed'] is False
                and tests['source_child_process_policy'] == report['source_child_process_policy']
                    == policy['source_child_process_policy'],
                'source final negative-command scope differs')
        final['allowed_negative_processes'] = tests['allowed_negative_processes']
        final['forbidden_attempts'] = tests['forbidden_attempts']
        final['status'] = 'SOURCE_INTEGRATION_PASS'
    except BaseException:
        final['status'] = 'HOLD'
        final['error'] = traceback.format_exc()
    finally:
        final['closed_owner_confirmed'] = closed
        final['child_originals_read'] = closed
        if closed:
            final['actual_originals'] = [pin(path) for path in sorted(folder.rglob('*')) if path.is_file()]
        else:
            final['actual_originals'] = []
            save(folder / 'PARENT-OBSERVATIONS.json', {
                'files': parent_pins, 'closed_owner_confirmed': False,
                'child_originals_read': False,
                'scope': 'Only files written by this parent; no traversal or child-body read.'})
        save(folder / 'FINAL.json', final)
    print(json.dumps({key: final[key] for key in ('status', 'native_executed', 'complete116_executed')}))
    return 0 if final['status'] == 'SOURCE_INTEGRATION_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
