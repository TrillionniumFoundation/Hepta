"""Root-reviewed, single fresh local source-control invocation; not Full32."""
from pathlib import Path
import importlib.util
import json
import os
import stat
import sys
import traceback

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('rust195_source_eight_common', ROOT / 'control/common.py')
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)

def main():
    request_pin, raw = common.read(ROOT / 'REQUEST.json')
    request = json.loads(raw)
    common.require(request['schema'] == 'hia.full32.rust195-source-eight-request.v1'
                   and request['qualification_seconds'] == 180 and request['cleanup_seconds'] == 3
                   and request['expected_methods'] == len(request['expected_ids']) == 8
                   and request['product_source_binding'] is None,
                   'source-only request scope or original budget differs')
    runtime, _ = common.read(Path(sys.executable).resolve())
    common.require(all(runtime[key] == request['runtime'][key] for key in ('path', 'bytes', 'sha256', 'identity'))
                   and list(sys.version_info[:3]) == request['runtime_version'] == [3, 12, 14],
                   'fixed local development interpreter differs')
    expected_env = {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PATH': '',
                    'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1', 'PYTHONUNBUFFERED': '1'}
    common.require(request['environment'] == expected_env
                   and request['command'] == [runtime['path'], '-I', '-S', '-B',
                         str(ROOT / 'control/worker.py'), str(ROOT / 'REQUEST.json')],
                   'exact source-only command or credential-free environment differs')
    before = common.input_records(ROOT, request)
    output = Path(request['operation_root'])
    common.require(output.parent == Path('/tmp') and not os.path.lexists(output),
                   'fresh fixed operation; old actions are never replayed')
    capacity = os.statvfs(output.parent)
    common.require(capacity.f_bavail * capacity.f_frsize >= request['minimum_free_bytes']
                   and capacity.f_favail >= request['minimum_free_inodes'], 'source-control storage unavailable')
    output.mkdir(mode=0o700)
    common.create(output / 'REQUEST.original.json', raw, raw=True)
    common.create(output / 'INPUTS-BEFORE.json', before)
    common.create(output / 'CAPACITY-BEFORE.json', {'free_bytes': capacity.f_bavail * capacity.f_frsize,
                                                  'free_inodes': capacity.f_favail})
    owner_spec = importlib.util.spec_from_file_location('rust195_source_eight_original_owner',
                                                       ROOT / 'control/process_owner_impl.py')
    owner = importlib.util.module_from_spec(owner_spec)
    owner_spec.loader.exec_module(owner)
    final = {'schema': 'hia.full32.rust195-source-eight-final.v1', 'status': 'HOLD',
             'request': request_pin, 'closed_owner': False, 'natural_owner': False,
             'source_eight_pass': False, 'supplier_executed': False, 'native_executed': False,
             'product_qualification_executed': False, 'original_results_reclassified': False,
             'product_source_binding': None, 'complete_output_custody': False, 'errors': []}
    try:
        returned = owner.run_owned(request['command'], cwd=ROOT, env=request['environment'],
            stdout_path=output / 'stdout.log', stderr_path=output / 'stderr.log',
            receipt_path=output / 'lifecycle.json', qualification_seconds=180, cleanup_seconds=3)
        common.create(output / 'OWNER-RETURN.json', returned)
        life_pin, life_raw = common.read(output / 'lifecycle.json')
        life = json.loads(life_raw)
        parent_request_pin, parent_request_raw = common.read(output / 'lifecycle.json.request.json', 262144)
        parent_request = json.loads(parent_request_raw)
        projected = dict(returned)
        supervisor_rc = projected.pop('supervisor_returncode', None)
        returned_sha = projected.pop('receipt_sha256', None)
        common.require(projected == life and type(supervisor_rc) is int and returned_sha == life_pin['sha256']
                       and life['schema'] == 'hepta.hia.selfhost-process-owner.v1'
                       and life['implementation_sha256'] == request['inputs']['control/process_owner_impl.py']['sha256']
                       and life['request_sha256'] == parent_request_pin['sha256']
                       and parent_request['command'] == request['command']
                       and parent_request['cwd'] == str(ROOT) and parent_request['env'] == expected_env
                       and life['qualification_seconds'] == 180 and life['cleanup_seconds'] == 3,
                       'current original owner/request/returned bytes binding differs')
        cleanup = life.get('cleanup', {})
        final['closed_owner'] = (life.get('subreaper_enabled') is True and life.get('event_overflow') is False
            and cleanup.get('complete') is True and cleanup.get('observed_echild') is True
            and cleanup.get('leader_reaped') is True and cleanup.get('remaining_direct_children') == []
            and cleanup.get('errors') == [] and cleanup.get('deadline_exceeded') is False)
        common.require(final['closed_owner'], 'child outputs must wait for this exact owner ECHILD')
        events = life.get('events', [])
        final['natural_owner'] = (supervisor_rc == 0 and life.get('status') == 'OWNED_PROCESS_COMPLETED'
            and life.get('returncode') == 0 and life.get('timed_out') is False
            and life.get('exit_observed_before_deadline') is True and life.get('owner_error') is None
            and life.get('interrupted_signals') == []
            and [row.get('kind') for row in events] == ['qualification_started', 'owned_child_observed',
                                                       'qualification_exit_observed', 'owned_child_reaped']
            and all(row.get('pid') == life.get('qualification_pid') for row in events))
        # Custody follows closure even for a nonzero original test process.
        rows, total = [], 0
        for path in sorted(output.rglob('*')):
            value = path.lstat()
            common.require(not stat.S_ISLNK(value.st_mode), 'unexpected output symlink')
            if stat.S_ISDIR(value.st_mode):
                continue
            actual, _ = common.read(path, 16 << 20)
            total += actual['bytes']
            common.require(total <= request['maximum_output_bytes'] and len(rows) < 64,
                           'complete small output custody exceeds fixed bound')
            rows.append(actual)
        common.create(output / 'ORIGINAL-CATALOG.json', {'records': rows, 'regular_bytes': total,
                         'complete_observed_namespace': True, 'after_current_ECHILD': True})
        final['complete_output_custody'] = True
        after = common.input_records(ROOT, request)
        common.create(output / 'INPUTS-AFTER.json', after)
        common.require(before == after, 'source/control inputs changed')
        report_pin, report_raw = common.read(output / 'tests/REPORT.json')
        report = json.loads(report_raw)
        final['report'] = report_pin
        final['source_eight_pass'] = (report.get('status') == 'EIGHT_INERT_SOURCE_CONTROLS_PASS_ONLY'
            and report.get('exception') is None
            and report.get('tests_run') == 8 and report.get('expected_ids') == report.get('loaded_ids')
            == report.get('actual_ids') == report.get('success_ids') == request['expected_ids']
            and report.get('inputs_before') == report.get('inputs_after') == before
            and all(report.get(k) == [] for k in ('failures', 'errors', 'skipped', 'expected_failures',
                                                  'unexpected_successes', 'denied_effects'))
            and all(report.get(k) is False for k in ('supplier_module_imported', 'supplier_executed',
                     'network_used', 'Rustup_executed', 'APT_executed', 'native_executed',
                     'product_qualification_executed', 'original_product_results_reclassified')))
        common.require(final['natural_owner'] and final['source_eight_pass'], 'source-only result remains HOLD')
        final['status'] = 'SOURCE_EIGHT_PASS_ONLY_NOT_FULL32'
    except BaseException as error:
        final['status'] = 'HOLD'
        final['errors'].append({'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()})
    common.create(output / 'FINAL.json', final)
    print(json.dumps({'status': final['status'], 'closed_owner': final['closed_owner'], 'output': str(output)}))
    return 0 if final['status'] == 'SOURCE_EIGHT_PASS_ONLY_NOT_FULL32' and not final['errors'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
