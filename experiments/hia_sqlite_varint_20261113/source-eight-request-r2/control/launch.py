"""New r2 request, not a replay of the interrupted original source8 plan."""
from pathlib import Path
import importlib.util
import json
import os
import stat
import sys
import traceback

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location('sqlite_source8_r2_support', ROOT / 'control/support.py')
support = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(support)
common = support.common

def main():
    request_pin, raw = common.read(ROOT / 'REQUEST.json')
    request = json.loads(raw)
    common.require(request['schema'] == 'hia.sqlite-varint.source-eight-request.v2'
        and request['status'] == 'REAUTHORED_CONTROLS_AFTER_ENVIRONMENT_CHANGE_UNEXECUTED'
        and request['qualification_seconds'] == 180 and request['cleanup_seconds'] == 3
        and request['expected_methods'] == len(request['expected_ids']) == 8
        and request['expected_vm_returns'] == sum(request['expected_vm_by_id'].values()) == 1618,
        'new source-only request population or original budget differs')
    runtime, _ = common.read(Path(sys.executable).resolve())
    common.require(all(runtime[k] == request['runtime'][k] for k in ('path', 'bytes', 'sha256', 'git_blob', 'identity'))
                   and list(sys.version_info[:3]) == request['runtime_version'] == [3, 12, 14],
                   'fixed new local development runtime differs')
    expected_env = {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PATH': '',
                    'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1', 'PYTHONUNBUFFERED': '1'}
    common.require(request['environment'] == expected_env
        and request['command'] == [runtime['path'], '-I', '-S', '-B',
                                  str(ROOT / 'control/worker.py'), str(ROOT / 'REQUEST.json')],
        'exact source-only command or credential-free environment differs')
    before = common.input_records(ROOT, request)
    source_before = support.source_records(request)
    output = Path(request['operation_root'])
    common.require(output == Path('/home/agent/hia-sqlite-varint-source-eight-actual-r2-20261113-e26e')
                   and not os.path.lexists(output), 'fresh independent r2 output required')
    capacity = os.statvfs(output.parent)
    common.require(request['minimum_free_bytes'] == 256 << 20 and request['minimum_free_inodes'] == 4096
                   and capacity.f_bavail * capacity.f_frsize >= request['minimum_free_bytes']
                   and capacity.f_favail >= request['minimum_free_inodes'],
                   'original source8 capacity gate not satisfied')
    output.mkdir(mode=0o700)
    common.create(output / 'REQUEST.original.json', raw, raw=True)
    common.create(output / 'INPUTS-BEFORE.json', before)
    common.create(output / 'SOURCE-BEFORE.json', source_before)
    common.create(output / 'CAPACITY-BEFORE.json', {'free_bytes': capacity.f_bavail * capacity.f_frsize,
                                                  'free_inodes': capacity.f_favail,
                                                  'device': output.parent.stat().st_dev})
    owner_spec = importlib.util.spec_from_file_location('sqlite_source8_r2_original_owner',
                                                       ROOT / 'control/process_owner_impl.py')
    owner = importlib.util.module_from_spec(owner_spec)
    owner_spec.loader.exec_module(owner)
    final = {'schema': 'hia.sqlite-varint.source-eight-final.v2', 'status': 'HOLD',
             'request': request_pin, 'closed_owner': False, 'natural_owner': False,
             'source_eight_pass': False, 'complete_output_custody': False, 'errors': [],
             'source_commit': request['source_commit'], 'source_tree': request['source_tree'],
             'old_source8_request_replayed': False, 'local_development_only': True}
    final.update({key: False for key in support.PUBLIC_FLAGS})
    try:
        returned = owner.run_owned(request['command'], cwd=ROOT, env=request['environment'],
            stdout_path=output / 'stdout.log', stderr_path=output / 'stderr.log',
            receipt_path=output / 'lifecycle.json', qualification_seconds=180, cleanup_seconds=3)
        common.create(output / 'OWNER-RETURN.json', returned)
        life_pin, life_raw = common.read(output / 'lifecycle.json')
        life = json.loads(life_raw)
        owner_request_pin, owner_request_raw = common.read(output / 'lifecycle.json.request.json', 262144)
        owner_request = json.loads(owner_request_raw)
        final['closed_owner'], final['natural_owner'] = support.natural_owner(
            returned, life, request, owner_request, owner_request_pin, life_pin)
        # Only the parent's returned/receipt/request originals are read before ECHILD.
        # All child output is retained and catalogued even for natural nonzero failure.
        rows, total = [], 0
        for path in sorted(output.rglob('*')):
            state = path.lstat()
            common.require(not stat.S_ISLNK(state.st_mode), 'unexpected output symlink')
            if stat.S_ISDIR(state.st_mode):
                continue
            pin, _ = common.read(path, 16 << 20)
            total += pin['bytes']
            common.require(request['maximum_output_bytes'] == 16 << 20
                           and total <= request['maximum_output_bytes'] and len(rows) < 64,
                           'complete closed output exceeds original fixed capacity')
            rows.append(pin)
        final['catalog'] = common.create(output / 'ORIGINAL-CATALOG.json',
            {'records': rows, 'regular_bytes': total, 'complete_observed_namespace': True,
             'scope': 'all existing originals after ECHILD and before parent final readback files',
             'after_current_ECHILD': True})
        final['complete_output_custody'] = True
        after = common.input_records(ROOT, request)
        source_after = support.source_records(request)
        common.create(output / 'INPUTS-AFTER.json', after)
        common.create(output / 'SOURCE-AFTER.json', source_after)
        common.require(after == before and source_after == source_before,
                       'full source/control input identities changed')
        report_pin, report_raw = common.read(output / 'tests/REPORT.json', 16 << 20)
        report = json.loads(report_raw)
        final['report'] = report_pin
        sb_pin, sb_raw = common.read(output / 'tests/SOURCE-BEFORE.json', 16 << 20)
        sa_pin, sa_raw = common.read(output / 'tests/SOURCE-AFTER.json', 16 << 20)
        source_joins = (json.loads(sb_raw) == json.loads(sa_raw) == source_before
                       and report.get('source_before') == sb_pin and report.get('source_after') == sa_pin)
        final['source_eight_pass'] = (
            report.get('schema') == 'hia.sqlite-varint.source-eight-report.v2'
            and report.get('status') == 'SQLITE_VARINT_SOURCE_EIGHT_VM_PASS_ONLY'
            and report.get('request') == request_pin and report.get('exception') is None
            and report.get('tests_run') == 8
            and report.get('expected_ids') == report.get('loaded_ids') == report.get('actual_ids')
            == report.get('success_ids') == request['expected_ids']
            and report.get('inputs_before') == report.get('inputs_after') == before and source_joins
            and report.get('original_test_body_sha256') == request['inputs']['candidate/inputs/tests/test_hia_sqlite_varint_source.py']['sha256']
            and report.get('local_development_runtime') == [3, 12, 14]
            and report.get('runtime') == runtime
            and report.get('old_source8_request_replayed') is False
            and all(report.get(k) == [] for k in ('failures', 'errors', 'skipped', 'expected_failures',
                        'unexpected_successes', 'denied_effects', 'secondary_errors'))
            and all(report.get(k) is False for k in support.PUBLIC_FLAGS))
        # Parent independently reads all VM bodies and both generated originals.
        final['vm'] = support.inspect_vm(request, output)
        final['core'] = support.inspect_core(output)
        common.require(report.get('vm') == final['vm'] and report.get('core') == final['core'],
                       'worker and independent full VM/Core readback differ')
        common.require(type(report.get('imports')) is list and report['imports'],
                       'actual source import identity list absent')
        imports = set()
        for item in report['imports']:
            name = item['module']
            common.require(name not in imports, 'duplicate imported module identity')
            imports.add(name)
            if item.get('namespace_only') is True:
                common.require(name == 'tools' and set(item) == {'module', 'namespace_only'},
                               'unexpected namespace-only import')
            else:
                observed = item['source']
                actual, _ = common.read(observed['path'])
                common.require(actual == observed and
                    (actual in list(source_before.values()) or
                     actual in [before[k] for k in before if k.startswith('candidate/inputs/')]),
                    'actual imported project source not in frozen full input set')
        common.require(request['test_module'] in imports, 'frozen source test module did not run')
        common.require(final['natural_owner'] and final['source_eight_pass'],
                       'source-only qualification remains HOLD')
        final['status'] = 'SQLITE_VARINT_SOURCE_EIGHT_VM_PASS_ONLY'
    except BaseException as error:
        final['status'] = 'HOLD'
        final['errors'].append({'type': type(error).__module__ + '.' + type(error).__qualname__,
                                'message': str(error), 'traceback': traceback.format_exc()})
    common.create(output / 'FINAL.json', final)
    print(json.dumps({'status': final['status'], 'closed_owner': final['closed_owner'], 'output': str(output)}))
    return 0 if final['status'] == 'SQLITE_VARINT_SOURCE_EIGHT_VM_PASS_ONLY' and not final['errors'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
