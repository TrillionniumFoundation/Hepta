"""Read the closed source-only owner and every result; execute no test again."""
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, '/workspace/scratch/e26ed3e2edcf/root')
from audit_cli_r2b_actual_publication import read, pin, js, save

BASE = Path('/workspace/scratch/e26ed3e2edcf')
PLAN = BASE / 'native-cli-c-runtime-lifetime-plan-r4b'
OUT = BASE / 'root/cli-runtime-layout-source28-r4b-invocation'
GUARD = BASE / 'root/cli-runtime-layout-source28-r4b-owner'
ACTUAL = BASE / 'native-cli-runtime-layout-source-controls-r4b'


def main():
    intent, wrapper, returned = (js(OUT / name) for name in ('INTENT.json', 'WRAPPER.json', 'RETURNED.json'))
    request_path = PLAN / 'SOURCE-CONTROL-REQUEST.json'
    request = js(request_path)
    owner_raw = read(GUARD / 'process-owner.json')
    owner = json.loads(owner_raw)
    request_raw = read(GUARD / 'process-owner.json.request.json')
    owner_request = json.loads(request_raw)
    assert set(wrapper) == set(owner) | {'receipt_sha256', 'supervisor_returncode'}
    assert {k: v for k, v in wrapper.items() if k in owner} == owner
    assert wrapper['receipt_sha256'] == hashlib.sha256(owner_raw).hexdigest()
    assert owner['request_sha256'] == hashlib.sha256(request_raw).hexdigest()
    assert owner['implementation_sha256'] == owner_request['implementation_sha256'] == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
    assert owner_request['command'] == intent['command'] == request['command']
    assert owner_request['cwd'] == intent['cwd'] == str(PLAN)
    assert owner_request['env'] == intent['environment'] == request['environment']
    assert owner_request['parent_pid'] == owner['parent_pid'] == intent['parent_pid']
    assert all(owner_request[k] == v for k, v in intent['paths'].items())
    assert owner_request['qualification_seconds'] == owner['qualification_seconds'] == request['new_source_control_wall_seconds'] == 20
    assert owner_request['cleanup_seconds'] == owner['cleanup_seconds'] == 3
    assert owner_request['deadline_ns'] - owner_request['started_ns'] == 20000000000
    cleanup = owner['cleanup']
    assert cleanup['complete'] is True and cleanup['observed_echild'] is True
    assert cleanup['leader_reaped'] is True and cleanup['deadline_exceeded'] is False
    assert cleanup['remaining_direct_children'] == cleanup['errors'] == []
    assert owner['subreaper_enabled'] is True and owner['event_overflow'] is False
    assert owner['qualification_started'] is True and owner['status'] == 'OWNED_PROCESS_COMPLETED'
    assert owner['returncode'] == wrapper['supervisor_returncode'] == 0
    assert owner['exit_observed_before_deadline'] is True and owner['timed_out'] is False
    assert owner['interrupted_signals'] == [] and owner.get('owner_error') is None
    assert [r['kind'] for r in owner['events']] == ['qualification_started', 'owned_child_observed',
        'qualification_exit_observed', 'owned_child_reaped']
    assert returned['qualification_returncode'] == returned['supervisor_returncode'] == 0
    report = js(ACTUAL / 'REPORT.json')
    assert report['status'] == 'PASS' and 'error' not in report
    assert report['request_sha256'] == pin(request_path)['sha256'] == intent['request']['sha256']
    assert report['expected_ids'] == report['loaded_ids'] == report['executed_ids'] == request['expected_ids']
    assert len(report['executed_ids']) == len(set(report['executed_ids'])) == 28
    assert [r['id'] for r in report['outcomes']] == request['expected_ids']
    assert all(r['status'] == 'PASS' and 'error' not in r for r in report['outcomes'])
    assert all(r['observation']['refusal_type'] == 'ValueError' for r in report['outcomes'][4:])
    for key in ('actual_runtime_symbol_admission_executed', 'ctypes_DSO_C_HIA_or_product_executed',
                'original_runtime8_or_lifetime10_executed', 'original17_or46_executed'):
        assert report[key] is False
    fresh = []
    for row in intent['source_inputs']:
        actual = pin(Path(row['path']))
        assert actual == row
        fresh.append(actual)
    assert pin(request_path) == intent['request']
    assert set(p.name for p in ACTUAL.iterdir()) == {'REPORT.json'}
    originals = []
    for folder in (ACTUAL, GUARD):
        for path in sorted(folder.rglob('*')):
            assert not path.is_symlink()
            if path.is_file():
                originals.append(pin(path))
    assert len(originals) == 7
    assert read(GUARD / 'qualification.stdout.log') == read(GUARD / 'qualification.stderr.log') == b''
    result = {'schema': 'hia.root.cli-source28-r4b-readback.v1', 'status': 'SOURCE28_ACTUAL_PASS_ONLY',
        'canonical_request': intent['canonical_request'], 'request': pin(request_path),
        'expected_loaded_executed_success_ids_equal': True, 'actual_ids': report['executed_ids'],
        'population': 28, 'positive_controls': 4, 'explicit_ValueError_refusal_controls': 24,
        'outcomes': [r['status'] for r in report['outcomes']], 'source_elapsed_ns': report['elapsed_ns'],
        'owner_seconds': 20, 'cleanup_seconds': 3,
        'owner_actual_exit_elapsed_ns': owner['events'][-2]['monotonic_ns'] - owner['events'][0]['monotonic_ns'],
        'raw_owner_projection_request_command_parent_paths_bound': True,
        'four_natural_events_and_ECHILD': True, 'complete_actual_originals': originals,
        'all_five_input_bytes_unchanged': fresh, 'native_runtime_or_C_DSO_HIA_execution': False,
        'original8_10_17_46_executed': False, 'historical_HOLDs_unchanged': True, 'whole_rewrite_closed': False}
    save(OUT / 'READBACK.json', result)
    print(json.dumps({'status': result['status'], 'population': 28, 'originals': 7,
        'source_elapsed_ns': report['elapsed_ns'], 'readback': pin(OUT / 'READBACK.json')}, sort_keys=True))


if __name__ == '__main__':
    main()
