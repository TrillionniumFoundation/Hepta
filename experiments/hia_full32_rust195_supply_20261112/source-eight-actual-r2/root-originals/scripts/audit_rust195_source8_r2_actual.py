"""Read the single closed source-eight execution; never rerun its methods."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import stat
import sys

ROOT = Path('/tmp/hia-full32-rust195-source-eight-plan-r2-20261112-e26e')
ACTUAL = Path('/tmp/hia-full32-rust195-source-eight-actual-r2-20261112-e26e')
OUT = Path('/workspace/scratch/e26ed3e2edcf/root/full32-rust195-source8-r2-invocation')
REVIEW = Path('/workspace/scratch/e26ed3e2edcf/root/full32-rust195-source8-r2-review')
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('root_source8_actual_common', ROOT / 'control/common.py')
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)


def load(path):
    pin, raw = common.read(path)
    return json.loads(raw), pin


def main():
    request, request_pin = load(ROOT / 'REQUEST.json')
    spawn, _ = load(OUT / 'SPAWN.json')
    before_review, _ = load(REVIEW / 'INPUTS-BEFORE.original.json')
    life, life_pin = load(ACTUAL / 'lifecycle.json')
    owned_request, owned_pin = load(ACTUAL / 'lifecycle.json.request.json')
    returned, returned_pin = load(ACTUAL / 'OWNER-RETURN.json')
    projection = dict(returned)
    assert projection.pop('supervisor_returncode') == 0
    assert projection.pop('receipt_sha256') == life_pin['sha256']
    assert projection == life
    assert life['request_sha256'] == owned_pin['sha256']
    assert life['implementation_sha256'] == owned_request['implementation_sha256'] == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
    assert life['parent_pid'] == owned_request['parent_pid'] == spawn['pid']
    assert owned_request['command'] == request['command'] and owned_request['cwd'] == str(ROOT)
    assert owned_request['env'] == request['environment']
    for role, name in [('stdout_path', 'stdout.log'), ('stderr_path', 'stderr.log'), ('receipt_path', 'lifecycle.json')]:
        assert owned_request[role] == str(ACTUAL / name)
    assert owned_request['deadline_ns'] - owned_request['started_ns'] == 180_000_000_000
    assert owned_request['qualification_seconds'] == life['qualification_seconds'] == 180
    assert owned_request['cleanup_seconds'] == life['cleanup_seconds'] == 3
    closure = life['cleanup']
    assert life['qualification_started'] and life['subreaper_enabled']
    assert closure['complete'] and closure['observed_echild'] and closure['leader_reaped']
    assert not closure['deadline_exceeded'] and closure['remaining_direct_children'] == closure['errors'] == []
    # Only after the exact owner/PID/request join and ECHILD read child outputs.
    assert life['status'] == 'OWNED_PROCESS_COMPLETED' and life['returncode'] == 0 and not life['timed_out']
    assert life['exit_observed_before_deadline'] and life['interrupted_signals'] == [] and life['owner_error'] is None and not life['event_overflow']
    assert [row['kind'] for row in life['events']] == ['qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped']
    assert all(row['pid'] == life['qualification_pid'] for row in life['events'])
    final, final_pin = load(ACTUAL / 'FINAL.json')
    assert final['status'] == 'SOURCE_EIGHT_PASS_ONLY_NOT_FULL32'
    assert final['closed_owner'] and final['natural_owner'] and final['source_eight_pass'] and final['complete_output_custody']
    assert final['errors'] == [] and final['product_source_binding'] is None
    assert final['request'] == request_pin
    copied_request_pin, copied_request = common.read(ACTUAL / 'REQUEST.original.json')
    original_request_pin, original_request = common.read(ROOT / 'REQUEST.json')
    assert copied_request == original_request and original_request_pin == request_pin
    report, report_pin = load(ACTUAL / 'tests/REPORT.json')
    assert report['request'] == request_pin and final['report'] == report_pin
    assert report['status'] == 'EIGHT_INERT_SOURCE_CONTROLS_PASS_ONLY' and report.get('exception') is None
    assert report['tests_run'] == 8
    assert report['expected_ids'] == report['loaded_ids'] == report['actual_ids'] == report['success_ids'] == request['expected_ids']
    for key in ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes', 'denied_effects'):
        assert report[key] == []
    for key in ('supplier_module_imported', 'supplier_executed', 'network_used', 'Rustup_executed', 'APT_executed', 'native_executed', 'product_qualification_executed', 'original_product_results_reclassified'):
        assert report[key] is False
    observations = [load(ACTUAL / name)[0] for name in ('INPUTS-BEFORE.json', 'INPUTS-AFTER.json', 'tests/INPUTS-BEFORE.json', 'tests/INPUTS-AFTER.json')]
    assert all(value == before_review == report['inputs_before'] == report['inputs_after'] for value in observations)
    assert common.input_records(ROOT, request) == before_review
    events, events_pin = load(ACTUAL / 'tests/TEST-EVENTS.json')
    assert [(row['kind'], row['id']) for row in events] == [(kind, name) for name in request['expected_ids'] for kind in ('start', 'stop')]
    assert all(type(row['monotonic_ns']) is int for row in events)
    catalog, catalog_pin = load(ACTUAL / 'ORIGINAL-CATALOG.json')
    assert catalog['complete_observed_namespace'] and catalog['after_current_ECHILD']
    rows = catalog['records']
    assert len(rows) == 14 and len({r['path'] for r in rows}) == 14
    assert sum(row['bytes'] for row in rows) == catalog['regular_bytes']
    for row in rows:
        current, _ = common.read(Path(row['path']))
        assert current == row
    originals = []
    for path in sorted(ACTUAL.rglob('*')):
        info = path.lstat()
        assert not stat.S_ISLNK(info.st_mode)
        if stat.S_ISREG(info.st_mode):
            current, _ = common.read(path, 16 << 20)
            originals.append(current)
        else:
            assert stat.S_ISDIR(info.st_mode)
    assert len(originals) == 17
    assert {row['path'] for row in originals} == {row['path'] for row in rows} | {str(ACTUAL / name) for name in ('ORIGINAL-CATALOG.json', 'INPUTS-AFTER.json', 'FINAL.json')}
    assert all(final[key] is False for key in ('supplier_executed', 'native_executed', 'product_qualification_executed', 'original_results_reclassified'))
    result = {'schema': 'hia.root.rust195-source-eight-actual-readback.v1', 'status': 'SOURCE_EIGHT_PASS_ONLY_NOT_FULL32',
        'canonical_request': '20bcabac0a7c6be1d5afc2d333622bbed3135dfa', 'request': request_pin,
        'expected': 8, 'loaded': 8, 'executed': 8, 'successes': 8, 'all_anomalies_zero': True,
        'denied_effects': 0, 'supplier_or_APT_or_Rustup_or_network_or_native_or_product_execution': False,
        'runtime': 'local CPython 3.12.14 source-only', 'worker_seconds': report['elapsed_ns'] / 1e9,
        'owner_seconds_to_exit': (life['events'][-2]['monotonic_ns'] - life['events'][0]['monotonic_ns']) / 1e9,
        'owner_natural_four_events_ECHILD': True, 'original_180_3': True,
        'actual_worker_request_pin_equals_frozen_root_request': True, 'all_four_input_snapshots_equal_root_preexec': True,
        'all_15_input_pins_freshly_rechecked': True, 'originals': originals, 'original_files': len(originals),
        'original_bytes': sum(row['bytes'] for row in originals), 'report': report_pin, 'final': final_pin,
        'life': life_pin, 'owner_request': owned_pin, 'owner_returned': returned_pin, 'events': events_pin, 'catalog': catalog_pin,
        'original_HOLD_and_UNKNOWN_states_unchanged': True, 'current_product_binding': None, 'whole_native_rewrite_closed': False}
    record = common.create(OUT / 'READBACK.json', result)
    print(json.dumps({'status': result['status'], 'expected': 8, 'loaded': 8, 'executed': 8,
        'worker_seconds': result['worker_seconds'], 'owner_seconds': result['owner_seconds_to_exit'],
        'originals': len(originals), 'readback': record}, sort_keys=True))


if __name__ == '__main__':
    main()
