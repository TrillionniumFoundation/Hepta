"""Read original owner before child outputs; independently join all20 results."""
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, '/workspace/scratch/e26ed3e2edcf/root')
from audit_cli_r2b_actual_publication import read, pin, js, save, identity

PLAN = Path('/home/agent/hia-v92-three-view-plan-r2-20261113-e26e')
ACTUAL = Path('/tmp/hia-v92-three-view-source20-r2-20261113-e26e')
OUT = Path('/home/agent/hia-root-v92-three-view-r2-20261113-e26e/source20-r2-invocation')


def check_pin(record):
    p = Path(record['path']); actual = pin(p)
    assert all(actual[k] == record[k] for k in ('path', 'bytes', 'sha256'))
    st = identity(p.lstat())
    assert [st[k] for k in ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns')] == record['identity']
    return actual


def main():
    request = js(PLAN / 'CONTROL-REQUEST.json')
    intent, returned = js(OUT / 'INTENT.json'), js(OUT / 'RETURNED.json')
    assert returned['returncode'] == 0 and returned['exact_launcher_returned'] is True
    assert pin(PLAN / 'CONTROL-REQUEST.json') == intent['request']
    life, actual_request, owner_return = (js(ACTUAL / n) for n in ('lifecycle.json', 'lifecycle.json.request.json', 'OWNER-RETURN.json'))
    projected = dict(owner_return)
    assert projected.pop('supervisor_returncode') == 0
    assert projected.pop('receipt_sha256') == pin(ACTUAL / 'lifecycle.json')['sha256']
    assert projected == life
    assert life['request_sha256'] == pin(ACTUAL / 'lifecycle.json.request.json')['sha256']
    assert life['implementation_sha256'] == actual_request['implementation_sha256'] == request['inputs']['control/process_owner_impl.py']['sha256']
    assert actual_request['command'] == request['command'] and actual_request['cwd'] == str(PLAN)
    assert actual_request['env'] == request['environment']
    assert life['qualification_seconds'] == actual_request['qualification_seconds'] == 20
    assert life['cleanup_seconds'] == actual_request['cleanup_seconds'] == 3
    assert actual_request['deadline_ns'] - actual_request['started_ns'] == 20_000_000_000
    assert life['status'] == 'OWNED_PROCESS_COMPLETED' and life['returncode'] == 0
    assert life['subreaper_enabled'] is True and life['event_overflow'] is False
    assert life['exit_observed_before_deadline'] is True and life['timed_out'] is False
    assert life['interrupted_signals'] == [] and life.get('owner_error') is None
    cleanup = life['cleanup']
    assert all(cleanup[k] is True for k in ('attempted', 'complete', 'leader_reaped', 'observed_echild'))
    assert cleanup['errors'] == cleanup['remaining_direct_children'] == [] and cleanup['deadline_exceeded'] is False
    events = life['events']
    assert [e['kind'] for e in events] == ['qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped']
    assert all(e['pid'] == life['qualification_pid'] for e in events)
    assert events[2]['si_code'] == 1 and events[2]['si_status'] == events[3]['returncode'] == 0
    assert events[2]['monotonic_ns'] < actual_request['deadline_ns']
    # ECHILD and exact original request are established above, before child bodies.
    final, report = js(ACTUAL / 'FINAL.json'), js(ACTUAL / 'tests/REPORT.json')
    assert final['status'] == 'TWENTY_SOURCE_IO_PASS_ONLY' and final['errors'] == []
    assert final['closed_owner'] is True and final['natural_owner'] is True
    for field in ('request', 'lifecycle', 'report'):
        check_pin(final[field])
    assert report['status'] == 'TWENTY_SOURCE_IO_CONTROLS_PASS_ONLY' and report.get('exception') is None
    assert report['expected_ids'] == report['loaded_ids'] == report['actual_ids'] == report['success_ids'] == request['expected_ids']
    assert len(set(report['actual_ids'])) == report['tests_run'] == 20
    assert all(report[k] == [] for k in ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes', 'denied_effects'))
    assert report['network_bytes'] == 0 and all(report[k] is False for k in ('private_proxy_capture_performed', 'product_execution', 'receiver_executed'))
    assert report['inputs_before'] == report['inputs_after'] == request['inputs']
    assert 0 <= report['elapsed_seconds'] < 20
    before, after = js(ACTUAL / 'INPUTS-BEFORE.json'), js(ACTUAL / 'INPUTS-AFTER.json')
    assert before == after and len(before) == 35
    for name, record in before.items():
        assert record['path'] == name
        check_pin(record)
    assert read(ACTUAL / 'REQUEST.original.json') == read(PLAN / 'CONTROL-REQUEST.json')
    original_index = js(ACTUAL / 'ORIGINALS.json')
    assert original_index['after_bound_ECHILD'] is True and len(original_index['files']) == 10
    assert sum(r['bytes'] for r in original_index['files']) == original_index['bytes'] and original_index['bytes'] < 32 << 20
    for row in original_index['files']:
        check_pin(row)
    files = [pin(p) for p in sorted(ACTUAL.rglob('*')) if p.is_file()]
    assert len(files) == 13 and sum(r['bytes'] for r in files) < 32 << 20
    assert {str(Path(r['path']).relative_to(ACTUAL)) for r in files} == {'FINAL.json', 'INPUTS-AFTER.json', 'INPUTS-BEFORE.json', 'ORIGINALS.json', 'OWNER-RETURN.json', 'REQUEST.original.json', 'lifecycle.json', 'lifecycle.json.request.json', 'lifecycle.json.stdout.log', 'lifecycle.json.stderr.log', 'stderr.log', 'stdout.log', 'tests/REPORT.json'}
    stderr = read(ACTUAL / 'stderr.log').decode()
    lines = stderr.splitlines()
    assert sum(line.endswith(' ... ok') for line in lines) == 20 and lines[-1] == 'OK'
    assert json.loads(read(ACTUAL / 'stdout.log')) == {'status': 'TWENTY_SOURCE_IO_CONTROLS_PASS_ONLY', 'tests_run': 20, 'network_bytes': 0}
    assert read(OUT / 'launcher.stderr.log') == b''
    result = {'schema': 'hia.root.v92-source20-actual-readback.v1', 'status': 'ROOT_ALL20_SOURCE_IO_CONTROLS_AND_ORIGINAL_OWNER_PASS',
        'canonical_request': intent['canonical_request'], 'request': intent['request'], 'expected_loaded_actual_success_ids': request['expected_ids'],
        'source_seconds': report['elapsed_seconds'], 'launcher_elapsed_ns': returned['elapsed_ns'],
        'original_owner_seconds': 20, 'original_cleanup_seconds': 3, 'owner_natural_zero_and_bound_ECHILD': True,
        'qualification_elapsed_ns': events[2]['monotonic_ns'] - events[0]['monotonic_ns'],
        'actual_files': files, 'all35_inputs_full_bytes_and_identity_preserved': True,
        'owner_read_before_child_outputs': True, 'network_bytes': 0, 'product_or_native_execution': False,
        'source_execution_count': 1, 'real_receiver_execution_count': 0, 'large_provider_reference_requests': 0,
        'large_local_GETs': 0, 'next_step_requires_fresh_two_volume_capacity_and_private_input_receipts': True,
        'full_HIA_native_rewrite_closed': False}
    save(OUT / 'READBACK.json', result)
    print(json.dumps({'status': result['status'], 'readback': pin(OUT / 'READBACK.json'), 'source_seconds': report['elapsed_seconds']}))


if __name__ == '__main__':
    main()
