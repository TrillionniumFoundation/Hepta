"""Independently read one completed CLI43 run; never import product modules."""
import hashlib
import json
import stat
from pathlib import Path

ROOT = Path('/workspace/scratch/dda74a4fae35')
BASE = ROOT / 'v119-inspect-retained-regressions-r3'
ATTEMPT = BASE / 'retained-groups-attempt-r1'
GROUP = ATTEMPT / '00-original-cli43'
OUT = ROOT / 'v95-audit-mount-r1/v139-progress/ROOT-INSPECT-R3-TERMINAL-READBACK.json'


def pin(path):
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode), str(path)
    raw = path.read_bytes()
    after = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
    assert all(getattr(before, k) == getattr(after, k) for k in fields), str(path)
    assert len(raw) == before.st_size
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'mode': '100755' if before.st_mode & 0o111 else '100644'}, stat.S_IMODE(before.st_mode)


def read(path):
    return json.loads(path.read_bytes())


plan = read(BASE / 'PLAN.json')
assert pin(BASE / 'PLAN.json')[0]['git_blob'] == '5d0994ff1fd5de94eb359be633343c6aa2171dab'
assert plan['ordered_group_names'] == ['original-cli43']
assert plan['original3_new_executions'] == 0
assert plan['limits'] == {'capacity': 1048576, 'cleanup_seconds': 3,
                          'compile_seconds': 20, 'qualification_seconds': 180}
assert plan['minimum_free_bytes'] == {'retained-groups': 1073741824}

parent = read(ATTEMPT / 'RESULT.json')
assert parent['status'] == 'ORIGINAL_CLI43_R3_PASS'
assert parent['owner_launch_attempts'] == 1 and parent['original3_new_executions'] == 0
assert parent['complete_source_guard_pass'] is True
assert parent['source_files'] == 3187
assert parent['source_tree'] == '7df49dd24bbba4ba3210168e639d6ea35a76a475'
for key in ('inspect_owner_executed', 'inspect_Native17_executed', 'inspect_VM12_executed',
            'matching_current_cold', 'whole_cli_native'):
    assert parent[key] is False

ids = plan['groups']['original-cli43']
tests = read(GROUP / 'TESTS.json')
assert len(ids) == len(set(ids)) == tests['tests_run'] == 43
assert tests['status'] == 'PASS'
assert all(tests[k] == ids for k in ('declared_ids', 'loaded_ids', 'started_ids', 'stopped_ids'))
assert tests['events'] == [event for name in ids for event in (['start', name], ['stop', name])]
anomalies = ('failures', 'errors', 'loader_errors', 'expected_failures', 'unexpected_successes', 'skipped')
assert all(tests[k] == [] for k in anomalies)
subtests = read(GROUP / 'wrapper/SUBTESTS.json')
observations = subtests['observations']
assert len(observations) == 493
assert all(row['ordinal'] == index and row['success'] is True and row['method_id'] in ids
           for index, row in enumerate(observations, 1))
assert subtests['original_TextTestResult_restored'] is True
assert subtests['foreign_parameter_protocols_not_probed'] is True

wrapper = read(GROUP / 'wrapper/RESULT.json')
request = read(GROUP / 'OWNER.json.request.json')
assert wrapper['status'] == 'PASS' and wrapper['original_child_returncode'] == 0
assert wrapper['all_source_bytes_modes_stats_unchanged'] is True
startup = wrapper['startup']
assert startup['orig_argv'] == request['command']
assert request['command'][1] == '-B' and request['command'][2] == str(BASE / 'run_retained_regressions.py')
assert {k: startup[k] for k in ('dont_write_bytecode', 'ignore_environment', 'isolated')} == {
    'dont_write_bytecode': 1, 'ignore_environment': 0, 'isolated': 0}
assert wrapper['request_pin'] == pin(GROUP / 'REQUEST.json')[0]
assert request['qualification_seconds'] == 180 and request['cleanup_seconds'] == 3
assert request['deadline_ns'] - request['started_ns'] == 180_000_000_000

owner = read(GROUP / 'OWNER.json')
returned = read(GROUP / 'OWNER-RETURNED.json')
assert returned == dict(owner, receipt_sha256=pin(GROUP / 'OWNER.json')[0]['sha256'], supervisor_returncode=0)
assert owner['status'] == 'OWNED_PROCESS_COMPLETED'
assert owner['returncode'] == 0 and owner['timed_out'] is False
assert owner['qualification_seconds'] == 180 and owner['cleanup_seconds'] == 3
assert owner['request_sha256'] == pin(GROUP / 'OWNER.json.request.json')[0]['sha256']
assert owner['exit_observed_before_deadline'] is True
cleanup = owner['cleanup']
assert cleanup['complete'] is True and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True
assert cleanup['deadline_exceeded'] is False and cleanup['errors'] == [] and cleanup['remaining_direct_children'] == []
assert owner['historical_descendant_inventory_complete'] is False
stage = read(GROUP / 'STAGE.json')
assert parent['stages'] == [stage] and stage['owner_returned'] == returned
assert stage['status'] == 'PASS' and stage['source_guard_pass'] is True

prior = plan['retained_r2']['files']
assert len(prior) == 19
for row in prior.values():
    actual, mode = pin(Path(row['path']))
    assert actual == row['pin'] and mode == row['posix_mode'], row['path']
old_parent = read(Path(prior['parent_result']['path']))
assert old_parent['status'] == 'FAIL'
old_tests = read(Path(prior['original_cli43_tests']['path']))
assert old_tests['status'] == 'FAIL' and len(old_tests['failures']) == 2
assert read(Path(prior['original3_tests']['path']))['status'] == 'PASS'

guard_records = []
source_maps = []
base_maps = []
for directory in (ATTEMPT, GROUP):
    before, after = (read(directory / ('GUARD-' + stage + '.json')) for stage in ('before', 'after'))
    assert before['source'] == after['source'] and before['base'] == after['base']
    for role, destination in (('source', source_maps), ('base', base_maps)):
        binding = before[role]
        path = Path(binding['path'])
        assert pin(path)[0] == binding['pin']
        data = read(path)
        assert data['errors'] == []
        assert len(data['files']) == len(data['stat']) == (3187 if role == 'source' else 3177)
        assert set(data['files']) == set(data['stat'])
        destination.append(data)
        guard_records.append({'role': role, 'path': str(path), 'pin': binding['pin']})
assert source_maps[0] == source_maps[1] and base_maps[0] == base_maps[1]
source = Path(plan['source']['path'])
current_bytes = 0
for name, expected in source_maps[0]['files'].items():
    path = source / name
    actual, mode = pin(path)
    assert actual == expected, name
    observed = path.lstat()
    metadata = {'bytes': observed.st_size, 'device': observed.st_dev, 'inode': observed.st_ino,
                'mode': mode, 'mtime_ns': observed.st_mtime_ns, 'ctime_ns': observed.st_ctime_ns,
                'nlink': observed.st_nlink}
    assert metadata == source_maps[0]['stat'][name], name
    current_bytes += actual['bytes']

paths = {'parent': ATTEMPT / 'RESULT.json', 'tests': GROUP / 'TESTS.json',
         'subtests': GROUP / 'wrapper/SUBTESTS.json', 'wrapper': GROUP / 'wrapper/RESULT.json',
         'owner': GROUP / 'OWNER.json', 'owner_returned': GROUP / 'OWNER-RETURNED.json',
         'owner_request': GROUP / 'OWNER.json.request.json', 'stage': GROUP / 'STAGE.json',
         'outer': BASE / 'retained-outer-r1/OUTER.json', 'reader': Path(__file__)}
outer = read(paths['outer'])
report = {
    'schema': 'hepta.root-inspect-cli43-r3-terminal-readback.v1',
    'status': 'ACTUAL_ORIGINAL_CLI43_R3_PASS_INDEPENDENTLY_VERIFIED',
    'methods': 43, 'events': 86, 'successful_subtests': 493,
    'exact_declared_loaded_started_stopped_ids': True, 'anomaly_collections_empty': list(anomalies),
    'actual_startup': startup, 'qualification_seconds': 180, 'cleanup_seconds': 3,
    'owner_raw_returned_exact_plus_two_fields': True, 'ECHILD': True,
    'historical_descendant_inventory_complete': False, 'prior_R2_19_files_full_bytes_modes_exact': True,
    'prior_R2_parent': 'FAIL', 'prior_R2_CLI43': 'FAIL', 'prior_R2_original3': 'PASS_UNDER_I_B',
    'original3_new_executions': 0, 'new_compiles': 0,
    'complete_parent_child_before_after_maps_exact': True,
    'current_source_files_independently_full_rehashed': 3187, 'current_source_bytes': current_bytes,
    'current_source_modes_and_metadata_match_actual_before_after': True,
    'source_tree': plan['source']['tree'], 'guards': guard_records,
    'outer': outer, 'raw_files': {k: {'path': str(p), 'pin': pin(p)[0], 'posix_mode': pin(p)[1]} for k, p in paths.items()},
    'new_product_execution_by_this_readback': False, 'inspect_owner_executed': False,
    'inspect_Native17_executed': False, 'inspect_VM12_executed': False,
    'matching_current_cold': False, 'whole_cli_native': False, 'production_legacy_retired': False,
}
with OUT.open('x', encoding='utf-8') as stream:
    stream.write(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps({'status': report['status'], 'report': str(OUT), 'pin': pin(OUT)[0],
                  'methods': 43, 'events': 86, 'subtests': 493, 'source_files': 3187}, sort_keys=True))
