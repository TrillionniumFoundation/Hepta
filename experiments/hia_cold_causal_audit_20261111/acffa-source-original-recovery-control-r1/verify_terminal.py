"""Read-only final custody acceptance; no project imports or child execution."""
from hashlib import sha256
import json
import os
from pathlib import Path
import stat

ROOT = Path('/home/qian-qi/he26stackv9-source-original-r1')
KEY = 'hia-e26e-desktop-acffa-source-original-recovery-r1'
PYTHON = '/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python'
PIN_SHA = '6948cf7f54d74533237baf2c48d3eccf560ed155f53406f9a0160dcc83acf2f0'
OWNER_SHA = '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
PYTHON_REAL = '/home/qian-qi/hia-e26e-python314-linux-r1/install/bin/python3.14'
PYTHON_SHA = 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'
FIXED = {
    'artifact-pins.json': PIN_SHA,
    'guardian.py': 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023',
    'process_owner_impl.py': OWNER_SHA,
    'recover_source_original.py': 'a5b1f23cc7f3a1a1c845077974c482bfd51ece60cb618d59cb73c5a7666f55d3',
}
NATURAL_EVENTS = {'qualification_started', 'owned_child_observed',
                  'qualification_exit_observed', 'owned_child_reaped'}


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path, maximum=8 << 20):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and before.st_size <= maximum,
                'regular bounded original required')
        data = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                  'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(len(data) == before.st_size and
                tuple(getattr(before, k) for k in fields) ==
                tuple(getattr(after, k) for k in fields) ==
                tuple(getattr(Path(path).lstat(), k) for k in fields), 'read identity changed')
    return data


def document(path):
    raw = read(path)
    value = json.loads(raw)
    require(type(value) is dict, 'JSON object required')
    return value, {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def accept(report, guardian, pins):
    require(report.get('schema') == 'hia.stack-source-original-recovery.v1'
            and report.get('status') == 'SOURCE_ORIGINAL_AND_ALL_EIGHT_MEMBERS_VERIFIED_PENDING_NATURAL_GUARDIAN'
            and report.get('stable_key') == KEY and report.get('root') == str(ROOT)
            and report.get('pins_sha256') == PIN_SHA, 'original source recovery report differs')
    for key in ('qualification_executed', 'project_code_executed', 'old_runs_replayed',
                'source_pack_objects_imported_or_reconstructed', 'source_package_program_executed',
                'consumer_clone_prerequisites_or_tests_requested'):
        require(report.get(key) is False, 'custody-only scope differs')
    life = guardian.get('lifecycle', {})
    cleanup = life.get('cleanup', {})
    events = life.get('events')
    require(guardian.get('schema') == 'hepta.hia.external-qualification-guardian.v1'
            and guardian.get('status') == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
            and guardian.get('external_controller_seconds') == 900
            and guardian.get('cold_180_second_gate_modified') is False
            and guardian.get('lifecycle_implementation_sha256') == OWNER_SHA
            and guardian.get('command') == [PYTHON, '-I', '-S', '-B', str(ROOT / 'control/recover_source_original.py')]
            and guardian.get('cwd') == str(ROOT)
            and guardian.get('input_identity_preserved') is True
            and guardian.get('source_identities_before') == guardian.get('source_identities_after'),
            'external guardian identity differs')
    require(life.get('schema') == 'hepta.hia.external-qualification-guardian.v1.lifecycle'
            and life.get('subreaper_enabled') is True and life.get('qualification_started') is True
            and life.get('status') == 'OWNED_PROCESS_COMPLETED' and life.get('returncode') == 0
            and life.get('qualification_seconds') == 900 and life.get('cleanup_seconds') == 3
            and life.get('exit_observed_before_deadline') is True and life.get('timed_out') is False
            and life.get('event_overflow') is False and life.get('interrupted_signals') == []
            and life.get('owner_error') is None, 'source custody process did not close naturally')
    require(cleanup.get('attempted') is True and cleanup.get('complete') is True
            and cleanup.get('observed_echild') is True and cleanup.get('leader_reaped') is True
            and cleanup.get('deadline_exceeded') is False and cleanup.get('errors') == []
            and cleanup.get('remaining_direct_children') == [], 'custody cleanup incomplete')
    require(type(events) is list and events and all(x.get('kind') in NATURAL_EVENTS for x in events)
            and {'qualification_started', 'qualification_exit_observed', 'owned_child_reaped'}
                <= {x.get('kind') for x in events}, 'non-natural lifecycle event')
    pin = pins['artifact']
    attempts, artifacts = report.get('GET_attempts'), report.get('artifacts')
    require(type(attempts) is list and type(artifacts) is list
            and len(attempts) == len(artifacts) == 1, 'one original artifact required')
    attempt, item = attempts[0], artifacts[0]
    require(attempt.get('artifact_id') == pin['id'] and attempt.get('attempt') == 1
            and attempt.get('retries') == 0 and attempt.get('redirects') == 0
            and attempt.get('bytes') == pin['bytes'] and attempt.get('sha256') == pin['sha256'],
            'single actual GET identity differs')
    before, after = item.get('zip_before'), item.get('zip_after')
    require(type(before) is dict and before == after
            and before.get('path') == str(ROOT / 'original' / ('artifact-%d.zip' % pin['id']))
            and before.get('bytes') == pin['bytes'] and before.get('sha256') == pin['sha256']
            and before.get('actual_bytes_independently_read') == pin['bytes'],
            'actual two complete ZIP reads differ')
    members = item.get('original_members')
    require(item.get('artifact') == pin and item.get('original_regular_member_count') == 8
            and item.get('all_original_regular_members_fully_read') is True
            and item.get('source_pack_objects_imported_or_reconstructed') is False
            and item.get('project_code_executed') is False
            and item.get('original_statuses_reclassified') is False
            and type(members) is list and len(members) == 8
            and {x.get('original_name') for x in members} == set(pins['members'])
            and all(x.get('actual_entire_member_read') is True and x.get('original_CRC_checked') is True
                    for x in members), 'full eight-member custody is incomplete')
    observed = item.get('source_observations', {})
    expected = pins['source']
    require(observed.get('head') == expected['commit'] and observed.get('tree') == expected['tree']
            and observed.get('manifest_sha256') == expected['manifest_sha256']
            and observed.get('original_Actions_reports_checked') is True
            and observed.get('original_Actions_reported_reconstruction_rerun_here') is False
            and observed.get('source_pack_objects_imported_or_reconstructed_here') is False
            and observed.get('qualification_executed') is False, 'original header observations differ')
    actual = {x['original_name']: {'bytes': x['bytes'], 'sha256': x['sha256']} for x in members}
    require(observed.get('exact_original_eight_member_pins') == actual
            and actual['package/source.pack'] ==
                {'bytes': expected['pack']['size'], 'sha256': expected['pack']['sha256']}
            and actual['package/manifest.json']['sha256'] == expected['manifest_sha256']
            and actual['package/source-package.py'] ==
                {'bytes': expected['consumer_bytes'], 'sha256': expected['consumer_sha256']}
            and observed.get('package_files') ==
                {name.removeprefix('package/'): row for name, row in actual.items() if name.startswith('package/')}
            and observed.get('receipt_files') ==
                {name: row for name, row in actual.items() if not name.startswith('package/')},
            'verified external source package pin mapping differs')
    require(item.get('actual_all_member_bytes_read') == sum(x['bytes'] for x in members),
            'actual full member byte denominator differs')
    custody = item.get('metadata_custody', {})
    require(item.get('retained_metadata_count') == 7 and custody.get('member_count') == 9
            and custody.get('all_member_SHA_and_CRC_verified') is True
            and custody.get('raw_files_included_without_transformation') is True,
            'seven original metadata files are not fully retained')
    return actual


def main():
    pins_raw = read(ROOT / 'control/artifact-pins.json')
    require(sha256(pins_raw).hexdigest() == PIN_SHA, 'fixed external pins differ')
    pins = json.loads(pins_raw)
    report, report_record = document(ROOT / 'recovery-terminal.json')
    guardian, guardian_record = document(ROOT / 'guard/guardian.json')
    private_raw = read(ROOT / 'control/request.private.json')
    private = json.loads(private_raw)
    controls = private.get('control_files')
    require(type(controls) is dict and set(controls) == set(FIXED) | {'bootstrap.py', 'verify_terminal.py'}
            and all(controls[name] == value for name, value in FIXED.items()),
            'fixed control population or identity differs')
    require(private.get('schema') == 'hia.stack-source-original-private-request.v1'
            and private.get('stable_key') == KEY
            and private.get('artifact_pins_sha256') == PIN_SHA
            and report.get('private_request_sha256') == sha256(private_raw).hexdigest(),
            'original private request binding differs')
    identities = {str(ROOT / 'control' / name): value for name, value in controls.items()}
    identities[str(ROOT / 'control/request.private.json')] = sha256(private_raw).hexdigest()
    stdin_raw = read(ROOT / 'control/bootstrap-stdin.private.json', maximum=1 << 20)
    identities[str(ROOT / 'control/bootstrap-stdin.private.json')] = sha256(stdin_raw).hexdigest()
    identities[PYTHON_REAL] = PYTHON_SHA
    for path, expected in identities.items():
        require(sha256(read(path, maximum=64 << 20)).hexdigest() == expected,
                'actual frozen input differs at acceptance')
    config, config_record = document(ROOT / 'guard/request.json')
    require(config.get('schema') == 'hia-external-guardian-request.v1'
            and config.get('controller_seconds') == 900
            and config.get('command') == [PYTHON, '-I', '-S', '-B', str(ROOT / 'control/recover_source_original.py')]
            and config.get('cwd') == str(ROOT) and config.get('source_identities') == identities
            and 'expected_qualification' not in config
            and guardian.get('source_identities_before') == identities
            and guardian.get('source_identities_after') == identities,
            'actual guardian config and full input inventory differ')
    expected_logs = {}
    for name in ('child.stdout.log', 'child.stderr.log'):
        path = ROOT / 'guard' / name
        expected_logs[str(path)] = sha256(read(path)).hexdigest()
    require(guardian.get('logs') == expected_logs, 'actual original child logs differ')
    members = accept(report, guardian, pins)
    item = report['artifacts'][0]
    print(json.dumps({'schema': 'hia.stack-source-original-custody-acceptance.v1',
        'status': 'EXACT_SOURCE_ARTIFACT_CUSTODY_READY_NOT_QUALIFICATION',
        'report': report_record, 'guardian': guardian_record, 'guardian_request': config_record,
        'head': pins['source']['commit'], 'tree': pins['source']['tree'],
        'artifact': pins['artifact'], 'original_archive': item['zip_after'],
        'manifest_sha256': pins['source']['manifest_sha256'],
        'exact_original_eight_member_pins': members,
        'package_files': item['source_observations']['package_files'],
        'receipt_files': item['source_observations']['receipt_files'],
        'metadata_custody': item['metadata_custody'],
        'source_pack_objects_imported_or_reconstructed_here': False,
        'qualification_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
