"""Read-only final custody acceptance; no project imports or child execution."""
from hashlib import sha256
import json
import os
from pathlib import Path
import stat

ROOT = Path('/home/qian-qi/he26-e8-ci-originals-r1')
KEY = 'hia-e26e-desktop-e8-two-ci-originals-recovery-r1'
PYTHON = '/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python'
PIN_SHA = 'e059ee85f8c9d56fff90582484e0587fdb6dea6064695b5b90c313f774d9dfc0'
OWNER_SHA = '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
PYTHON_REAL = '/home/qian-qi/hia-e26e-python314-linux-r1/install/bin/python3.14'
PYTHON_SHA = 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'
FIXED = {
    'artifact-pins.json': PIN_SHA,
    'guardian.py': 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023',
    'process_owner_impl.py': OWNER_SHA,
    'recover_ci_originals.py': '685476ed4637759898b02d4ca620462922a03c35a7329e21971bf6fbfc2802cd',
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
    require(report.get('schema') == 'hia.e8.two-original-CI-recovery.v1'
            and report.get('status') == 'ORIGINALS_AND_SELECTED_REPORTS_VERIFIED_PENDING_NATURAL_GUARDIAN'
            and report.get('stable_key') == KEY and report.get('root') == str(ROOT)
            and report.get('pins_sha256') == PIN_SHA, 'original recovery report differs')
    for key in ('qualification_executed', 'project_code_executed', 'old_runs_replayed',
                'unselected_inner_stage_binaries_independently_replayed'):
        require(report.get(key) is False, 'scope differs')
    life = guardian.get('lifecycle', {})
    cleanup = life.get('cleanup', {})
    events = life.get('events')
    require(guardian.get('schema') == 'hepta.hia.external-qualification-guardian.v1'
            and guardian.get('status') == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
            and guardian.get('external_controller_seconds') == 900
            and guardian.get('cold_180_second_gate_modified') is False
            and guardian.get('lifecycle_implementation_sha256') == OWNER_SHA
            and guardian.get('command') == [PYTHON, '-I', '-S', '-B', str(ROOT / 'control/recover_ci_originals.py')]
            and guardian.get('cwd') == str(ROOT)
            and guardian.get('input_identity_preserved') is True
            and guardian.get('source_identities_before') == guardian.get('source_identities_after'),
            'external guardian identity differs')
    require(life.get('schema') == 'hepta.hia.external-qualification-guardian.v1.lifecycle'
            and life.get('subreaper_enabled') is True and life.get('qualification_started') is True
            and life.get('status') == 'OWNED_PROCESS_COMPLETED' and life.get('returncode') == 0
            and life.get('qualification_seconds') == 900 and life.get('cleanup_seconds') == 3
            and life.get('exit_observed_before_deadline') is True
            and life.get('timed_out') is False and life.get('event_overflow') is False
            and life.get('interrupted_signals') == [] and life.get('owner_error') is None,
            'owned custody process did not complete naturally')
    require(cleanup.get('attempted') is True and cleanup.get('complete') is True
            and cleanup.get('observed_echild') is True and cleanup.get('leader_reaped') is True
            and cleanup.get('deadline_exceeded') is False and cleanup.get('errors') == []
            and cleanup.get('remaining_direct_children') == [], 'custody cleanup is incomplete')
    require(type(events) is list and events
            and all(x.get('kind') in NATURAL_EVENTS for x in events)
            and {'qualification_started', 'qualification_exit_observed', 'owned_child_reaped'}
                <= {x.get('kind') for x in events}, 'non-natural lifecycle event')
    expected = pins['artifacts']
    attempts, artifacts = report.get('GET_attempts'), report.get('artifacts')
    require(type(attempts) is list and type(artifacts) is list
            and len(attempts) == len(artifacts) == len(expected) == 2, 'two originals required')
    for pin, attempt, item in zip(expected, attempts, artifacts, strict=True):
        require(attempt.get('artifact_id') == pin['id'] and attempt.get('attempt') == 1
                and attempt.get('retries') == 0 and attempt.get('redirects') == 0
                and attempt.get('bytes') == pin['bytes'] and attempt.get('sha256') == pin['sha256'],
                'actual one-GET binding differs')
        before, after = item.get('zip_before'), item.get('zip_after')
        require(type(before) is dict and before == after
                and before.get('path') == str(ROOT / 'original' / ('artifact-%d.zip' % pin['id']))
                and before.get('bytes') == pin['bytes'] and before.get('sha256') == pin['sha256']
                and before.get('actual_bytes_independently_read') == pin['bytes'],
                'two original full readbacks differ')
        require(item.get('artifact') == pin and item.get('selected_member_count') == pins['selected_count']
                and item.get('inner_phase_ZIPs_replayed') is False
                and item.get('project_code_executed') is False, 'selected custody scope differs')
        custody = item.get('selected_custody', {})
        require(custody.get('member_count') == pins['selected_count'] + 2
                and custody.get('all_member_SHA_and_CRC_verified') is True
                and custody.get('raw_files_included_without_transformation') is True,
                'selected archive readback incomplete')
    return True


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
    require(private.get('schema') == 'hia.e8.ci-original-private-request.v1'
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
            and config.get('command') == [PYTHON, '-I', '-S', '-B', str(ROOT / 'control/recover_ci_originals.py')]
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
    accept(report, guardian, pins)
    print(json.dumps({'schema': 'hia.e8.CI-original-custody-acceptance.v1',
        'status': 'TWO_ORIGINAL_ZIPS_AND_SELECTED_REPORTS_RETAINED_NOT_QUALIFICATION',
        'report': report_record, 'guardian': guardian_record, 'guardian_request': config_record,
        'artifact_ids': [x['id'] for x in pins['artifacts']],
        'scope': 'Exact ZIP bytes plus selected JSON raw bytes and full ZIP directory metadata',
        'unselected_inner_phase_archives_replayed': False, 'qualification_executed': False},
        sort_keys=True))


if __name__ == '__main__':
    main()
