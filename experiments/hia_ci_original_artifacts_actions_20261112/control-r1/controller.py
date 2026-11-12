"""Prepare, own, and retain a fixed read-only historical-artifact operation."""
from __future__ import annotations

from hashlib import sha256
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

REPO = 'TrillionniumFoundation/Hepta'
TOKEN_VARIABLE = 'HIA_CUSTODY_GITHUB_TOKEN'
CHUNK = 1 << 20
MAX_PUBLIC_BYTES = 480 << 20
MAX_PUBLIC_FILES = 64
NATURAL_EVENTS = {'qualification_started', 'owned_child_observed',
                  'qualification_exit_observed', 'owned_child_reaped'}


class Refusal(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise Refusal(message)


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def read(path, maximum=8 << 20, expected=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and before.st_size <= maximum,
                'bounded owned single-link original required')
        raw = stream.read(maximum + 1)
        require(len(raw) == before.st_size
                and identity(before) == identity(os.fstat(stream.fileno()))
                and identity(before) == identity(Path(path).lstat()), 'input identity changed')
    require(expected is None or sha256(raw).hexdigest() == expected, 'input SHA differs')
    return raw


def file_record(path, maximum=MAX_PUBLIC_BYTES, *, system_binary=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum,
                'bounded regular file required')
        if system_binary:
            require(before.st_uid in (0, os.geteuid()) and before.st_nlink >= 1
                    and not stat.S_IMODE(before.st_mode) & 0o022,
                    'immutable runner tool identity required')
        else:
            require(before.st_uid == os.geteuid() and before.st_nlink == 1,
                    'owned single-link retained file required')
        count, digest = 0, sha256()
        while True:
            block = stream.read(CHUNK)
            if not block:
                break
            count += len(block)
            require(count <= before.st_size, 'input grew')
            digest.update(block)
        require(count == before.st_size
                and identity(before) == identity(os.fstat(stream.fileno()))
                and identity(before) == identity(Path(path).lstat()), 'input changed during full read')
    return {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest(),
            'identity': list(identity(before))}


def create(path, raw, mode=0o400):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def document(path, maximum=8 << 20):
    raw = read(path, maximum)
    value = json.loads(raw)
    require(type(value) is dict, 'original JSON object required')
    return value, {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def policy_and_context(args):
    control = Path(__file__).resolve().parent
    raw = read(control / 'policy.json', 1 << 20, args.policy_sha256)
    policy = json.loads(raw)
    require(policy.get('schema') == 'hia.actions.elf-original-custody-policy.v1'
            and policy.get('repository') == REPO
            and re.fullmatch(r'[0-9a-f]{40}', args.control_commit) is not None,
            'fixed policy/commit differs')
    require(Path(sys.executable).resolve().is_file() and sys.version_info[:3] == (3, 14, 4),
            'fixed control interpreter version differs')
    checkout = Path(os.environ['GITHUB_WORKSPACE']).resolve() / 'control'
    require(control == checkout / policy['control_prefix']
            and read(checkout / '.git/HEAD', 256).decode().strip() == args.control_commit,
            'exact detached control checkout differs')
    event_raw = read(Path(os.environ['GITHUB_EVENT_PATH']), 1 << 20)
    event = json.loads(event_raw)
    require(os.environ.get('GITHUB_REPOSITORY') == REPO
            and os.environ.get('GITHUB_EVENT_NAME') == 'create'
            and os.environ.get('GITHUB_RUN_ATTEMPT') == '1'
            and event.get('ref_type') == 'branch'
            and event.get('ref') == policy['trigger_branch']
            and event.get('repository', {}).get('full_name') == REPO
            and os.environ.get('GITHUB_REF') == 'refs/heads/' + policy['trigger_branch'],
            'unique create event or original attempt differs')
    workflow_sha = os.environ.get('HIA_CUSTODY_WORKFLOW_SHA')
    require(re.fullmatch(r'[0-9a-f]{40}', os.environ.get('GITHUB_SHA', '')) is not None
            and workflow_sha == os.environ['GITHUB_SHA'], 'actual workflow commit differs')
    source_records = {}
    for name, pin in policy['control_files'].items():
        require(re.fullmatch(r'[A-Za-z0-9_.-]+', name) is not None, 'unsafe control name')
        value = read(control / name, 1 << 20, pin['sha256'])
        require(len(value) == pin['bytes'], 'control size differs')
        source_records[str(control / name)] = pin['sha256']
    source_records[str(control / 'policy.json')] = sha256(raw).hexdigest()
    for name, pin in policy['unchanged_original_workflows'].items():
        value = read(checkout / name, 1 << 20, pin['sha256'])
        require(len(value) == pin['bytes'], 'original workflow size differs')
        source_records[str(checkout / name)] = pin['sha256']
    temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    root = temp / policy['work_root_name']
    public = temp / policy['public_root_name']
    require(args.root.is_absolute() and args.root == root
            and not any(x.is_symlink() for x in (temp, *temp.parents)),
            'new runner root or ancestor differs')
    context = {'schema': 'hia.actions.elf-original-custody-context.v1',
        'repository': REPO, 'event': 'create', 'event_ref': event['ref'], 'event_ref_type': 'branch',
        'event_sha256': sha256(event_raw).hexdigest(), 'run_attempt': 1,
        'run_id': int(os.environ['GITHUB_RUN_ID']), 'run_number': int(os.environ['GITHUB_RUN_NUMBER']),
        'actual_workflow_commit': workflow_sha, 'actual_control_checkout': args.control_commit,
        'original_product_commit': policy['source']['head'], 'original_product_tree': policy['source']['tree'],
        'policy_sha256': args.policy_sha256, 'root': str(root), 'public_root': str(public),
        'python': {'executable': sys.executable, 'resolved': str(Path(sys.executable).resolve()),
                   'version': sys.version, 'binary': file_record(Path(sys.executable).resolve(), 64 << 20, system_binary=True)},
        'control_sources': source_records, 'token_or_signed_URL_in_context': False,
        'qualification_executed': False}
    return control, policy, raw, root, public, context


def prepare(args):
    require(TOKEN_VARIABLE not in os.environ, 'read token entered preparation')
    control, policy, raw, root, public, context = policy_and_context(args)
    require(not os.path.lexists(root) and not os.path.lexists(public), 'new custody roots already exist')
    capacity = os.statvfs(root.parent)
    require(capacity.f_bavail * capacity.f_frsize >= 8 << 30 and capacity.f_favail >= 100000,
            'original storage reserve unavailable')
    os.umask(0o077)
    root.mkdir(mode=0o700, exist_ok=False)
    for name in ('control', 'guard', 'original', 'selected', 'api'):
        (root / name).mkdir(mode=0o700, exist_ok=False)
    identities = dict(context['control_sources'])
    for name, pin in policy['control_files'].items():
        value = read(control / name, 1 << 20, pin['sha256'])
        target = root / 'control' / name
        create(target, value)
        require(read(target, 1 << 20, pin['sha256']) == value, 'control copy readback differs')
        identities[str(target)] = pin['sha256']
    create(root / 'control/policy.json', raw)
    identities[str(root / 'control/policy.json')] = args.policy_sha256
    create(root / 'context.json', wire(context))
    identities[str(root / 'context.json')] = sha256(wire(context)).hexdigest()
    identities[context['python']['resolved']] = context['python']['binary']['sha256']
    command = [context['python']['resolved'], '-I', '-S', '-B',
               str(root / 'control/worker.py'), '--root', str(root),
               '--policy-sha256', args.policy_sha256]
    config = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 900,
              'command': command, 'cwd': str(root), 'source_identities': identities}
    config_raw = wire(config)
    create(root / 'guard/request.json', config_raw)
    setup = {'schema': 'hia.actions.elf-original-custody-setup.v1',
        'status': 'PREPARED_NOT_EXECUTED', 'context': context,
        'guardian_config_sha256': sha256(config_raw).hexdigest(),
        'source_identities': identities, 'command': command,
        'controller_seconds': 900, 'cleanup_seconds': 3,
        'capacity_before': {'free_bytes': capacity.f_bavail * capacity.f_frsize,
                            'free_inodes': capacity.f_favail},
        'token_received': False, 'project_code_executed': False}
    create(root / 'setup.json', wire(setup))
    for directory in (root / 'control', root / 'guard', root, root.parent):
        sync_dir(directory)
    print(json.dumps({'status': setup['status'], 'root': str(root),
                      'policy_sha256': args.policy_sha256,
                      'setup_sha256': sha256(wire(setup)).hexdigest()}), flush=True)
    return 0


def run(args):
    control, policy, _, root, _, context = policy_and_context(args)
    require(type(os.environ.get(TOKEN_VARIABLE)) is str and bool(os.environ[TOKEN_VARIABLE]),
            'Actions read token absent from owned collection step')
    setup, _ = document(root / 'setup.json')
    require(setup.get('context') == context and setup.get('controller_seconds') == 900
            and setup.get('cleanup_seconds') == 3, 'original setup context differs')
    config_raw = read(root / 'guard/request.json', 1 << 20, setup['guardian_config_sha256'])
    for path, expected in setup['source_identities'].items():
        require(file_record(Path(path), 64 << 20,
                            system_binary=path == context['python']['resolved'])['sha256'] == expected, 'fixed input changed before ownership')
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(('HEPTA_HIA_', 'GIT_', 'PYTHON'))
           and k not in {'GITHUB_TOKEN', 'GH_TOKEN', 'LD_PRELOAD', 'LD_LIBRARY_PATH'}}
    env.update(PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1')
    for descriptor, name in ((1, 'supervisor.stdout.log'), (2, 'supervisor.stderr.log')):
        fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        os.dup2(fd, descriptor)
        if fd != descriptor:
            os.close(fd)
    os.chdir(root)
    python = context['python']['resolved']
    os.execve(python, [python, '-I', '-S', '-B', str(root / 'control/guardian.py'),
                      '--config', str(root / 'guard/request.json'),
                      '--config-sha256', sha256(config_raw).hexdigest(),
                      '--implementation', str(root / 'control/process_owner_impl.py')], env)


def closed_guardian(value):
    life = value.get('lifecycle', {})
    cleanup = life.get('cleanup', {})
    return (cleanup.get('attempted') is True and cleanup.get('complete') is True
            and cleanup.get('observed_echild') is True and cleanup.get('leader_reaped') is True
            and cleanup.get('deadline_exceeded') is False
            and cleanup.get('errors') == [] and cleanup.get('remaining_direct_children') == [])


def natural_guardian(value, setup, policy, root):
    life = value.get('lifecycle', {})
    events = life.get('events', [])
    require(value.get('schema') == 'hepta.hia.external-qualification-guardian.v1'
            and value.get('status') == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
            and value.get('external_controller_seconds') == 900
            and value.get('lifecycle_implementation_sha256') ==
                policy['control_files']['process_owner_impl.py']['sha256']
            and value.get('command') == setup['command'] and value.get('cwd') == str(root)
            and value.get('source_identities_before') == setup['source_identities']
            and value.get('source_identities_after') == setup['source_identities']
            and value.get('input_identity_preserved') is True,
            'natural guardian input/command identity differs')
    require(life.get('schema') == 'hepta.hia.external-qualification-guardian.v1.lifecycle'
            and life.get('subreaper_enabled') is True and life.get('qualification_started') is True
            and life.get('status') == 'OWNED_PROCESS_COMPLETED' and life.get('returncode') == 0
            and life.get('qualification_seconds') == 900 and life.get('cleanup_seconds') == 3
            and life.get('timed_out') is False and life.get('exit_observed_before_deadline') is True
            and life.get('event_overflow') is False and life.get('interrupted_signals') == []
            and life.get('owner_error') is None and closed_guardian(value), 'natural lifecycle incomplete')
    require(type(events) is list and events
            and all(x.get('kind') in NATURAL_EVENTS for x in events)
            and {'qualification_started', 'qualification_exit_observed', 'owned_child_reaped'}
                <= {x.get('kind') for x in events}, 'non-natural lifecycle event')
    logs = {str(root / 'guard' / n): file_record(root / 'guard' / n, 8 << 20)['sha256']
            for n in ('child.stdout.log', 'child.stderr.log')}
    require(value.get('logs') == logs, 'original child log identity differs')


def accept_worker(report, policy, setup):
    require(report.get('schema') == 'hia.actions.elf-original-custody-worker.v1'
            and report.get('status') == 'TWO_ORIGINALS_RETAINED_PENDING_NATURAL_GUARDIAN'
            and report.get('policy_sha256') == setup['context']['policy_sha256']
            and report.get('root') == setup['context']['root']
            and report.get('source') == policy['source'], 'worker identity or terminal status differs')
    for key in ('qualification_executed', 'project_code_executed', 'old_runs_replayed',
                'original_product_statuses_reclassified', 'unselected_inner_phase_ZIPs_replayed',
                'source_file_payloads_independently_read', 'token_or_signed_URL_recorded'):
        require(report.get(key) is False, 'custody-only worker scope differs')
    calls, gets, items = report.get('API_attempts'), report.get('GET_attempts'), report.get('artifacts')
    require(type(calls) is list and len(calls) == 4 and type(gets) is list and len(gets) == 2
            and type(items) is list and len(items) == 2, 'complete original operation denominator differs')
    original = json.loads(read(Path(setup['context']['root']) / 'control/artifact-pins.json', 1 << 20,
                               policy['control_files']['artifact-pins.json']['sha256']))
    for index, (pin, get, item) in enumerate(zip(policy['artifacts'], gets, items, strict=True)):
        api = calls[index * 2:index * 2 + 2]
        require([x.get('role') for x in api] == ['official_metadata', 'official_download_redirect']
                and all(x.get('artifact_id') == pin['id'] and x.get('attempt') == 1
                        and x.get('retries') == 0 and x.get('host') == 'api.github.com'
                        and x.get('credential_sent_only_to_official_API') is True for x in api)
                and api[0].get('status') == 200 and api[1].get('status') == 302
                and api[1].get('authorization_forwarded') is False
                and api[1].get('signed_Location_recorded') is False, 'official API credential/attempt binding differs')
        require(get.get('artifact_id') == pin['id'] and get.get('attempt') == 1
                and get.get('redirects') == 0 and get.get('retries') == 0
                and get.get('authorization_sent') is False and get.get('cookies_sent') is False
                and get.get('bytes') == pin['bytes'] and get.get('sha256') == pin['sha256'],
                'single anonymous original GET binding differs')
        before, after = item.get('zip_before'), item.get('zip_after')
        require(item.get('artifact') == pin and type(before) is dict and before == after
                and before.get('bytes') == pin['bytes'] and before.get('sha256') == pin['sha256']
                and before.get('actual_bytes_independently_read') == pin['bytes'],
                'two full original ZIP reads differ')
        names, missing = item.get('selected_member_names'), item.get('missing_requested_members')
        require(type(names) is list and type(missing) is list and len(set(names)) == len(names)
                and len(set(missing)) == len(missing) and not set(names).intersection(missing)
                and set(names) | set(missing) == set(original['selected_members'])
                and names == [n for n in original['selected_members'] if n not in missing]
                and set(original['required_members']) <= set(names)
                and item.get('requested_member_count') == 17
                and item.get('selected_member_count') == len(names), '17-member present/missing accounting differs')
        custody = item.get('selected_custody', {})
        require(custody.get('member_count') == len(names) + 2
                and custody.get('all_member_SHA_and_CRC_verified') is True
                and custody.get('raw_files_included_without_transformation') is True,
                'selected original archive full readback differs')
        header = item.get('header_observations', {})
        require(header.get('source_manifest_matches_canonical_mapping') is True
                and header.get('canonical_source_manifest_sha256') ==
                    policy['source']['source_manifest_canonical_sha256']
                and header.get('original_statuses_reclassified') is False
                and header.get('original_checks_independently_rerun') is False,
                'original source-bound header observations differ')


def copy_original(source, target, expected):
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    with os.fdopen(source_fd, 'rb') as incoming, os.fdopen(target_fd, 'wb') as outgoing:
        before = os.fstat(incoming.fileno())
        require(list(identity(before)) == expected['identity'], 'retained input changed before copying')
        count, digest = 0, sha256()
        while True:
            block = incoming.read(CHUNK)
            if not block:
                break
            count += len(block)
            require(count <= expected['bytes'], 'retained input grew')
            outgoing.write(block)
            digest.update(block)
        require(count == expected['bytes'] and digest.hexdigest() == expected['sha256']
                and identity(before) == identity(os.fstat(incoming.fileno()))
                and identity(before) == identity(source.lstat()), 'retained input changed during copying')
        outgoing.flush()
        os.fsync(outgoing.fileno())
    observed = file_record(target)
    require(observed['bytes'] == expected['bytes'] and observed['sha256'] == expected['sha256'],
            'independent retained copy readback differs')
    return observed


def fixed_capture_paths(root, policy):
    names = ['context.json', 'setup.json', 'recovery.json', 'recovery-terminal.json',
             'supervisor.stdout.log', 'supervisor.stderr.log',
             'guard/request.json', 'guard/guardian.json',
             'guard/child.stdout.log', 'guard/child.stderr.log']
    for pin in policy['artifacts']:
        aid = str(pin['id'])
        names.append('api/artifact-' + aid + '.metadata.original.json')
        folder = root / 'selected' / aid
        names.extend('selected/' + aid + '/' + n for n in
                     ('DIRECTORY.json', 'SELECTED.json', 'CUSTODY.json', 'OBSERVATIONS.json'))
        if os.path.lexists(folder / 'selected-originals.zip'):
            names.append('selected/' + aid + '/selected-originals.zip')
        else:
            # If the original worker failed before closing a selected archive,
            # preserve the bounded raw partials without claiming member validity.
            names.extend('selected/' + aid + '/%04d.raw' % i for i in range(17))
    require(len(names) == len(set(names)) and len(names) <= MAX_PUBLIC_FILES, 'capture allowlist differs')
    require(not any(n.startswith(('original/', 'control/')) for n in names), 'large ZIP/control leakage')
    return names


def finalize(args):
    require(TOKEN_VARIABLE not in os.environ, 'read token entered finalization')
    _, policy, _, root, public, context = policy_and_context(args)
    require(not os.path.lexists(public), 'new public capture directory already exists')
    os.umask(0o077)
    public.mkdir(mode=0o700, exist_ok=False)
    final = {'schema': 'hia.actions.elf-original-custody-final.v1',
        'status': 'CUSTODY_HOLD', 'context': context,
        'artifacts': policy['artifacts'], 'captured': [], 'missing_capture_paths': [],
        'original_600MB_ZIPs_included': False, 'token_or_signed_URL_included': False,
        'qualification_executed': False, 'project_code_executed': False,
        'original_product_statuses_reclassified': False, 'original_CI_rerun': False,
        'maximum_public_payload_bytes': MAX_PUBLIC_BYTES, 'capture_complete': False,
        'large_original_ZIPs_only_ephemeral_runner_custody': True}
    errors = []
    try:
        setup, setup_record = document(root / 'setup.json')
        require(setup.get('context') == context, 'final context differs')
        guardian, guardian_record = document(root / 'guard/guardian.json')
        require(closed_guardian(guardian), 'no closed ECHILD boundary; do not read possible live child originals')
        final['setup_original'] = setup_record
        final['guardian_original'] = guardian_record
        final['cleanup_closed_before_capture'] = True
        try:
            config_raw = read(root / 'guard/request.json', 1 << 20, setup['guardian_config_sha256'])
            config = json.loads(config_raw)
            require(config.get('source_identities') == setup['source_identities']
                    and config.get('command') == setup['command']
                    and config.get('controller_seconds') == 900 and 'expected_qualification' not in config,
                    'original guardian config differs')
            natural_guardian(guardian, setup, policy, root)
            for path, wanted in setup['source_identities'].items():
                require(file_record(Path(path), 64 << 20,
                                    system_binary=path == setup['context']['python']['resolved'])['sha256'] == wanted,
                        'frozen input changed at final readback')
            report, report_record = document(root / 'recovery-terminal.json', 16 << 20)
            accept_worker(report, policy, setup)
            final['worker_original'] = report_record
            final['selected_original_member_accounting'] = [
                {'artifact_id': x['artifact']['id'], 'present': x['selected_member_names'],
                 'missing': x['missing_requested_members'], 'selected_custody': x['selected_custody']}
                for x in report['artifacts']]
            final['source_bound_originals_and_natural_owner_accepted'] = True
        except BaseException as error:
            errors.append({'stage': 'ACCEPTANCE', 'type': type(error).__name__,
                           'safe_refusal': str(error) if type(error) is Refusal else None})
            final['source_bound_originals_and_natural_owner_accepted'] = False
        candidates = []
        for name in fixed_capture_paths(root, policy):
            source = root / name
            if not os.path.lexists(source):
                final['missing_capture_paths'].append(name)
                continue
            record = file_record(source)
            candidates.append((name, source, record))
        require(len(candidates) <= MAX_PUBLIC_FILES
                and sum(x[2]['bytes'] for x in candidates) <= MAX_PUBLIC_BYTES - (1 << 20),
                'selected public originals exceed small-artifact budget; do not include large ZIPs')
        for index, (name, source, record) in enumerate(candidates):
            output_name = '%03d.original' % index
            observed = copy_original(source, public / output_name, record)
            final['captured'].append({'source_relative_path': name, 'retained_file': output_name,
                'bytes': observed['bytes'], 'sha256': observed['sha256'],
                'source_identity': record['identity'], 'independent_copy_readback': True})
        final['capture_complete'] = True
        if not errors and final.get('source_bound_originals_and_natural_owner_accepted') is True:
            final['status'] = 'TWO_HISTORICAL_CI_ORIGINALS_SMALL_CUSTODY_READY_NOT_QUALIFICATION'
    except BaseException as error:
        errors.append({'stage': 'CAPTURE', 'type': type(error).__name__,
                       'safe_refusal': str(error) if type(error) is Refusal else None})
    final['errors'] = errors
    final['actual_public_original_bytes'] = sum(x['bytes'] for x in final['captured'])
    raw = wire(final)
    require(len(raw) <= 1 << 20, 'bounded public receipt required')
    create(public / 'FINAL.json', raw)
    actual = [file_record(x) for x in public.iterdir()]
    require(len(actual) <= MAX_PUBLIC_FILES + 1
            and sum(x['bytes'] for x in actual) <= MAX_PUBLIC_BYTES, 'public artifact boundary exceeded')
    # ZIP metadata for at most65 short fixed filenames is far smaller than the
    # retained32MiB margin below the connector's512MiB original-artifact limit.
    sync_dir(public)
    sync_dir(public.parent)
    print(json.dumps({'status': final['status'], 'public_root': str(public),
        'public_files': len(actual), 'public_bytes': sum(x['bytes'] for x in actual),
        'receipt_sha256': sha256(raw).hexdigest(),
        'original_product_statuses_reclassified': False, 'qualification_executed': False}), flush=True)
    return 0 if final['status'] == 'TWO_HISTORICAL_CI_ORIGINALS_SMALL_CUSTODY_READY_NOT_QUALIFICATION' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'run', 'finalize'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--control-commit', required=True)
    args = parser.parse_args()
    return {'prepare': prepare, 'run': run, 'finalize': finalize}[args.operation](args)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Refusal as error:
        print(json.dumps({'status': 'CONTROL_HOLD', 'safe_refusal': str(error)}), flush=True)
        raise SystemExit(1)
