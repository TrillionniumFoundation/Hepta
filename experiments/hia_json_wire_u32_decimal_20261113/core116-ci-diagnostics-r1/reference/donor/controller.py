"""Deliver all available fixed step42 originals from one failed v92 CI ZIP; execute no product code."""
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
MAX_PUBLIC_BYTES = 320 << 20
MAX_DIAGNOSTIC_BYTES = 2 << 20
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
    fixed_policy(policy)
    require(policy.get('schema') == 'hia.actions.v92-ci-diagnostics-only-policy.v2'
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
    context = {'schema': 'hia.actions.v92-ci-diagnostics-only-context.v2',
        'repository': REPO, 'event': 'create', 'event_ref': event['ref'], 'event_ref_type': 'branch',
        'event_sha256': sha256(event_raw).hexdigest(), 'run_attempt': 1,
        'run_id': int(os.environ['GITHUB_RUN_ID']), 'run_number': int(os.environ['GITHUB_RUN_NUMBER']),
        'actual_workflow_commit': workflow_sha, 'actual_control_checkout': args.control_commit,
        'original_product_commit': policy['source']['head'], 'original_product_tree': policy['source']['tree'],
        'policy_sha256': args.policy_sha256, 'root': str(root), 'public_root': str(public),
        'python': {'executable': sys.executable, 'resolved': str(Path(sys.executable).resolve()),
                   'version': sys.version, 'binary': file_record(Path(sys.executable).resolve(), 64 << 20, system_binary=True)},
        'control_sources': source_records, 'token_or_signed_URL_in_context': False,
        'runner': {'requested_label': 'ubuntu-latest',
                   'actual_environment': {name: os.environ.get(name) for name in
                       ('RUNNER_OS', 'RUNNER_ARCH', 'ImageOS', 'ImageVersion')},
                   'uname': list(os.uname()),
                   'runtime_equivalence_to_original_CI_claimed': False},
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
    for name in ('control', 'guard', 'original', 'api'):
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
    setup = {'schema': 'hia.actions.v92-ci-diagnostics-only-setup.v2',
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
    check_setup(setup, context, policy, root)
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


def expected_setup_identities(context, policy, root):
    identities = dict(context['control_sources'])
    for name, pin in policy['control_files'].items():
        identities[str(root / 'control' / name)] = pin['sha256']
    identities[str(root / 'control/policy.json')] = context['policy_sha256']
    identities[str(root / 'context.json')] = sha256(wire(context)).hexdigest()
    identities[context['python']['resolved']] = context['python']['binary']['sha256']
    return identities


def check_setup(setup, context, policy, root):
    command = [context['python']['resolved'], '-I', '-S', '-B',
               str(root / 'control/worker.py'), '--root', str(root),
               '--policy-sha256', context['policy_sha256']]
    require(setup.get('schema') == 'hia.actions.v92-ci-diagnostics-only-setup.v2'
            and setup.get('status') == 'PREPARED_NOT_EXECUTED'
            and setup.get('context') == context and setup.get('command') == command
            and setup.get('source_identities') == expected_setup_identities(context, policy, root)
            and setup.get('controller_seconds') == 900 and setup.get('cleanup_seconds') == 3,
            'exact original setup identity differs')


def closed_guardian(value, setup, policy, root):
    # A cleanup-shaped dictionary from another operation is not a read boundary.
    # Failure or forced cleanup is permitted only for partial-custody HOLD.
    life = value.get('lifecycle', {})
    require(value.get('schema') == 'hepta.hia.external-qualification-guardian.v1'
            and value.get('command') == setup['command'] and value.get('cwd') == str(root)
            and value.get('external_controller_seconds') == 900
            and value.get('cold_180_second_gate_modified') is False
            and value.get('lifecycle_implementation_sha256') ==
                policy['control_files']['process_owner_impl.py']['sha256']
            and value.get('source_identities_before') == setup['source_identities']
            and life.get('schema') == 'hepta.hia.external-qualification-guardian.v1.lifecycle'
            and life.get('subreaper_enabled') is True and life.get('qualification_started') is True
            and life.get('qualification_seconds') == 900 and life.get('cleanup_seconds') == 3,
            'closed guardian is not this exact original owned operation')
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
            and life.get('owner_error') is None and closed_guardian(value, setup, policy, root), 'natural lifecycle incomplete')
    require(type(events) is list and events
            and all(x.get('kind') in NATURAL_EVENTS for x in events)
            and {'qualification_started', 'qualification_exit_observed', 'owned_child_reaped'}
                <= {x.get('kind') for x in events}, 'non-natural lifecycle event')
    logs = {str(root / 'guard' / n): file_record(root / 'guard' / n, 8 << 20)['sha256']
            for n in ('child.stdout.log', 'child.stderr.log')}
    require(value.get('logs') == logs, 'original child log identity differs')


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




def fixed_policy(policy):
    require(policy.get('schema') == 'hia.actions.v92-ci-diagnostics-only-policy.v2'
            and policy.get('status') == 'FROZEN_OFFICIAL_TRANSPORT_INPUTS_UNEXECUTED'
            and policy.get('input_pins_frozen') is True,
            'draft policy has no frozen official artifact identity; execution refused')
    pin = policy.get('artifact')
    require(type(pin) is dict
            and all(type(pin.get(name)) is int and 0 < pin[name] < 1 << 63
                    for name in ('id', 'run_id', 'job_id'))
            and type(pin.get('run_attempt')) is int and pin['run_attempt'] == 2
            and type(pin.get('sha256')) is str and re.fullmatch(r'[0-9a-f]{64}', pin['sha256'])
            and all(type(pin.get(name)) is str and re.fullmatch(r'[0-9a-f]{40}', pin[name])
                    for name in ('checkout_commit', 'checkout_tree'))
            and pin.get('event') in ('push', 'pull_request', 'create')
            and pin.get('workflow_terminal') in ('success', 'failure', 'cancelled', 'timed_out'),
            'complete original artifact identity is not frozen')
    require(policy.get('repository') == REPO
            and policy.get('limits') == {
                'controller_seconds': 900, 'cleanup_seconds': 3, 'transfer_seconds': 720,
                'maximum_original_bytes': 3 << 30, 'maximum_parts': 10,
                'part_bytes': 256 << 20, 'public_part_bytes': 320 << 20,
                'diagnostic_bytes_per_part': 2 << 20, 'document_bytes_per_part': 3 << 20,
                'private_metadata_reserve_bytes': 64 << 20,
                'minimum_free_bytes': 8 << 30, 'minimum_free_inodes': 100000},
            'original ownership or new bounded transport scope differs')
    source = policy.get('source')
    require(type(source) is dict and source.get('head') == pin['checkout_commit']
            and source.get('tree') == pin['checkout_tree']
            and type(source.get('cold_source_count')) is int and 0 < source['cold_source_count'] < 100000
            and all(type(source.get(name)) is str and re.fullmatch(r'[0-9a-f]{64}', source[name])
                    for name in ('contract_sha256', 'source_manifest_canonical_sha256'))
            and type(source.get('profile')) is str and 0 < len(source['profile']) <= 256,
            'source provenance identity differs')
    require(set(policy.get('control_files', {})) == {
        'controller.py', 'worker.py', 'guardian.py', 'process_owner_impl.py', 'original_receiver.py', 'diagnostics.py'},
        'fixed six custody controls differ')
    require(policy.get('proxy_policy') == 'USE_CONFIGURED_ENVIRONMENT_PROXIES'
            and policy.get('slice_publication') == 'NONE_DIAGNOSTICS_ONLY'
            and policy.get('diagnostic_publication') == 'RELOCATE_SAME_FILESYSTEM_AFTER_CLOSED_ECHILD'
            and policy.get('original_product_thresholds_changed') is False
            and policy.get('new_product_execution') is False,
            'transport credential, disk or product scope differs')
    require(type(pin.get('bytes')) is int and 0 < pin['bytes'] <= 3 << 30
            and policy.get('parts') == [] and policy.get('partition_files_created') is False,
            'this request permits no partition production or publication')
    require(policy.get('expected_diagnostics') == {'population': 'OBSERVE_CURRENT_COMPLETE_ZIP', 'selector_sha256': '50c1d07dd3a452ba189a8a87a06f49114da061a76256c9a69fa06391e5884831', 'metadata_files': 3},
            'fixed current-artifact selection declaration differs')
    return pin

def same_original_record(expected, actual):
    require(type(expected) is dict
            and all(expected.get(key) == actual[key] for key in ('path', 'bytes', 'sha256', 'identity'))
            and expected.get('actual_bytes_independently_read') == actual['bytes'],
            'actual original full read differs from worker receipt')


def accept_worker(report, policy, setup, root):
    pin = fixed_policy(policy)
    require(report.get('schema') == 'hia.actions.v92-ci-diagnostics-only-worker.v2'
            and report.get('status') == 'SEALED_DIAGNOSTICS_PENDING_NATURAL_GUARDIAN'
            and report.get('root') == str(root)
            and report.get('policy_sha256') == setup['context']['policy_sha256']
            and report.get('source') == policy['source'] and report.get('artifact') == pin
            and report.get('qualification_executed') is False
            and report.get('project_code_executed') is False
            and report.get('old_runs_replayed') is False
            and report.get('original_product_statuses_reclassified') is False
            and report.get('original_ZIP_member_inspection_started') is True
            and type(report.get('elapsed_ns')) is int and 0 <= report['elapsed_ns'] <= 720 * 1000000000
            and report.get('token_or_signed_URL_recorded') is False
            and report.get('natural_guardian_acceptance_required') is True
            and report.get('proxy_policy') == 'USE_CONFIGURED_ENVIRONMENT_PROXIES'
            and report.get('proxy_URLs_or_credentials_recorded') is False
            and report.get('partition_files_created') is False and 'partition' not in report,
            'worker complete diagnostic result or scope differs')
    apis = report.get('API_attempts', [])
    gets = report.get('GET_attempts', [])
    require(len(apis) == 2 and [x.get('role') for x in apis] ==
            ['official_metadata', 'official_download_redirect']
            and len(gets) == 1, 'exact original request denominator differs')
    for entry, suffix, status in zip(apis, ('', '/zip'), (200, 302)):
        require(entry.get('artifact_id') == pin['id'] and entry.get('method') == 'GET'
                and entry.get('host') == 'api.github.com'
                and entry.get('path') == '/repos/' + REPO + '/actions/artifacts/%d' % pin['id'] + suffix
                and entry.get('attempt') == 1 and entry.get('retries') == 0
                and entry.get('status') == status
                and entry.get('credential_sent_only_to_official_API') is True,
                'official request identity differs')
    require(apis[1].get('automatic_redirects') == 0
            and apis[1].get('signed_Location_recorded') is False
            and apis[1].get('authorization_forwarded') is False,
            'signed redirect credential boundary differs')
    get = gets[0]
    require(get.get('artifact_id') == pin['id'] and get.get('method') == 'GET'
            and get.get('attempt') == 1 and get.get('retries') == 0 and get.get('redirects') == 0
            and get.get('authorization_sent') is False and get.get('cookies_sent') is False
            and get.get('bytes') == pin['bytes'] and get.get('sha256') == pin['sha256']
            and get.get('output') == str(root / 'original' / ('artifact-%d.zip' % pin['id']))
            and get.get('socket_seconds') == 30,
            'single sealed storage GET result differs')
    metadata_path = root / 'api' / ('artifact-%d.metadata.original.json' % pin['id'])
    raw = read(metadata_path, 1 << 20)
    meta = json.loads(raw)
    require(meta.get('id') == pin['id'] and meta.get('size_in_bytes') == pin['bytes']
            and meta.get('digest') == 'sha256:' + pin['sha256'] and meta.get('expired') is False
            and meta.get('workflow_run', {}).get('id') == pin['run_id']
            and meta.get('workflow_run', {}).get('head_sha') == pin['checkout_commit']
            and meta.get('archive_download_url') ==
                'https://api.github.com/repos/' + REPO + '/actions/artifacts/%d/zip' % pin['id'],
            'actual provider metadata differs from external pins')
    meta_record = {'path': str(metadata_path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                   'artifact_id': pin['id'], 'run_id': pin['run_id'],
                   'provider_head_sha_observed': pin['checkout_commit']}
    require(report.get('official_metadata') == meta_record
            and apis[0].get('original_metadata') == meta_record,
            'actual metadata differs from worker identity')
    source = root / 'original' / ('artifact-%d.zip' % pin['id'])
    original = file_record(source, pin['bytes'])
    require(original['bytes'] == pin['bytes'] and original['sha256'] == pin['sha256']
            and stat.S_IMODE(original['identity'][2]) == 0o400,
            'independent original ZIP seal differs')
    same_original_record(report.get('zip_before'), original)
    same_original_record(report.get('zip_after'), original)
    return original




def relocate_diagnostic(root, public, name, expected):
    """Relocate one fixed diagnostic leaf after bound ECHILD, preserving bytes.

    The two namespaces are constructed here, not inferred from a generic
    slice name. All directory components below the two admitted private roots
    remain held, and all body reads use those descriptors. Failure never
    changes a file's permissions or fabricates a successful custody pin.
    """
    root, public = Path(root), Path(public)
    require(root.is_absolute() and public.is_absolute() and root.parent == public.parent
            and root != public and type(name) is str
            and (re.fullmatch(r'member-[0-9]{5}\.bin', name) is not None
                 or name in ('INDEX.json', 'DIRECTORY.jsonl', 'FULL-INVENTORY.jsonl')),
            'only a fixed diagnostic original may be relocated')
    source = root / 'diagnostics' / name
    target = public / 'small/originals' / name
    require(type(expected) is dict and expected.get('path') == str(source)
            and type(expected.get('bytes')) is int and 0 <= expected['bytes'] <= 64 << 20
            and type(expected.get('sha256')) is str
            and re.fullmatch('[0-9a-f]{64}', expected['sha256']) is not None
            and type(expected.get('identity')) is list and len(expected['identity']) == 9,
            'fixed diagnostic original record differs')
    held = []
    def directory(path, parent=None, component=None):
        fd = os.open(path if parent is None else component,
                     os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
        held.append((fd, path, parent, component, os.fstat(fd)))
        entry = held[-1][4]
        require(stat.S_ISDIR(entry.st_mode) and entry.st_uid == os.geteuid()
                and not stat.S_IMODE(entry.st_mode) & 0o077
                and entry.st_dev == expected['identity'][0],
                'diagnostic parents must be owned private directories on one device')
        return fd
    def stable_parents():
        for fd, path, parent, component, initial in held:
            observed = os.fstat(fd)
            named = path.lstat() if parent is None else os.stat(component, dir_fd=parent, follow_symlinks=False)
            require(all(getattr(observed, key) == getattr(named, key) == getattr(initial, key)
                        for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid')),
                    'diagnostic parent identity changed')
    def record_at(parent, path):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                    and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o400
                    and before.st_size == expected['bytes'], 'sealed diagnostic original identity differs')
            count, digest = 0, sha256()
            while True:
                block = stream.read(CHUNK)
                if not block:
                    break
                count += len(block)
                require(count <= expected['bytes'], 'diagnostic original grew during full read')
                digest.update(block)
            require(count == expected['bytes'] and digest.hexdigest() == expected['sha256']
                    and identity(before) == identity(os.fstat(stream.fileno()))
                    and identity(before) == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'diagnostic original changed during full read')
        return {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest(),
                'identity': list(identity(before))}
    try:
        rfd = directory(root)
        pfd = directory(public)
        sfd = directory(root / 'diagnostics', rfd, 'diagnostics')
        mfd = directory(public / 'small', pfd, 'small')
        tfd = directory(public / 'small/originals', mfd, 'originals')
        stable_parents()
        original = record_at(sfd, source)
        require(original == expected, 'diagnostic original changed before relocation')
        before = os.stat(name, dir_fd=sfd, follow_symlinks=False)
        os.link(name, name, src_dir_fd=sfd, dst_dir_fd=tfd, follow_symlinks=False)
        left = os.stat(name, dir_fd=sfd, follow_symlinks=False)
        right = os.stat(name, dir_fd=tfd, follow_symlinks=False)
        stable = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns')
        require(all(getattr(left, key) == getattr(right, key) == getattr(before, key) for key in stable)
                and left.st_nlink == right.st_nlink == 2,
                'diagnostic link boundary changed; retain both names as HOLD')
        os.unlink(name, dir_fd=sfd)
        os.fsync(sfd)
        os.fsync(tfd)
        try:
            os.stat(name, dir_fd=sfd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refusal('private diagnostic name remains after relocation')
        retained = record_at(tfd, target)
        require(all(retained['identity'][i] == expected['identity'][i] for i in (0, 1, 2, 3, 4, 6, 7)),
                'relocated diagnostic original identity differs')
        stable_parents()
        return retained
    finally:
        for fd, *_ in reversed(held):
            os.close(fd)

def typed_observation(path):
    try:
        item = path.lstat()
    except FileNotFoundError:
        return {'path': str(path), 'present': False}
    return {'path': str(path), 'present': True, 'identity': list(identity(item)),
            'regular': stat.S_ISREG(item.st_mode), 'symlink': stat.S_ISLNK(item.st_mode),
            'bytes_read_by_this_observation': 0}




def retain_diagnostics(root, public, policy, worker_report=None):
    """Only called after this operation's bound ECHILD; retain failures too."""
    import importlib.util
    source = root / 'control/diagnostics.py'
    expected = policy['control_files']['diagnostics.py']
    require(len(read(source, 1 << 20, expected['sha256'])) == expected['bytes'],
            'diagnostic control identity differs')
    spec = importlib.util.spec_from_file_location('v92_fixed_diagnostic_reader', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(policy.get('diagnostics') == module.LIMITS, 'diagnostic policy differs')
    folder = root / 'diagnostics'
    destination = public / 'small/originals'
    result = {'schema': 'hia.v92.closed-step42-original-capture.v1',
              'status': 'HOLD', 'closed_echild_required': True,
              'original_failure_reclassified': False, 'qualification_executed': False,
              'files': [], 'errors': [], 'observed_partial_originals_preserved': True}
    validated = False
    expected_records = {}
    def error(stage, exc):
        result['errors'].append({'stage': stage, 'type': type(exc).__name__,
                                'refusal': str(exc) if type(exc) in (Refusal, module.Refusal) else None})
    try:
        value, index_pin = document(folder / 'INDEX.json', 4 << 20)
        full_index_pin = file_record(folder / 'INDEX.json', 4 << 20)
        if worker_report is not None:
            same_original_record(worker_report.get('diagnostics'), full_index_pin)
        require(worker_report is not None and value.get('schema') == 'hia.v92-original-step42-diagnostics.v1'
                and value.get('artifact') == policy['artifact']
                and value.get('status') == 'AVAILABLE_STEP42_ORIGINALS_PRESERVED_NOT_QUALIFICATION'
                and value.get('all_members_fully_read') is True
                and value.get('complete_selection_of_available_originals') is True
                and value.get('original_workflow_status') == 'failure'
                and value.get('qualification_executed') is False
                and value.get('product_code_imported') is False
                and value.get('original_failure_reclassified') is False
                and value.get('errors') == [] and value.get('limits') == module.LIMITS
                and value.get('selection') == {'top_level': list(module.TOP_LEVEL),
                    'prefix': module.PREFIX, 'suffixes': ['.json', '.jsonl', '.log']},
                'complete original ZIP/diagnostic result binding differs')
        inventory_raw = read(folder / 'FULL-INVENTORY.jsonl', 64 << 20)
        directory_raw = read(folder / 'DIRECTORY.jsonl', 64 << 20)
        require(inventory_raw.endswith(b'\n') and directory_raw.endswith(b'\n'),
                'complete original metadata final newline missing')
        inventory = [json.loads(line) for line in inventory_raw.splitlines()]
        directory = [json.loads(line) for line in directory_raw.splitlines()]
        require(type(value.get('members')) is int and 0 < len(inventory) == len(directory)
                == value['members'] <= module.LIMITS['maximum_members'],
                'complete original ZIP metadata denominator differs')
        names = []
        for index, (observed, declared) in enumerate(zip(inventory, directory)):
            name = module.safe_name(observed['name'], observed['directory'])
            require(type(observed.get('index')) is int and observed['index'] == index
                    and type(declared.get('index')) is int and declared['index'] == index
                    and observed.get('body_fully_read') is True
                    and type(observed.get('bytes')) is int and observed['bytes'] >= 0
                    and type(observed.get('crc32')) is int
                    and type(observed.get('directory')) is bool
                    and re.fullmatch('[0-9a-f]{64}', observed.get('sha256', ''))
                    and all(observed[k] == declared[k] for k in ('name', 'bytes', 'crc32')),
                    'original full body inventory row differs')
            names.append(name)
        require(len(names) == len(set(names))
                and sum(row['bytes'] for row in inventory) == value.get('expanded_bytes')
                and value['expanded_bytes'] <= module.LIMITS['maximum_expanded_bytes'],
                'duplicate original inventory or expanded bytes differ')
        selected = [row for row in inventory if not row['directory'] and module.selected_name(row['name'])]
        require(type(value.get('selected')) is list and len(value['selected']) == len(selected)
                <= module.LIMITS['maximum_selected_files']
                and sum(row['bytes'] for row in selected) == value.get('selected_bytes')
                <= module.LIMITS['maximum_selected_bytes'],
                'complete fixed diagnostic original set differs')
        for observed, chosen in zip(selected, value['selected']):
            require(all(chosen.get(k) == v for k, v in observed.items())
                    and chosen.get('retained_name') == 'member-%05d.bin' % observed['index']
                    and chosen.get('truncated') is False
                    and chosen['bytes'] <= module.LIMITS['maximum_selected_file_bytes'],
                    'fixed diagnostic original mapping differs')
            actual = file_record(folder / chosen['retained_name'], module.LIMITS['maximum_selected_file_bytes'])
            same_original_record(chosen.get('actual'), actual)
            require(actual['bytes'] == observed['bytes'] and actual['sha256'] == observed['sha256'],
                    'actual diagnostic original bytes differ from complete ZIP inventory')
            expected_records[chosen['retained_name']] = actual
        for name, key in [('DIRECTORY.jsonl', 'directory'), ('FULL-INVENTORY.jsonl', 'inventory')]:
            actual = file_record(folder / name, 64 << 20)
            same_original_record(value.get(key), actual)
            expected_records[name] = actual
        expected_records['INDEX.json'] = full_index_pin
        require(sum(record['bytes'] for name, record in expected_records.items() if not name.startswith('member-'))
                <= module.LIMITS['maximum_metadata_bytes'], 'whole diagnostic metadata bound exceeded')
        expected_missing = [name for name in module.EXPECTED if name not in names]
        require(value.get('missing_expected') == expected_missing
                and value.get('expected_originals_all_present') == (not expected_missing),
                'original missing report inventory is inaccurate')
        observed_population = {'members': len(inventory), 'expanded_bytes': value['expanded_bytes'],
            'selected_count': len(selected), 'selected_bytes': value['selected_bytes'],
            'missing_expected': expected_missing, 'metadata_files': 3}
        require(observed_population['metadata_files'] == policy['expected_diagnostics']['metadata_files'],
                'complete current diagnostic metadata population differs')
        require(set(os.listdir(folder)) == set(expected_records),
                'complete diagnostic namespace differs from original INDEX')
        result.update(index_original=index_pin, complete_members=len(inventory),
                      complete_expanded_bytes=value['expanded_bytes'], selected_count=len(selected),
                      selected_bytes=value['selected_bytes'], missing_expected=expected_missing,
                      original_reports_missing_does_not_imply_product_success=True)
        validated = True
    except BaseException as exc:
        error('COMPLETE_DIAGNOSTIC_ACCEPTANCE', exc)
    # Even if acceptance failed, preserve each actual bounded fixed namespace
    # original independently; one damaged item cannot suppress the others.
    if os.path.lexists(folder):
        entry = folder.lstat()
        if stat.S_ISDIR(entry.st_mode) and not stat.S_ISLNK(entry.st_mode) and entry.st_uid == os.geteuid():
            names = sorted(os.listdir(folder))
            reserved_data = reserved_metadata = 0
            if len(names) > module.LIMITS['maximum_selected_files'] + 3:
                error('DIAGNOSTIC_FILE_COUNT', Refusal('fixed diagnostic file count exceeded'))
                names = []
            for name in names:
                try:
                    is_data = re.fullmatch(r'member-[0-9]{5}\.bin', name) is not None
                    require(is_data or name in ('INDEX.json', 'DIRECTORY.jsonl', 'FULL-INVENTORY.jsonl'),
                            'unexpected fixed diagnostic file name')
                    maximum = module.LIMITS['maximum_selected_file_bytes'] if is_data else module.LIMITS['maximum_metadata_bytes']
                    record = file_record(folder / name, maximum)
                    if is_data:
                        reserved_data += record['bytes']
                        require(reserved_data <= module.LIMITS['maximum_selected_bytes'],
                                'actual partial diagnostic data budget exceeded')
                    else:
                        reserved_metadata += record['bytes']
                        require(reserved_metadata <= module.LIMITS['maximum_metadata_bytes'],
                                'actual partial diagnostic metadata budget exceeded')
                    if validated:
                        require(record == expected_records[name], 'accepted diagnostic original changed')
                    actual = relocate_diagnostic(root, public, name, record)
                    result['files'].append({'name': name, 'original': record, 'retained': actual,
                        'accepted_complete_original': validated, 'partial_not_promoted': not validated})
                except BaseException as exc:
                    error('PRESERVE_' + name, exc)
        else:
            error('DIAGNOSTIC_DIRECTORY', Refusal('diagnostic namespace is not an owned ordinary directory'))
    else:
        result['missing_directory'] = True
    result['complete'] = validated and not result['errors'] and len(result['files']) == len(expected_records)
    if result['complete']:
        result['status'] = 'AVAILABLE_STEP42_ORIGINALS_VERIFIED_NOT_QUALIFICATION'
    raw = wire(result)
    require(len(raw) <= 4 << 20, 'diagnostic capture receipt exceeds bound')
    create(public / 'small/SMALL-READBACK.json', raw)
    require(read(public / 'small/SMALL-READBACK.json', 4 << 20) == raw,
            'small diagnostic capture receipt full readback differs')
    return result


def closed_storage_observation(root, public, policy):
    """Bound this operation's actual files after ECHILD, before final documents.

    This reads metadata only; all admitted payload bodies have already been
    independently hashed. Unknown/special/cross-device entries cannot produce a
    complete result. Planned upload/filesystem reserves are separate from the
    actual observed file allocation and are never called product evidence.
    """
    pin = policy['artifact']
    data_paths = {root / 'original' / ('artifact-%d.zip' % pin['id']),
                  root / 'original' / ('artifact-%d.zip.partial' % pin['id'])}
    private_files = {root / 'control' / name for name in
                     (*policy['control_files'], 'policy.json')}
    private_files |= {root / name for name in (
        'context.json', 'setup.json', 'guard/request.json', 'guard/guardian.json',
        'guard/child.stdout.log', 'guard/child.stderr.log',
        'supervisor.stdout.log', 'supervisor.stderr.log',
        'recovery.json', 'recovery.next.json', 'recovery-terminal.json',
        'api/artifact-%d.metadata.original.json' % pin['id'])}
    diagnostic_names = ('context.json', 'setup.json', 'guard/request.json',
        'guard/guardian.json', 'guard/child.stdout.log', 'guard/child.stderr.log',
        'supervisor.stdout.log', 'supervisor.stderr.log', 'recovery.json',
        'recovery-terminal.json', 'api/artifact-%d.metadata.original.json' % pin['id'])
    public_files = set()
    small = public / 'small'
    small_controls = {small / 'controls' / name.replace('/', '--') for name in diagnostic_names}
    diagnostic_metadata = {'INDEX.json', 'DIRECTORY.jsonl', 'FULL-INVENTORY.jsonl'}
    def diagnostic_category(child):
        if child.parent in (root / 'diagnostics', small / 'originals'):
            if re.fullmatch(r'member-[0-9]{5}\.bin', child.name):
                return 'step42_original'
            if child.name in diagnostic_metadata:
                return 'step42_metadata'
        if child in small_controls or child == small / 'SMALL-READBACK.json':
            return 'small_controls'
        return None
    allowed_dirs = {root, public} | {root / name for name in
                                    ('control', 'guard', 'original', 'api', 'diagnostics')}
    allowed_dirs |= {small, small / 'originals', small / 'controls'}
    device = root.lstat().st_dev
    rows = []
    unique = {}
    def visit(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            require(path in allowed_dirs and stat.S_ISDIR(before.st_mode)
                    and before.st_dev == device and before.st_uid == os.geteuid()
                    and not stat.S_IMODE(before.st_mode) & 0o077,
                    'actual storage directory identity differs')
            rows.append({'path': str(path), 'kind': 'directory',
                         'identity': list(identity(before)), 'allocated_bytes': before.st_blocks * 512})
            names = os.listdir(fd)
            require(len(rows) + len(names) <= 4096, 'actual storage entry count exceeds fixed bound')
            for name in sorted(names):
                child = path / name
                observed = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(observed.st_mode):
                    visit(child)
                else:
                    require(stat.S_ISREG(observed.st_mode) and observed.st_dev == device
                            and observed.st_uid == os.geteuid() and observed.st_nlink == 1,
                            'actual retained storage is not owned single-link regular data')
                    category = ('payload' if child in data_paths else
                                'private_metadata' if child in private_files else
                                'public_diagnostic' if child in public_files else diagnostic_category(child))
                    require(category is not None, 'unexpected file in the fixed custody namespace')
                    inode = (observed.st_dev, observed.st_ino)
                    require(inode not in unique, 'duplicate retained inode in closed storage')
                    unique[inode] = observed.st_size
                    rows.append({'path': str(child), 'kind': 'regular', 'category': category,
                                 'identity': list(identity(observed)),
                                 'allocated_bytes': observed.st_blocks * 512})
                require(identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == identity(observed),
                        'actual storage child changed during observation')
                require(len(rows) <= 4096, 'actual storage entry count exceeds fixed bound')
            require(identity(os.fstat(fd)) == identity(before)
                    and identity(path.lstat()) == identity(before),
                    'actual storage directory changed during observation')
        finally:
            os.close(fd)
    visit(root)
    visit(public)
    sizes = {key: sum(row['identity'][6] for row in rows
                      if row.get('category') == key)
             for key in ('payload', 'private_metadata', 'public_diagnostic',
                         'step42_original', 'step42_metadata', 'small_controls')}
    require(sizes['payload'] <= 2 * pin['bytes']
            and sizes['private_metadata'] <= 64 << 20
            and sizes['public_diagnostic'] == 0
            and sizes['step42_original'] <= 128 << 20
            and sizes['step42_metadata'] <= 64 << 20
            and sizes['small_controls'] <= 6 << 20,
            'actual retained byte budget exceeds the unchanged original custody ceilings')
    allocation = sum(row['allocated_bytes'] for row in rows)
    final_documents = 4 * (3 << 20)  # Preserve the original r1 reserve, although only one FINAL is produced.
    upload_workspace = 320 << 20
    filesystem_reserve = 512 << 20
    require(allocation + final_documents + upload_workspace + filesystem_reserve <= 8 << 30,
            'observed storage plus remaining bounded reserves exceeds admission capacity')
    capacity = os.statvfs(root.parent)
    remaining_inode_reserve = 1032
    require(capacity.f_bavail * capacity.f_frsize >= final_documents + upload_workspace + filesystem_reserve
            and capacity.f_favail >= remaining_inode_reserve,
            'remaining ordinary storage reserve is unavailable')
    return {'schema': 'hia.v92-diagnostics-only.closed-storage.v2',
            'entry_count': len(rows), 'single_link_regular_files': len(unique),
            'logical_bytes_by_category': sizes, 'allocated_bytes_observed': allocation,
            'future_final_document_bytes_reserved': final_documents,
            'one_serial_upload_workspace_reserved': upload_workspace,
            'filesystem_overhead_reserved': filesystem_reserve,
            'remaining_free_bytes': capacity.f_bavail * capacity.f_frsize,
            'remaining_free_inodes': capacity.f_favail,
            'remaining_inode_reserve': remaining_inode_reserve,
            'records': rows, 'file_bodies_read_by_this_observation': False,
            'original_ZIP_or_slice_bytes_rewritten': False}


def final_input_records(setup, context):
    output = {}
    for path, digest in setup['source_identities'].items():
        actual = file_record(Path(path), 64 << 20, system_binary=path == context['python']['resolved'])
        require(actual['sha256'] == digest, 'original control input changed at final readback')
        output[path] = actual
    return output



def finalize(args):
    require(TOKEN_VARIABLE not in os.environ and 'GITHUB_TOKEN' not in os.environ
            and 'GH_TOKEN' not in os.environ, 'read token entered public finalization')
    _, policy, _, root, public, context = policy_and_context(args)
    pin = fixed_policy(policy)
    require(not os.path.lexists(public), 'public custody already exists; do not replay')
    public.mkdir(mode=0o700)
    for name in ('small', 'small/originals', 'small/controls'):
        (public / name).mkdir(mode=0o700)
    result = {'schema': 'hia.actions.v92-ci-diagnostics-only-final.v2',
              'status': 'DIAGNOSTIC_CUSTODY_HOLD', 'context': context, 'artifact': pin,
              'errors': [], 'missing_originals': [], 'typed_download_observations': [],
              'new_product_execution': False, 'old_runs_replayed': False,
              'historical_results_reclassified': False,
              'old_local_R4_owner_status': 'UNKNOWN_NOT_RECLASSIFIED',
              'old_remote_recovery_status': 'HOLD_NOT_RECLASSIFIED',
              'original_ZIP_member_inspection_started': None,
              'full_5400_retained_suite_executed': False, 'artifact_uploads_not_yet_observed': True,
              'original_full_ZIP_retained_private': False,
              'diagnostic_originals_relocated_not_duplicated': True,
              'partition_files_created': False, 'original_ZIP_bytes_or_compression_changed': False}
    setup = report = original = None
    closed = natural = accepted = storage_observed = diagnostics_complete = False
    captures_complete = True
    def error(stage, exc):
        result['errors'].append({'stage': stage, 'type': type(exc).__name__,
                                'safe_refusal': str(exc) if type(exc) is Refusal else None})
    try:
        setup, setup_record = document(root / 'setup.json')
        check_setup(setup, context, policy, root)
        request = read(root / 'guard/request.json', 262144, setup['guardian_config_sha256'])
        expected_request = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 900,
                            'command': setup['command'], 'cwd': str(root),
                            'source_identities': setup['source_identities']}
        require(json.loads(request) == expected_request, 'actual original guardian request differs')
        guardian, guardian_record = document(root / 'guard/guardian.json')
        closed = closed_guardian(guardian, setup, policy, root)
        require(closed, 'this guardian did not prove closed ECHILD')
        result.update(setup=setup_record, guardian=guardian_record, closed_echild=True)
        try:
            natural_guardian(guardian, setup, policy, root)
            natural = True
        except BaseException as exc:
            error('NATURAL_GUARDIAN', exc)
        try:
            report, report_record = document(root / 'recovery-terminal.json')
            result['worker'] = report_record
            original = accept_worker(report, policy, setup, root)
            result['original_zip'] = original
            accepted = True
            result['original_full_ZIP_retained_private'] = True
        except BaseException as exc:
            error('ORIGINAL_ZIP_AND_WORKER', exc)
    except BaseException as exc:
        error('CLOSED_BOUNDARY', exc)

    # No child-body read, directory enumeration, partial capture or storage walk
    # occurs before this operation's bound raw request and ECHILD are confirmed.
    if closed:
        original_name = 'artifact-%d.zip' % pin['id']
        for path in (root / 'original' / original_name,
                     root / 'original' / (original_name + '.partial')):
            try:
                result['typed_download_observations'].append(typed_observation(path))
            except BaseException as exc:
                error('DOWNLOAD_TYPE', exc)
        try:
            diagnostic_capture = retain_diagnostics(root, public, policy, report)
            result['diagnostic_capture'] = diagnostic_capture
            diagnostics_complete = diagnostic_capture['complete']
            result['original_ZIP_member_inspection_started'] = None if report is None else report.get('original_ZIP_member_inspection_started')
            result['complete_original_ZIP_member_read_verified'] = diagnostics_complete
            require(diagnostics_complete, 'fixed diagnostic originals are incomplete; preserve HOLD')
        except BaseException as exc:
            error('STEP42_DIAGNOSTIC_CAPTURE', exc)
        fixed = ['context.json', 'setup.json', 'guard/request.json', 'guard/guardian.json',
                 'guard/child.stdout.log', 'guard/child.stderr.log',
                 'supervisor.stdout.log', 'supervisor.stderr.log',
                 'recovery.json', 'recovery-terminal.json',
                 'api/artifact-%d.metadata.original.json' % pin['id']]
        small_control_bytes = 0
        result['small_controls'] = []
        for name in fixed:
            try:
                source = root / name
                if not os.path.lexists(source):
                    result['missing_originals'].append(name)
                    captures_complete = False
                    continue
                actual = file_record(source, 8 << 20)
                small_control_bytes += actual['bytes']
                require(small_control_bytes <= MAX_DIAGNOSTIC_BYTES, 'whole small control bound exceeded')
                retained = copy_original(source, public / 'small/controls' / name.replace('/', '--'), actual)
                result['small_controls'].append({'name': name, 'original': actual, 'retained': retained})
            except BaseException as exc:
                captures_complete = False
                error('SMALL_CONTROL_' + name, exc)
        result['small_control_bytes'] = small_control_bytes
        try:
            result['source_inputs_final'] = final_input_records(setup, context)
            result['source_inputs_preserved'] = True
        except BaseException as exc:
            error('FINAL_SOURCE_INPUTS', exc)
        if original is not None:
            try:
                require(file_record(Path(original['path']), pin['bytes']) == original,
                        'original ZIP changed during diagnostic custody')
                result['original_zip_final_readback'] = original
            except BaseException as exc:
                accepted = False
                error('ORIGINAL_ZIP_FINAL_READBACK', exc)
        try:
            result['closed_storage_observation'] = closed_storage_observation(root, public, policy)
            storage_observed = True
        except BaseException as exc:
            error('CLOSED_STORAGE_BUDGET', exc)

    complete = (closed and natural and accepted and captures_complete and storage_observed and diagnostics_complete
                and result.get('original_full_ZIP_retained_private') is True
                and result.get('source_inputs_preserved') is True
                and not result['errors'] and not result['missing_originals'])
    result['complete_local_diagnostic_readback'] = complete
    if complete:
        result['status'] = 'ALL_AVAILABLE_STEP42_ORIGINALS_VERIFIED_NOT_QUALIFICATION'
    final_raw = wire(result)
    require(len(final_raw) <= 2 << 20, 'whole FINAL document exceeds fixed bound')
    create(public / 'small/FINAL.json', final_raw)
    require(read(public / 'small/FINAL.json', 2 << 20) == final_raw,
            'small FINAL complete readback differs')
    small_records = []
    for path in sorted((public / 'small').rglob('*')):
        entry = path.lstat()
        require(not stat.S_ISLNK(entry.st_mode), 'small public symlink refused')
        if stat.S_ISDIR(entry.st_mode):
            require(entry.st_uid == os.geteuid(), 'small public directory ownership differs')
        else:
            small_records.append(file_record(path, 64 << 20))
    require(len(small_records) <= 1040 and sum(x['bytes'] for x in small_records) <= 224 << 20,
            'small complete public artifact exceeds its fixed bound')
    for folder in ('originals', 'controls'):
        sync_dir(public / 'small' / folder)
    sync_dir(public / 'small')
    sync_dir(public)
    print(json.dumps({'status': result['status'], 'partition_files_created': False,
                      'complete_local_diagnostic_readback': complete,
                      'original_bytes': pin['bytes'], 'original_sha256': pin['sha256'],
                      'qualification_executed': False}), flush=True)
    return 0 if complete else 1

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
    except Refusal as exc:
        print(json.dumps({'status': 'CONTROL_HOLD', 'safe_refusal': str(exc)}), flush=True)
        raise SystemExit(1)
