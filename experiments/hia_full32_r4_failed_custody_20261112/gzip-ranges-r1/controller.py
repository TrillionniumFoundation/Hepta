"""Deliver one to ten sealed contiguous parts of one historical ZIP; execute no product code."""
from __future__ import annotations
from hashlib import sha256
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

REPO = 'TrillionniumFoundation/Hepta'
TOKEN_VARIABLE = 'HIA_CUSTODY_GITHUB_TOKEN'
CHUNK = 1 << 20
GZIP_HELPER = None
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
    require(policy.get('schema') == 'hia.actions.failed-full32-gzip-parts-policy.v1'
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
    context = {'schema': 'hia.actions.v88-full-original-parts-context.v1',
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
    for name in ('control', 'guard', 'original', 'parts', 'api'):
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
    setup = {'schema': 'hia.actions.v88-full-original-parts-setup.v1',
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
    require(setup.get('schema') == 'hia.actions.v88-full-original-parts-setup.v1'
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


def load_gzip_helper(control, policy):
    pin = policy['control_files']['gzip_evidence.py']
    path = control / 'gzip_evidence.py'
    raw = read(path, 1 << 20, pin['sha256'])
    require(len(raw) == pin['bytes'], 'frozen gzip evidence helper size differs')
    spec = importlib.util.spec_from_file_location('frozen_gzip_evidence', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module



def expected_parts(policy):
    pin = policy['artifact']
    require(type(pin) is dict and type(pin.get('bytes')) is int
            and 0 < pin['bytes'] <= 3 << 30, 'frozen original ZIP byte count differs')
    parts = []
    offset = 0
    while offset < pin['bytes']:
        ordinal = len(parts)
        count = min(312 << 20, pin['bytes'] - offset)
        parts.append({'ordinal': ordinal, 'offset': offset, 'bytes': count,
                      'name': 'part-%02d.bin.gz' % ordinal})
        offset += count
    require(1 <= len(parts) <= 10 and offset == pin['bytes'], 'bounded partition count differs')
    declared = policy.get('parts')
    require(type(declared) is list and len(declared) == len(parts)
            and all(type(row) is dict and type(row.get('ordinal')) is int
                    and type(row.get('offset')) is int and type(row.get('bytes')) is int
                    and row == actual for row, actual in zip(declared, parts)),
            'frozen contiguous partition differs from the complete original ZIP')
    return parts


def fixed_policy(policy):
    require(policy.get('schema') == 'hia.actions.failed-full32-gzip-parts-policy.v1'
            and policy.get('status') == 'FROZEN_OFFICIAL_TRANSPORT_INPUTS_UNEXECUTED'
            and policy.get('input_pins_frozen') is True,
            'draft policy has no frozen official artifact identity; execution refused')
    pin = policy.get('artifact')
    require(type(pin) is dict
            and all(type(pin.get(name)) is int and 0 < pin[name] < 1 << 63
                    for name in ('id', 'run_id', 'job_id'))
            and type(pin.get('run_attempt')) is int and pin['run_attempt'] == 1
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
                'part_bytes': 312 << 20, 'public_part_bytes': 320 << 20,
                'diagnostic_bytes_per_part': 2 << 20, 'document_bytes_per_part': 3 << 20,
                'private_metadata_reserve_bytes': 64 << 20,
                'minimum_free_bytes': 8 << 30, 'minimum_free_inodes': 100000,
                'compressed_part_bytes': 313 << 20,
                'small_original_bytes': 160 << 20, 'small_derived_bytes': 32 << 20,
                'small_public_bytes': 224 << 20,
                'inner_stream_bytes': 16 << 30, 'outer_stream_bytes': 4 << 30},
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
        'controller.py', 'worker.py', 'guardian.py', 'process_owner_impl.py', 'original_receiver.py', 'gzip_evidence.py'},
        'fixed six custody controls differ')
    require(policy.get('proxy_policy') == 'USE_CONFIGURED_ENVIRONMENT_PROXIES'
            and policy.get('slice_publication') == 'RELOCATE_SAME_FILESYSTEM_AFTER_CLOSED_ECHILD'
            and policy.get('original_product_thresholds_changed') is False
            and policy.get('new_product_execution') is False,
            'transport credential, disk or product scope differs')
    expected_parts(policy)
    return pin


def same_original_record(expected, actual):
    require(type(expected) is dict
            and all(expected.get(key) == actual[key] for key in ('path', 'bytes', 'sha256', 'identity'))
            and expected.get('actual_bytes_independently_read') == actual['bytes'],
            'actual original full read differs from worker receipt')


def accept_worker(report, policy, setup, root):
    pin = fixed_policy(policy)
    parts = expected_parts(policy)
    require(report.get('schema') == 'hia.actions.v88-full-original-parts-worker.v1'
            and report.get('status') == 'SEALED_PARTS_PENDING_NATURAL_GUARDIAN'
            and report.get('root') == str(root)
            and report.get('policy_sha256') == setup['context']['policy_sha256']
            and report.get('source') == policy['source'] and report.get('artifact') == pin
            and report.get('qualification_executed') is False
            and report.get('project_code_executed') is False
            and report.get('old_runs_replayed') is False
            and report.get('original_product_statuses_reclassified') is False
            and report.get('all_available_original_bodies_read') is True
            and report.get('token_or_signed_URL_recorded') is False
            and report.get('natural_guardian_acceptance_required') is True
            and report.get('proxy_policy') == 'USE_CONFIGURED_ENVIRONMENT_PROXIES'
            and report.get('proxy_URLs_or_credentials_recorded') is False,
            'worker complete multipart result or scope differs')
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
    partition = report.get('partition', {})
    require(partition.get('exact_contiguous_partition') is True
            and partition.get('total_bytes') == pin['bytes']
            and partition.get('concatenated_sha256') == pin['sha256']
            and partition.get('original_identity') == original['identity']
            and len(partition.get('parts', [])) == len(parts),
            'multipart worker partition differs')
    records = []
    for expected, produced in zip(parts, partition['parts']):
        require(all(produced.get(k) == v for k, v in expected.items()), 'part range differs')
        actual = file_record(root / 'parts' / expected['name'], 313 << 20)
        require(actual['bytes'] > 0 and stat.S_IMODE(actual['identity'][2]) == 0o400,
                'complete read-only part required')
        same_original_record(produced.get('original'), actual)
        restored = GZIP_HELPER.decode_range(actual['path'], expected, actual)
        require(produced.get('compression') == 'gzip' and produced.get('compresslevel') == 1
                and produced.get('mtime') == 0 and produced.get('raw_bytes') == expected['bytes']
                and produced.get('raw_sha256') == restored['sha256']
                and produced.get('restoration') == restored, 'actual gzip range restoration differs')
        records.append(actual)
    return original, records


def concat_parts(records, pin, parts):
    return GZIP_HELPER.concat_parts(records, pin, parts)


def relocate_slice(source, target, expected):
    """Publish one already retained range without a third full-byte replica.

    Only fresh custody slices may use this helper, after bound ECHILD. The
    original ZIP is never renamed or removed. An interrupted link/unlink window
    leaves two names for the same inode and is HOLD, not single-link admission.
    """
    source, target = Path(source), Path(target)
    require(source.name.startswith('part-') and source.name.endswith('.bin.gz')
            and target.name in ('slice.bin.gz', 'unverified-range.bin.gz')
            and source.parent.name == 'parts', 'only a fixed private slice may be relocated')
    original = file_record(source, expected['bytes'])
    require(original == expected, 'private slice changed before relocation')
    sdir = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    tdir = None
    try:
        tdir = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        a, b = os.fstat(sdir), os.fstat(tdir)
        require(stat.S_ISDIR(a.st_mode) and stat.S_ISDIR(b.st_mode)
                and a.st_uid == b.st_uid == os.geteuid() and a.st_dev == b.st_dev == expected['identity'][0]
                and not stat.S_IMODE(a.st_mode) & 0o077 and not stat.S_IMODE(b.st_mode) & 0o077,
                'private/public slice parents must be owned private directories on one device')
        before = os.stat(source.name, dir_fd=sdir, follow_symlinks=False)
        require(list(identity(before)) == expected['identity'], 'slice name changed before link')
        os.link(source.name, target.name, src_dir_fd=sdir, dst_dir_fd=tdir, follow_symlinks=False)
        left = os.stat(source.name, dir_fd=sdir, follow_symlinks=False)
        right = os.stat(target.name, dir_fd=tdir, follow_symlinks=False)
        stable = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns')
        require(all(getattr(left, key) == getattr(right, key) == getattr(before, key) for key in stable)
                and left.st_nlink == right.st_nlink == 2,
                'slice link boundary changed; retain both names as HOLD')
        os.unlink(source.name, dir_fd=sdir)
        os.fsync(sdir)
        os.fsync(tdir)
        after = os.stat(target.name, dir_fd=tdir, follow_symlinks=False)
        require(after.st_nlink == 1 and all(getattr(after, key) == getattr(before, key) for key in stable),
                'relocated slice identity differs')
        require(not os.path.lexists(source), 'private slice name still exists after relocation')
        for held, parent, initial in ((sdir, source.parent, a), (tdir, target.parent, b)):
            observed = os.fstat(held)
            named = parent.lstat()
            require(all(getattr(observed, key) == getattr(named, key) == getattr(initial, key)
                        for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid')),
                    'slice parent identity changed')
    finally:
        if tdir is not None:
            os.close(tdir)
        os.close(sdir)
    retained = file_record(target, expected['bytes'])
    require(retained['bytes'] == expected['bytes'] and retained['sha256'] == expected['sha256']
            and retained['identity'][0:2] == expected['identity'][0:2],
            'complete public slice readback differs')
    return retained


def typed_observation(path):
    try:
        item = path.lstat()
    except FileNotFoundError:
        return {'path': str(path), 'present': False}
    return {'path': str(path), 'present': True, 'identity': list(identity(item)),
            'regular': stat.S_ISREG(item.st_mode), 'symlink': stat.S_ISLNK(item.st_mode),
            'bytes_read_by_this_observation': 0}


def copy_unverified_range(source, target, record, expected):
    # This is failure custody only. It cannot be promoted by an external-seal flag.
    require(record['bytes'] > expected['offset'], 'failed original has no bytes in this range')
    length = min(expected['bytes'], record['bytes'] - expected['offset'])
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as incoming:
        before = os.fstat(incoming.fileno())
        require(list(identity(before)) == record['identity'], 'failed original changed before copying')
        incoming.seek(expected['offset'])
        outfd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
        count, digest = 0, sha256()
        with os.fdopen(outfd, 'wb') as output:
            os.fchmod(output.fileno(), 0o400)
            while count < length:
                block = incoming.read(min(CHUNK, length - count))
                require(block, 'failed original range changed')
                output.write(block)
                digest.update(block)
                count += len(block)
            output.flush()
            os.fsync(output.fileno())
        require(identity(before) == identity(os.fstat(incoming.fileno()))
                and identity(before) == identity(source.lstat()), 'failed original changed while copying')
    actual = file_record(target, expected['bytes'])
    require(actual['bytes'] == length and actual['sha256'] == digest.hexdigest(),
            'failed original independent range copy differs')
    return actual


def closed_storage_observation(root, public, policy):
    """Actual same-device file allocation plus remaining immutable reserves."""
    pin, parts = policy['artifact'], expected_parts(policy)
    data_paths = {root / 'original' / ('artifact-%d.zip' % pin['id']),
                  root / 'original' / ('artifact-%d.zip.partial' % pin['id'])}
    private_files = {root / 'control' / name for name in (*policy['control_files'], 'policy.json')}
    names = ('context.json', 'setup.json', 'guard/request.json', 'guard/guardian.json',
             'guard/child.stdout.log', 'guard/child.stderr.log', 'supervisor.stdout.log',
             'supervisor.stderr.log', 'recovery.json', 'recovery.next.json', 'recovery-terminal.json',
             'api/artifact-%d.metadata.original.json' % pin['id'])
    private_files |= {root / name for name in names}
    diagnostic_names = tuple(x for x in names if x != 'recovery.next.json')
    public_files = set()
    allowed_dirs = {root, public, root / 'small', public / 'small'} | {
        root / name for name in ('control', 'guard', 'original', 'parts', 'api')}
    for part in parts:
        directory = public / ('part-%02d' % part['ordinal'])
        allowed_dirs |= {directory, directory / 'controls'}
        data_paths |= {root / 'parts' / part['name'], directory / 'slice.bin.gz',
                       directory / 'unverified-range.bin.gz', directory / 'unverified-range.bin'}
        public_files |= {directory / 'controls' / name.replace('/', '--') for name in diagnostic_names}
    public_files |= {public / 'small' / ('current--' + name.replace('/', '--')) for name in diagnostic_names}
    device, rows, unique = root.lstat().st_dev, [], {}
    def small_name(name):
        return name in GZIP_HELPER.SMALL_DOCUMENTS or re.fullmatch('[OI][0-9]{6}\\.original', name)
    def visit(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            require(path in allowed_dirs and stat.S_ISDIR(before.st_mode) and before.st_dev == device
                    and before.st_uid == os.geteuid() and not stat.S_IMODE(before.st_mode) & 0o077,
                    'actual storage directory identity differs')
            rows.append({'path': str(path), 'kind': 'directory', 'identity': list(identity(before)),
                         'allocated_bytes': before.st_blocks * 512})
            names = os.listdir(fd)
            require(len(rows) + len(names) <= 12288, 'actual storage entry bound exceeded')
            for name in sorted(names):
                child = path / name
                observed = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(observed.st_mode):
                    visit(child)
                else:
                    require(stat.S_ISREG(observed.st_mode) and observed.st_dev == device
                            and observed.st_uid == os.geteuid() and observed.st_nlink == 1,
                            'closed storage is not owned single-link regular bytes')
                    category = ('payload' if child in data_paths else 'private_metadata' if child in private_files
                        else 'public_diagnostic' if child in public_files
                        else 'private_small' if path == root / 'small' and small_name(name)
                        else 'public_small' if path == public / 'small' and (small_name(name) or name == 'SMALL-CAPTURE.json')
                        else None)
                    require(category is not None, 'unexpected file in exact custody namespace')
                    inode = (observed.st_dev, observed.st_ino)
                    require(inode not in unique, 'duplicate retained inode after closed storage')
                    unique[inode] = observed.st_size
                    rows.append({'path': str(child), 'kind': 'regular', 'category': category,
                                 'identity': list(identity(observed)), 'allocated_bytes': observed.st_blocks * 512})
                require(identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == identity(observed),
                        'storage child identity changed')
                require(len(rows) <= 12288, 'actual storage entry bound exceeded')
            require(identity(os.fstat(fd)) == identity(before) == identity(path.lstat()),
                    'storage directory identity changed')
        finally:
            os.close(fd)
    visit(root)
    visit(public)
    keys = ('payload', 'private_metadata', 'public_diagnostic', 'private_small', 'public_small')
    sizes = {key: sum(row['identity'][6] for row in rows if row.get('category') == key) for key in keys}
    require(sizes['payload'] <= pin['bytes'] + len(parts) * (313 << 20)
            and sizes['private_metadata'] <= 64 << 20
            and sizes['public_diagnostic'] <= (len(parts) + 1) * MAX_DIAGNOSTIC_BYTES
            and sizes['private_small'] <= 192 << 20 and sizes['public_small'] <= 200 << 20,
            'actual retained bytes exceed fixed two-payload-copy and small-channel bounds')
    allocation = sum(row['allocated_bytes'] for row in rows)
    final_documents = len(parts) * (3 << 20) + (16 << 20)
    upload_workspace, filesystem_reserve = 320 << 20, 512 << 20
    require(allocation + final_documents + upload_workspace + filesystem_reserve <= 8 << 30,
            'actual allocation plus final/upload/filesystem reserve exceeds original 8 GiB')
    capacity = os.statvfs(root.parent)
    inode_reserve = 1024 + 2 * len(parts)
    require(capacity.f_bavail * capacity.f_frsize >= final_documents + upload_workspace + filesystem_reserve
            and capacity.f_favail >= inode_reserve, 'remaining ordinary storage reserve unavailable')
    result = {'schema': 'hia.failed-full32-gzip.closed-storage.v1', 'entry_count': len(rows),
        'single_link_regular_files': len(unique), 'logical_bytes_by_category': sizes,
        'allocated_bytes_observed': allocation, 'future_final_document_bytes_reserved': final_documents,
        'one_serial_upload_workspace_reserved': upload_workspace, 'filesystem_overhead_reserved': filesystem_reserve,
        'remaining_free_bytes': capacity.f_bavail * capacity.f_frsize, 'remaining_free_inodes': capacity.f_favail,
        'remaining_inode_reserve': inode_reserve, 'records': rows,
        'file_bodies_read_by_this_observation': False, 'original_ZIP_bytes_rewritten': False}
    raw = wire(result)
    require(len(raw) <= 8 << 20, 'complete storage inventory exceeds fixed document reserve')
    create(public / 'small' / 'CLOSED-STORAGE.json', raw)
    stored = file_record(public / 'small' / 'CLOSED-STORAGE.json', 8 << 20)
    require(stored['sha256'] == sha256(raw).hexdigest() and stored['bytes'] == len(raw),
            'closed storage full inventory readback differs')
    return {key: value for key, value in result.items() if key != 'records'} | {'full_inventory': stored}



def final_input_records(setup, context):
    output = {}
    for path, digest in setup['source_identities'].items():
        actual = file_record(Path(path), 64 << 20, system_binary=path == context['python']['resolved'])
        require(actual['sha256'] == digest, 'original control input changed at final readback')
        output[path] = actual
    return output


def capture_small(root, public, policy, inspection):
    """Only called after the current original guardian proves closed ECHILD."""
    private, destination = root / 'small', public / 'small'
    result = {'schema': 'hia.failed-full32.closed-small-capture.v1', 'status': 'HOLD',
              'files': [], 'errors': [], 'complete': False, 'original_results_reclassified': False,
              'product_execution_performed': False, 'child_bytes_read_only_after_bound_ECHILD': True}
    expected = {}
    index = None
    bound = False
    try:
        index, index_record = document(private / 'INDEX.json', 16 << 20)
        require(type(inspection) is dict and inspection.get('status') ==
                'ALL_AVAILABLE_BODIES_VERIFIED_HISTORICAL_RESULTS_UNCHANGED'
                and inspection.get('diagnostic_channel_complete') is True,
                'worker did not complete bounded original inspection')
        actual = file_record(private / 'INDEX.json', 16 << 20)
        same_original_record(inspection.get('index'), actual)
        require(index.get('schema') == 'hia.failed-full32.small-original-index.v1'
                and index.get('artifact') == policy['artifact']
                and index.get('diagnostic_channel_complete') is True
                and index.get('original_results_reclassified') is False
                and index.get('omitted_whole_originals') == [], 'small diagnostic index differs')
        physical, physical_pin = document(private / 'PHYSICAL-READBACK.json', 8 << 20)
        same_original_record(index.get('physical_readback'), file_record(private / 'PHYSICAL-READBACK.json', 8 << 20))
        require(physical.get('status') == inspection['status']
                and physical.get('artifact') == policy['artifact']
                and physical.get('all_available_original_bodies_independently_read') is True
                and physical.get('qualification_executed') is False
                and physical.get('original_results_reclassified') is False
                and physical.get('whole_originals_omitted_for_transport') == []
                and index.get('critical_originals') == physical.get('critical_originals'),
                'whole original physical readback differs')
        directory, _ = document(private / 'DIRECTORY.json', 8 << 20)
        inventory, _ = document(private / 'OUTER-INVENTORY.json', 8 << 20)
        same_original_record(physical.get('directory'), file_record(private / 'DIRECTORY.json', 8 << 20))
        same_original_record(physical.get('outer_inventory'), file_record(private / 'OUTER-INVENTORY.json', 8 << 20))
        declared, actual_rows = directory.get('members'), inventory.get('files')
        require(type(declared) is list and type(actual_rows) is list
                and 4 <= len(declared) <= 256 and inventory.get('complete') is True
                and len(declared) == len(actual_rows) == physical.get('outer_entries'),
                'complete observed original ZIP denominator differs')
        by_name = {row.get('name'): row for row in declared}
        actual_names = {row.get('path') for row in actual_rows}
        require(len(by_name) == len(declared) and len(actual_names) == len(actual_rows)
                and set(by_name) == actual_names
                and all(name in by_name and by_name[name].get('kind') == 'regular' for name in
                        (GZIP_HELPER.TAR_NAME, GZIP_HELPER.CAT_NAME, GZIP_HELPER.CUSTODY_NAME, GZIP_HELPER.FINAL_NAME)),
                'full observed outer member set or four mandatory originals differ')
        for row in actual_rows:
            declared_row = by_name[row['path']]
            require(row.get('kind') == declared_row.get('kind')
                    and type(row.get('bytes')) is int and row['bytes'] == declared_row.get('uncompressed_bytes')
                    and row.get('crc32') == '%08x' % declared_row['crc32_from_directory']
                    and type(row.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
                    'actual full outer CRC/SHA/size record differs from observed directory')
        require(sum(row['bytes'] for row in actual_rows) == directory.get('declared_total_bytes')
                == physical.get('outer_bytes')
                and sum(row['kind'] == 'regular' for row in actual_rows) == physical.get('outer_files')
                and sum(row['kind'] == 'directory' for row in actual_rows) == physical.get('outer_directories'),
                'observed outer full-body totals differ')
        critical = physical.get('critical_originals')
        require(type(critical) is list and [x.get('path') for x in critical] == list(GZIP_HELPER.CRITICAL_INNER)
                and all(x.get('status') in ('PRESENT', 'ORIGINAL_MISSING', 'ORIGINAL_UNREADABLE') for x in critical),
                'complete fixed original diagnostic denominator differs')
        originals = index.get('originals')
        require(type(originals) is list and len(originals) == physical.get('selected_original_files')
                and len(originals) <= GZIP_HELPER.MAX_CAPTURE_FILES,
                'whole small-original count differs')
        paths = set()
        for row in originals:
            name = row.get('saved')
            require(type(name) is str and re.fullmatch('[OI][0-9]{6}\\.original', name)
                    and name not in expected and (row.get('scope'), row.get('path')) not in paths
                    and row.get('whole_original') is True and row.get('derived') is False,
                    'duplicate or non-whole selected original')
            paths.add((row['scope'], row['path']))
            expected[name] = row['actual']
        for name, pin in (('INDEX.json', inspection['index']),
                          ('PHYSICAL-READBACK.json', index['physical_readback']),
                          ('DIRECTORY.json', physical['directory']),
                          ('OUTER-INVENTORY.json', physical['outer_inventory']),
                          ('INNER-INVENTORY.json', physical['inner_inventory'])):
            expected[name] = pin
        require(set(os.listdir(private)) == set(expected), 'successful small namespace differs')
        bound = True
    except BaseException as exc:
        result['errors'].append({'stage': 'SMALL_ACCEPTANCE', 'type': type(exc).__name__,
            'safe_refusal': str(exc) if type(exc) is Refusal else None})
    reserved = 0
    try:
        parent = private.lstat()
        require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
                and parent.st_dev == root.lstat().st_dev and not stat.S_IMODE(parent.st_mode) & 0o077,
                'small original directory differs')
        names = sorted(os.listdir(private))
        require(len(names) <= GZIP_HELPER.MAX_CAPTURE_FILES + len(GZIP_HELPER.SMALL_DOCUMENTS),
                'small original file count exceeds bound')
        for name in names:
            try:
                require(name in GZIP_HELPER.SMALL_DOCUMENTS or re.fullmatch('[OI][0-9]{6}\\.original', name),
                        'unexpected file in small original namespace')
                path = private / name
                actual = file_record(path, 64 << 20)
                require(reserved + actual['bytes'] <= 192 << 20, 'whole small original total exceeds bound')
                reserved += actual['bytes']
                if bound:
                    same_original_record(expected[name], actual)
                copied = copy_original(path, destination / name, actual)
                result['files'].append({'name': name, 'original': actual, 'copy': copied,
                    'whole_original_or_whole_derived_document': True,
                    'verified_against_worker_and_index': bound})
            except BaseException as exc:
                result['errors'].append({'stage': 'SMALL_COPY_' + name, 'type': type(exc).__name__,
                    'safe_refusal': str(exc) if type(exc) is Refusal else None})
        require(identity(private.lstat()) == identity(parent), 'small original directory changed')
    except BaseException as exc:
        result['errors'].append({'stage': 'SMALL_NAMESPACE', 'type': type(exc).__name__,
            'safe_refusal': str(exc) if type(exc) is Refusal else None})
    result['complete'] = bound and not result['errors'] and len(result['files']) == len(expected)
    result['status'] = 'WHOLE_SMALL_ORIGINALS_BOUND_AND_COPIED' if result['complete'] else 'HOLD'
    result['bytes_reserved'] = reserved
    raw = wire(result)
    require(len(raw) <= 8 << 20, 'whole small capture inventory exceeds fixed bound')
    create(destination / 'SMALL-CAPTURE.json', raw)
    actual = file_record(destination / 'SMALL-CAPTURE.json', 8 << 20)
    require(actual['bytes'] == len(raw) and actual['sha256'] == sha256(raw).hexdigest(),
            'small capture inventory readback differs')
    return {'status': result['status'], 'complete': result['complete'], 'files': len(result['files']),
            'bytes_reserved': reserved, 'receipt': actual, 'errors': result['errors'][:32],
            'all_errors_retained_in_complete_receipt': True}



def finalize(args):
    require(TOKEN_VARIABLE not in os.environ and 'GITHUB_TOKEN' not in os.environ
            and 'GH_TOKEN' not in os.environ, 'read token entered public finalization')
    control, policy, _, root, public, context = policy_and_context(args)
    global GZIP_HELPER
    GZIP_HELPER = load_gzip_helper(control, policy)
    pin = fixed_policy(policy)
    parts = expected_parts(policy)
    require(not os.path.lexists(public), 'public custody already exists; do not replay')
    public.mkdir(mode=0o700)
    (public / 'small').mkdir(mode=0o700)
    for item in parts:
        directory = public / ('part-%02d' % item['ordinal'])
        directory.mkdir(mode=0o700)
        (directory / 'controls').mkdir(mode=0o700)
    result = {'schema': 'hia.actions.v88-full-original-parts-final.v1',
              'status': 'FULL_ZIP_CUSTODY_HOLD', 'context': context, 'artifact': pin,
              'expected_parts': parts, 'parts': [], 'errors': [], 'missing_originals': [],
              'typed_download_observations': [], 'typed_slice_observations': [], 'captured_controls': [],
              'new_product_execution': False, 'old_runs_replayed': False,
              'historical_results_reclassified': False, 'all_available_original_bodies_read': False,
              'full_5400_retained_suite_executed': False, 'artifact_uploads_not_yet_observed': True,
              'original_full_ZIP_retained_private': False,
              'private_slice_copies_relocated_not_duplicated': True,
              'original_ZIP_bytes_or_compression_changed': False}
    setup = None
    closed = False
    natural = False
    accepted = False
    captures_complete = True
    storage_observed = False
    small_complete = False
    report = None
    copied = []
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
            original, originals = accept_worker(report, policy, setup, root)
            result['original_zip'] = original
            result['private_partition_readback'] = concat_parts(originals, pin, parts)
            for item, source_record in zip(parts, originals):
                destination = public / ('part-%02d' % item['ordinal']) / 'slice.bin.gz'
                actual = relocate_slice(Path(source_record['path']), destination, source_record)
                copied.append(actual)
                result['parts'].append({**item, 'kind': 'SEALED_SINGLE_GZIP_OF_ORIGINAL_RANGE',
                                        'source': source_record, 'retained': actual,
                                        'publication': 'SAME_INODE_RELOCATION_AFTER_CLOSED_ECHILD',
                                        'private_slice_name_removed': True})
            result['public_partition_readback'] = concat_parts(copied, pin, parts)
            require(file_record(Path(original['path']), pin['bytes']) == original,
                    'original ZIP changed after public copies')
            accepted = True
            result['original_full_ZIP_retained_private'] = True
        except BaseException as exc:
            error('ORIGINAL_AND_PARTS', exc)
    except BaseException as exc:
        error('CLOSED_BOUNDARY', exc)

    if closed:
        try:
            result['small_diagnostics'] = capture_small(root, public, policy,
                report.get('inspection') if type(report) is dict else None)
            small_complete = result['small_diagnostics']['complete']
            result['all_available_original_bodies_read'] = small_complete
        except BaseException as exc:
            error('SMALL_DIAGNOSTIC_CUSTODY', exc)
        original_name = 'artifact-%d.zip' % pin['id']
        fixed_downloads = [root / 'original' / original_name,
                           root / 'original' / (original_name + '.partial')]
        for path in fixed_downloads:
            try:
                result['typed_download_observations'].append(typed_observation(path))
            except BaseException as exc:
                error('DOWNLOAD_TYPE', exc)
        if not accepted:
            # Preserve one bounded payload per part. Never replace a partial or
            # completed copy already made above. nlink2 and nonregular originals
            # remain typed observations and HOLD, not weakened admission.
            for item in parts:
                directory = public / ('part-%02d' % item['ordinal'])
                destination = directory / 'slice.bin.gz'
                if os.path.lexists(destination):
                    if not any(x['ordinal'] == item['ordinal'] for x in result['parts']):
                        try:
                            actual = file_record(destination, 313 << 20)
                            result['parts'].append({**item, 'kind': 'UNVERIFIED_PARTIAL_PUBLIC_COPY',
                                                    'source': None, 'retained': actual})
                        except BaseException as exc:
                            error('PARTIAL_PUBLIC_%d' % item['ordinal'], exc)
                    continue
                try:
                    source = root / 'parts' / item['name']
                    if os.path.lexists(source):
                        source_record = file_record(source, 313 << 20)
                        actual = relocate_slice(source, directory / 'unverified-range.bin.gz', source_record)
                    else:
                        source = next((p for p in fixed_downloads if os.path.lexists(p)), None)
                        require(source is not None, 'no failed original bytes available')
                        source_record = file_record(source, pin['bytes'])
                        actual = copy_unverified_range(source, directory / 'unverified-range.bin', source_record, item)
                    result['parts'].append({**item, 'kind': 'UNVERIFIED_FAILURE_RANGE',
                                            'source': source_record, 'retained': actual})
                except BaseException as exc:
                    error('FAILURE_RANGE_%d' % item['ordinal'], exc)
        for item in parts:
            for observed_path in (root / 'parts' / item['name'],
                                  public / ('part-%02d' % item['ordinal']) / 'slice.bin.gz',
                                  public / ('part-%02d' % item['ordinal']) / 'unverified-range.bin',
                                  public / ('part-%02d' % item['ordinal']) / 'unverified-range.bin.gz'):
                try:
                    result['typed_slice_observations'].append(typed_observation(observed_path))
                except BaseException as exc:
                    error('SLICE_TYPE_%d' % item['ordinal'], exc)
        fixed = ['context.json', 'setup.json', 'guard/request.json', 'guard/guardian.json',
                 'guard/child.stdout.log', 'guard/child.stderr.log',
                 'supervisor.stdout.log', 'supervisor.stderr.log',
                 'recovery.json', 'recovery-terminal.json',
                 'api/artifact-%d.metadata.original.json' % pin['id']]
        diagnostic_bytes = 0
        diagnostic_reserved_bytes = 0
        for name in fixed:
            path = root / name
            try:
                if not os.path.lexists(path):
                    result['missing_originals'].append(name)
                    captures_complete = False
                    continue
                actual = file_record(path, 8 << 20)
                require(diagnostic_reserved_bytes + actual['bytes'] <= MAX_DIAGNOSTIC_BYTES,
                        'whole diagnostic originals exceed per-part bound')
                # Reserve before the first copy. A partial copy failure cannot
                # make its actual occupied bytes disappear from the next gate.
                diagnostic_reserved_bytes += actual['bytes']
                destinations = []
                for item in parts:
                    destination = public / ('part-%02d' % item['ordinal']) / 'controls' / name.replace('/', '--')
                    destinations.append(copy_original(path, destination, actual))
                destinations.append(copy_original(path, public / 'small' / ('current--' + name.replace('/', '--')), actual))
                diagnostic_bytes += actual['bytes']
                result['captured_controls'].append({'name': name, 'original': actual, 'copies': destinations})
            except BaseException as exc:
                captures_complete = False
                error('CAPTURE_' + name, exc)
        result['diagnostic_bytes_per_part'] = diagnostic_bytes
        result['diagnostic_budget_reserved_bytes_per_part'] = diagnostic_reserved_bytes
        try:
            result['source_inputs_final'] = final_input_records(setup, context)
            result['source_inputs_preserved'] = True
        except BaseException as exc:
            error('FINAL_SOURCE_INPUTS', exc)
        try:
            result['closed_storage_observation'] = closed_storage_observation(root, public, policy)
            storage_observed = True
        except BaseException as exc:
            error('CLOSED_STORAGE_BUDGET', exc)

    complete = (closed and natural and accepted and captures_complete and storage_observed and small_complete
                and result.get('original_full_ZIP_retained_private') is True
                and result.get('source_inputs_preserved') is True
                and len(result['parts']) == len(parts) and not result['errors']
                and not result['missing_originals'])
    result['complete_local_multipart_readback'] = complete
    if complete:
        result['status'] = 'SEALED_CONTIGUOUS_PARTS_VERIFIED_NOT_QUALIFICATION'
    for item in parts:
        directory = public / ('part-%02d' % item['ordinal'])
        member = next((x for x in result['parts'] if x['ordinal'] == item['ordinal']), None)
        part_doc = {'schema': 'hia.v88-original-zip-part.v1', 'artifact': pin,
                    'expected': item, 'observed': member, 'status': result['status'],
                    'run_id': context['run_id'], 'run_attempt': 1,
                    'workflow_commit': context['actual_workflow_commit'],
                    'control_commit': context['actual_control_checkout'],
                    'policy_sha256': context['policy_sha256'],
                    'qualification_executed': False, 'artifact_upload_not_yet_observed': True}
        raw = wire(part_doc)
        require(len(raw) <= 1 << 20, 'whole PART document exceeds fixed bound')
        create(directory / 'PART.json', raw)
        require(read(directory / 'PART.json', 1 << 20) == raw, 'PART independent readback differs')
    final_raw = wire(result)
    require(len(final_raw) <= 2 << 20, 'whole FINAL document exceeds fixed bound')
    for item in parts:
        directory = public / ('part-%02d' % item['ordinal'])
        create(directory / 'FINAL.json', final_raw)
        require(read(directory / 'FINAL.json', 2 << 20) == final_raw, 'FINAL independent readback differs')
        actual_files = []
        for path in sorted(directory.rglob('*')):
            entry = path.lstat()
            require(not stat.S_ISLNK(entry.st_mode), 'public symlink refused')
            if stat.S_ISDIR(entry.st_mode):
                require(entry.st_uid == os.geteuid(), 'public directory ownership differs')
            else:
                actual_files.append(file_record(path, MAX_PUBLIC_BYTES))
        require(len(actual_files) <= 14
                and sum(x['bytes'] for x in actual_files) <= MAX_PUBLIC_BYTES,
                'public fixed artifact exceeds file or byte cap')
        sync_dir(directory / 'controls')
        sync_dir(directory)
    create(public / 'small' / 'FINAL.json', final_raw)
    require(read(public / 'small' / 'FINAL.json', 2 << 20) == final_raw,
            'small-channel FINAL readback differs')
    small_files = []
    for path in sorted((public / 'small').iterdir()):
        small_files.append(file_record(path, 64 << 20))
    require(len(small_files) <= 4128 and sum(x['bytes'] for x in small_files) <= 224 << 20,
            'complete small diagnostic artifact exceeds fixed count/byte bound')
    sync_dir(public / 'small')
    sync_dir(public)
    print(json.dumps({'status': result['status'], 'parts': len(parts),
                      'complete_local_multipart_readback': complete,
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
