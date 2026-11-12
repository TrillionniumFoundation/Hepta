"""Deliver two sealed contiguous parts of one historical ZIP; execute no product code."""
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
PARTS = [
    {'ordinal': 0, 'offset': 0, 'bytes': 314572800, 'name': 'part-00.bin'},
    {'ordinal': 1, 'offset': 314572800, 'bytes': 299648266, 'name': 'part-01.bin'},
]

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
    require(policy.get('schema') == 'hia.actions.v79-full-original-two-parts-policy.v1'
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
    context = {'schema': 'hia.actions.v79-full-original-two-parts-context.v1',
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
    setup = {'schema': 'hia.actions.v79-full-original-two-parts-setup.v1',
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
    require(setup.get('schema') == 'hia.actions.v79-full-original-two-parts-setup.v1'
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
    pin = policy['artifact']
    require(policy['parts'] == PARTS and pin['id'] == 13929074168
            and pin['bytes'] == 614221066
            and pin['sha256'] == 'b2a546f720b3a29b71a3f6372cd0f122adb1c6bbe4593aaee3b9d135175aa471'
            and pin['run_id'] == 43182678063 and pin['run_attempt'] == 1
            and pin['checkout_commit'] == '9739fb896037aedd9f29dae178c6ae1c8bc31827'
            and pin['checkout_tree'] == '83a43be6fd510e55c4843cfa8a00aa4889b246cf'
            and policy['limits'] == {'controller_seconds': 900, 'cleanup_seconds': 3,
                'transfer_seconds': 720, 'part_bytes': 314572800,
                'public_part_bytes': 335544320, 'diagnostic_bytes_per_part': 2097152},
            'fixed artifact, two ranges, or custody limits differ')
    return pin


def same_original_record(expected, actual):
    require(type(expected) is dict
            and all(expected.get(key) == actual[key] for key in ('path', 'bytes', 'sha256', 'identity'))
            and expected.get('actual_bytes_independently_read') == actual['bytes'],
            'actual original full read differs from worker receipt')


def accept_worker(report, policy, setup, root):
    pin = fixed_policy(policy)
    require(report.get('schema') == 'hia.actions.v79-full-original-two-parts-worker.v1'
            and report.get('status') == 'TWO_SEALED_PARTS_PENDING_NATURAL_GUARDIAN'
            and report.get('root') == str(root)
            and report.get('policy_sha256') == setup['context']['policy_sha256']
            and report.get('source') == policy['source'] and report.get('artifact') == pin
            and report.get('qualification_executed') is False
            and report.get('project_code_executed') is False
            and report.get('old_runs_replayed') is False
            and report.get('original_product_statuses_reclassified') is False
            and report.get('original_ZIP_members_decompressed') is False
            and report.get('token_or_signed_URL_recorded') is False
            and report.get('natural_guardian_acceptance_required') is True,
            'worker complete two-part result or scope differs')
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
            and len(partition.get('parts', [])) == 2,
            'two-part worker partition differs')
    records = []
    for expected, produced in zip(PARTS, partition['parts']):
        require(all(produced.get(k) == v for k, v in expected.items()), 'part range differs')
        actual = file_record(root / 'parts' / expected['name'], expected['bytes'])
        require(actual['bytes'] == expected['bytes'] and stat.S_IMODE(actual['identity'][2]) == 0o400,
                'complete read-only part required')
        same_original_record(produced.get('original'), actual)
        records.append(actual)
    return original, records


def concat_parts(records, pin):
    combined, total = sha256(), 0
    for expected, record in zip(PARTS, records):
        path = Path(record['path'])
        require(total == expected['offset'] and record['bytes'] == expected['bytes'],
                'concatenation range differs')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as source:
            before = os.fstat(source.fileno())
            require(list(identity(before)) == record['identity'], 'part changed before concatenation')
            count, digest = 0, sha256()
            while True:
                block = source.read(CHUNK)
                if not block:
                    break
                count += len(block)
                require(count <= expected['bytes'], 'part grew while concatenating')
                combined.update(block)
                digest.update(block)
            require(count == expected['bytes'] and digest.hexdigest() == record['sha256']
                    and identity(before) == identity(os.fstat(source.fileno()))
                    and identity(before) == identity(path.lstat()), 'part changed while concatenating')
            total += count
    require(total == pin['bytes'] and combined.hexdigest() == pin['sha256'],
            'concatenated actual parts do not reproduce original ZIP')
    return {'bytes': total, 'sha256': combined.hexdigest(), 'exact_contiguous_partition': True}


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
    for item in PARTS:
        directory = public / ('part-%02d' % item['ordinal'])
        directory.mkdir(mode=0o700)
        (directory / 'controls').mkdir(mode=0o700)
    result = {'schema': 'hia.actions.v79-full-original-two-parts-final.v1',
              'status': 'FULL_ZIP_CUSTODY_HOLD', 'context': context, 'artifact': pin,
              'expected_parts': PARTS, 'parts': [], 'errors': [], 'missing_originals': [],
              'typed_download_observations': [], 'captured_controls': [],
              'new_product_execution': False, 'old_runs_replayed': False,
              'historical_results_reclassified': False, 'original_ZIP_members_decompressed': False,
              'full_5400_retained_suite_executed': False, 'artifact_uploads_not_yet_observed': True}
    setup = None
    closed = False
    natural = False
    accepted = False
    captures_complete = True
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
            result['private_partition_readback'] = concat_parts(originals, pin)
            for item, source_record in zip(PARTS, originals):
                destination = public / ('part-%02d' % item['ordinal']) / 'slice.bin'
                actual = copy_original(Path(source_record['path']), destination, source_record)
                copied.append(actual)
                result['parts'].append({**item, 'kind': 'SEALED_ORIGINAL_RANGE',
                                        'source': source_record, 'retained': actual})
            result['public_partition_readback'] = concat_parts(copied, pin)
            require(file_record(Path(original['path']), pin['bytes']) == original,
                    'original ZIP changed after public copies')
            accepted = True
        except BaseException as exc:
            error('ORIGINAL_AND_PARTS', exc)
    except BaseException as exc:
        error('CLOSED_BOUNDARY', exc)

    if closed:
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
            for item in PARTS:
                directory = public / ('part-%02d' % item['ordinal'])
                destination = directory / 'slice.bin'
                if os.path.lexists(destination):
                    if not any(x['ordinal'] == item['ordinal'] for x in result['parts']):
                        try:
                            actual = file_record(destination, item['bytes'])
                            result['parts'].append({**item, 'kind': 'UNVERIFIED_PARTIAL_PUBLIC_COPY',
                                                    'source': None, 'retained': actual})
                        except BaseException as exc:
                            error('PARTIAL_PUBLIC_%d' % item['ordinal'], exc)
                    continue
                try:
                    source = root / 'parts' / item['name']
                    if os.path.lexists(source):
                        source_record = file_record(source, item['bytes'])
                        actual = copy_original(source, directory / 'unverified-range.bin', source_record)
                    else:
                        source = next((p for p in fixed_downloads if os.path.lexists(p)), None)
                        require(source is not None, 'no failed original bytes available')
                        source_record = file_record(source, pin['bytes'])
                        actual = copy_unverified_range(source, directory / 'unverified-range.bin', source_record, item)
                    result['parts'].append({**item, 'kind': 'UNVERIFIED_FAILURE_RANGE',
                                            'source': source_record, 'retained': actual})
                except BaseException as exc:
                    error('FAILURE_RANGE_%d' % item['ordinal'], exc)
        fixed = ['context.json', 'setup.json', 'guard/request.json', 'guard/guardian.json',
                 'guard/child.stdout.log', 'guard/child.stderr.log',
                 'supervisor.stdout.log', 'supervisor.stderr.log',
                 'recovery.json', 'recovery-terminal.json',
                 'api/artifact-13929074168.metadata.original.json']
        diagnostic_bytes = 0
        for name in fixed:
            path = root / name
            try:
                if not os.path.lexists(path):
                    result['missing_originals'].append(name)
                    captures_complete = False
                    continue
                actual = file_record(path, 8 << 20)
                require(diagnostic_bytes + actual['bytes'] <= MAX_DIAGNOSTIC_BYTES,
                        'whole diagnostic originals exceed per-part bound')
                destinations = []
                for item in PARTS:
                    destination = public / ('part-%02d' % item['ordinal']) / 'controls' / name.replace('/', '--')
                    destinations.append(copy_original(path, destination, actual))
                diagnostic_bytes += actual['bytes']
                result['captured_controls'].append({'name': name, 'original': actual, 'copies': destinations})
            except BaseException as exc:
                captures_complete = False
                error('CAPTURE_' + name, exc)
        result['diagnostic_bytes_per_part'] = diagnostic_bytes
        try:
            result['source_inputs_final'] = final_input_records(setup, context)
            result['source_inputs_preserved'] = True
        except BaseException as exc:
            error('FINAL_SOURCE_INPUTS', exc)

    complete = (closed and natural and accepted and captures_complete
                and result.get('source_inputs_preserved') is True
                and len(result['parts']) == 2 and not result['errors']
                and not result['missing_originals'])
    result['complete_local_two_part_readback'] = complete
    if complete:
        result['status'] = 'TWO_SEALED_CONTIGUOUS_PARTS_VERIFIED_NOT_QUALIFICATION'
    for item in PARTS:
        directory = public / ('part-%02d' % item['ordinal'])
        member = next((x for x in result['parts'] if x['ordinal'] == item['ordinal']), None)
        part_doc = {'schema': 'hia.v79-original-zip-part.v1', 'artifact': pin,
                    'expected': item, 'observed': member, 'status': result['status'],
                    'run_id': context['run_id'], 'run_attempt': 1,
                    'workflow_commit': context['actual_workflow_commit'],
                    'control_commit': context['actual_control_checkout'],
                    'policy_sha256': context['policy_sha256'],
                    'qualification_executed': False, 'artifact_upload_not_yet_observed': True}
        raw = wire(part_doc)
        create(directory / 'PART.json', raw)
        require(read(directory / 'PART.json', 1 << 20) == raw, 'PART independent readback differs')
    final_raw = wire(result)
    for item in PARTS:
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
    sync_dir(public)
    print(json.dumps({'status': result['status'], 'parts': 2,
                      'complete_local_two_part_readback': complete,
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
