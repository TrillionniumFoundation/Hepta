"""Own one small-artifact read and frame exact original bytes after cleanup."""
from __future__ import annotations

from hashlib import sha256
import argparse
import base64
import json
import importlib.util
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
    require(policy.get('schema') == 'hia.actions.970-inner-archive-slice-policy.v1'
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
    partition = load_selector(control, policy).partition_for(policy, args.partition)
    root = temp / (policy['work_root_name'] + '-' + partition['id'])
    public = temp / (policy['public_root_name'] + '-' + partition['id'])
    require(args.root.is_absolute() and args.root == root
            and not any(x.is_symlink() for x in (temp, *temp.parents)),
            'new runner root or ancestor differs')
    context = {'schema': 'hia.actions.970-inner-archive-slice-context.v1',
        'repository': REPO, 'event': 'create', 'event_ref': event['ref'], 'event_ref_type': 'branch',
        'event_sha256': sha256(event_raw).hexdigest(), 'run_attempt': 1,
        'run_id': int(os.environ['GITHUB_RUN_ID']), 'run_number': int(os.environ['GITHUB_RUN_NUMBER']),
        'actual_workflow_commit': workflow_sha, 'actual_control_checkout': args.control_commit,
        'original_product_commit': policy['source']['head'], 'original_product_tree': policy['source']['tree'],
        'policy_sha256': args.policy_sha256, 'root': str(root), 'public_root': str(public),
        'partition': partition, 'inner_archive_pin': policy['inner_archive'],
        'python': {'executable': sys.executable, 'resolved': str(Path(sys.executable).resolve()),
                   'version': sys.version, 'binary': file_record(Path(sys.executable).resolve(), 64 << 20, system_binary=True)},
        'runtime_observed': {'uname': list(os.uname()),
            'ImageOS': os.environ.get('ImageOS'), 'ImageVersion': os.environ.get('ImageVersion'),
            'runner_label_requested': policy['runner_label_requested'],
            'runtime_equivalence_to_prior_CI_claimed': False},
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
               '--policy-sha256', args.policy_sha256, '--partition', partition_id(context)]
    config = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 900,
              'command': command, 'cwd': str(root), 'source_identities': identities}
    config_raw = wire(config)
    create(root / 'guard/request.json', config_raw)
    setup = {'schema': 'hia.actions.970-inner-archive-slice-setup.v1',
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


def partition_id(context):
    value = context.get('partition')
    require(type(value) is dict and type(value.get('id')) is str
            and re.fullmatch(r'(?:0[0-9]|1[0-8])', value['id']) is not None,
            'current context partition identity differs')
    return value['id']


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
               '--policy-sha256', context['policy_sha256'], '--partition', partition_id(context)]
    require(setup.get('schema') == 'hia.actions.970-inner-archive-slice-setup.v1'
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




def load_selector(control, policy):
    path = control / 'diagnostic_selection.py'
    pin = policy['control_files']['diagnostic_selection.py']
    raw = read(path, 1 << 20, pin['sha256'])
    require(len(raw) == pin['bytes'], 'fixed pure diagnostic selector size differs')
    spec = importlib.util.spec_from_file_location('_hia_970_diagnostic_selection', path)
    require(spec is not None and spec.loader is not None, 'diagnostic selector loader unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(list(module.HISTORICAL_TARGETS) == policy['diagnostic_targets']['historical']
            and list(module.CURRENT_READER_TARGETS) == policy['diagnostic_targets']['reader']
            and module.RAW_LIMIT == 512 << 10 and module.STDOUT_LIMIT == 1 << 20
            and module.FRAME_BYTES == 24 << 10
            and module.HISTORICAL_ALLOWANCE == 448 << 10
            and module.CURRENT_READER_ALLOWANCE == 64 << 10,
            'fixed pure diagnostic selector contract differs')
    return module


FRAME_BYTES = 24 << 10
MAX_FRAME_RAW = 512 << 10
MAX_FRAME_STDOUT = 1 << 20
MAX_FRAME_FILES = 6

ORIGINAL_BASE_RECORDS = (
    'context.json', 'setup.json', 'recovery.json', 'recovery-terminal.json',
    'supervisor.stdout.log', 'supervisor.stderr.log', 'guard/request.json',
    'guard/guardian.json', 'guard/child.stdout.log', 'guard/child.stderr.log',
    'api/artifact-13911977275.metadata.original.json',
    'selected/13911977275/DIRECTORY.json', 'selected/13911977275/SELECTED.json',
    'selected/13911977275/CUSTODY.json', 'selected/13911977275/OBSERVATIONS.json',
)


def frame_target_names(policy):
    names = policy['diagnostic_targets']['historical']
    require(type(names) is list and len(names) == len(set(names)) == 1
            and all(type(name) is str and name.startswith('custody/') for name in names),
            'fixed one compressed-original slice target differs')
    return names


def observed_frame_files(report, policy, root, *, partition, partial_metadata=False):
    expected = set(frame_target_names(policy))
    require(partition == load_selector(root / 'control', policy).partition_for(policy, partition['id'])
            and report.get('partition') == partition,
            'worker partition differs from fixed current setup')
    files = report.get('frame_files')
    require(type(files) is list and len(files) <= 1
            and all(type(x) is dict for x in files)
            and len({x.get('logical_path') for x in files}) == len(files)
            and {x.get('logical_path') for x in files} <= expected,
            'fixed original slice inventory differs')
    observed = []
    for item in files:
        record = item['record']
        path = Path(record['path'])
        relative = path.relative_to(root).as_posix()
        require(relative == 'selected/inner-archive.slice.bin'
                and item['logical_path'] == partition['logical_path'] ==
                    'custody/inner-selected.zip.slice',
                'slice source is outside the fixed owned location')
        require(not any(x.is_symlink() for x in (path, *path.parents)),
                'slice source ancestor changed to a link')
        actual = file_record(path, 448 << 10)
        require(actual['bytes'] == record['bytes'] == partition['bytes']
                and actual['sha256'] == record['sha256']
                and actual['identity'] == record['identity']
                and record['actual_bytes_independently_read'] == actual['bytes'],
                'actual slice differs from owned original interval')
        claim, pin = report.get('archive_slice'), policy['inner_archive']
        require(type(claim) is dict and claim.get('partition') == partition
                and claim.get('inner_archive_pin') == pin
                and claim.get('bytes') == actual['bytes'] and claim.get('sha256') == actual['sha256']
                and claim.get('source_relative_path') == pin['source_relative_path']
                and claim.get('retained_original_member') == pin['retained_file']
                and claim.get('full_inner_sha256_verified') is True
                and claim.get('same_original_range_independently_read') is True
                and claim.get('inner_members_opened') is False
                and claim.get('original_bytes_recompressed') is False,
                'owned slice-to-whole-original binding differs')
        inner_path = root / 'captured' / pin['retained_file']
        inner = file_record(inner_path, pin['bytes'])
        sealed = claim.get('inner_before')
        require(type(sealed) is dict
                and set(sealed) == {'path', 'bytes', 'sha256', 'identity',
                                    'actual_bytes_independently_read'}
                and sealed == claim.get('inner_after')
                and inner == {key: value for key, value in sealed.items()
                              if key != 'actual_bytes_independently_read'}
                and inner['bytes'] == pin['bytes'] == 8316154
                and inner['sha256'] == pin['sha256'] ==
                    'd72ca1e53539f1cab6ab836c20a02c39b6700025e62890f0e5a1cfeaea700a5e'
                and sealed['actual_bytes_independently_read'] == pin['bytes'],
                'actual whole compressed original differs after cleanup')
        # Compare the actual interval again, after the bound owner is closed.
        # The full inner ZIP remains opaque compressed bytes throughout this job.
        raw = read(inner_path, pin['bytes'], pin['sha256'])
        piece = read(path, partition['bytes'], actual['sha256'])
        require(len(raw) == pin['bytes']
                and piece == raw[partition['offset']:partition['offset'] + partition['bytes']]
                and file_record(inner_path, pin['bytes']) == inner,
                'independent interval-to-original byte comparison differs')
        observed.append({'logical_path': item['logical_path'], 'record': actual,
                         'origin': item['origin']})
    if partial_metadata:
        require(report.get('outer_originals_verified') is True
                and report.get('original_final_sha256') == policy['original_final_sha256']
                and report.get('original_final_status') == 'CUSTODY_HOLD',
                'partial slice lacks authenticated original outer binding')
        read(root / 'captured/FINAL.json', 1 << 20, policy['original_final_sha256'])
    else:
        missing = report.get('missing_frame_targets')
        require(type(missing) is list and len(set(missing)) == len(missing)
                and not {x['logical_path'] for x in files} & set(missing)
                and {x['logical_path'] for x in files} | set(missing) == expected
                and report.get('expected_frame_targets') == frame_target_names(policy),
                'one original slice present/missing accounting differs')
    return observed


def accept_small_reader(report, setup, policy, root):
    require(report.get('schema') == 'hia.actions.970-inner-archive-slice-worker.v1'
            and report.get('status') == 'INNER_ARCHIVE_SLICE_VERIFIED_PENDING_NATURAL_GUARDIAN'
            and report.get('root') == str(root)
            and report.get('policy_sha256') == setup['context']['policy_sha256']
            and report.get('small_artifact') == policy['small_artifact']
            and report.get('original_final_sha256') == policy['original_final_sha256'],
            'source-bound small-reader terminal differs')
    for name in ('original_large_artifacts_downloaded', 'project_code_executed',
                 'qualification_executed', 'original_product_statuses_reclassified',
                 'token_or_signed_URL_recorded'):
        require(report.get(name) is False, 'small-reader scope differs')
    calls, gets = report.get('API_attempts'), report.get('GET_attempts')
    pin = policy['small_artifact']
    require(type(calls) is list and len(calls) == 2
            and [x.get('role') for x in calls] == ['official_metadata', 'official_download_redirect']
            and all(x.get('artifact_id') == pin['id'] and x.get('attempt') == 1
                    and x.get('retries') == 0 and x.get('host') == 'api.github.com'
                    and x.get('credential_sent_only_to_official_API') is True for x in calls)
            and calls[0].get('status') == 200 and calls[1].get('status') == 302
            and calls[1].get('authorization_forwarded') is False
            and calls[1].get('signed_Location_recorded') is False
            and type(gets) is list and len(gets) == 1,
            'one-small-artifact official request denominator differs')
    get = gets[0]
    require(get.get('artifact_id') == pin['id'] and get.get('attempt') == 1
            and get.get('redirects') == 0 and get.get('retries') == 0
            and get.get('authorization_sent') is False and get.get('cookies_sent') is False
            and get.get('bytes') == pin['bytes'] and get.get('sha256') == pin['sha256'],
            'single anonymous small ZIP GET differs')
    before, after = report.get('small_zip_before'), report.get('small_zip_after')
    require(type(before) is dict and before == after and before.get('bytes') == pin['bytes']
            and before.get('sha256') == pin['sha256']
            and before.get('actual_bytes_independently_read') == pin['bytes'],
            'two independent small ZIP full reads differ')
    require(report.get('original_final_status') == 'CUSTODY_HOLD'
            and report.get('outer_originals_verified') is True
            and report.get('original_captured_count') == policy['expected_captured_count']
            and report.get('original_cold_or_compiler_headers_reclassified') is False
            and report.get('unselected_original_product_members_executed') is False
            and report.get('inner_selected_archive_opened') is False
            and report.get('original354_bodies_read') is False,
            'historical HOLD or no-product scope differs')
    require(report.get('official_metadata', {}).get('provider_head_sha_observed') ==
            policy['original_operation']['workflow_commit'],
            'small artifact provider head differs from original custody workflow')
    return observed_frame_files(report, policy, root, partition=setup['context']['partition'])


def output_frames(files, context, extra, terminal_status):
    require(len(files) <= MAX_FRAME_FILES and len({x['logical_path'] for x in files}) == len(files)
            and sum(x['record']['bytes'] for x in files) <= MAX_FRAME_RAW,
            'all original frame sources exceed the fixed output bound')
    manifest = {'schema': 'hia.original-log-frame-manifest.v1', 'context': context,
        'files': [{'path': x['logical_path'], 'bytes': x['record']['bytes'],
                   'sha256': x['record']['sha256'], 'origin': x['origin']} for x in files],
        'frame_bytes': FRAME_BYTES,
        'frame_count': sum((x['record']['bytes'] + FRAME_BYTES - 1) // FRAME_BYTES for x in files),
        'total_raw_bytes': sum(x['record']['bytes'] for x in files),
        'maximum_raw_bytes': MAX_FRAME_RAW, 'maximum_stdout_bytes': MAX_FRAME_STDOUT,
        'original_product_statuses_reclassified': False, 'qualification_executed': False,
        **extra}
    manifest_raw = wire(manifest)
    require(len(manifest_raw) <= 128 << 10, 'frame manifest exceeds bound')
    manifest_sha = sha256(manifest_raw).hexdigest()
    manifest_path = Path(context['public_root']) / 'FRAME-MANIFEST.json'
    create(manifest_path, manifest_raw)
    require(read(manifest_path, 128 << 10) == manifest_raw, 'frame manifest readback differs')
    sync_dir(manifest_path.parent)
    count, raw_count, stdout_count = 0, 0, 0
    def emit(prefix, value):
        nonlocal stdout_count
        line = (prefix + ' ' + json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
        require(stdout_count + len(line) <= MAX_FRAME_STDOUT, 'bounded Actions log output exhausted')
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
        stdout_count += len(line)
    emit('HIA_ORIGINAL_FRAME_MANIFEST_V1', {
        'bytes': len(manifest_raw), 'sha256': manifest_sha,
        'base64': base64.b64encode(manifest_raw).decode('ascii')})
    for item in files:
        path = Path(item['record']['path'])
        expected = item['record']
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(list(identity(before)) == expected['identity'], 'frame source identity changed before output')
            offset, digest = 0, sha256()
            while True:
                block = stream.read(FRAME_BYTES)
                if not block:
                    break
                require(offset + len(block) <= expected['bytes'], 'frame source grew')
                emit('HIA_ORIGINAL_FRAME_V1', {
                    'manifest_sha256': manifest_sha, 'path': item['logical_path'],
                    'offset': offset, 'length': len(block), 'sha256': sha256(block).hexdigest(),
                    'base64': base64.b64encode(block).decode('ascii')})
                digest.update(block)
                offset += len(block)
                count += 1
                raw_count += len(block)
            require(offset == expected['bytes'] and digest.hexdigest() == expected['sha256']
                    and identity(before) == identity(os.fstat(stream.fileno()))
                    and identity(before) == identity(path.lstat()),
                    'complete frame source changed during output')
    require(count == manifest['frame_count'] and raw_count == manifest['total_raw_bytes'],
            'complete frame count or raw-byte denominator differs')
    terminal = {
        'schema': 'hia.original-log-frame-terminal.v1', 'status': terminal_status,
        'manifest_sha256': manifest_sha, 'files': len(files), 'frames': count,
        'raw_bytes': raw_count, 'source_bytes_complete': True,
        'original_custody_status': extra.get('original_custody_status'),
        'missing_frame_targets': extra.get('missing_frame_targets', []),
        'original_product_statuses_reclassified': False, 'qualification_executed': False}
    return ({'manifest_sha256': manifest_sha, 'files': len(files), 'frames': count,
             'raw_bytes': raw_count, 'stdout_bytes': stdout_count, 'status': terminal_status}, terminal)


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


def finalize(args):
    require(TOKEN_VARIABLE not in os.environ, 'read token entered original log framing')
    _, policy, _, root, public, context = policy_and_context(args)
    require(not os.path.lexists(public), 'new original-recovery directory already exists')
    os.umask(0o077)
    public.mkdir(mode=0o700, exist_ok=False)
    expected = frame_target_names(policy)
    result = {'schema': 'hia.actions.970-inner-archive-slice-result.v1', 'status': 'FRAMING_HOLD',
        'context': context, 'qualification_executed': False,
        'original_product_statuses_reclassified': False, 'original_CI_rerun': False,
        'original_large_artifacts_downloaded': False, 'errors': [],
        'original_custody_status': 'CUSTODY_HOLD', 'historical_targets': expected,
        'source_missing_targets': list(expected), 'budget_omitted_targets': [],
        'partition': context['partition'], 'inner_archive_pin': policy['inner_archive'],
        'retained_originals': [], 'expected_historical_targets': 1,
        'previous_large_frame_recovery': policy['previous_recovery']}
    files, pending_terminal = [], None
    source_ok = False
    report = None
    try:
        setup, _ = document(root / 'setup.json')
        check_setup(setup, context, policy, root)
        guardian, _ = document(root / 'guard/guardian.json')
        require(closed_guardian(guardian, setup, policy, root),
                'no bound closed cleanup; do not inspect live child originals')
        result['closed_ECHILD_before_read'] = True
        small_path = root / 'original' / ('artifact-%d.zip' % policy['small_artifact']['id'])
        partial_path = small_path.with_name(small_path.name + '.partial')
        result['download_name_observations'] = []
        for name, path in (('complete', small_path), ('partial', partial_path)):
            try:
                info = path.lstat()
                result['download_name_observations'].append({'name': name,
                    'path': str(path), 'identity': list(identity(info)),
                    'regular': stat.S_ISREG(info.st_mode), 'symlink': stat.S_ISLNK(info.st_mode),
                    'observation_only_not_complete_seal': True})
            except FileNotFoundError:
                result['download_name_observations'].append({'name': name, 'path': str(path),
                    'missing': True, 'observation_only_not_complete_seal': True})
            except BaseException as error:
                result['errors'].append({'stage': 'DOWNLOAD_NAME_OBSERVATION',
                    'name': name, 'type': type(error).__name__})
        try:
            require(os.path.lexists(small_path), 'complete original small ZIP is missing')
            actual_small = file_record(small_path, policy['small_artifact']['bytes'])
            require(actual_small['bytes'] == policy['small_artifact']['bytes']
                    and actual_small['sha256'] == policy['small_artifact']['sha256'],
                    'retained small ZIP differs from external original seal')
            copied_small = copy_original(small_path, public / 'SMALL-ARTIFACT.original.zip', actual_small)
            result['retained_small_artifact'] = copied_small
            result['retained_small_artifact_source'] = actual_small
            result['complete_small_artifact_independently_retained'] = True
        except BaseException as error:
            result['complete_small_artifact_independently_retained'] = False
            result['errors'].append({'stage': 'SMALL_ARCHIVE_CUSTODY', 'type': type(error).__name__,
                'safe_refusal': str(error) if type(error) is Refusal else None})
        # A failed HTTP transfer is evidence, never a complete sealed input.
        # Keep the strict single-link rule: a two-alias link/unlink window is
        # recorded above as typed metadata and refused as readable custody.
        if os.path.lexists(partial_path):
            try:
                partial_record = file_record(partial_path, policy['small_artifact']['bytes'])
                partial_copy = copy_original(partial_path, public / 'SMALL-ARTIFACT.partial.original',
                                             partial_record)
                result['retained_partial_download'] = partial_copy
                result['retained_partial_download_source'] = partial_record
                result['partial_download_is_complete_sealed_input'] = False
                result['errors'].append({'stage': 'PARTIAL_DOWNLOAD_RETAINED',
                                        'type': 'IncompleteTransferOriginal'})
            except BaseException as error:
                result['errors'].append({'stage': 'PARTIAL_DOWNLOAD_CUSTODY', 'type': type(error).__name__,
                    'safe_refusal': str(error) if type(error) is Refusal else None})
        try:
            natural_guardian(guardian, setup, policy, root)
            report, _ = document(root / 'recovery-terminal.json', 4 << 20)
            files = accept_small_reader(report, setup, policy, root)
            source_ok = True
        except BaseException as error:
            result['errors'].append({'stage': 'SOURCE_ACCEPTANCE', 'type': type(error).__name__,
                                     'safe_refusal': str(error) if type(error) is Refusal else None})
            try:
                if report is None:
                    report, _ = document(root / 'recovery-terminal.json', 4 << 20)
                files = observed_frame_files(report, policy, root,
                    partition=context['partition'], partial_metadata=True)
                result['authenticated_partial_metadata_only'] = True
            except BaseException as partial_error:
                files = []
                result['errors'].append({'stage': 'PARTIAL_ORIGINAL_METADATA', 'type': type(partial_error).__name__,
                    'safe_refusal': str(partial_error) if type(partial_error) is Refusal else None})
        historical = {x['logical_path'] for x in files}
        result['source_missing_targets'] = [name for name in expected if name not in historical]
        controls = []
        reader_refusals = []
        for name in ('guard/guardian.json', 'guard/child.stdout.log', 'guard/child.stderr.log',
                     'recovery-terminal.json', 'setup.json'):
            path = root / name
            if os.path.lexists(path):
                try:
                    controls.append({'logical_path': 'reader/' + name,
                        'record': file_record(path, 4 << 20),
                        'origin': 'current read-only operation raw control record'})
                except BaseException as error:
                    reader_refusals.append({'name': 'reader/' + name,
                                            'type': type(error).__name__})
                    result['errors'].append({'stage': 'CURRENT_READER_ORIGINAL',
                                             'name': name, 'type': type(error).__name__})
        reader_names = policy['diagnostic_targets']['reader']
        observed_reader_names = {item['logical_path'] for item in controls}
        result['unavailable_reader_targets'] = [
            name for name in reader_names if name not in observed_reader_names]
        result['reader_read_refusals'] = reader_refusals
        selector = load_selector(root / 'control', policy)
        historical_metadata = {item['logical_path']: {
            'bytes': item['record']['bytes'], 'sha256': item['record']['sha256']}
            for item in files}
        reader_metadata = {item['logical_path']: {
            'bytes': item['record']['bytes'], 'sha256': item['record']['sha256']}
            for item in controls}
        selection = selector.plan_original_frames(historical_metadata, reader_metadata)
        result['selection_plan'] = selection
        ordered_by_name = {item['logical_path']: item for item in files + controls}
        ordered_names = list(selector.HISTORICAL_TARGETS) + list(selector.CURRENT_READER_TARGETS)
        ordered = [ordered_by_name[name] for name in ordered_names if name in ordered_by_name]
        require(len(ordered) <= 6 and len(ordered_by_name) == len(ordered),
                'fixed one slice plus five current controls differs')
        require(sum(x['record']['bytes'] for x in ordered) +
                result.get('retained_small_artifact', {}).get('bytes', 0) +
                result.get('retained_partial_download', {}).get('bytes', 0) <= MAX_PUBLIC_BYTES - (4 << 20),
                'retained actual originals exceed public budget')
        copied = []
        for number, item in enumerate(ordered):
            name = '%03d.original' % number
            observed = copy_original(Path(item['record']['path']), public / name, item['record'])
            row = {'logical_path': item['logical_path'], 'retained_file': name,
                'bytes': observed['bytes'], 'sha256': observed['sha256'],
                'original_source_identity': item['record']['identity'],
                'independent_copy_readback': True}
            result['retained_originals'].append(row)
            copied.append({'logical_path': item['logical_path'], 'record': observed, 'origin': item['origin']})
        capture_raw = wire({'schema': 'hia.970.inner-archive-slice-captured.v1',
            'context': context, 'historical_custody_status': 'CUSTODY_HOLD',
            'files': result['retained_originals'],
            'small_artifact': result.get('retained_small_artifact'),
            'original_product_statuses_reclassified': False})
        create(public / 'CAPTURED.json', capture_raw)
        require(read(public / 'CAPTURED.json', 2 << 20) == capture_raw, 'capture map readback differs')
        copied_by_name = {item['logical_path']: item for item in copied}
        require(set(copied_by_name) == set(ordered_by_name),
                'copied diagnostic population differs')
        chosen = [copied_by_name[name] for name in selection['selected_names']]
        result['budget_omitted_targets'] = [
            row['name'] for row in selection['rows'] if row['status'] == 'OMITTED_RAW_BUDGET']
        require(sum(item['record']['bytes'] for item in chosen) ==
                selection['total_original_raw_bytes_selected'] <= MAX_FRAME_RAW,
                'actual copied diagnostic budget differs from fixed selection')
        # Every admitted original is preserved in public; only the fixed
        # 448KiB history and64KiB current-control partitions enter stdout.
        source_missing = result['source_missing_targets']
        reader_missing = result['unavailable_reader_targets']
        omitted = result['budget_omitted_targets']
        source_complete = (source_ok and not source_missing and not reader_missing and not omitted
            and result.get('complete_small_artifact_independently_retained') is True
            and not result['errors'])
        if omitted:
            result['errors'].append({'stage': 'FRAME_BUDGET', 'type': 'FixedDiagnosticBudget',
                                     'omitted_count': len(omitted)})
        if source_missing or reader_missing:
            result['errors'].append({'stage': 'FIXED_DIAGNOSTIC_ORIGINALS',
                'type': 'UnavailableOriginals',
                'historical_count': len(source_missing), 'reader_count': len(reader_missing)})
        index = {'schema': 'hia.970.inner-archive-slice-index.v1',
            'scope': 'DERIVED_METADATA_ONLY_NOT_ORIGINAL_FILE_BODY',
            'small_artifact': policy['small_artifact'],
            'original_final_sha256': policy['original_final_sha256'],
            'original_custody_status': 'CUSTODY_HOLD', 'original_frame_status': 'FRAMING_HOLD',
            'current_source_acceptance': source_ok,
            'partition': context['partition'], 'inner_archive_pin': policy['inner_archive'],
            'actual_archive_slice_binding': report.get('archive_slice') if report else None,
            'outer_directory': report.get('original_outer_directory', []) if report else [],
            'outer_member_hashes': report.get('original_small_inventory', {}) if report else {},
            'original_captured_rows': report.get('original_captured_inventory', []) if report else [],
            'original_missing_capture_paths': report.get('original_custody_missing_capture_paths') if report else None,
            'selection_plan': selection, 'reader_read_refusals': reader_refusals,
            'inner_selected_archive_opened': False, 'original354_bodies_read': False,
            'additional_large_artifact_downloads': 0,
            'previous_recovery': policy['previous_recovery'],
            'original_product_statuses_reclassified': False, 'qualification_executed': False}
        index_raw = wire(index)
        require(len(index_raw) <= selector.INDEX_MAX_BYTES, 'derived diagnostic index exceeds bound')
        create(public / 'INDEX.json', index_raw)
        require(read(public / 'INDEX.json', selector.INDEX_MAX_BYTES) == index_raw,
                'derived diagnostic index readback differs')
        result['derived_index'] = {'bytes': len(index_raw), 'sha256': sha256(index_raw).hexdigest()}
        for path, wanted in setup['source_identities'].items():
            require(file_record(Path(path), 64 << 20,
                    system_binary=path == context['python']['resolved'])['sha256'] == wanted,
                    'frozen reader source changed before framing')
        terminal = 'INNER_ARCHIVE_SLICE_FRAMES_COMPLETE_NOT_QUALIFICATION' if source_complete else 'FRAMING_HOLD'
        extra = {'source_originals_accepted': source_ok,
            'all_historical_targets_framed': source_complete,
            'original_small_artifact': policy['small_artifact'],
            'partition': context['partition'], 'inner_archive_pin': policy['inner_archive'],
            'original_custody_status': 'CUSTODY_HOLD',
            'original_custody_run_id': policy['original_operation']['run_id'],
            'original_final_sha256': policy['original_final_sha256'],
            'missing_frame_targets': source_missing + reader_missing + omitted,
            'source_missing_targets': source_missing,
            'unavailable_reader_targets': reader_missing, 'budget_omitted_targets': omitted,
            'expected_historical_target_count': 1, 'maximum_reader_control_count': 5,
            'derived_diagnostic_index': {**result['derived_index'],
                'base64': base64.b64encode(index_raw).decode('ascii')},
            'original354_bodies_read': False, 'inner_selected_archive_opened': False,
            'previous_recovery': policy['previous_recovery'],
            'errors': result['errors'], 'additional_large_artifact_downloads': 0}
        observed, pending_terminal = output_frames(chosen, context, extra, terminal)
        for path, wanted in setup['source_identities'].items():
            require(file_record(Path(path), 64 << 20,
                    system_binary=path == context['python']['resolved'])['sha256'] == wanted,
                    'frozen reader source changed while framing')
        for item in copied:
            current = file_record(Path(item['record']['path']), MAX_PUBLIC_BYTES)
            require(current == item['record'], 'retained original changed across framing')
        if 'retained_small_artifact' in result:
            current = file_record(public / 'SMALL-ARTIFACT.original.zip', policy['small_artifact']['bytes'])
            require(current == result['retained_small_artifact'],
                    'retained small original changed across framing')
        if 'retained_partial_download' in result:
            current = file_record(public / 'SMALL-ARTIFACT.partial.original', policy['small_artifact']['bytes'])
            require(current == result['retained_partial_download'],
                    'retained partial download changed across framing')
        result.update(status=terminal, frames=observed, frozen_source_preserved=True,
            source_originals_accepted=source_ok, all_historical_targets_framed=source_complete)
    except BaseException as error:
        pending_terminal = None
        result['status'] = 'FRAMING_HOLD'
        result['errors'].append({'stage': 'FRAMING', 'type': type(error).__name__,
                                'safe_refusal': str(error) if type(error) is Refusal else None})
        print('HIA_ORIGINAL_FRAME_FAILURE_V1 ' + json.dumps({
            'status': 'FRAMING_HOLD', 'error_type': type(error).__name__,
            'safe_refusal': str(error) if type(error) is Refusal else None,
            'original_product_statuses_reclassified': False}), flush=True)
    result_raw = wire(result)
    create(public / 'RESULT.json', result_raw)
    require(read(public / 'RESULT.json', 2 << 20) == result_raw, 'frame receipt readback differs')
    actual = [file_record(path) for path in public.iterdir()]
    require(len(actual) <= MAX_PUBLIC_FILES
            and sum(x['bytes'] for x in actual) <= MAX_PUBLIC_BYTES, 'public recovery budget exceeded')
    sync_dir(public)
    sync_dir(public.parent)
    if pending_terminal is not None:
        pending_terminal['result_sha256'] = sha256(result_raw).hexdigest()
        line = ('HIA_ORIGINAL_FRAME_END_V1 ' + json.dumps(
            pending_terminal, sort_keys=True, separators=(',', ':')) + '\n').encode()
        require(result['frames']['stdout_bytes'] + len(line) <= MAX_FRAME_STDOUT,
                'terminal exceeds fixed stdout budget')
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
    return 0 if result['status'] == 'INNER_ARCHIVE_SLICE_FRAMES_COMPLETE_NOT_QUALIFICATION' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'run', 'finalize'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--control-commit', required=True)
    parser.add_argument('--partition', required=True)
    args = parser.parse_args()
    return {'prepare': prepare, 'run': run, 'finalize': finalize}[args.operation](args)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Refusal as error:
        print('HIA_ORIGINAL_FRAME_FAILURE_V1 ' + json.dumps({
            'status': 'CONTROL_HOLD', 'safe_refusal': str(error)}), flush=True)
        raise SystemExit(1)
