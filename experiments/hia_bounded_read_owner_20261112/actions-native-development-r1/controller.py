"""One fixed bounded-read Actions development; no trigger is performed by this file."""
from __future__ import annotations
import argparse
import base64
from contextlib import contextmanager
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import traceback

REPOSITORY = 'TrillionniumFoundation/Hepta'
PREFIX = 'experiments/hia_bounded_read_owner_20261112/actions-native-development-r1'
CANDIDATE = '0e36619bc65ada7072c1e8a1f1454728036fee4e'
TREE = '1d95802c453a006f077eb8735a6939b1957d500b'
TRIGGER = 'codex/hia-bounded-read-native-r4b-run-r1-20261112-e26e'
WORK_ROOT = 'hia-bounded-read-native-r4b-development-r1'
MAX_RECEIPT = 32 << 20
NATURAL = {'qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped'}
CONTROL_NAMES = set(['actions_custody.py', 'actions_verify.py', 'caller_observer.py', 'control-manifest.json', 'controller.py', 'diagnostic-targets.json', 'diagnostics.py', 'filesystem_cases.py', 'git_binding.py', 'guardian.py', 'lifetime_cases.py', 'native_driver.py', 'native_support.py', 'original_eight.py', 'permission_cases.py', 'populations.json', 'prepare_native.py', 'process_owner_impl.py', 'read_bounded.original.py', 'reject_cases.py', 'source-manifest.json', 'source_common.py'])

def require(value, message):
    if not value:
        raise RuntimeError(message)

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)

def _directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)

def _checked_parent(path):
    """Retain the complete absolute directory chain without following symlinks."""
    path = Path(path)
    require(path.is_absolute() and path.anchor == '/' and '..' not in path.parts
            and len(path.parts) > 1, 'noncanonical controlled IO path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptors = [os.open('/', flags)]
    links = []
    def stable():
        for parent, name, child, expected in links:
            require(_directory_identity(os.fstat(child)) == expected
                    and _directory_identity(os.stat(name, dir_fd=parent,
                                                     follow_symlinks=False)) == expected,
                    'controlled IO directory chain changed')
    try:
        for name in path.parts[1:-1]:
            parent = descriptors[-1]
            child = os.open(name, flags, dir_fd=parent)
            descriptors.append(child)
            info = os.fstat(child)
            require(stat.S_ISDIR(info.st_mode), 'controlled IO ancestor is not a directory')
            links.append((parent, name, child, _directory_identity(info)))
        stable()
        yield descriptors[-1], path.parts[-1], stable
        stable()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)

def _read_extent(descriptor, size):
    chunks, remaining = [], size
    while remaining:
        block = os.read(descriptor, min(1 << 20, remaining))
        if not block:
            break
        chunks.append(block)
        remaining -= len(block)
    require(remaining == 0, 'controlled IO original ended before its declared extent')
    return b''.join(chunks)

def _create_bytes(path, raw, mode):
    """Create through the retained parent; read back the same open descriptor."""
    with _checked_parent(path) as (parent, name, stable):
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent)
        try:
            os.fchmod(descriptor, mode)
            remaining = memoryview(raw)
            while remaining:
                count = os.write(descriptor, remaining)
                require(count > 0, 'controlled IO write made no progress')
                remaining = remaining[count:]
            os.fsync(descriptor)
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                    and before.st_nlink == 1 and before.st_size == len(raw),
                    'create-only controlled output identity differs')
            expected = (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                        before.st_gid, before.st_nlink, before.st_size,
                        before.st_mtime_ns, before.st_ctime_ns)
            def same_leaf(info):
                return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                        info.st_gid, info.st_nlink, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns) == expected
            require(same_leaf(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'create-only output name changed')
            stable()
            os.lseek(descriptor, 0, os.SEEK_SET)
            require(_read_extent(descriptor, len(raw)) == raw
                    and same_leaf(os.fstat(descriptor))
                    and same_leaf(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'create-only descriptor readback differs')
            stable()
        finally:
            os.close(descriptor)

def _create_directory(path, mode=0o700):
    with _checked_parent(path) as (parent, name, stable):
        os.mkdir(name, mode=mode, dir_fd=parent)
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                             | os.O_CLOEXEC, dir_fd=parent)
        try:
            observed = os.fstat(descriptor)
            require(stat.S_ISDIR(observed.st_mode) and observed.st_uid == os.geteuid()
                    and not stat.S_IMODE(observed.st_mode) & 0o077
                    and _directory_identity(os.stat(name, dir_fd=parent,
                                                     follow_symlinks=False))
                        == _directory_identity(observed),
                    'create-only private directory differs')
            stable()
        finally:
            os.close(descriptor)

def read(path, maximum=MAX_RECEIPT, *, system_binary=False):
    with _checked_parent(path) as (parent, name, stable):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                             | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode), 'regular input required: ' + str(path))
            if system_binary:
                require(before.st_uid in (0, os.geteuid()) and before.st_nlink >= 1
                        and not stat.S_IMODE(before.st_mode) & 0o022,
                        'runner tool is writable or has unexpected ownership')
            else:
                require(before.st_uid == os.geteuid() and before.st_nlink == 1,
                        'owned single-link input required')
            require(0 <= before.st_size <= maximum, 'bounded original input required')
            require(identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                        == identity(before), 'input changed before reading')
            stable()
            raw = _read_extent(descriptor, before.st_size)
            require(identity(os.fstat(descriptor)) == identity(before)
                    and identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                        == identity(before), 'input changed during reading')
            stable()
            return raw, {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                         'identity': list(identity(before))}
        finally:
            os.close(descriptor)

def create(path, raw):
    _create_bytes(path, raw, 0o400)
    copied, record = read(path, max(len(raw), 1))
    require(copied == raw, 'create-only original readback differs')
    return record

def save(path, value):
    return create(path, wire(value))

def clean_environment():
    environment = {name: value for name, value in os.environ.items()
                   if not name.startswith(('GIT_', 'LD_', 'HEPTA_HIA_', 'PYTHON'))
                   and name not in ('GITHUB_TOKEN', 'GH_TOKEN')}
    environment.update(PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1')
    return environment

def verified_helpers(control):
    # context() has read every exact policy-bound byte before this import.
    sys.path.insert(0, str(control))
    from native_support import source_manifest
    from git_binding import source_git
    return source_manifest, source_git

def runtime_binary(path):
    try:
        return read(path, 64 << 20, system_binary=True)
    except BaseException as error:
        observation = {'path': str(path), 'euid': os.geteuid(), 'error_type': type(error).__name__,
                       'original_error': str(error)}
        try:
            observation['lstat_identity'] = list(identity(path.lstat()))
            observation['mode_octal'] = oct(stat.S_IMODE(path.lstat().st_mode))
        except BaseException as stat_error:
            observation['lstat_error_type'] = type(stat_error).__name__
        raise RuntimeError('fixed runtime executable refusal: ' + json.dumps(observation, sort_keys=True)) from error

def context(args):
    require(not any(value for name, value in os.environ.items() if name.startswith(('GIT_', 'LD_'))),
            'ambient Git/loader redirection is outside this development profile')
    require(not os.environ.get('GITHUB_TOKEN') and not os.environ.get('GH_TOKEN'),
            'publication or API token must not enter development')
    require(sys.version_info[:3] == (3, 14, 4) and platform.python_implementation() == 'CPython'
            and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
            'actual fixed CPython 3.14.4 -I -S -B differs')
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    control_checkout = workspace / 'control'
    control = Path(__file__).absolute().parent
    require(control == control_checkout / PREFIX
            and re.fullmatch(r'[0-9a-f]{40}', args.control_commit) is not None
            and read(control_checkout / '.git/HEAD', 256)[0] == (args.control_commit + '\n').encode(),
            'actual detached reviewed control checkout differs')
    policy_raw, policy_record = read(control / 'policy.json', 1 << 20)
    require(policy_record['sha256'] == args.policy_sha256, 'frozen policy bytes differ')
    policy = json.loads(policy_raw)
    require(policy['schema'] == 'hia.bounded-read-actions-policy.v1'
            and policy['candidate'] == {'commit': CANDIDATE, 'tree': TREE, 'leaves': 4025}
            and policy['controller_seconds'] == 180 and policy['cleanup_seconds'] == 3
            and policy['trigger_branch'] == TRIGGER and policy['finite_cases'] == 55
            and policy['original_methods'] == 8 and policy['original_CLI_children'] == 7
            and policy['original_CLI_timeout_seconds'] == 20
            and policy['compile_wall_seconds'] == 20 and policy['compile_CPU_seconds'] == 10
            and policy['fresh_B0_B1_B2'] is True and policy['cold_qualification'] is False,
            'frozen development policy differs')
    require(set(policy['controls']) == CONTROL_NAMES, 'complete frozen control inventory differs')
    event_raw, event_record = read(Path(os.environ['GITHUB_EVENT_PATH']), 1 << 20)
    event = json.loads(event_raw)
    require(os.environ.get('GITHUB_REPOSITORY') == REPOSITORY
            and os.environ.get('GITHUB_EVENT_NAME') == 'create'
            and os.environ.get('GITHUB_RUN_ATTEMPT') == '1'
            and event.get('ref_type') == 'branch' and event.get('ref') == TRIGGER
            and event.get('repository', {}).get('full_name') == REPOSITORY
            and os.environ.get('GITHUB_REF') == 'refs/heads/' + TRIGGER,
            'unique original create event differs')
    workflow_sha = os.environ.get('GITHUB_SHA', '')
    require(re.fullmatch(r'[0-9a-f]{40}', workflow_sha) is not None
            and os.environ.get('HIA_BOUNDED_READ_WORKFLOW_SHA') == workflow_sha
            and os.environ.get('GITHUB_WORKFLOW_SHA') == workflow_sha,
            'actual workflow commit identity differs')
    temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    root, source = temp / WORK_ROOT, workspace / 'source'
    require(args.root == root and args.source == source and source.resolve(strict=True) == source,
            'fixed private output/source path differs')
    with _checked_parent(source / '.spine-observation'):
        pass
    with _checked_parent(root):
        pass
    python = Path(sys.executable).resolve(strict=True)
    _, python_record = runtime_binary(python)
    git_executable = Path(shutil.which('git')).resolve(strict=True)
    _, git_record = runtime_binary(git_executable)
    git_version = subprocess.run([str(git_executable), '--version'], env=clean_environment(),
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5).stdout.decode().strip()
    records = {}
    for name, expected in policy['controls'].items():
        require(re.fullmatch(r'[a-z0-9_.-]+', name) is not None, 'control basename refused')
        raw, observed = read(control / name, 1 << 20)
        require(observed['bytes'] == expected['bytes'] and observed['sha256'] == expected['sha256']
                and sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected['git_blob_sha1'],
                'frozen complete control source differs: ' + name)
        records[str(control / name)] = expected['sha256']
    records[str(control / 'policy.json')] = policy_record['sha256']
    value = {'schema': 'hia.bounded-read-actions-context.v1', 'repository': REPOSITORY,
        'event': 'create', 'trigger_branch': TRIGGER, 'run_id': int(os.environ['GITHUB_RUN_ID']),
        'run_attempt': 1, 'run_number': int(os.environ['GITHUB_RUN_NUMBER']),
        'event_sha256': event_record['sha256'], 'workflow_commit': workflow_sha,
        'workflow_ref': os.environ['GITHUB_WORKFLOW_REF'], 'actual_control_commit': args.control_commit,
        'policy_sha256': policy_record['sha256'], 'control_sources': records,
        'control_manifest_sha256': policy['controls']['control-manifest.json']['sha256'],
        'candidate_commit': CANDIDATE, 'candidate_tree': TREE, 'candidate_leaves': 4025,
        'source': str(source), 'root': str(root), 'evidence': str(root / 'evidence'),
        'inner_PATH': os.environ['PATH'], 'controller_seconds': 180, 'cleanup_seconds': 3,
        'python': {'source': 'actions/setup-python fixed 3.14.4', 'executable': sys.executable,
            'resolved': str(python), 'version': sys.version, 'implementation': platform.python_implementation(),
            'version_info': list(sys.version_info), 'prefix': sys.prefix, 'base_prefix': sys.base_prefix,
            'platform': sys.platform, 'machine': platform.machine(), 'binary': python_record,
            'desktop_binary_identity_claimed': False},
        'git': {'resolved': str(git_executable), 'version': git_version, 'binary': git_record},
        'native_execution_requested': True, 'finite_cases': 55, 'original_methods': 8,
        'original_CLI_children': 7, 'fresh_B0_B1_B2': True, 'cold_qualification_requested': False,
        'installed_qualification_requested': False, 'whole_native_delivery_qualification_requested': False}
    return control, policy, policy_raw, root, source, value

def expected_inputs(control, policy, root, value):
    result = dict(value['control_sources'])
    for name, expected in policy['controls'].items():
        result[str(root / 'control' / name)] = expected['sha256']
    result[str(root / 'control/policy.json')] = value['policy_sha256']
    result[str(root / 'context.json')] = sha256(wire(value)).hexdigest()
    result[value['python']['resolved']] = value['python']['binary']['sha256']
    result[value['git']['resolved']] = value['git']['binary']['sha256']
    return result

def command(root, source, value):
    return [value['python']['resolved'], '-I', '-S', '-B', str(root / 'control/native_driver.py'),
        '--source-root', str(source), '--source-manifest', str(root / 'control/source-manifest.json'),
        '--control-manifest', str(root / 'control/control-manifest.json'),
        '--control-manifest-sha256', value['control_manifest_sha256'], '--output', str(root / 'evidence')]

def prepare(args):
    control, policy, raw, root, source, value = context(args)
    require(not os.path.lexists(root), 'new development root already exists; reconcile original operation')
    capacity = os.statvfs(root.parent)
    available = capacity.f_bavail * capacity.f_frsize
    require(available >= 8 << 30 and capacity.f_favail >= 100000,
            'original development eight-GiB/100k-inode preparation reserve unavailable')
    source_manifest, source_git = verified_helpers(control)
    rows, _, _ = source_manifest(control / 'source-manifest.json')
    actual_source = source_git(source, rows)
    os.umask(0o077)
    _create_directory(root)
    for name in ('control', 'guard', 'public'):
        _create_directory(root / name)
    for name, expected in policy['controls'].items():
        data, observed = read(control / name, 1 << 20)
        require(observed['sha256'] == expected['sha256'], 'control changed before copying')
        create(root / 'control' / name, data)
    create(root / 'control/policy.json', raw)
    create(root / 'context.json', wire(value))
    inputs, invocation = expected_inputs(control, policy, root, value), command(root, source, value)
    config = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
              'command': invocation, 'cwd': str(source), 'source_identities': inputs}
    config_record = save(root / 'guard/request.json', config)
    setup = {'schema': 'hia.bounded-read-actions-setup.v1', 'status': 'PREPARED_NOT_EXECUTED',
        'context': value, 'source_actual_HEAD': actual_source, 'source_identities': inputs,
        'command': invocation, 'guardian_config_sha256': config_record['sha256'],
        'controller_seconds': 180, 'cleanup_seconds': 3,
        'resource_observation': {'available_bytes': available, 'available_inodes': capacity.f_favail,
            'minimum_available_bytes': 8 << 30, 'minimum_available_inodes': 100000,
            'formal_full_resource_qualification_claimed': False}}
    record = save(root / 'setup.json', setup)
    # Always-upload sees only ordinary independent copies, never fixture trees.
    for name, data in (('setup.json', wire(setup)), ('context.json', wire(value)),
                       ('guardian-request.json', wire(config))):
        create(root / 'public' / name, data)
    print(json.dumps({'status': setup['status'], 'setup_sha256': record['sha256'],
                      'root': str(root), 'actual_source_head': actual_source['head']}), flush=True)
    return 0

def setup_record(control, policy, root, source, value):
    raw, record = read(root / 'setup.json', 1 << 20)
    setup = json.loads(raw)
    require(setup['schema'] == 'hia.bounded-read-actions-setup.v1'
            and setup['status'] == 'PREPARED_NOT_EXECUTED' and setup['context'] == value
            and setup['command'] == command(root, source, value)
            and setup['source_identities'] == expected_inputs(control, policy, root, value)
            and setup['controller_seconds'] == 180 and setup['cleanup_seconds'] == 3,
            'original setup is not this fixed operation')
    require(read(root / 'context.json', 1 << 20)[0] == wire(value), 'original actual context differs')
    config_raw, config_pin = read(root / 'guard/request.json', 1 << 20)
    require(config_pin['sha256'] == setup['guardian_config_sha256']
            and json.loads(config_raw) == {'schema': 'hia-external-guardian-request.v1',
                'controller_seconds': 180, 'command': setup['command'], 'cwd': str(source),
                'source_identities': setup['source_identities']}, 'original guardian request differs')
    return setup, record

def fixed_inputs(setup, value):
    for path, expected in setup['source_identities'].items():
        if path in (value['python']['resolved'], value['git']['resolved']):
            _, record = runtime_binary(Path(path))
        else:
            _, record = read(Path(path), 64 << 20)
        require(record['sha256'] == expected, 'frozen input changed: ' + path)

def run(args):
    control, policy, _, root, source, value = context(args)
    setup, _ = setup_record(control, policy, root, source, value)
    fixed_inputs(setup, value)
    source_manifest, source_git = verified_helpers(control)
    rows, _, _ = source_manifest(control / 'source-manifest.json')
    require(source_git(source, rows) == setup['source_actual_HEAD'], 'original actual source changed before run')
    os.chdir(root)
    python = value['python']['resolved']
    os.execve(python, [python, '-I', '-S', '-B', str(root / 'control/guardian.py'),
        '--config', str(root / 'guard/request.json'), '--config-sha256', setup['guardian_config_sha256'],
        '--implementation', str(root / 'control/process_owner_impl.py')], clean_environment())

def closed_owner(guardian, setup, root):
    life = guardian.get('lifecycle', {})
    require(guardian.get('schema') == 'hepta.hia.external-qualification-guardian.v1'
            and guardian.get('command') == setup['command'] and guardian.get('cwd') == setup['context']['source']
            and guardian.get('external_controller_seconds') == 180
            and guardian.get('source_identities_before') == setup['source_identities']
            and guardian.get('lifecycle_implementation_sha256') ==
                setup['source_identities'][str(root / 'control/process_owner_impl.py')]
            and life.get('schema') == 'hepta.hia.external-qualification-guardian.v1.lifecycle'
            and life.get('qualification_seconds') == 180 and life.get('cleanup_seconds') == 3
            and life.get('subreaper_enabled') is True and life.get('qualification_started') is True,
            'guardian does not bind this exact original operation')
    cleanup = life.get('cleanup', {})
    require(cleanup.get('attempted') is True and cleanup.get('complete') is True
            and cleanup.get('observed_echild') is True and cleanup.get('leader_reaped') is True
            and cleanup.get('deadline_exceeded') is False and cleanup.get('errors') == []
            and cleanup.get('remaining_direct_children') == [], 'no closed current ECHILD boundary')
    return life

def natural_guardian(guardian, life, setup):
    require(guardian['status'] == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
            and guardian['input_identity_preserved'] is True
            and guardian['source_identities_after'] == setup['source_identities']
            and guardian['cold_180_second_gate_modified'] is False and guardian['qualification'] is None
            and life['status'] == 'OWNED_PROCESS_COMPLETED' and life['returncode'] == 0
            and life['timed_out'] is False and life['exit_observed_before_deadline'] is True
            and life['event_overflow'] is False and life['interrupted_signals'] == []
            and life.get('owner_error') is None and life['events']
            and all(row['kind'] in NATURAL for row in life['events'])
            and {'qualification_started', 'qualification_exit_observed', 'owned_child_reaped'}
                <= {row['kind'] for row in life['events']}, 'outer did not finish naturally within 180/3')

def finalize(args):
    control, policy, _, root, source, value = context(args)
    require(root.is_dir(), 'preparation did not create its output root')
    final = {'schema': 'hia.bounded-read-actions-final.v1', 'status': 'HOLD', 'context': value,
        'scope': 'FINITE_NATIVE_DEVELOPMENT_NOT_COLD_OR_FULL_DOMAIN_QUALIFICATION',
        'cold_qualified': False, 'whole_native_delivery_qualified': False,
        'all_input_equivalence_proved': False, 'old_results_inherited': False,
        'checked_in_global_contract_updated': False, 'original_limits_changed': False,
        'closed_ECHILD_before_output_read': False, 'errors': []}
    setup = life = guardian = None
    try:
        setup, setup_pin = setup_record(control, policy, root, source, value)
        final['setup_original'] = setup_pin
        guardian_raw, guardian_pin = read(root / 'guard/guardian.json', 8 << 20)
        guardian = json.loads(guardian_raw)
        final['guardian_original'] = guardian_pin
        life = closed_owner(guardian, setup, root)
        final['closed_ECHILD_before_output_read'] = True
    except BaseException as error:
        final['errors'].append({'phase': 'closed_boundary', 'type': type(error).__name__,
            'message': str(error), 'traceback': traceback.format_exc()})
    if final['closed_ECHILD_before_output_read']:
        # Retain failed original products before requiring a successful result.
        verified_helpers(control)
        from actions_custody import capture_terminal, retain_typed_owned_output
        try:
            terminal, terminal_pin = capture_terminal(root, source)
            final['terminal_originals'] = terminal_pin
            require(not terminal['errors'], 'terminal original observation incomplete')
        except BaseException as error:
            final['errors'].append({'phase': 'terminal_original_custody', 'type': type(error).__name__,
                'message': str(error), 'traceback': traceback.format_exc()})
        try:
            natural_guardian(guardian, life, setup)
            log_pins = {}
            for name in ('child.stdout.log', 'child.stderr.log'):
                _, actual = read(root / 'guard' / name, 32 << 20)
                log_pins[str(root / 'guard' / name)] = actual['sha256']
            require(guardian['logs'] == log_pins, 'actual original child logs differ')
            fixed_inputs(setup, value)
            from actions_verify import verify_outputs
            final['outputs'] = verify_outputs(root, setup, policy)
            fixed_inputs(setup, value)
        except BaseException as error:
            final['errors'].append({'phase': 'independent_product_readback', 'type': type(error).__name__,
                'message': str(error), 'traceback': traceback.format_exc()})
        try:
            final['typed_original_custody'] = retain_typed_owned_output(root)
        except BaseException as error:
            final['errors'].append({'phase': 'typed_archive_custody', 'type': type(error).__name__,
                'message': str(error), 'traceback': traceback.format_exc()})
    # Only fixed metadata may be copied if the child tree was not proved closed.
    metadata = []
    for name, destination in (('setup.json', 'setup.json'), ('context.json', 'context.json'),
            ('guard/request.json', 'guardian-request.json'), ('guard/guardian.json', 'guardian.json'),
            ('TERMINAL-ORIGINALS.json', 'TERMINAL-ORIGINALS.json'), ('EVIDENCE-INVENTORY.json', 'EVIDENCE-INVENTORY.json')):
        if not final['closed_ECHILD_before_output_read'] and name not in ('setup.json', 'context.json', 'guard/request.json'):
            continue
        try:
            raw, actual = read(root / name, 16 << 20)
            target = root / 'public' / destination
            if os.path.lexists(target):
                require(read(target, 16 << 20)[0] == raw, 'earlier public metadata copy differs')
                copied = read(target, 16 << 20)[1]
            else:
                copied = create(target, raw)
            metadata.append({'original': actual, 'copy': copied})
        except BaseException as error:
            final['errors'].append({'phase': 'fixed_metadata_copy', 'path': name, 'type': type(error).__name__,
                'message': str(error), 'traceback': traceback.format_exc()})
    final['public_metadata'] = metadata
    if not final['errors'] and final.get('outputs') and final.get('typed_original_custody'):
        final['status'] = 'BOUNDED_READ_FINITE_NATIVE_ACTIONS_DEVELOPMENT_PASS'
    raw = wire(final)
    record = create(root / 'FINAL.json', raw)
    public_record = create(root / 'public/FINAL.json', raw)
    require(read(root / 'FINAL.json', 16 << 20)[0] == read(root / 'public/FINAL.json', 16 << 20)[0],
            'independent public final original differs')
    print(json.dumps({'status': final['status'], 'final': record, 'public_final': public_record,
                      'cold_qualified': False}), flush=True)
    return 0 if final['status'] == 'BOUNDED_READ_FINITE_NATIVE_ACTIONS_DEVELOPMENT_PASS' else 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'run', 'finalize'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--control-commit', required=True)
    args = parser.parse_args()
    return {'prepare': prepare, 'run': run, 'finalize': finalize}[args.operation](args)

if __name__ == '__main__':
    raise SystemExit(main())
