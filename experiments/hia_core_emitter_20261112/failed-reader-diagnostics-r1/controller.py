"""Read one sealed failed-reader artifact; print only bounded fixed diagnostics."""
from __future__ import annotations

from hashlib import sha1, sha256
from contextlib import contextmanager
import argparse
import base64
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile

REPO = 'TrillionniumFoundation/Hepta'
TOKEN_VARIABLE = 'HIA_CUSTODY_GITHUB_TOKEN'
CHUNK = 1 << 20
MAX_PUBLIC_BYTES = 16 << 20
MAX_PUBLIC_FILES = 25
NATURAL_EVENTS = {'qualification_started', 'owned_child_observed',
                  'qualification_exit_observed', 'owned_child_reaped'}


class Refusal(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise Refusal(message)


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def blob(raw):
    return sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

class OriginalTooLarge(RuntimeError):
    def __init__(self, path, size):
        super().__init__('unbounded original: ' + str(path))
        self.size = size

@contextmanager
def parent_descriptor(path):
    """Keep a no-follow descriptor spine for the entire fixed path operation."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts and len(path.parts) > 1,
            'noncanonical absolute original path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptors = [os.open('/', flags)]
    links = []
    def directory_identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    def stable():
        for parent, name, child, wanted in links:
            require(directory_identity(os.fstat(child)) == wanted
                    and directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == wanted,
                    'original directory chain changed')
    try:
        for name in path.parts[1:-1]:
            parent = descriptors[-1]
            child = os.open(name, flags, dir_fd=parent)
            descriptors.append(child)
            observed = os.fstat(child)
            require(stat.S_ISDIR(observed.st_mode), 'original ancestor is not a directory')
            links.append((parent, name, child, directory_identity(observed)))
        stable()
        yield descriptors[-1], path.parts[-1]
        stable()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)

def inspect_file(path, maximum=1 << 30, *, system_binary=False, retain=False, reserve=None):
    path = Path(path)
    with parent_descriptor(path) as (parent, name):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode), 'nonregular original: ' + str(path))
        require(before.st_size >= 0, 'invalid original size')
        if before.st_size > maximum:
            raise OriginalTooLarge(path, before.st_size)
        if system_binary:
            require(before.st_uid in (0, os.geteuid()) and before.st_nlink >= 1
                    and not stat.S_IMODE(before.st_mode) & 0o022, 'mutable runtime binary')
        else:
            require(before.st_uid == os.geteuid() and before.st_nlink == 1,
                    'owned single-link original required: ' + str(path))
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        chunks, count = ([] if retain else None), 0
        digest = sha256()
        git_digest = sha1(b'blob ' + str(before.st_size).encode() + b'\0')
        try:
            require(identity(os.fstat(fd)) == identity(before), 'original changed before descriptor read')
            if reserve is not None:
                reserve(before.st_size)
            while count < before.st_size:
                block = os.read(fd, min(1 << 20, before.st_size - count))
                if not block:
                    break
                count += len(block)
                digest.update(block)
                git_digest.update(block)
                if retain:
                    chunks.append(block)
            require(count == before.st_size and identity(os.fstat(fd)) == identity(before)
                    and identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity(before),
                    'original changed during descriptor read')
        finally:
            os.close(fd)
        pin = {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest(),
               'git_blob_sha1': git_digest.hexdigest(), 'posix_mode': stat.S_IMODE(before.st_mode),
               'identity': list(identity(before))}
        return (b''.join(chunks) if retain else None), pin

def descriptor_read(path, maximum=32 << 20, *, system_binary=False, reserve=None):
    return inspect_file(path, maximum, system_binary=system_binary, retain=True, reserve=reserve)

def descriptor_create(path, raw):
    path = Path(path)
    with parent_descriptor(path) as (parent, name):
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o400, dir_fd=parent)
        try:
            os.fchmod(fd, 0o400)
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                require(written > 0, 'short create-only original write')
                offset += written
            os.fsync(fd)
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o400
                    and before.st_size == len(raw), 'created original identity differs')
            os.lseek(fd, 0, os.SEEK_SET)
            chunks, count = [], 0
            while count < len(raw):
                part = os.read(fd, min(1 << 20, len(raw) - count))
                if not part:
                    break
                chunks.append(part)
                count += len(part)
            observed = b''.join(chunks)
            require(observed == raw and count == len(raw)
                    and identity(os.fstat(fd)) == identity(before)
                    and identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity(before),
                    'create-only original descriptor readback differs')
            pin = {'path': str(path), 'bytes': count, 'sha256': sha256(observed).hexdigest(),
                   'git_blob_sha1': blob(observed), 'posix_mode': stat.S_IMODE(before.st_mode),
                   'identity': list(identity(before))}
        finally:
            os.close(fd)
        return pin


def read(path, maximum=8 << 20, expected=None):
    raw, _ = descriptor_read(Path(path), maximum)
    require(expected is None or sha256(raw).hexdigest() == expected, 'input SHA differs')
    return raw

def file_record(path, maximum=64 << 20, *, system_binary=False):
    _, pin = inspect_file(Path(path), maximum, system_binary=system_binary)
    return {key: pin[key] for key in ('path', 'bytes', 'sha256', 'identity')}

def create(path, raw, mode=0o400):
    require(mode == 0o400, 'fixed immutable create mode required')
    return descriptor_create(Path(path), raw)

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
    require(policy.get('schema') == 'hia.actions.core-failed-reader-diagnostic-policy.v1'
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
    require(not any(value for name, value in os.environ.items()
                    if name.startswith(('GIT_', 'LD_'))),
            'ambient Git or loader redirection refused before creating roots')
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
    context = {'schema': 'hia.actions.core-failed-reader-diagnostic-context.v1',
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
    setup = {'schema': 'hia.actions.core-failed-reader-diagnostic-setup.v1',
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
    require(setup.get('schema') == 'hia.actions.core-failed-reader-diagnostic-setup.v1'
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


FRAME_BYTES = 8 << 10
MAX_FRAME_RAW = 512 << 10
MAX_FRAME_STDOUT = 1 << 20
ARCHIVE_RAW_LIMIT = 41 << 20
MAX_ARCHIVE_FILES = 116

def zip_inventory(path, pins):
    allowed = {'RESULT.json'}
    allowed.update('%03d.original' % i for i in range(59))
    allowed.update('partial/%03d.original' % i for i in range(56))
    optional_root = 'hia-core-emitter-generated-asset-receipts-r2/'
    inventory, total, names, prefix_mode = [], 0, set(), None
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        require(len(infos) <= MAX_ARCHIVE_FILES + 2, 'failed artifact entry denominator exceeded')
        for info in infos:
            raw_name = info.filename
            require(type(raw_name) is str and re.fullmatch(r'[A-Za-z0-9_./-]+', raw_name)
                    and not raw_name.startswith('/') and '\\' not in raw_name
                    and all(p not in ('.', '..') for p in raw_name.split('/')),
                    'unsafe failed artifact member name')
            rooted = raw_name.startswith(optional_root)
            name = raw_name[len(optional_root):] if rooted else raw_name
            if raw_name == optional_root and info.is_dir():
                require(info.file_size == 0, 'nonempty root directory member')
                continue
            if prefix_mode is None:
                prefix_mode = rooted
            require(prefix_mode == rooted, 'mixed failed artifact root prefixes')
            require(name not in names, 'duplicate failed artifact member')
            names.add(name)
            require(not info.flag_bits & 1
                    and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                    'encrypted or unsupported failed artifact member')
            if info.is_dir():
                require(name == 'partial/' and info.file_size == 0,
                        'unexpected failed artifact directory')
                continue
            mode = info.external_attr >> 16
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG) and name in allowed,
                    'nonregular or nonfixed failed artifact member: ' + name)
            require(type(info.file_size) is int and 0 <= info.file_size <= 32 << 20,
                    'failed artifact member exceeds bound')
            total += info.file_size
            require(total <= ARCHIVE_RAW_LIMIT, 'failed artifact inflated extent exceeds bound')
            count, digest = 0, sha256()
            git = sha1(b'blob ' + str(info.file_size).encode() + b'\0')
            with archive.open(info, 'r') as source:
                while True:
                    part = source.read(min(CHUNK, info.file_size + 1 - count))
                    if not part:
                        break
                    count += len(part)
                    require(count <= info.file_size, 'failed member expanded beyond metadata')
                    digest.update(part)
                    git.update(part)
            require(count == info.file_size, 'failed member byte count differs')
            inventory.append({'archive_path': raw_name, 'normalized_path': name,
                'bytes': count, 'sha256': digest.hexdigest(), 'git_blob_sha1': git.hexdigest(),
                'zip_crc32': info.CRC, 'full_member_CRC_read': True})
    require(len(inventory) <= MAX_ARCHIVE_FILES, 'failed artifact file denominator exceeded')
    return inventory, total


def old_context(value, pins):
    old = pins['original_failed_reader']
    require(type(value) is dict
            and value.get('schema') == old['schema_context']
            and value.get('repository') == REPO and value.get('event') == 'create'
            and value.get('run_attempt') == 1 and value.get('run_id') == old['run_id']
            and value.get('actual_control_checkout') == old['control_commit']
            and value.get('actual_workflow_commit') == old['workflow_commit']
            and value.get('policy_sha256') == old['policy_sha256']
            and value.get('root') == old['root']
            and value.get('token_or_signed_URL_in_context') is False
            and value.get('qualification_executed') is False,
            'diagnostic JSON belongs to another reader operation')
    return value

def accept_diagnostic_reader(report, setup, policy, root):
    pin = policy['source_artifact']
    raw = read(root / 'control/asset-pins.json', 1 << 20,
               policy['control_files']['asset-pins.json']['sha256'])
    pins = json.loads(raw)
    require(pins.get('schema') == 'hia.core-failed-reader-diagnostic-pins.v1'
            and pins.get('artifact') == pin, 'fixed diagnostic pin artifact differs')
    require(report.get('schema') == 'hia.actions.core-failed-reader-diagnostic-worker.v1'
            and report.get('status') == 'FAILURE_DIAGNOSTICS_VERIFIED_PENDING_NATURAL_GUARDIAN'
            and report.get('root') == str(root)
            and report.get('policy_sha256') == setup['context']['policy_sha256']
            and report.get('external_pins_sha256') ==
                policy['control_files']['asset-pins.json']['sha256']
            and report.get('source_artifact') == pin
            and report.get('original_run_conclusion') == 'failure'
            and report.get('original_failed_run') == pins['original_failed_reader']
            and report.get('assembly_count_in_original_inventory') == 39
            and report.get('assembly_body_bytes_output') == 0
            and report.get('error_type') is None,
            'fixed diagnostic worker terminal differs')
    for name in ('project_code_executed', 'qualification_executed',
                 'original_product_statuses_reclassified', 'original_failure_reclassified',
                 'source_generated_again', 'native_compiler_executed', 'Core_VM_executed',
                 'product_tests_executed', 'token_or_signed_URL_recorded', 'source_bodies_recovered'):
        require(report.get(name) is False, 'failed-reader diagnostic scope differs')
    calls, gets = report.get('API_attempts'), report.get('GET_attempts')
    metadata_path = '/repos/' + REPO + '/actions/artifacts/%d' % pin['id']
    require(type(calls) is list and len(calls) == 2
            and [x.get('role') for x in calls] == ['official_metadata', 'official_download_redirect']
            and [x.get('path') for x in calls] == [metadata_path, metadata_path + '/zip']
            and all(x.get('artifact_id') == pin['id'] and x.get('method') == 'GET'
                    and x.get('attempt') == 1 and x.get('retries') == 0
                    and x.get('host') == 'api.github.com'
                    and x.get('credential_sent_only_to_official_API') is True for x in calls)
            and calls[0].get('status') == 200 and calls[1].get('status') == 302
            and calls[1].get('automatic_redirects') == 0
            and calls[1].get('authorization_forwarded') is False
            and calls[1].get('signed_Location_recorded') is False
            and type(gets) is list and len(gets) == 1,
            'one-artifact official request denominator differs')
    get = gets[0]
    require(get.get('artifact_id') == pin['id'] and get.get('method') == 'GET'
            and get.get('attempt') == 1 and get.get('redirects') == 0 and get.get('retries') == 0
            and get.get('authorization_sent') is False and get.get('cookies_sent') is False
            and get.get('bytes') == pin['bytes'] and get.get('sha256') == pin['sha256']
            and get.get('output') == str(root / 'original' / ('artifact-%d.zip' % pin['id']))
            and get.get('host') == calls[1].get('storage_host')
            and type(get.get('host')) is str
            and get['host'].endswith(('.blob.core.windows.net', '.actions.githubusercontent.com'))
            and get.get('url_sha256') == calls[1].get('location_sha256'),
            'single anonymous original ZIP GET differs')
    metadata = report.get('official_metadata')
    require(type(metadata) is dict and metadata.get('path') ==
                str(root / 'api' / ('artifact-%d.metadata.original.json' % pin['id']))
            and metadata == calls[0].get('original_metadata'),
            'original official metadata record differs')
    metadata_raw = read(Path(metadata['path']), 1 << 20, metadata['sha256'])
    require(len(metadata_raw) == metadata['bytes'], 'original official metadata byte count differs')
    provider = json.loads(metadata_raw)
    require(provider.get('id') == pin['id'] and provider.get('name') == pin['name']
            and provider.get('size_in_bytes') == pin['bytes']
            and provider.get('digest') == 'sha256:' + pin['sha256']
            and provider.get('expired') is False
            and provider.get('workflow_run', {}).get('id') == pin['run_id']
            and provider.get('workflow_run', {}).get('head_sha') == pin['head_sha']
            and provider.get('archive_download_url') == 'https://api.github.com' + metadata_path + '/zip',
            'actual official artifact metadata differs from frozen identity')
    before, after = report.get('artifact_before'), report.get('artifact_after')
    archive_path = root / 'original' / ('artifact-%d.zip' % pin['id'])
    require(type(before) is dict and before == after and before.get('path') == str(archive_path)
            and before.get('bytes') == pin['bytes'] and before.get('sha256') == pin['sha256']
            and before.get('actual_bytes_independently_read') == pin['bytes'],
            'owned worker two complete original ZIP reads differ')
    actual_archive = file_record(archive_path, 32 << 20)
    require(all(actual_archive[key] == before[key] for key in ('path', 'bytes', 'sha256', 'identity')),
            'independent finalizer full original ZIP read differs')

    inventory, total = zip_inventory(archive_path, pins)
    require(inventory == report.get('archive_inventory')
            and len(inventory) == report.get('archive_member_count')
            and total == report.get('archive_uncompressed_bytes')
            and report.get('all_members_fully_read_and_CRC_verified') is True,
            'independent full ZIP inventory and CRC read differs')
    expected_targets = [x['logical_path'] for x in pins['historical_targets']
                        if x['role'] == 'original']
    expected_targets += [x['logical_path'] for x in pins['reader_targets']]
    expected_targets.append('failed-reader/RESULT.json')
    require(len(expected_targets) == 20 and report.get('diagnostic_targets') == expected_targets,
            'fixed twenty diagnostic targets differ')
    by_member = {row['archive_path']: row for row in inventory}
    files = report.get('frame_files')
    missing = report.get('missing_diagnostic_targets')
    require(type(files) is list and type(missing) is list
            and len({x['logical_path'] for x in files}) == len(files)
            and len(set(missing)) == len(missing)
            and [x for x in expected_targets if x not in missing] ==
                [x['logical_path'] for x in files]
            and set(missing) <= set(expected_targets)
            and report.get('all_selected_originals_fully_read') is True,
            'present/missing diagnostic target accounting differs')
    observed, raw_count, original_raw = [], 0, {}
    historical = {row['logical_path']: row for row in pins['historical_targets']
                  if row['role'] == 'original'}
    prior_controls = {row['logical_path']: row for row in pins['reader_targets']}
    for item in files:
        logical = item['logical_path']
        index = expected_targets.index(logical)
        path = root / 'selected' / ('%03d.original' % index)
        row = by_member.get(item.get('archive_path'))
        require(row is not None and not logical.startswith('source/')
                and item.get('origin') == 'exact failed reader artifact member ' + row['archive_path'],
                'nonfixed or assembly body in diagnostic output')
        actual = file_record(path, MAX_FRAME_RAW)
        require(actual == item.get('record') and actual['path'] == str(path)
                and actual['bytes'] == row['bytes'] and actual['sha256'] == row['sha256'],
                'retained diagnostic original differs from inventoried member')
        if logical in historical:
            frozen = historical[logical]
            require(row['normalized_path'] in frozen['archive_aliases']
                    and all(row[name] == frozen[name] for name in ('bytes', 'sha256', 'git_blob_sha1')),
                    'historical diagnostic is not its exact known original bytes')
        elif logical in prior_controls:
            frozen = prior_controls[logical]
            require(row['normalized_path'] in (frozen['main_member'], frozen['hold_member']),
                    'prior reader diagnostic uses another fixed member')
        else:
            require(logical == 'failed-reader/RESULT.json' and row['normalized_path'] == 'RESULT.json',
                    'frame-result diagnostic path differs')
        original_raw[logical] = read(path, MAX_FRAME_RAW, actual['sha256'])
        raw_count += actual['bytes']
        observed.append({'logical_path': logical, 'record': actual, 'origin': item['origin']})
    require(raw_count == report.get('selected_original_bytes') and raw_count <= MAX_FRAME_RAW,
            'complete original diagnostic extent differs')
    prior_root = pins['original_failed_reader']['root']
    setup_value = None
    guard_value = None
    if 'failed-reader/setup.json' in original_raw:
        setup_value = json.loads(original_raw['failed-reader/setup.json'])
        old_context(setup_value.get('context'), pins)
        require(setup_value.get('schema') == 'hia.actions.core-emitter-assets-setup.v1',
                'prior setup diagnostic schema differs')
    if 'failed-reader/guard/guardian.json' in original_raw:
        guard_value = json.loads(original_raw['failed-reader/guard/guardian.json'])
        require(setup_value is not None
                and guard_value.get('schema') == 'hepta.hia.external-qualification-guardian.v1'
                and guard_value.get('command') == setup_value.get('command')
                and guard_value.get('cwd') == prior_root
                and guard_value.get('source_identities_before') == setup_value.get('source_identities')
                and guard_value.get('lifecycle', {}).get('cleanup', {}).get('complete') is True
                and guard_value.get('lifecycle', {}).get('cleanup', {}).get('observed_echild') is True,
                'prior guardian diagnostic is not the bound closed operation')
    for logical in ('failed-reader/guard/child.stdout.log', 'failed-reader/guard/child.stderr.log'):
        if logical in original_raw:
            require(guard_value is not None and guard_value.get('logs', {}).get(
                        prior_root + '/' + logical.removeprefix('failed-reader/'))
                    == sha256(original_raw[logical]).hexdigest(),
                    'prior diagnostic log is not bound by the actual original guardian')
    if 'failed-reader/recovery-terminal.json' in original_raw:
        value = json.loads(original_raw['failed-reader/recovery-terminal.json'])
        require(value.get('schema') == 'hia.actions.core-emitter-assets-worker.v1'
                and value.get('root') == prior_root
                and value.get('policy_sha256') == pins['original_failed_reader']['policy_sha256']
                and value.get('source_artifact') == pins['historical_source_artifact']
                and value.get('token_or_signed_URL_recorded') is False
                and value.get('source_generated_again') is False,
                'prior recovery diagnostic scope differs')
    if 'failed-reader/RESULT.json' in original_raw:
        value = json.loads(original_raw['failed-reader/RESULT.json'])
        old_context(value.get('context'), pins)
        require(value.get('schema') == 'hia.actions.core-emitter-assets-log-result.v1'
                and value.get('status') in ('FRAMING_HOLD', 'ORIGINAL_FRAMES_COMPLETE_NOT_QUALIFICATION')
                and value.get('qualification_executed') is False
                and value.get('original_product_statuses_reclassified') is False,
                'prior frame result diagnostic scope differs')
    return observed

def capture_original_files(files, public, result):
    require(len(files) <= 64 and sum(item['record']['bytes'] for item in files) <= MAX_FRAME_RAW,
            'complete retained original set exceeds the fixed framing bound')
    result['captured'] = []
    observed = []
    for index, item in enumerate(files):
        original = item['record']
        raw = read(Path(original['path']), MAX_FRAME_RAW, original['sha256'])
        require(len(raw) == original['bytes']
                and list(identity(Path(original['path']).lstat())) == original['identity'],
                'original changed before independent public custody copy')
        name = '%03d.original' % index
        target = public / name
        create(target, raw)
        record = file_record(target, MAX_FRAME_RAW)
        require(record['bytes'] == original['bytes'] and record['sha256'] == original['sha256'],
                'complete public custody copy differs')
        result['captured'].append({'logical_path': item['logical_path'], 'retained_file': name,
                                  'bytes': record['bytes'], 'sha256': record['sha256'],
                                  'independent_copy_readback': True})
        observed.append({'logical_path': item['logical_path'], 'record': record, 'origin': item['origin']})
    return observed



def retain_download_originals(root, public, policy, result):
    pin = policy['source_artifact']
    names = ['artifact-%d.zip' % pin['id'], 'artifact-%d.zip.partial' % pin['id']]
    result['transport_originals'] = []
    result['transport_original_errors'] = []
    attempted = 0
    for index, name in enumerate(names):
        path = root / 'original' / name
        try:
            if not os.path.lexists(path):
                continue
            with parent_descriptor(path) as (parent, leaf):
                fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=parent)
                try:
                    before = os.fstat(fd)
                    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                            and 0 <= before.st_size <= pin['bytes'], 'unbounded failed ZIP original')
                    if before.st_nlink != 1:
                        require(before.st_nlink == 2, 'failed ZIP link count refused')
                        aliases = [os.stat(value, dir_fd=parent, follow_symlinks=False) for value in names]
                        require(all(stat.S_ISREG(value.st_mode) and value.st_dev == before.st_dev
                                    and value.st_ino == before.st_ino and value.st_nlink == 2
                                    and value.st_uid == os.geteuid() for value in aliases),
                                'two links are not the exact fixed ZIP publication pair')
                    attempted += before.st_size
                    require(attempted <= 2 * pin['bytes'], 'two original ZIP extents exceeded')
                    parts, count = [], 0
                    while count < before.st_size:
                        part = os.read(fd, min(CHUNK, before.st_size - count))
                        if not part:
                            break
                        parts.append(part)
                        count += len(part)
                    require(count == before.st_size and identity(before) == identity(os.fstat(fd))
                            and identity(before) ==
                                identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)),
                            'failed ZIP original changed during bounded retention')
                finally:
                    os.close(fd)
            raw = b''.join(parts)
            target = public / ('failed-artifact-%d-%d.zip' % (pin['id'], index))
            create(target, raw)
            copied = file_record(target, pin['bytes'])
            require(copied['bytes'] == len(raw) and copied['sha256'] == sha256(raw).hexdigest(),
                    'failed ZIP independent retention differs')
            result['transport_originals'].append({
                'source_name': name, 'retained_file': target.name,
                'bytes': copied['bytes'], 'sha256': copied['sha256'],
                'matches_fixed_complete_artifact': copied['bytes'] == pin['bytes']
                    and copied['sha256'] == pin['sha256'], 'frame_included': False})
        except BaseException as error:
            result['transport_original_errors'].append({'source_name': name,
                'type': type(error).__name__,
                'safe_refusal': str(error) if type(error) is Refusal else None})
    return any(row['matches_fixed_complete_artifact'] for row in result['transport_originals'])

def output_frames(files, context, extra, terminal_status):
    require(len(files) <= 25 and len({x['logical_path'] for x in files}) == len(files)
            and sum(x['record']['bytes'] for x in files) <= MAX_FRAME_RAW,
            'all fixed diagnostic sources exceed the raw output bound')
    manifest = {'schema': 'hia.core-failed-reader-diagnostic-frame-manifest.v1',
        'context': context,
        'files': [{'path': x['logical_path'], 'bytes': x['record']['bytes'],
                   'sha256': x['record']['sha256'], 'origin': x['origin']} for x in files],
        'frame_bytes': FRAME_BYTES,
        'frame_count': sum((x['record']['bytes'] + FRAME_BYTES - 1) // FRAME_BYTES for x in files),
        'total_raw_bytes': sum(x['record']['bytes'] for x in files),
        'maximum_raw_bytes': MAX_FRAME_RAW, 'maximum_stdout_bytes': MAX_FRAME_STDOUT,
        'assembly_body_bytes_output': 0, 'original_run_conclusion': 'failure',
        'original_failure_reclassified': False, 'qualification_executed': False, **extra}
    manifest_raw = wire(manifest)
    require(len(manifest_raw) <= 64 << 10, 'fixed diagnostic manifest exceeds bound')
    manifest_sha = sha256(manifest_raw).hexdigest()
    count, raw_count, stdout_count = 0, 0, 0
    def emit(prefix, value):
        nonlocal stdout_count
        line = (prefix + ' ' + json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
        require(stdout_count + len(line) <= MAX_FRAME_STDOUT, 'diagnostic log output bound exhausted')
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
        stdout_count += len(line)
    emit('HIA_CORE_READER_DIAGNOSTIC_MANIFEST_V1', {
        'bytes': len(manifest_raw), 'sha256': manifest_sha,
        'base64': base64.b64encode(manifest_raw).decode('ascii')})
    for item in files:
        expected = item['record']
        path = Path(expected['path'])
        raw = read(path, MAX_FRAME_RAW, expected['sha256'])
        require(len(raw) == expected['bytes'] and file_record(path, MAX_FRAME_RAW) == expected,
                'diagnostic frame source changed before output')
        for offset in range(0, len(raw), FRAME_BYTES):
            part = raw[offset:offset + FRAME_BYTES]
            emit('HIA_CORE_READER_DIAGNOSTIC_FRAME_V1', {
                'manifest_sha256': manifest_sha, 'path': item['logical_path'],
                'offset': offset, 'length': len(part), 'sha256': sha256(part).hexdigest(),
                'base64': base64.b64encode(part).decode('ascii')})
            count += 1
            raw_count += len(part)
        require(file_record(path, MAX_FRAME_RAW) == expected,
                'diagnostic original changed while its immutable bytes were framed')
    require(count == manifest['frame_count'] and raw_count == manifest['total_raw_bytes'],
            'diagnostic raw and frame denominators differ')
    terminal = {'schema': 'hia.core-failed-reader-diagnostic-frame-terminal.v1',
        'status': terminal_status, 'manifest_sha256': manifest_sha,
        'files': len(files), 'frames': count, 'raw_bytes': raw_count, 'diagnostic_bytes_complete': True,
        'original_run_conclusion': 'failure', 'original_failure_reclassified': False,
        'assembly_body_bytes_output': 0, 'qualification_executed': False,
        'missing_diagnostic_targets': extra.get('missing_diagnostic_targets', [])}
    return {'manifest_sha256': manifest_sha, 'files': len(files), 'frames': count,
            'raw_bytes': raw_count, 'stdout_bytes': stdout_count}, terminal

def finalize(args):
    require(TOKEN_VARIABLE not in os.environ, 'read token entered diagnostic framing')
    _, policy, _, root, public, context = policy_and_context(args)
    require(not os.path.lexists(public), 'new diagnostic custody root already exists')
    os.umask(0o077)
    public.mkdir(mode=0o700, exist_ok=False)
    result = {'schema': 'hia.actions.core-failed-reader-diagnostic-result.v1',
        'status': 'DIAGNOSTIC_HOLD', 'context': context, 'errors': [],
        'original_run_conclusion': 'failure', 'original_failure_reclassified': False,
        'qualification_executed': False, 'assembly_body_bytes_output': 0}
    files, report, pending_terminal = [], None, None
    accepted = False
    try:
        setup, _ = document(root / 'setup.json')
        check_setup(setup, context, policy, root)
        guardian, _ = document(root / 'guard/guardian.json')
        require(closed_guardian(guardian, setup, policy, root),
                'no bound closed cleanup; do not inspect live diagnostic originals')
        result['closed_ECHILD_before_read'] = True
        retained_complete = retain_download_originals(root, public, policy, result)
        try:
            natural_guardian(guardian, setup, policy, root)
            report, _ = document(root / 'recovery-terminal.json', 2 << 20)
            files = accept_diagnostic_reader(report, setup, policy, root)
            require(retained_complete, 'complete fixed failed artifact was not independently retained')
            accepted = True
        except BaseException as error:
            accepted = False
            files = []
            result['errors'].append({'stage': 'DIAGNOSTIC_ACCEPTANCE', 'type': type(error).__name__,
                                     'safe_refusal': str(error) if type(error) is Refusal else None})
        for name in ('guard/guardian.json', 'guard/child.stdout.log', 'guard/child.stderr.log',
                     'recovery-terminal.json', 'setup.json'):
            path = root / name
            if os.path.lexists(path):
                files.append({'logical_path': 'diagnostic-reader/' + name,
                    'record': file_record(path, 2 << 20),
                    'origin': 'current independent diagnostic read raw control record'})
        for path, expected in setup['source_identities'].items():
            require(file_record(Path(path), 64 << 20,
                    system_binary=path == context['python']['resolved'])['sha256'] == expected,
                    'frozen diagnostic source changed before framing')
        files = capture_original_files(files, public, result)
        terminal = 'DIAGNOSTICS_COMPLETE_ORIGINAL_FAILURE_UNCHANGED' if accepted else 'DIAGNOSTIC_HOLD'
        extra = {'diagnostics_accepted': accepted, 'failed_artifact': policy['source_artifact'],
                 'original_failed_run_id': 43152508792,
                 'missing_diagnostic_targets': report.get('missing_diagnostic_targets', []) if report else [],
                 'errors': result['errors']}
        observed, pending_terminal = output_frames(files, context, extra, terminal)
        for path, expected in setup['source_identities'].items():
            require(file_record(Path(path), 64 << 20,
                    system_binary=path == context['python']['resolved'])['sha256'] == expected,
                    'frozen diagnostic source changed while framing')
        result.update(status=terminal, frames=observed, frozen_source_preserved=True)
    except BaseException as error:
        pending_terminal = None
        result['status'] = 'DIAGNOSTIC_HOLD'
        result['errors'].append({'stage': 'FRAMING', 'type': type(error).__name__,
                                'safe_refusal': str(error) if type(error) is Refusal else None})
        print('HIA_CORE_READER_DIAGNOSTIC_FAILURE_V1 ' + json.dumps({
            'status': 'DIAGNOSTIC_HOLD', 'error_type': type(error).__name__,
            'safe_refusal': str(error) if type(error) is Refusal else None,
            'original_failure_reclassified': False}), flush=True)
    raw = wire(result)
    create(public / 'RESULT.json', raw)
    require(read(public / 'RESULT.json', 1 << 20) == raw, 'diagnostic result readback differs')
    sync_dir(public)
    if pending_terminal is not None:
        pending_terminal['result_sha256'] = sha256(raw).hexdigest()
        line = ('HIA_CORE_READER_DIAGNOSTIC_END_V1 ' + json.dumps(
            pending_terminal, sort_keys=True, separators=(',', ':')) + '\n').encode()
        require(result['frames']['stdout_bytes'] + len(line) <= MAX_FRAME_STDOUT,
                'diagnostic terminal exceeds stdout bound')
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
    return 0 if result['status'] == 'DIAGNOSTICS_COMPLETE_ORIGINAL_FAILURE_UNCHANGED' else 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'run', 'finalize'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--control-commit', required=True)
    args = parser.parse_args()
    return {'prepare': prepare, 'run': run, 'finalize': finalize}[args.action](args)

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Refusal as error:
        print(json.dumps({'status': 'INPUT_HOLD', 'safe_refusal': str(error)}), flush=True)
        raise SystemExit(1)
