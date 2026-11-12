"""Own one fixed Actions development authoring run and retain its original output."""
from __future__ import annotations
import argparse
import ast
import gzip
import io
from contextlib import contextmanager
from hashlib import sha1, sha256
import json
import tarfile
import zipfile
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
PREFIX = 'experiments/hia_json_pretty_20261112/installed-development-r1'
CANDIDATE = 'a74a030680bb73da9a4599567962d01a9d6bcac0'
TREE = '2d47e3af79e558d2651d5f43f0759a02a404b6a5'
TRIGGER = 'codex/hia-json-pretty-installed-run-r1-20261112-e26e'
WORK_ROOT = 'hia-json-pretty-installed-development-r1'
NATURAL = {'qualification_started', 'owned_child_observed',
           'qualification_exit_observed', 'owned_child_reaped'}
MAX_RECEIPT = 32 << 20

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

@contextmanager
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

def git(source, executable, *arguments):
    environment = clean_environment()
    environment['GIT_OPTIONAL_LOCKS'] = '0'
    return subprocess.run([str(executable), '--no-replace-objects', *arguments],
                          cwd=source, env=environment, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True).stdout

def source_head(source, executable):
    head = git(source, executable, 'rev-parse', 'HEAD').decode().strip()
    tree = git(source, executable, 'rev-parse', 'HEAD^{tree}').decode().strip()
    git(source, executable, 'diff', '--cached', '--quiet', TREE, '--')
    require(head == CANDIDATE and tree == TREE, 'actual source HEAD/tree differs')
    require(read(source / '.git/HEAD', 256)[0].decode().strip() == CANDIDATE,
            'source checkout is not detached at the exact input commit')
    return {'head': head, 'tree': tree, 'actual_HEAD_is_candidate': True}

def context(args):
    require(not any(value for name, value in os.environ.items()
                    if name.startswith(('GIT_', 'LD_'))),
            'ambient Git/loader redirection is outside this development profile')
    require(not os.environ.get('GITHUB_TOKEN') and not os.environ.get('GH_TOKEN'),
            'publication or API token must not enter native development')
    require(sys.version_info[:3] == (3, 14, 4) and platform.python_implementation() == 'CPython',
            'actual setup-python interpreter version differs')
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    control_checkout = workspace / 'control'
    control = Path(__file__).resolve().parent
    require(control == control_checkout / PREFIX
            and re.fullmatch(r'[0-9a-f]{40}', args.control_commit) is not None
            and read(control_checkout / '.git/HEAD', 256)[0].decode().strip() == args.control_commit,
            'actual detached reviewed control checkout differs')
    policy_raw, policy_record = read(control / 'policy.json', 1 << 20)
    require(policy_record['sha256'] == args.policy_sha256, 'frozen policy bytes differ')
    policy = json.loads(policy_raw)
    require(policy['schema'] == 'hia.json-pretty-actions-policy.v1'
            and policy['candidate'] == {'commit': CANDIDATE, 'tree': TREE, 'leaves': 4027}
            and policy['controller_seconds'] == 180 and policy['cleanup_seconds'] == 3
            and policy['trigger_branch'] == TRIGGER,
            'frozen development policy differs')
    require(set(policy['controls']) == {'authoring.py', 'controller.py', 'diagnostics.py',
            'guardian.py', 'process_owner_impl.py', 'native_cases.py', 'byte_bridge.py',
            'package_helper.py', 'installed_cases.py',
            'json_pretty.hiaasm', 'json_pretty.hia.json', 'cases.json'},
            'complete frozen control and HIA input inventory differs')
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
            and os.environ.get('HIA_JSON_PRETTY_WORKFLOW_SHA') == workflow_sha
            and os.environ.get('GITHUB_WORKFLOW_SHA') == workflow_sha,
            'actual workflow commit identity differs')
    temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    root = temp / WORK_ROOT
    source = workspace / 'source'
    require(args.root == root and args.source == source and source.resolve(strict=True) == source
            and not any(p.is_symlink() for p in (root.parent, *root.parent.parents,
                                                source, *source.parents)),
            'fixed private output/source path differs')
    python = Path(sys.executable).resolve(strict=True)
    python_raw, python_record = read(python, 64 << 20, system_binary=True)
    git_executable = Path(shutil.which('git')).resolve(strict=True)
    _, git_record = read(git_executable, 64 << 20, system_binary=True)
    git_version = subprocess.run([str(git_executable), '--version'], env=clean_environment(),
                                 check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()
    records = {}
    for name, pin in policy['controls'].items():
        require(re.fullmatch(r'[a-z0-9_.]+', name) is not None, 'control basename differs')
        raw, observed = read(control / name, 1 << 20)
        require(observed['bytes'] == pin['bytes'] and observed['sha256'] == pin['sha256'],
                'frozen control source differs: ' + name)
        records[str(control / name)] = pin['sha256']
    records[str(control / 'policy.json')] = policy_record['sha256']
    value = {'schema': 'hia.json-pretty-actions-context.v1',
             'repository': REPOSITORY, 'event': 'create', 'trigger_branch': TRIGGER,
             'run_id': int(os.environ['GITHUB_RUN_ID']), 'run_attempt': 1,
             'run_number': int(os.environ['GITHUB_RUN_NUMBER']),
             'event_sha256': event_record['sha256'], 'workflow_commit': workflow_sha,
             'workflow_ref': os.environ['GITHUB_WORKFLOW_REF'],
             'actual_control_commit': args.control_commit,
             'policy_sha256': policy_record['sha256'], 'control_sources': records,
             'candidate_commit': CANDIDATE, 'candidate_tree': TREE, 'candidate_leaves': 4027,
             'source': str(source), 'root': str(root), 'evidence': str(root / 'evidence'),
             'controller_seconds': 180, 'cleanup_seconds': 3,
             'python': {'source': 'actions/setup-python fixed action with python-version 3.14.4',
                        'executable': sys.executable, 'resolved': str(python), 'version': sys.version,
                        'implementation': platform.python_implementation(),
                        'version_info': list(sys.version_info), 'prefix': sys.prefix,
                        'base_prefix': sys.base_prefix, 'platform': sys.platform,
                        'machine': platform.machine(), 'binary': python_record,
                        'desktop_binary_identity_claimed': False},
             'git': {'resolved': str(git_executable), 'version': git_version, 'binary': git_record},
             'native_execution_requested': True, 'product_tests_requested': False,
             'cold_qualification_requested': False}
    return control, policy, policy_raw, root, source, value

def expected_inputs(control, policy, root, value):
    result = dict(value['control_sources'])
    for name, pin in policy['controls'].items():
        result[str(root / 'control' / name)] = pin['sha256']
    result[str(root / 'control/policy.json')] = value['policy_sha256']
    result[str(root / 'context.json')] = sha256(wire(value)).hexdigest()
    result[value['python']['resolved']] = value['python']['binary']['sha256']
    result[value['git']['resolved']] = value['git']['binary']['sha256']
    return result

def command(root, source, value):
    return [value['python']['resolved'], '-I', '-S', '-B', str(root / 'control/authoring.py'),
            '--source', str(source), '--output', str(root / 'evidence'),
            '--context', str(root / 'context.json'), '--policy-sha256', value['policy_sha256']]

def prepare(args):
    control, policy, raw, root, source, value = context(args)
    require(not os.path.lexists(root), 'new native development root already exists')
    capacity = os.statvfs(root.parent)
    available = capacity.f_bavail * capacity.f_frsize
    require(available >= 2 << 30, 'development development output reserve unavailable')
    actual_source = source_head(source, value['git']['resolved'])
    os.umask(0o077)
    _create_directory(root)
    _create_directory(root / 'control')
    _create_directory(root / 'guard')
    for name, pin in policy['controls'].items():
        original, observed = read(control / name, 1 << 20)
        require(observed['sha256'] == pin['sha256'], 'control changed before copying')
        create(root / 'control' / name, original)
    create(root / 'control/policy.json', raw)
    create(root / 'context.json', wire(value))
    inputs = expected_inputs(control, policy, root, value)
    invocation = command(root, source, value)
    config = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
              'command': invocation, 'cwd': str(root), 'source_identities': inputs}
    config_record = save(root / 'guard/request.json', config)
    setup = {'schema': 'hia.json-pretty-actions-setup.v1', 'status': 'PREPARED_NOT_EXECUTED',
             'context': value, 'source_actual_HEAD': actual_source,
             'source_identities': inputs, 'command': invocation,
             'guardian_config_sha256': config_record['sha256'],
             'controller_seconds': 180, 'cleanup_seconds': 3,
             'resource_observation': {'available_bytes': available,
                 'minimum_source_only_available_bytes': 2 << 30,
                 'formal_full_resource_or_inode_qualification': False}}
    record = save(root / 'setup.json', setup)
    print(json.dumps({'status': setup['status'], 'setup_sha256': record['sha256'],
                      'root': str(root), 'actual_source_head': actual_source['head']}), flush=True)
    return 0

def setup_record(control, policy, root, source, value):
    setup_raw, record = read(root / 'setup.json', 1 << 20)
    setup = json.loads(setup_raw)
    require(setup['schema'] == 'hia.json-pretty-actions-setup.v1'
            and setup['status'] == 'PREPARED_NOT_EXECUTED'
            and setup['context'] == value and setup['command'] == command(root, source, value)
            and setup['source_identities'] == expected_inputs(control, policy, root, value)
            and setup['controller_seconds'] == 180 and setup['cleanup_seconds'] == 3,
            'original setup differs from this exact operation')
    require(read(root / 'context.json', 1 << 20)[0] == wire(value), 'actual original context differs')
    return setup, record

def run(args):
    control, policy, _, root, source, value = context(args)
    setup, _ = setup_record(control, policy, root, source, value)
    source_head(source, value['git']['resolved'])
    config_raw, config_record = read(root / 'guard/request.json', 1 << 20)
    require(config_record['sha256'] == setup['guardian_config_sha256'], 'guardian request changed')
    config = json.loads(config_raw)
    require(config == {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
                       'command': setup['command'], 'cwd': str(root),
                       'source_identities': setup['source_identities']}, 'unexpected guardian request')
    for path, expected in setup['source_identities'].items():
        _, record = read(Path(path), 64 << 20,
                         system_binary=path in (value['python']['resolved'], value['git']['resolved']))
        require(record['sha256'] == expected, 'frozen input changed before owned authoring')
    os.chdir(root)
    python = value['python']['resolved']
    os.execve(python, [python, '-I', '-S', '-B', str(root / 'control/guardian.py'),
                      '--config', str(root / 'guard/request.json'),
                      '--config-sha256', setup['guardian_config_sha256'],
                      '--implementation', str(root / 'control/process_owner_impl.py')], clean_environment())

def closed_owner(guardian, setup, root):
    life = guardian.get('lifecycle', {})
    require(guardian.get('schema') == 'hepta.hia.external-qualification-guardian.v1'
            and guardian.get('command') == setup['command'] and guardian.get('cwd') == str(root)
            and guardian.get('external_controller_seconds') == 180
            and guardian.get('source_identities_before') == setup['source_identities']
            and guardian.get('lifecycle_implementation_sha256') ==
                setup['source_identities'][str(root / 'control/process_owner_impl.py')]
            and life.get('schema') == 'hepta.hia.external-qualification-guardian.v1.lifecycle'
            and life.get('qualification_seconds') == 180 and life.get('cleanup_seconds') == 3
            and life.get('subreaper_enabled') is True and life.get('qualification_started') is True,
            'guardian is not the exact original authoring operation')
    cleanup = life.get('cleanup', {})
    require(cleanup.get('attempted') is True and cleanup.get('complete') is True
            and cleanup.get('observed_echild') is True and cleanup.get('leader_reaped') is True
            and cleanup.get('deadline_exceeded') is False and cleanup.get('errors') == []
            and cleanup.get('remaining_direct_children') == [],
            'original authoring process tree has no closed ECHILD boundary')
    return life

def retained(path, expected, *, maximum=32 << 20):
    raw, record = read(path, maximum)
    require(expected['path'] == str(path) and expected['size'] == len(raw)
            and expected['sha256'] == record['sha256']
            and expected['git_blob_sha1'] ==
                sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'actual retained original differs from worker pin')
    return raw, record

INSTALLATION_IDS = (
    'installed_package_sources_and_native_output',
    'invalid_manifest_schema',
    'invalid_manifest_source_hash',
    'invalid_manifest_image_hash',
    'invalid_manifest_shape_and_compiler_field',
    'warm_source_mutation_rejected_and_restored',
    'warm_source_missing_rejected_and_restored',
    'missing_data_root_refuses_checkout_and_cwd_fallback',
    'manifest_size_duplicate_keys_and_reentry',
)

def content_pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest()}

def package_name(name):
    require(type(name) is str and name and '\\' not in name and '\0' not in name
            and not name.startswith('/') and all(part not in ('', '.', '..')
                for part in name.split('/')), 'noncanonical package member')
    return name

def installation_projection(rows):
    return [{key: row[key] for key in ('path', 'bytes', 'sha256', 'git_blob_sha1', 'mode')}
            for row in rows]

def installation_snapshot(root):
    def names():
        result = []
        def fail(error):
            raise error
        require(stat.S_ISDIR(root.lstat().st_mode), 'installed root is not an ordinary directory')
        for directory, subdirs, files in os.walk(root, followlinks=False, onerror=fail):
            for name in subdirs:
                require(stat.S_ISDIR((Path(directory) / name).lstat().st_mode),
                        'installed directory is not ordinary')
            for name in files:
                path = Path(directory) / name
                require(stat.S_ISREG(path.lstat().st_mode), 'installed member is not ordinary')
                result.append(package_name(path.relative_to(root).as_posix()))
                require(len(result) <= 4096, 'installed namespace exceeds this fixed control')
        return sorted(result)
    first = names()
    rows, total = [], 0
    for name in first:
        raw, observed = read(root / name, 64 << 20)
        total += len(raw)
        require(total <= 128 << 20, 'installed bytes exceed the fixed package bound')
        rows.append({'path': name, **content_pin(raw),
                     'mode': format(stat.S_IMODE(observed['identity'][2]), '04o'),
                     'identity': observed['identity']})
    require(names() == first, 'installed namespace changed while reading')
    return rows

def archive_inventory(raw, kind):
    rows, seen, total = [], set(), 0
    if kind == 'wheel':
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for info in archive.infolist():
                name = package_name(info.filename.rstrip('/') if info.is_dir() else info.filename)
                require(name not in seen and not info.flag_bits & 1, 'wheel duplicate/encryption')
                seen.add(name)
                mode = info.external_attr >> 16
                require(not stat.S_ISLNK(mode)
                        and (info.is_dir() or mode == 0 or stat.S_ISREG(mode)), 'wheel special member')
                if info.is_dir():
                    continue
                require(0 <= info.file_size <= 64 << 20, 'wheel member bound')
                total += info.file_size
                require(total <= 128 << 20, 'wheel aggregate bound')
                data = archive.read(info)
                require(len(data) == info.file_size, 'wheel member length')
                rows.append({'path': name, **content_pin(data), 'zip_crc32': info.CRC,
                             'mode': format(stat.S_IMODE(mode), '04o')})
    else:
        require(kind == 'sdist', 'unknown archive kind')
        with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as compressed:
            decoded = compressed.read((128 << 20) + 1)
            require(len(decoded) <= 128 << 20 and compressed.read(1) == b'', 'sdist decoded bound')
        roots = set()
        with tarfile.open(fileobj=io.BytesIO(decoded), mode='r:') as archive:
            for member in archive.getmembers():
                name = package_name(member.name.rstrip('/') if member.isdir() else member.name)
                require(name not in seen and (member.isdir() or member.isfile()), 'sdist duplicate/special member')
                seen.add(name)
                roots.add(name.split('/')[0])
                if member.isdir():
                    continue
                require('/' in name and 0 <= member.size <= 64 << 20, 'sdist member shape/bound')
                total += member.size
                require(total <= 128 << 20, 'sdist aggregate bound')
                stream = archive.extractfile(member)
                require(stream is not None, 'sdist member unavailable')
                data = stream.read(member.size + 1)
                require(len(data) == member.size, 'sdist member length')
                rows.append({'path': name.split('/', 1)[1], **content_pin(data),
                             'mode': format(member.mode, '04o')})
        require(len(roots) == 1, 'sdist top-level population differs')
    return rows

def verify_installation(root, setup, report, source_rows, image_pin, compiler_pin, bridge_pin, assembly_pin):
    evidence = root / 'evidence'
    base = evidence / 'installation'
    installed = base / 'installed'
    source = Path(setup['context']['source'])
    python = setup['context']['python']['resolved']
    policy = json.loads(read(root / 'control/policy.json', 1 << 20)[0])
    require(report['support_contract_recomputed_in_memory'] is True
            and report['source_contract_exact_byte_check'] is True
            and report['source_contract_file_count'] == 790
            and report['contract_sha256'] == '54a44cea1d69f7528714883f1a5482d506010e48651301e0a1d54d48f79f713e'
            and report['language_inventory_recomputed_in_memory'] is True
            and report['language_inventory_exact_byte_check'] is True
            and report['language_inventory_sha256'] == '7fd2470f93c30f6f214d3917e0dcf13b375d772d6e87e19d971034f70be02cc3'
            and report['installed_package_exercised'] is True
            and report['installed_resource_cases_executed'] is True
            and report['old_43_cases_preserved'] is True,
            'runtime source-contract or installation scope was not established')
    originals = {}
    for name, field in (
            ('package-report.json', 'installation_package_report_original'),
            ('installed-cases.json', 'installation_cases_original'),
            ('installed-child.stdout.log', 'installation_child_stdout'),
            ('installed-child.stderr.log', 'installation_child_stderr')):
        originals[name] = retained(base / name, report[field])
    package = json.loads(originals['package-report.json'][0])
    cases = json.loads(originals['installed-cases.json'][0])
    summary_names = ('schema', 'status', 'candidate_commit', 'installed_root', 'bridge_path',
                     'manifest_path', 'expected_test_ids', 'source_and_inputs_stable',
                     'installed_bytes_and_modes_restored')
    require(report['installation_result'] == {name: package[name] for name in summary_names}
            and package['schema'] == 'hia.json-pretty.development-installation.v1'
            and package['status'] == 'DEVELOPMENT_INSTALLATION_PASS'
            and package['scope'] == 'DEVELOPMENT_INSTALLATION'
            and package['candidate_commit'] == package['source_head'] == CANDIDATE
            and package['source'] == str(source) and package['evidence'] == str(base)
            and package['installed_root'] == str(installed)
            and package['bridge_path'] == str(installed / 'hepta/hia_json_pretty_native.py')
            and package['manifest_path'] == str(base / 'native/manifest.json')
            and report['native_case_source_root'] == str(installed)
            and report['native_case_bridge_path'] == package['bridge_path']
            and package['expected_test_ids'] == list(INSTALLATION_IDS)
            and package['installed_cases'] == originals['installed-cases.json'][1]
            and package['errors'] == []
            and package['source_and_inputs_stable'] is True
            and package['installed_bytes_and_modes_restored'] is True
            and all(package[name] is False for name in (
                'native_compilation_performed_here', 'formal_cold_qualification',
                'CLI_replacement_tested', 'whole_native_delivery_qualified')),
            'actual package report does not describe this exact isolated installation')
    head_raw, head_pin = read(source / '.git/HEAD', 128)
    require(head_raw == (CANDIDATE + '\n').encode()
            and head_pin == package['source_head_original'] == package['source_head_after'],
            'installation source checkout HEAD changed')
    owner_raw, owner_pin = read(root / 'control/process_owner_impl.py', 1 << 20)
    owner_sha = sha256(owner_raw).hexdigest()
    require(owner_sha == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
            and owner_pin == package['owner_implementation'], 'installation owner differs')
    contract_raw, _ = read(source / 'hepta/hia_agent_contract.py', 1 << 20)
    tree = ast.parse(contract_raw, filename='hepta/hia_agent_contract.py')
    declarations = {}
    for name, count in (('DISCOVERY_FILES', 11), ('NATIVE_SOURCE_FILES', 81), ('PUBLICATION_BUILD_FILES', 4)):
        matches = [node for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
        require(len(matches) == 1, 'resource declaration cardinality')
        values = ast.literal_eval(matches[0].value)
        require(type(values) is tuple and len(values) == count
                and all(type(value) is str for value in values), 'resource declaration shape')
        declarations[name] = list(values)
    resources = (['docs/' + name for name in declarations['DISCOVERY_FILES']]
                 + declarations['NATIVE_SOURCE_FILES'] + declarations['PUBLICATION_BUILD_FILES'])
    require(len(resources) == len(set(resources)) == 96
            and declarations == package['actual_resource_declarations']
            and package['source_resource_count'] == 96 and package['native_source_resource_count'] == 81
            and package['source_python_count'] == 169, 'complete resource denominator differs')
    expected = {row['path']: row for row in source_rows}
    module_names = sorted(name for name in expected if name.startswith('hepta/') and name.endswith('.py'))
    hepta_names = {name for name in expected if name.startswith('hepta/')}
    require(len(module_names) == 169 and len(hepta_names) == 170
            and hepta_names - set(module_names) == {'hepta/hia_core_lowering_abi.json'},
            'outer candidate hepta population differs')
    wanted_inputs = sorted(hepta_names | set(resources) | {'setup.py', 'pyproject.toml', 'MANIFEST.in'})
    before = package['source_inputs_before']
    require(before == package['source_inputs_after'] and [row['path'] for row in before] == wanted_inputs,
            'actual packaging source inventory is incomplete or changed')
    for row in before:
        name = package_name(row['path'])
        raw, observed = read(source / name, 64 << 20)
        source_row = expected[name]
        require({key: row[key] for key in content_pin(raw)} == content_pin(raw)
                and row['identity'] == observed['identity']
                and row['mode'] == format(stat.S_IMODE(observed['identity'][2]), '04o')
                and source_row['size'] == len(raw) and source_row['sha256'] == observed['sha256']
                and source_row['git_blob_sha1'] == row['git_blob_sha1']
                and source_row['posix_mode'] == stat.S_IMODE(observed['identity'][2]),
                'package input differs from original full candidate inventory: ' + name)
    for name, path in (('image', evidence / 'native/json-pretty.image.bin'),
                       ('compiler', evidence / 'native/B2.image.bin'),
                       ('child_script', root / 'control/installed_cases.py'),
                       ('python', Path(python))):
        _, actual = read(path, 64 << 20, system_binary=name == 'python')
        require(actual == package['immutable_inputs_before'][name]
                == package['immutable_inputs_after'][name], 'installation immutable input changed: ' + name)
    request_raw, request_pin = read(base / 'installed-request.json', 4 << 20)
    require(request_pin == package['installed_request'], 'installed request original differs')
    request = json.loads(request_raw)
    manifest_raw, manifest_pin = read(base / 'native/manifest.json', 16384)
    require(manifest_pin == package['manifest']
            and json.loads(manifest_raw) == {
                'schema': 'hepta.hia.json-pretty-native.v1', 'source_sha256': assembly_pin['sha256'],
                'image_path': 'native.bin', 'image_sha256': image_pin['sha256'],
                'compiler_sha256': compiler_pin['sha256']}, 'actual development manifest differs')
    image_raw, copied_pin = read(base / 'native/native.bin', 1 << 20)
    require(copied_pin == package['native_image']
            and content_pin(image_raw)['sha256'] == image_pin['sha256']
            and len(image_raw) == image_pin['bytes'], 'copied native image differs from fresh compilation')
    child_raw, child_pin = read(base / 'control/installed_cases.py', 1 << 20)
    require(child_pin == package['executed_child']
            and len(child_raw) == policy['controls']['installed_cases.py']['bytes']
            and sha256(child_raw).hexdigest() == policy['controls']['installed_cases.py']['sha256'],
            'actual installed consumer differs from frozen control')
    require(request['schema'] == 'hia.json-pretty.installed-request.v1'
            and request['scope'] == 'DEVELOPMENT_INSTALLATION'
            and request['candidate_commit'] == CANDIDATE
            and request['source_head_original'] == head_pin
            and request['installation_root'] == str(base) and request['installed_root'] == str(installed)
            and request['source_checkout'] == str(source)
            and request['manifest_path'] == str(base / 'native/manifest.json')
            and request['manifest_original'] == manifest_pin and request['image_original'] == copied_pin
            and request['compiler_input'] == package['immutable_inputs_before']['compiler']
            and request['source_sha256'] == assembly_pin['sha256']
            and request['bridge_sha256'] == bridge_pin['sha256']
            and request['child_script'] == child_pin
            and request['source_resource'] == 'examples/hia_bootstrap/json_pretty.hiaasm'
            and request['expected_test_ids'] == list(INSTALLATION_IDS)
            and request['expected_native_completions'] == 14
            and request['installed_before'] == package['installed_before']
            and request['module_names'] == module_names and request['resource_names'] == resources
            and request['output'] == str(base / 'installed-cases.json')
            and request['qualification_seconds'] == 5 and request['cleanup_seconds'] == 3
            and request['formal_cold_qualification'] is False and request['CLI_replacement_tested'] is False,
            'actual installed child request is not bound to all current original inputs')
    source_pins = {row['path']: {key: row[key] for key in ('bytes', 'sha256', 'git_blob_sha1')} for row in before}
    archives = {}
    for kind, suffix in (('sdist', '.tar.gz'), ('wheel', '.whl')):
        archive_path = Path(package[kind]['path'])
        expected_parent = base / ('sdist' if kind == 'sdist' else 'wheels')
        require(archive_path.parent == expected_parent and archive_path.name.endswith(suffix)
                and sorted(path.name for path in expected_parent.iterdir()) == [archive_path.name],
                'actual archive namespace differs')
        raw, actual_pin = read(archive_path, 128 << 20)
        require(actual_pin == package[kind], 'actual archive bytes changed')
        actual_members = archive_inventory(raw, kind)
        require(actual_members == package[kind + '_members'], 'full archive membership differs')
        members = {row['path']: row for row in actual_members}
        if kind == 'sdist':
            required = source_pins
        else:
            required = {name: pin for name, pin in source_pins.items() if name.startswith('hepta/')}
            required.update({'hepta/_data/' + name: source_pins[name] for name in resources})
            require({name for name in members if name.startswith('hepta/_data/')}
                    == {'hepta/_data/' + name for name in resources}
                    and {name for name in members if name.startswith('hepta/') and name.endswith('.py')
                         and not name.startswith('hepta/_data/')} == set(module_names),
                    'wheel lost or added product modules/resources')
        for name, pin in required.items():
            require(name in members and all(members[name][key] == value for key, value in pin.items()),
                    'archive required source changed: ' + name)
        archives[kind] = actual_pin
    installed_after = installation_snapshot(installed)
    require(installed_after == package['installed_after'] == cases['installed_after']
            and installation_projection(installed_after) == installation_projection(package['installed_before'])
            and cases['installed_source_bytes_and_modes_restored'] is True,
            'actual installed members were not restored or changed during original43 cases')
    installed_map = {row['path']: row for row in installed_after}
    require({name for name in installed_map if name.startswith('hepta/_data/')}
            == {'hepta/_data/' + name for name in resources}
            and {name for name in installed_map if name.startswith('hepta/') and name.endswith('.py')
                 and not name.startswith('hepta/_data/')} == set(module_names), 'installed namespace denominator')
    for name in sorted(hepta_names | {'hepta/_data/' + name for name in resources}):
        original = name[len('hepta/_data/'):] if name.startswith('hepta/_data/') else name
        require(name in installed_map
                and all(installed_map[name][key] == value for key, value in source_pins[original].items()),
                'installed product/resource bytes differ: ' + name)
    require(cases['schema'] == 'hia.json-pretty.installed-cases.v1'
            and cases['status'] == 'DEVELOPMENT_INSTALLED_CASES_PASS'
            and cases['scope'] == 'DEVELOPMENT_INSTALLATION'
            and cases['request_sha256'] == request_pin['sha256']
            and cases['expected_test_ids'] == cases['loaded_test_ids'] == cases['executed_test_ids']
                == list(INSTALLATION_IDS)
            and cases['tests_run'] == 9 and [row['id'] for row in cases['cases']] == list(INSTALLATION_IDS)
            and all(row['status'] == 'PASS' for row in cases['cases'])
            and [row['native_completed_calls'] for row in cases['cases']] == [2, 0, 0, 0, 0, 2, 2, 2, 6]
            and all(cases[name] == 0 for name in (
                'failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'))
            and cases['forbidden_authoring_attempts'] == cases['forbidden_host_layout_attempts'] == []
            and cases['isolated_no_site'] is True and cases['empty_PATH'] is True
            and cases['cold_qualified'] is False and cases['CLI_replacement_tested'] is False
            and cases['native_completions'] == len(cases['native_entry_attempts'])
                == len(cases['native_entry_completed']) == 14
            and all(row['status'] == 0 for row in cases['native_entry_completed'])
            and all(row['returned_status'] == 0 and row['argument_count'] == 6
                    for row in cases['native_entry_attempts'])
            and cases.get('fatal_error') is None, 'installed nine-case conjunction failed')
    expected_calls = [name for name, count in zip(INSTALLATION_IDS, [2, 0, 0, 0, 0, 2, 2, 2, 6], strict=True)
                      for _ in range(count)]
    require([row['case'] for row in cases['native_entry_attempts']]
            == [row['case'] for row in cases['native_entry_completed']] == expected_calls,
            'installed native call ownership differs')
    origins = cases['module_origins']
    require({'hepta', 'hepta.hia_json_preflight_native', 'hepta.hia_json_pretty_native'} <= set(origins),
            'installed product imports were not observed')
    for name, origin in origins.items():
        require(name == 'hepta' or name.startswith('hepta.'), 'unexpected origin namespace')
        relative = Path(origin).relative_to(installed).as_posix()
        require(relative in hepta_names and Path(origin) == installed / relative,
                'product module came from outside the exact installed package')
    negative_names = {'schema', 'source', 'image', 'shape', 'compiler-format', 'oversized', 'duplicate-key'}
    negative = cases['negative_manifest_originals']
    require(len(negative) == 7 and {Path(row['path']).name for row in negative}
            == {name + '.json' for name in negative_names}, 'negative manifest population differs')
    for row in negative:
        path = Path(row['path'])
        require(path.parent == base / 'invalid-manifests', 'negative manifest path differs')
        _, actual = read(path, 16385)
        require(actual == row, 'negative manifest original changed')
    build_env = {'PATH': str(Path(python).parent) + ':/usr/bin:/bin',
                 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
                 'PIP_NO_INDEX': '1', 'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_CONFIG_FILE': '/dev/null'}
    child_env = {'PATH': '', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}
    version_code = 'import importlib.metadata,json;print(json.dumps({k:importlib.metadata.version(k) for k in ("pip","setuptools","wheel")},sort_keys=True))'
    commands = [
        ('packaging-tools', [python, '-I', '-B', '-c', version_code], base / 'consumer-cwd', build_env, 15),
        ('sdist', [python, '-I', '-B', 'setup.py', 'sdist', '--dist-dir', str(base / 'sdist')],
         base / 'package-source', build_env, 120),
        ('wheel', [python, '-I', '-B', '-m', 'pip', '--isolated', 'wheel', '--no-cache-dir', '--no-deps',
                   '--no-index', '--no-build-isolation', '--wheel-dir', str(base / 'wheels'), package['sdist']['path']],
         base / 'consumer-cwd', build_env, 120),
        ('install', [python, '-I', '-B', '-m', 'pip', '--isolated', 'install', '--no-cache-dir', '--no-deps',
                     '--no-index', '--no-compile', '--target', str(installed), package['wheel']['path']],
         base / 'consumer-cwd', build_env, 120),
        ('installed-child', [python, '-I', '-S', '-B', str(base / 'control/installed_cases.py'),
                             '--request', str(base / 'installed-request.json'),
                             '--request-sha256', request_pin['sha256']],
         base / 'consumer-cwd', child_env, 5),
    ]
    require([step['label'] for step in package['processes']] == [row[0] for row in commands],
            'exact five owned package/consumer processes were not retained')
    process_pins = []
    for step, (label, command, cwd, environment, seconds) in zip(package['processes'], commands, strict=True):
        receipt_path = base / (label + '.process-owner.json')
        request_path = Path(str(receipt_path) + '.request.json')
        out_path, err_path = base / (label + '.stdout.log'), base / (label + '.stderr.log')
        receipt_raw, receipt_pin = read(receipt_path, 4 << 20)
        owner_request_raw, owner_request_pin = read(request_path, 1 << 20)
        receipt, owner_request = json.loads(receipt_raw), json.loads(owner_request_raw)
        require(step['status'] == 'OWNED_STEP_PASS'
                and step['cleanup_closed_before_original_read'] is True
                and step.get('custody_errors') is None and step.get('custody_deferred_until_outer_cleanup') is None
                and step['command'] == command and step['cwd'] == str(cwd)
                and step['qualification_seconds'] == seconds and step['cleanup_seconds'] == 3
                and step['receipt'] == receipt_pin and step['request'] == owner_request_pin
                and step['owner_returned'] == dict(receipt, supervisor_returncode=0,
                                                  receipt_sha256=receipt_pin['sha256'])
                and owner_request['schema'] == receipt['schema'] == 'hepta.hia.selfhost-process-owner.v1'
                and owner_request['command'] == command and owner_request['cwd'] == str(cwd)
                and owner_request['env'] == environment
                and owner_request['qualification_seconds'] == seconds and owner_request['cleanup_seconds'] == 3
                and owner_request['stdout_path'] == str(out_path) and owner_request['stderr_path'] == str(err_path)
                and owner_request['receipt_path'] == str(receipt_path)
                and owner_request['implementation_sha256'] == receipt['implementation_sha256'] == owner_sha
                and owner_request['deadline_ns'] - owner_request['started_ns'] == seconds * 1000000000
                and receipt['request_sha256'] == owner_request_pin['sha256']
                and receipt['status'] == 'OWNED_PROCESS_COMPLETED'
                and receipt['returncode'] == 0 and receipt['qualification_seconds'] == seconds
                and receipt['cleanup_seconds'] == 3 and receipt['qualification_started'] is True
                and receipt['exit_observed_before_deadline'] is True and receipt['timed_out'] is False
                and receipt['subreaper_enabled'] is True and receipt['event_overflow'] is False
                and receipt['interrupted_signals'] == [] and receipt.get('owner_error') is None,
                'actual owned package process differs from fixed invocation: ' + label)
        cleanup = receipt['cleanup']
        require(cleanup['complete'] is True and cleanup['observed_echild'] is True
                and cleanup['leader_reaped'] is True and cleanup['deadline_exceeded'] is False
                and cleanup['remaining_direct_children'] == [] and cleanup['errors'] == []
                and all(event['kind'] in NATURAL for event in receipt['events'])
                and {'qualification_started', 'qualification_exit_observed', 'owned_child_reaped'}
                    <= {event['kind'] for event in receipt['events']},
                'package child did not close naturally: ' + label)
        originals = []
        for path in (out_path, err_path, receipt_path, request_path,
                     Path(str(receipt_path) + '.stdout.log'), Path(str(receipt_path) + '.stderr.log')):
            _, actual = read(path, 16 << 20)
            originals.append(actual)
        require(originals == step['original_files']
                and originals[0] == step['stdout'] and originals[1] == step['stderr']
                and json.loads(read(base / (label + '.step.json'), 4 << 20)[0]) == step,
                'actual complete package process originals differ')
        process_pins.append({'label': label, 'receipt': receipt_pin, 'request': owner_request_pin})
    versions = json.loads(read(base / 'packaging-tools.stdout.log', 1 << 20)[0])
    require(versions == package['packaging_versions']
            and versions['setuptools'] == '78.1.1' and versions['wheel'] == '0.46.3',
            'actual packaging dependency versions differ')
    return {'package_report': report['installation_package_report_original'],
            'installed_cases': report['installation_cases_original'], 'installed_request': request_pin,
            'tests': 9, 'native_completions': 14, 'owned_processes': process_pins,
            'sdist': archives['sdist'], 'wheel': archives['wheel'],
            'installed_files': len(installed_after), 'source_python_files': 169,
            'source_resources': 96, 'manifest': manifest_pin, 'native_image': copied_pin,
            'scope': 'REAL_DEVELOPMENT_INSTALLATION_NOT_CLI_OR_COLD'}


def verify_outputs(root, setup):
    evidence = root / 'evidence'
    report_raw, report_pin = read(evidence / 'report.json', 32 << 20)
    report = json.loads(report_raw)
    require(report['schema'] == 'hia.json-pretty-actions-authoring.v1'
            and report['status'] == 'DEVELOPMENT_JSON_PRETTY_INSTALLED_NATIVE_PASS'
            and report.get('error') is None and report.get('preservation_error') is None
            and report['candidate_commit'] == CANDIDATE and report['candidate_tree'] == TREE
            and report['actual_checkout_HEAD_is_candidate'] is True
            and report['context_sha256'] == sha256(wire(setup['context'])).hexdigest()
            and report['policy_sha256'] == setup['context']['policy_sha256']
            and report['python'] == setup['context']['python']
            and report['source_preserved'] is True
            and report['candidate_physical_namespace_verified'] is True
            and report['outer_controller_seconds'] == 180 and report['cleanup_seconds'] == 3,
            'actual complete native development report differs')
    for flag in ('Core_VM_executed', 'product_tests_executed', 'original_CLI_callers_run',
                 'cold_qualified', 'old_v1_results_inherited', 'original_limits_changed',
                 'derived_global_contracts_regenerated', 'formal_full_resource_prerequisites_checked',
                 'desktop_interpreter_identity_claimed'):
        require(report[flag] is False, 'development report widened its scope')
    require(report['native_compiler_executed'] is True and report['native_execution'] is True
            and report['linker_preserved'] is True,
            'actual native development execution is not established')
    before, _ = retained(evidence / 'candidate-before.json', report['candidate_before'])
    after, _ = retained(evidence / 'candidate-after.json', report['candidate_after'])
    physical_before, _ = retained(evidence / 'candidate-physical-before.json',
                                  report['candidate_physical_before'])
    physical_after, _ = retained(evidence / 'candidate-physical-after.json',
                                 report['candidate_physical_after'])
    require(before == after and physical_before == physical_after,
            'complete before/after source originals differ')
    rows = json.loads(before)
    namespace = json.loads(physical_before)
    require(type(rows) is list and len(rows) == 4027
            and len({x['path'] for x in rows}) == 4027
            and namespace['file_count'] == 4027
            and namespace['files'] == sorted(x['path'] for x in rows)
            and namespace['excluded_only'] == ['.git']
            and namespace['ignored_and_untracked_extras_rejected'] is True,
            'complete physical source denominator differs')
    metadata = report['candidate_metadata_before']
    require(metadata == report['candidate_metadata_after']
            and metadata['actual_head'] == CANDIDATE and metadata['actual_head_tree'] == TREE
            and metadata['actual_index_tree'] == TREE and metadata['actual_head_is_candidate'] is True
            and metadata['tracked_status'] == '', 'real source Git identity was not stable')

    policy_raw, _ = read(root / 'control/policy.json', 1 << 20)
    policy = json.loads(policy_raw)
    bridge_raw, bridge_pin = retained(evidence / 'byte_bridge.py', report['byte_bridge_source'])
    require(len(bridge_raw) == policy['controls']['byte_bridge.py']['bytes']
            and bridge_pin['sha256'] == policy['controls']['byte_bridge.py']['sha256'],
            'new byte bridge source differs from frozen controls')
    assembly, assembly_pin = retained(evidence / 'json_pretty.hiaasm', report['assembly'])
    document_raw, document_pin = retained(evidence / 'json_pretty.hia.json', report['IR_document'])
    cases_raw, cases_pin = retained(evidence / 'cases.json', report['cases'])
    for name, raw in (('json_pretty.hiaasm', assembly), ('json_pretty.hia.json', document_raw),
                       ('cases.json', cases_raw)):
        require(len(raw) == policy['controls'][name]['bytes']
                and sha256(raw).hexdigest() == policy['controls'][name]['sha256'],
                'actual native test source differs from frozen original')
    limits = {'source_bytes': 1048576, 'functions': 128, 'blocks_total': 1536,
              'blocks_per_function': 256, 'instructions': 8192,
              'ssa_names_per_function': 2048, 'parameters_or_arguments': 16,
              'source_lines': 16384}
    require(report['unchanged_limits'] == limits
            and all(type(report['structure'][key]) is int
                    and 0 <= report['structure'][key] <= maximum for key, maximum in limits.items())
            and report['structure']['source_bytes'] == len(assembly)
            and report['structure']['source_lines'] == len(assembly.splitlines())
            and report['public_Core_verifier']['status'] == 'PASS'
            and report['public_Core_verifier']['assembly_and_IR_equal'] is True,
            'original limits or public Core result differ')
    native = evidence / 'native'
    compiler = report['development_compiler']
    require(compiler['scope'] == 'CURRENT_SOURCE_B0_TO_B1_B2_DEVELOPMENT_NOT_COLD_FIXED_POINT'
            and compiler['B1_equals_B2'] is True
            and compiler['cold_qualification_claimed'] is False
            and compiler['B3_or_mutation_qualification_claimed'] is False,
            'development bootstrap result misstates qualification')
    first, first_pin = read(native / 'B1.image.bin', 1 << 20)
    second, second_pin = read(native / 'B2.image.bin', 1 << 20)
    image, image_pin = read(native / 'json-pretty.image.bin', 1 << 20)
    require(first == second and second_pin['sha256'] == compiler['compiler_sha256']
            and report['native_image']['path'] == str(native / 'json-pretty.image.bin')
            and report['native_image']['bytes'] == len(image)
            and report['native_image']['sha256'] == image_pin['sha256'],
            'actual development executable bytes differ')
    for label, expected in (('B1', compiler['B1']), ('B2', compiler['B2']),
                             ('json-pretty', report['native_build'])):
        raw, _ = read(native / (label + '.receipt.json'), 1 << 20)
        observed = json.loads(raw)
        require(observed == expected and observed['status'] == 'returned'
                and observed['abi_status'] == 0
                and observed['forbidden_compiler_modules_loaded'] == []
                and observed['source_unchanged'] is True,
                'actual native compilation receipt differs')
    raw, native_cases_pin = retained(evidence / 'native-cases.json', report['native_cases_original'])
    cases = json.loads(raw)
    expected_ids = [row['name'] for row in json.loads(cases_raw)]
    require(cases == report['native_cases']
            and cases['schema'] == 'hia.json-pretty-native-cases.v1'
            and cases['status'] == 'NATIVE_JSON_LAYOUT_DEVELOPMENT_CASES_PASS'
            and cases['image_sha256'] == image_pin['sha256']
            and cases['cases_sha256'] == cases_pin['sha256']
            and cases['bridge_source_sha256'] == bridge_pin['sha256']
            and cases['installed_bridge_resource_qualified'] is False
            and cases['original37_guarded_native_invocations'] == 61
            and cases['bridge6_actual_native_invocations'] == 47
            and cases['bridge6_include_one_host_type_admission_control'] is True
            and len(expected_ids) == len(set(expected_ids)) == 43
            and report['expected_development_test_ids'] == expected_ids
            and cases['loaded_test_ids'] == cases['executed_test_ids'] == expected_ids
            and [row['id'] for row in cases['tests']] == expected_ids
            and all(row['status'] == 'PASS' for row in cases['tests'])
            and all(cases[field] == 0 for field in
                ('failures', 'errors', 'skips', 'expectedFailures', 'unexpectedSuccesses'))
            and cases['forbidden_host_compiler_modules_loaded'] == [],
            'exact 43 new native development cases did not all pass')
    original_rows, bridge_rows = cases['tests'][:37], cases['tests'][37:]
    require(len(original_rows) == 37 and len(bridge_rows) == 6
            and sum(len(row['native_invocations']) for row in original_rows) == 61
            and sum(len(row['native_invocations']) for row in bridge_rows) == 47
            and all(call['source_unchanged'] is True
                    and call['all_guard_regions_preserved'] is True
                    for row in original_rows for call in row['native_invocations'])
            and all(call['source_unchanged'] is True and call['native_entry_executed'] is True
                    for row in bridge_rows for call in row['native_invocations'])
            and bridge_rows[-1]['native_entry_executed'] is False,
            'original guarded calls or new byte bridge call population differs')
    stdout, stdout_pin = retained(evidence / 'native-child.stdout.log', report['native_child_stdout'])
    stderr, stderr_pin = retained(evidence / 'native-child.stderr.log', report['native_child_stderr'])
    expected_command = [setup['context']['python']['resolved'], '-I', '-S', '-B',
        str(root / 'control/native_cases.py'), '--source', str(evidence / 'installation/installed'),
        '--image', str(native / 'json-pretty.image.bin'), '--image-sha256', image_pin['sha256'],
        '--cases', str(root / 'control/cases.json'), '--cases-sha256', cases_pin['sha256'],
        '--bridge', str(evidence / 'installation/installed/hepta/hia_json_pretty_native.py'),
        '--bridge-sha256', bridge_pin['sha256'],
        '--report', str(evidence / 'native-cases.json')]
    require(report['native_case_command'] == expected_command
            and report['native_child']['status'] == 'RETURNED'
            and report['native_child']['returncode'] == 0
            and report['native_child']['deadline_seconds'] == 5
            and report['native_child_environment'] == {'PATH': '', 'LANG': 'C.UTF-8',
                'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}
            and report['new_native_case_child_deadline_seconds'] == 5,
            'new native child invocation differs')
    installation = verify_installation(root, setup, report, rows, image_pin, second_pin,
                                       bridge_pin, assembly_pin)
    return {'report': report_pin, 'assembly': assembly_pin, 'IR': document_pin,
            'cases': cases_pin, 'native_cases': native_cases_pin,
            'native_image': image_pin, 'compiler': second_pin, 'tests': 43,
            'byte_bridge_source': bridge_pin, 'original37_guarded_native_invocations': 61,
            'bridge6_actual_native_invocations': 47,
            'installation': installation,
            'scope': 'DEVELOPMENT_INSTALLED_COMPONENT_NOT_ORIGINAL_CLI_OR_COLD',
            'original_source_metadata': metadata}

def finalize(args):
    control, policy, _, root, source, value = context(args)
    require(root.is_dir(), 'development preparation never created its output root')
    final = {'schema': 'hia.json-pretty-actions-final.v1', 'status': 'HOLD',
             'context': value, 'qualification_executed': False,
             'native_compiler_executed': None, 'Core_VM_executed': False,
             'product_tests_executed': False, 'cold_qualified': False,
             'old_v1_results_inherited': False, 'original_limits_changed': False,
             'scope': 'REAL_INSTALLED_JSON_LAYOUT_NATIVE_DEVELOPMENT_NOT_COLD',
             'desktop_interpreter_identity_claimed': False}
    try:
        setup, setup_pin = setup_record(control, policy, root, source, value)
        final['setup_original'] = setup_pin
        guardian_raw, guardian_pin = read(root / 'guard/guardian.json', 8 << 20)
        guardian = json.loads(guardian_raw)
        life = closed_owner(guardian, setup, root)
        final['guardian_original'] = guardian_pin
        final['closed_ECHILD_before_output_read'] = True
        require(guardian['status'] == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
                and guardian['input_identity_preserved'] is True
                and guardian['source_identities_after'] == setup['source_identities']
                and guardian['cold_180_second_gate_modified'] is False
                and guardian['qualification'] is None
                and life['status'] == 'OWNED_PROCESS_COMPLETED' and life['returncode'] == 0
                and life['timed_out'] is False and life['exit_observed_before_deadline'] is True
                and life['event_overflow'] is False and life['interrupted_signals'] == []
                and life.get('owner_error') is None,
                'development authoring did not end naturally within its original owner')
        events = life['events']
        require(type(events) is list and events
                and all(x['kind'] in NATURAL for x in events)
                and {'qualification_started', 'qualification_exit_observed', 'owned_child_reaped'}
                    <= {x['kind'] for x in events}, 'non-natural process lifecycle event')
        log_pins = {}
        for name in ('child.stdout.log', 'child.stderr.log'):
            _, pin = read(root / 'guard' / name, 32 << 20)
            log_pins[str(root / 'guard' / name)] = pin['sha256']
        require(guardian['logs'] == log_pins, 'original child log identity differs')
        for path, wanted in setup['source_identities'].items():
            _, pin = read(Path(path), 64 << 20,
                          system_binary=path in (value['python']['resolved'], value['git']['resolved']))
            require(pin['sha256'] == wanted, 'fixed input changed at final observation')
        final['outputs'] = verify_outputs(root, setup)
        final['native_compiler_executed'] = True
        final['native_execution'] = True
        final['source_actual_HEAD_after'] = source_head(source, value['git']['resolved'])
        final['status'] = 'JSON_PRETTY_INSTALLED_NATIVE_DEVELOPMENT_PASS'
    except BaseException as error:
        final['status'] = 'HOLD'
        final['error'] = {'type': type(error).__name__, 'message': str(error),
                          'traceback': traceback.format_exc()}
    record = save(root / 'FINAL.json', final)
    print(json.dumps({'status': final['status'], 'final': record,
                      'qualification_executed': False}), flush=True)
    return 0 if final['status'] == 'JSON_PRETTY_INSTALLED_NATIVE_DEVELOPMENT_PASS' else 1

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
