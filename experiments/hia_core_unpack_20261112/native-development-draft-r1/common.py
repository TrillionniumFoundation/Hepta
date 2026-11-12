"""Fixed mechanical custody helpers for new Core Emitter v2 development.

This module does not select product semantics or relax any product/compiler gate.
The only writable tracked source inputs are the two explicitly regenerated JSON
inventories during preparation. Later execution requires the complete derived
physical source tree to remain byte-for-byte and mode-for-mode stable.
"""
from __future__ import annotations
from contextlib import contextmanager
from hashlib import sha1, sha256
import ast
import json
import os
from pathlib import Path
import stat
import subprocess

REPO = 'TrillionniumFoundation/Hepta'
PREFIX = 'experiments/hia_core_unpack_20261112/native-development-r1'
GENERATED = (
    'docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json',
    'docs/HIA_SELFHOST_CORE_SUPPORT.json',
)
LIMITS = {'source_bytes': 1048576, 'source_lines': 16384, 'functions': 128,
          'blocks_total': 1536, 'blocks_per_function': 256, 'instructions': 8192,
          'ssa_names_per_function': 2048, 'parameters_or_arguments': 16}
COMPILE_SUFFIXES = ('.receipt.json', '.stdout.log', '.stderr.log',
                    '.request.json', '.input.bin', '.output.bin')
NATURAL = {'qualification_started', 'owned_child_observed',
           'qualification_exit_observed', 'owned_child_reaped'}

def require(value, message):
    if not value:
        raise RuntimeError(message)

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')

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

def read(path, maximum=32 << 20, *, system_binary=False, reserve=None):
    return inspect_file(path, maximum, system_binary=system_binary, retain=True, reserve=reserve)

def create(path, raw):
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

def save(path, value):
    return create(path, wire(value))

def document(path, maximum=32 << 20):
    raw, pin = read(path, maximum)
    return json.loads(raw), pin

def relative(name):
    require(type(name) is str and name and '\0' not in name, 'invalid source member name')
    path = Path(name)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == name
            and path.parts[0] != '.git', 'noncanonical source member name')
    return path

def clean_environment():
    environment = {name: value for name, value in os.environ.items()
                   if not name.startswith(('GIT_', 'LD_', 'HEPTA_HIA_', 'PYTHON'))
                   and name not in ('GITHUB_TOKEN', 'GH_TOKEN')}
    environment.update(PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1')
    return environment

def git(source, executable, *arguments):
    environment = clean_environment()
    environment['GIT_OPTIONAL_LOCKS'] = '0'
    return subprocess.run([str(executable), '--no-replace-objects', *arguments], cwd=source,
                          env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True).stdout

def metadata(source, executable, candidate):
    head = git(source, executable, 'rev-parse', 'HEAD').decode().strip()
    tree = git(source, executable, 'rev-parse', 'HEAD^{tree}').decode().strip()
    git(source, executable, 'diff', '--cached', '--quiet', candidate['tree'], '--')
    require(head == candidate['commit'] and tree == candidate['tree']
            and read(source / '.git/HEAD', 256)[0].decode().strip() == head,
            'actual detached HEAD/tree/index differs from the canonical input')
    index = git(source, executable, 'ls-files', '--stage', '-z')
    return {'actual_head': head, 'actual_head_tree': tree,
            'actual_index_tree': candidate['tree'], 'actual_index_sha256': sha256(index).hexdigest(),
            'actual_HEAD_is_initial_candidate': True,
            'derived_worktree_is_a_new_commit': False}

def git_leaves(source, executable, candidate):
    rows = []
    for item in git(source, executable, 'ls-tree', '-rz', candidate['tree']).split(b'\0'):
        if not item:
            continue
        header, raw_name = item.split(b'\t', 1)
        mode, kind, digest = header.decode('ascii').split()
        name = raw_name.decode('utf-8')
        relative(name)
        require(kind == 'blob' and mode in ('100644', '100755'), 'nonregular Git source leaf')
        rows.append({'path': name, 'mode': mode, 'git_blob_sha1': digest})
    rows.sort(key=lambda x: x['path'])
    require(len(rows) == candidate['leaves'] and len({x['path'] for x in rows}) == len(rows),
            'complete canonical input population differs')
    return rows

def inventory(source, expected, *, mutable=()):
    rows = []
    for item in expected:
        name = item['path']
        _, pin = inspect_file(source / relative(name))
        require(bool(pin['posix_mode'] & 0o111) == (item['mode'] == '100755'),
                'source executable mode differs: ' + name)
        if name not in mutable:
            require(pin['git_blob_sha1'] == item['git_blob_sha1'], 'source Git blob differs: ' + name)
            if 'sha256' in item:
                require(pin['sha256'] == item['sha256'] and pin['bytes'] == item['bytes']
                        and pin['posix_mode'] == item['posix_mode'], 'source byte/mode pin differs: ' + name)
        rows.append({'path': name, 'mode': item['mode'], 'bytes': pin['bytes'],
                     'sha256': pin['sha256'], 'git_blob_sha1': pin['git_blob_sha1'],
                     'posix_mode': pin['posix_mode']})
    return rows

def physical_source(source, rows):
    require(stat.S_ISDIR(source.lstat().st_mode), 'source root is not a physical directory')
    wanted_files = {item['path'] for item in rows}
    wanted_directories = {''}
    for name in wanted_files:
        parent = relative(name).parent
        while str(parent) != '.':
            wanted_directories.add(parent.as_posix())
            parent = parent.parent
    files, directories, stack, seen_git = set(), {''}, [(source, '')], False
    while stack:
        directory, relative_directory = stack.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                name = entry.name if not relative_directory else relative_directory + '/' + entry.name
                observed = entry.stat(follow_symlinks=False)
                if name == '.git':
                    require(stat.S_ISDIR(observed.st_mode), 'private checkout Git metadata is not a directory')
                    seen_git = True
                elif stat.S_ISDIR(observed.st_mode):
                    require(name not in directories, 'duplicate physical source directory')
                    directories.add(name)
                    stack.append((Path(entry.path), name))
                else:
                    require(stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1
                            and name not in files, 'extra symlink, alias, or nonregular source member')
                    files.add(name)
    require(seen_git and files == wanted_files and directories == wanted_directories,
            'complete physical source namespace differs')
    return {'schema': 'hia.core-emitter-physical-source.v1', 'root': str(source),
            'excluded_only': ['.git'], 'file_count': len(files), 'directory_count': len(directories),
            'files': sorted(files), 'directories': sorted(directories),
            'ignored_and_untracked_extras_rejected': True}

def tree_identity(rows):
    """Compute the complete worktree's Git tree object identity without changing its index."""
    root = {}
    for row in rows:
        node = root
        parts = relative(row['path']).parts
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            require(type(node) is dict, 'source file/directory collision')
        require(parts[-1] not in node, 'duplicate tree member')
        node[parts[-1]] = (row['mode'], row['git_blob_sha1'])
    def build(node):
        result = []
        for name, value in node.items():
            raw_name = name.encode('utf-8')
            if type(value) is dict:
                result.append((raw_name + b'/', b'40000 ' + raw_name + b'\0' + bytes.fromhex(build(value))))
            else:
                mode, identity = value
                require(mode in ('100644', '100755') and len(identity) == 40,
                        'invalid tree blob entry')
                result.append((raw_name, mode.encode('ascii') + b' ' + raw_name + b'\0' + bytes.fromhex(identity)))
        payload = b''.join(value for _, value in sorted(result))
        return sha1(b'tree ' + str(len(payload)).encode() + b'\0' + payload).hexdigest()
    return build(root)

def snapshot(source, executable, candidate, expected, *, mutable=()):
    physical_before = physical_source(source, expected)
    actual = inventory(source, expected, mutable=mutable)
    physical_after = physical_source(source, actual)
    require(physical_before == physical_after, 'physical source namespace changed during complete read')
    return {'rows': actual, 'physical': physical_after,
            'metadata': metadata(source, executable, candidate),
            'actual_worktree_tree': tree_identity(actual)}

def retained(path, wanted, maximum=32 << 20):
    raw, pin = read(path, maximum)
    require(wanted['path'] == str(path) and wanted['bytes'] == pin['bytes']
            and wanted['sha256'] == pin['sha256']
            and wanted['git_blob_sha1'] == pin['git_blob_sha1'], 'retained original bytes differ')
    return raw, pin

def compile_originals(folder, label):
    return {'stage': label, 'files': [inspect_file(Path(folder) / (label + suffix), 2 << 20)[1]
                                    for suffix in COMPILE_SUFFIXES]}

def observe_inputs(mapping, system_paths):
    for path, wanted in mapping.items():
        _, pin = inspect_file(Path(path), 1 << 30, system_binary=path in system_paths)
        require(pin['sha256'] == wanted, 'frozen input changed: ' + path)

def closed_owner(guardian, setup, root, guard):
    lifecycle = guardian.get('lifecycle', {})
    require(guardian.get('schema') == 'hepta.hia.external-qualification-guardian.v1'
            and guardian.get('command') == setup['command'] and guardian.get('cwd') == str(root)
            and guardian.get('external_controller_seconds') == 180
            and guardian.get('source_identities_before') == setup['source_identities']
            and guardian.get('lifecycle_implementation_sha256') ==
                setup['source_identities'][str(root / 'control/process_owner_impl.py')]
            and lifecycle.get('schema') == 'hepta.hia.external-qualification-guardian.v1.lifecycle'
            and lifecycle.get('qualification_seconds') == 180
            and lifecycle.get('cleanup_seconds') == 3
            and lifecycle.get('subreaper_enabled') is True
            and lifecycle.get('qualification_started') is True,
            'guardian is not this exact original development phase')
    cleanup = lifecycle.get('cleanup', {})
    require(cleanup.get('attempted') is True and cleanup.get('complete') is True
            and cleanup.get('observed_echild') is True and cleanup.get('leader_reaped') is True
            and cleanup.get('deadline_exceeded') is False and cleanup.get('errors') == []
            and cleanup.get('remaining_direct_children') == [], 'phase lacks a closed ECHILD boundary')
    return lifecycle

def natural_owner(guardian, setup, root, guard):
    lifecycle = closed_owner(guardian, setup, root, guard)
    require(guardian.get('status') == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
            and guardian.get('input_identity_preserved') is True
            and guardian.get('source_identities_after') == setup['source_identities']
            and guardian.get('cold_180_second_gate_modified') is False
            and guardian.get('qualification') is None
            and lifecycle.get('status') == 'OWNED_PROCESS_COMPLETED'
            and lifecycle.get('returncode') == 0
            and lifecycle.get('exit_observed_before_deadline') is True
            and lifecycle.get('timed_out') is False and lifecycle.get('interrupted_signals') == []
            and lifecycle.get('event_overflow') is False and lifecycle.get('owner_error') is None,
            'phase failed, timed out, was interrupted, or changed inputs')
    events = lifecycle.get('events')
    require(type(events) is list and events and all(x.get('kind') in NATURAL for x in events)
            and {'qualification_started', 'qualification_exit_observed', 'owned_child_reaped'}
                <= {x['kind'] for x in events}, 'nonnatural lifecycle event')
    pins = {}
    for name in ('child.stdout.log', 'child.stderr.log'):
        _, pin = inspect_file(guard / name, 32 << 20)
        pins[str(guard / name)] = pin['sha256']
    require(guardian.get('logs') == pins, 'actual phase log SHA differs from guardian')
    return lifecycle

def declared_inputs(source, rows):
    raw, _ = read(source / 'tools/hia_selfhost_contract.py', 1 << 20)
    document = ast.parse(raw, filename='tools/hia_selfhost_contract.py')
    assignments = [node for node in document.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'SOURCE_FILES'
                           for target in node.targets)]
    require(len(assignments) == 1, 'one explicit SOURCE_FILES tuple required for controller binding')
    names = ast.literal_eval(assignments[0].value)
    require(type(names) is tuple and names and all(type(name) is str for name in names),
            'declared source inventory is not the frozen literal tuple')
    selected = set(names) | {row['path'] for row in rows
                            if row['path'].startswith('hepta/') and row['path'].endswith('.py')}
    selected.add('docs/HIA_SELFHOST_CORE_SUPPORT.json')
    mapped = {row['path']: row for row in rows}
    require(selected <= set(mapped), 'declared input missing from complete source tree')
    return {str(source / name): mapped[name]['sha256'] for name in sorted(selected)}
