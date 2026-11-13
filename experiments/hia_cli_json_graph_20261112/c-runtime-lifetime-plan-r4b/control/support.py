"""Fixed request, original owner and complete output custody joins.

All system files have explicit physical identity and complete byte pins. This
module never treats a path suffix as authority for an unpinned system file.
"""
from __future__ import annotations

from hashlib import sha256, sha1
import importlib.util
import os
from pathlib import Path
import stat
import traceback

from common import (require, read_file, pin, save, create, wire, identity,
                    parent_fd, directory_identity, physical_files)
from original_current_compiler import json_original

OWNER_SHA = '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
ROOT = Path(__file__).resolve().parents[1]


def private_directory(path):
    path = Path(path)
    with parent_fd(path) as (parent, name):
        os.mkdir(name, 0o700, dir_fd=parent)
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o700, 'private directory admission differs')


def read_policy(path, expected):
    raw, record = read_file(Path(path), 2 << 20)
    require(record['sha256'] == expected, 'fixed policy bytes differ')
    value = json_original(raw)
    require(value['schema'] == 'hia.cli-json.C-runtime-lifetime-policy.v1'
            and value['qualification_seconds'] == 180 and value['cleanup_seconds'] == 3
            and value['compiler_limits'] == {'wall_seconds': 20, 'cpu_seconds': 10,
                                              'output_capacity': 1 << 20}
            and value['child_seconds'] == 5, 'fixed policy identity or limits differ')
    return value, record


def environment(temporary, *, compiler=False):
    result = {'PATH': '/usr/bin:/bin' if compiler else '', 'LANG': 'C.UTF-8',
              'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
              'PYTHONUNBUFFERED': '1', 'TMPDIR': str(temporary)}
    return result


def stage_command(policy, policy_path, policy_sha256, label, *, dso=None, image=None):
    work = Path(policy['operation_root']) / 'work'
    base = [policy['python']['path'], '-I', '-S', '-B']
    fixed = ['--policy', str(policy_path), '--policy-sha256', policy_sha256]
    if label in ('c-compile', 'hia-compile'):
        return base + [str(ROOT / 'control/compile_child.py')] + fixed + [
            '--stage', 'c' if label == 'c-compile' else 'hia']
    require(label in ('runtime', 'lifetime') and dso is not None,
            'exact finite stage and actual DSO binding required')
    command = base + [str(ROOT / 'control/cases.py')] + fixed + [
        '--dso', dso['image']['path'], '--dso-sha256', dso['image']['sha256'], '--kind', label]
    if label == 'lifetime':
        require(image is not None, 'actual compiled HIA binding required')
        command.extend(['--image', image['image']['path'], '--image-sha256', image['image']['sha256']])
    command.extend(['--output', str(work / label)])
    return command


def system_file(row):
    """An exact pre-frozen system leaf; never follow an unobserved symlink.

    The provisioned runtime account owns the headers and binaries. Its UID is
    not changed or silently treated as root. Every such exception is a fixed
    complete row including its original mode/owner/link count and file SHA.
    """
    path = Path(row['physical_path'])
    with parent_fd(path) as (parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            before = identity(info)
            require(stat.S_ISREG(info.st_mode) and before == row['identity']
                    and before == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'fixed system leaf identity differs: ' + str(path))
            require(info.st_size == row['bytes'], 'fixed system leaf size differs')
            digest = sha256()
            git = sha1(b'blob ' + str(info.st_size).encode() + b'\0')
            remaining = info.st_size
            while remaining:
                value = os.read(fd, min(remaining, 65536))
                require(bool(value), 'system input was truncated')
                digest.update(value); git.update(value); remaining -= len(value)
            require(not os.read(fd, 1) and before == identity(os.fstat(fd))
                    == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'system input grew or changed')
        finally:
            os.close(fd)
    require(digest.hexdigest() == row['sha256'] and git.hexdigest() == row['git_blob'],
            'fixed system input bytes differ: ' + str(path))
    return {'path': str(path), 'identity': before, 'bytes': info.st_size,
            'sha256': digest.hexdigest(), 'git_blob': git.hexdigest()}


def system_namespace(manifest):
    """Inspect exact declared header namespaces without traversing symlinks."""
    result = []
    for tree in manifest['trees']:
        base = Path(tree['root'])
        names = []
        pending = [base]
        while pending:
            directory = pending.pop()
            info = directory.lstat()
            require(stat.S_ISDIR(info.st_mode), 'system namespace directory changed')
            for path in sorted(directory.iterdir()):
                information = path.lstat()
                relative = path.relative_to(base).as_posix()
                if relative in tree.get('excluded_subtrees', []):
                    require(stat.S_ISDIR(information.st_mode), 'excluded site directory changed type')
                    names.append({'path': relative, 'kind': 'excluded-site-directory',
                                  'identity': list(directory_identity(information))})
                    continue
                if stat.S_ISDIR(information.st_mode):
                    names.append({'path': relative, 'kind': 'directory',
                                  'identity': list(directory_identity(information))})
                    pending.append(path)
                elif stat.S_ISREG(information.st_mode):
                    names.append({'path': relative, 'kind': 'regular',
                                  'identity': identity(information)})
                elif stat.S_ISLNK(information.st_mode):
                    names.append({'path': relative, 'kind': 'symlink',
                                  'identity': identity(information), 'target': os.readlink(path),
                                  'resolved': str(path.resolve(strict=True))})
                else:
                    raise ValueError('special member in fixed system input namespace: ' + str(path))
        names.sort(key=lambda value: value['path'])
        require(names == tree['entries'], 'fixed header namespace changed: ' + str(base))
        result.append({'root': str(base), 'entries': len(names),
                       'namespace_sha256': sha256(wire(names)).hexdigest()})
    for link in manifest['standalone_links']:
        path = Path(link['path'])
        info = path.lstat()
        require(stat.S_ISLNK(info.st_mode) and identity(info) == link['identity']
                and os.readlink(path) == link['target']
                and str(path.resolve(strict=True)) == link['resolved'],
                'fixed standalone system link changed: ' + str(path))
    return result


def frozen(policy, *, include_system=True):
    expected_names = [row['path'] for row in policy['source_files']]
    names, directories = physical_files(ROOT / 'source')
    require(names == expected_names and directories == policy['source_directories'],
            'complete isolated source namespace differs')
    records = []
    for base, group in ((ROOT / 'source', policy['source_files']),
                        (ROOT, policy['control_files'] + policy['asset_files'])):
        for row in group:
            path = base / row['path']
            raw, actual = read_file(path, row['bytes'])
            require(actual['size'] == row['bytes'] and actual['sha256'] == row['sha256']
                    and actual['mode'] == row['mode']
                    and sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == row['git_blob'],
                    'isolated frozen input differs: ' + str(path))
            records.append(actual)
    for row in policy['external_files']:
        raw, actual = read_file(Path(row['path']), row['bytes'])
        require(actual['size'] == row['bytes'] and actual['sha256'] == row['sha256']
                and sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == row['git_blob'],
                'existing compiler original differs: ' + row['path'])
        records.append(actual)
    names_after, directories_after = physical_files(ROOT / 'source')
    require(names_after == names and directories_after == directories, 'source namespace changed during read')
    system_result = None
    if include_system:
        system_raw, system_pin = read_file(ROOT / policy['system_manifest']['path'], 8 << 20)
        require(system_pin['sha256'] == policy['system_manifest']['sha256'],
                'fixed system input manifest differs')
        system = json_original(system_raw)
        before = system_namespace(system)
        actual = [system_file(row) for row in system['files']]
        require(system_namespace(system) == before, 'header namespace changed during actual reads')
        system_result = {'namespace': before, 'files': actual, 'manifest': system_pin}
    return {'schema': 'hia.cli-json.C-finite-input-readback.v1',
            'source_files': len(names), 'source_directories': directories,
            'files': records, 'system': system_result}


def load_owner():
    path = ROOT / 'control/process_owner_impl.py'
    require(pin(path)['sha256'] == OWNER_SHA, 'unchanged original owner implementation differs')
    spec = importlib.util.spec_from_file_location('cli_finite_original_owner', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def owner_paths(folder, label):
    return {'stdout_path': str(folder / (label + '.stdout.log')),
            'stderr_path': str(folder / (label + '.stderr.log')),
            'receipt_path': str(folder / (label + '.lifecycle.json'))}


def closed_owner(wrapper, life_raw, request_raw, *, command, cwd, env, paths, seconds, parent):
    life, request = json_original(life_raw), json_original(request_raw)
    extra = {'receipt_sha256', 'supervisor_returncode'}
    require(type(wrapper) is dict and set(wrapper) == set(life) | extra
            and {k: v for k, v in wrapper.items() if k not in extra} == life
            and wrapper['receipt_sha256'] == sha256(life_raw).hexdigest(),
            'complete raw owner receipt does not match its API projection')
    require(request['schema'] == life['schema'] == 'hepta.hia.selfhost-process-owner.v1'
            and request['implementation_sha256'] == life['implementation_sha256'] == OWNER_SHA
            and life['request_sha256'] == sha256(request_raw).hexdigest()
            and request['command'] == command and request['cwd'] == str(cwd)
            and request['env'] == env and all(request[k] == v for k, v in paths.items())
            and request['qualification_seconds'] == life['qualification_seconds'] == seconds
            and request['cleanup_seconds'] == life['cleanup_seconds'] == 3,
            'actual owner request/implementation/command/environment/budget differs')
    require(type(request['started_ns']) is int and type(request['deadline_ns']) is int
            and request['deadline_ns'] - request['started_ns'] == seconds * 1_000_000_000
            and request['parent_pid'] == life['parent_pid'] == parent
            and life['qualification_started'] is True and life['subreaper_enabled'] is True
            and type(life['qualification_pid']) is int and life['qualification_pid'] > 0,
            'actual owner process/start/deadline binding differs')
    cleanup = life['cleanup']
    require(cleanup['complete'] is True and cleanup['observed_echild'] is True
            and cleanup['leader_reaped'] is True and cleanup['deadline_exceeded'] is False
            and cleanup['remaining_direct_children'] == [] and cleanup['errors'] == [],
            'actual child process tree is not confirmed closed')
    return life


def natural_owner(wrapper, life):
    require(wrapper['supervisor_returncode'] == 0
            and life['status'] == 'OWNED_PROCESS_COMPLETED' and life['returncode'] == 0
            and life['timed_out'] is False and life['exit_observed_before_deadline'] is True
            and life['interrupted_signals'] == [] and life['event_overflow'] is False
            and life.get('owner_error') is None
            and [event['kind'] for event in life['events']] == [
                'qualification_started', 'owned_child_observed',
                'qualification_exit_observed', 'owned_child_reaped'],
            'fixed finite owner did not complete naturally')


def run_step(owner, folder, label, command, *, cwd, env, seconds):
    paths = owner_paths(folder, label)
    intent = {'command': command, 'cwd': str(cwd), 'env': env, 'paths': paths,
              'seconds': seconds, 'cleanup_seconds': 3, 'owner_sha256': OWNER_SHA}
    save(folder / (label + '.INTENT.json'), intent)
    # The unchanged run_owned implementation is responsible for child launch
    # and its natural/timeout cleanup. This caller never retries or kills it.
    wrapper = owner.run_owned(command, cwd=str(cwd), env=env,
        **{key: Path(value) for key, value in paths.items()},
        qualification_seconds=seconds, cleanup_seconds=3)
    save(folder / (label + '.WRAPPER.json'), wrapper)
    require(wrapper.get('cleanup', {}).get('complete') is True
            and wrapper.get('cleanup', {}).get('observed_echild') is True
            and wrapper.get('cleanup', {}).get('leader_reaped') is True
            and wrapper.get('cleanup', {}).get('remaining_direct_children') == [],
            'unknown child closure; retain metadata and do not read child outputs')
    life_raw, life_pin = read_file(Path(paths['receipt_path']), 4 << 20)
    request_raw, request_pin = read_file(Path(paths['receipt_path'] + '.request.json'), 262144)
    life = closed_owner(wrapper, life_raw, request_raw, command=command, cwd=cwd,
                        env=env, paths=paths, seconds=seconds, parent=os.getpid())
    originals = {}
    for role, path in {**paths,
        'request_path': paths['receipt_path'] + '.request.json',
        'owner_stdout': paths['receipt_path'] + '.stdout.log',
        'owner_stderr': paths['receipt_path'] + '.stderr.log'}.items():
        originals[role] = pin(Path(path), 4 << 20)
    result = {'status': 'CLOSED_PENDING_NATURAL_SUCCESS', 'intent': intent,
              'wrapper': wrapper, 'life': life_pin, 'request': request_pin, 'originals': originals}
    save(folder / (label + '.CLOSED.json'), result)
    try:
        natural_owner(wrapper, life)
        result['status'] = 'NATURAL_CLOSED_PASS'
    except BaseException:
        result['status'] = 'CLOSED_HOLD'
        result['classification_error'] = traceback.format_exc()
    return result


def capture_closed(root, maximum):
    """Full actual originals after bound ECHILD, including failures and links.

    Every allowed regular file is hashed independently. Specials get lstat /
    readlink metadata only, never opened. Refusals remain explicit and do not
    prevent later independent regular members from being retained.
    """
    rows, errors, total = [], [], 0
    pending = [Path(root)]
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            info = path.lstat()
            row = {'path': path.relative_to(root).as_posix(), 'identity': identity(info)}
            try:
                if stat.S_ISDIR(info.st_mode):
                    row['kind'] = 'directory'
                    require(info.st_uid == os.geteuid() and not info.st_mode & 0o022,
                            'foreign/writable output directory')
                    pending.append(path)
                elif stat.S_ISREG(info.st_mode):
                    row['kind'] = 'regular'
                    require(info.st_size <= 16 << 20 and total + info.st_size <= maximum,
                            'closed finite evidence budget exceeded')
                    row['actual'] = pin(path, 16 << 20)
                    total += info.st_size
                elif stat.S_ISLNK(info.st_mode):
                    row.update(kind='symlink-not-followed', target=os.readlink(path))
                    raise ValueError('special output is not byte-admitted')
                else:
                    row['kind'] = 'special-not-opened'
                    raise ValueError('special output is not byte-admitted')
            except BaseException:
                row['error'] = traceback.format_exc()
                errors.append(row['path'])
            rows.append(row)
            require(len(rows) <= 4096, 'finite output inode budget exceeded')
    return {'schema': 'hia.cli-json.C-finite-closed-custody.v1',
            'status': 'COMPLETE_ACTUAL_ORIGINALS' if not errors else 'HOLD',
            'regular_bytes': total, 'rows': rows, 'errors': errors,
            'original_paths_preserved': True, 'closed_before_any_product_read': True}
