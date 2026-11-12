"""Frozen remote relocation of four CLI JSON source-only components.

This controller never compiles or runs HIA machine code, loads the CPython
leaf DSO, runs the original 17 CLI methods, or executes the 46 trace plan.
The original 11800-byte worker and d0b/369 guardian pair are copied unchanged.
Only the source/config/output paths and actual remote runtime pins are new.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from hashlib import sha1, sha256
import io
import json
import os
from pathlib import Path
import platform
import stat
import struct
import subprocess
import sys
import sysconfig
import tarfile
import time
import traceback

SCHEMA = 'hia.cli-json.remote-source-r3c.v1'
MAX_FILE = 32 << 20
MAX_RAW = 192 << 20
MAX_ARCHIVE = 256 << 20
SMALL_RAW = 512 << 10
SMALL_STDOUT = 1 << 20
OWNER_SHA = '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
GUARDIAN_SCHEMA = 'hepta.hia.external-qualification-guardian.v1'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()


def unique_object(pairs):
    answer = {}
    for key, value in pairs:
        require(key not in answer, 'duplicate JSON key')
        answer[key] = value
    return answer


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def identity(item):
    return [item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns]


def directory_identity(item):
    return [item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid]


def absolute(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts and '\0' not in str(path),
            'absolute lexical input path required')
    return path


@contextmanager
def parent_fd(path):
    """Keep every no-follow ancestor fd until the leaf transaction completes."""
    path = absolute(path)
    require(path.name not in ('', '.', '..'), 'named input leaf required')
    descriptors = []
    links = []
    root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptors.append(root)
    try:
        parent = root
        for name in path.parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
            descriptors.append(child)
            observed = directory_identity(os.fstat(child))
            require(directory_identity(os.stat(name, dir_fd=parent,
                                                follow_symlinks=False)) == observed,
                    'parent name/descriptor identity differs')
            links.append((parent, name, child, observed))
            parent = child
        yield parent, path.name
        for ancestor, name, child, before in links:
            require(directory_identity(os.fstat(child)) == before
                    and directory_identity(os.stat(name, dir_fd=ancestor,
                                                   follow_symlinks=False)) == before,
                    'parent chain changed during transaction')
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def read(path, maximum=MAX_FILE, *, owned=False):
    path = absolute(path)
    with parent_fd(path) as (parent, name):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 <= before.st_size <= maximum
                and (not owned or before.st_uid == os.geteuid()),
                'bounded single-link regular input required: ' + str(path))
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            require(identity(os.fstat(fd)) == identity(before), 'input descriptor differs')
            chunks = []
            total = 0
            while total < before.st_size:
                chunk = os.read(fd, min(1 << 16, before.st_size - total))
                require(bool(chunk), 'input became short')
                chunks.append(chunk)
                total += len(chunk)
            require(os.read(fd, 1) == b'', 'input grew beyond observed size')
            raw = b''.join(chunks)
            require(identity(os.fstat(fd)) == identity(before), 'input changed during read')
        finally:
            os.close(fd)
        require(identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity(before),
                'input name changed during read')
    record = {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
              'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
              'identity': identity(before)}
    return record, raw


def create(path, raw):
    path = absolute(path)
    with parent_fd(path) as (parent, name):
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                    and before.st_nlink == 1, 'created file identity differs')
            at = 0
            while at < len(raw):
                count = os.write(fd, raw[at:])
                require(count > 0, 'short create write')
                at += count
            os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            seen = []
            while True:
                block = os.read(fd, 1 << 16)
                if not block:
                    break
                seen.append(block)
            require(b''.join(seen) == raw, 'same-descriptor create readback differs')
            after = os.fstat(fd)
            require(after.st_ino == before.st_ino and after.st_dev == before.st_dev
                    and after.st_uid == os.geteuid() and after.st_nlink == 1
                    and after.st_size == len(raw), 'created file changed')
            require(identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity(after),
                    'created name/descriptor differs')
        finally:
            os.close(fd)
    record, checked = read(path, max(MAX_FILE, len(raw)), owned=True)
    require(checked == raw, 'created named readback differs')
    return record


def private_directory(path, *, exist=False):
    path = absolute(path)
    with parent_fd(path) as (parent, name):
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
        except FileExistsError:
            require(exist, 'create-only directory already exists: ' + str(path))
        item = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISDIR(item.st_mode) and item.st_uid == os.geteuid()
                and stat.S_IMODE(item.st_mode) == 0o700,
                'owned private physical directory required')
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            require(directory_identity(os.fstat(fd)) == directory_identity(item),
                    'created directory descriptor differs')
        finally:
            os.close(fd)


def subdirectories(root, relative):
    current = root
    for part in Path(relative).parts:
        require(part not in ('', '.', '..'), 'relative directory component differs')
        current /= part
        private_directory(current, exist=True)


def expected_pin(record, expected):
    return all(record.get(key) == expected.get(key) for key in ('bytes', 'sha256', 'git_blob'))


def context(args):
    require(sys.implementation.name == 'cpython' and tuple(sys.version_info[:3]) == (3, 14, 4)
            and platform.system() == 'Linux' and platform.machine() == 'x86_64',
            'new remote CPython 3.14.4/Linux x86-64 runtime required')
    policy_path = absolute(args.policy)
    policy_record, policy_raw = read(policy_path, 1 << 20)
    require(policy_record['sha256'] == args.policy_sha256, 'remote policy SHA differs')
    policy = parse(policy_raw)
    require(policy['schema'] == SCHEMA + '.policy' and policy['source_files'] == 160
            and policy['source_bytes'] == 2498584 and policy['owner_seconds'] == 180
            and policy['cleanup_seconds'] == 3 and policy['caps_measured'] == 9
            and policy['compiler_line_gate_measured'] is False,
            'fixed remote scope differs')
    require(os.environ.get('GITHUB_EVENT_NAME') == 'create'
            and os.environ.get('GITHUB_RUN_ATTEMPT') == '1'
            and os.environ.get('GITHUB_REF') == 'refs/heads/' + policy['trigger_branch'],
            'new create/attempt-one operation identity required')
    directory = policy_path.parent
    originals = {}
    for name, pin in policy['controls'].items():
        observed, raw = read(directory / name)
        require(expected_pin(observed, pin), 'controller authority differs: ' + name)
        originals[name] = (observed, raw)
    require(Path(__file__).absolute() == directory / 'controller.py',
            'actual controller path differs')
    checkout = absolute(args.checkout)
    temp = absolute(os.environ['RUNNER_TEMP'])
    root = temp / policy['operation_name']
    public = temp / (policy['operation_name'] + '-public')
    require(root != public and root.parent == temp and public.parent == temp,
            'remote output layout differs')
    return policy, policy_record, policy_raw, directory, originals, checkout, root, public


def source_namespace(source, pins):
    expected_files = set(pins)
    expected_directories = {'.'}
    for name in pins:
        parent = Path(name).parent
        while str(parent) != '.':
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    actual_files = set()
    actual_directories = set()
    stack = [source]
    while stack:
        current = stack.pop()
        rel = current.relative_to(source).as_posix()
        with parent_fd(current / 'unused') as (fd, unused):
            actual_directories.add(rel)
            for name in sorted(os.listdir(fd)):
                item = os.stat(name, dir_fd=fd, follow_symlinks=False)
                child = current / name
                relative = child.relative_to(source).as_posix()
                if stat.S_ISDIR(item.st_mode):
                    stack.append(child)
                else:
                    require(stat.S_ISREG(item.st_mode), 'source has a nonregular leaf: ' + relative)
                    actual_files.add(relative)
    require(actual_files == expected_files and actual_directories == expected_directories,
            'full physical source namespace differs')


def runtime_record():
    executable = Path(sys.executable).resolve(strict=True)
    main, _ = read(executable, 64 << 20)
    require(not (main['identity'][2] & 0o022) and main['identity'][3] in (0, os.geteuid()),
            'runtime executable identity is mutable')
    result = {'executable': main, 'version': sys.version, 'version_info': list(sys.version_info),
              'hexversion': sys.hexversion, 'implementation': sys.implementation.name,
              'platform': sys.platform, 'machine': platform.machine(),
              'pointer_bytes': struct.calcsize('P'), 'shared_library': None,
              'stdlib_or_entire_OS_closure_claimed': False}
    if sysconfig.get_config_var('Py_ENABLE_SHARED'):
        libdir = sysconfig.get_config_var('LIBDIR')
        library = sysconfig.get_config_var('LDLIBRARY')
        require(type(libdir) is str and type(library) is str, 'shared runtime location missing')
        shared = (Path(libdir) / library).resolve(strict=True)
        record, _ = read(shared, 64 << 20)
        require(not (record['identity'][2] & 0o022), 'runtime shared library is mutable')
        result['shared_library'] = record
        # Observe only this interpreter's actual libpython mappings. Addresses
        # are intentionally excluded so two fresh controller processes can
        # compare the same immutable runtime file without pretending ASLR is
        # a source change. This is not a full OS/stdlib closure claim.
        with open('/proc/self/maps', 'rb') as maps_stream:
            maps_raw = maps_stream.read(8 << 20)
            require(not maps_stream.read(1), 'runtime mapping record too large')
        mapped = []
        for line in maps_raw.decode('utf-8', 'strict').splitlines():
            fields = line.split(None, 5)
            if len(fields) == 6 and fields[5] == str(shared):
                major, minor = (int(part, 16) for part in fields[3].split(':'))
                require(os.makedev(major, minor) == record['identity'][0]
                        and int(fields[4]) == record['identity'][1],
                        'actual mapped libpython identity differs')
                mapped.append({'permissions': fields[1], 'offset': int(fields[2], 16)})
        require(bool(mapped), 'configured libpython was not actually mapped')
        result['shared_library_mapping'] = {'path': str(shared), 'segments': mapped,
                                            'same_actual_device_inode_checked': True}
    return result


def prepare(args):
    policy, policy_record, policy_raw, authority, controls, checkout, root, public = context(args)
    private_directory(root)
    for name in ('control', 'source', 'guardian', 'authority'):
        private_directory(root / name)
    report = {'schema': SCHEMA + '.setup', 'status': 'HOLD', 'errors': [],
              'source_revision': 'implementation-r3c', 'source_commit': policy['source_commit'],
              'source_tree': policy['source_tree'], 'control_commit': args.control_commit,
              'event': {name: os.environ.get(name) for name in (
                  'GITHUB_SHA', 'GITHUB_REF', 'GITHUB_EVENT_NAME', 'GITHUB_RUN_ID',
                  'GITHUB_RUN_ATTEMPT', 'RUNNER_OS', 'RUNNER_ARCH')},
              'policy': policy_record, 'authority': {}, 'source': {}, 'controls': {},
              'runtime': None, 'request': None, 'configuration': None}
    try:
        report['authority']['POLICY.json'] = create(root / 'authority' / 'POLICY.json', policy_raw)
        for name, (record, raw) in controls.items():
            report['authority'][name] = create(root / 'authority' / name, raw)
        base = checkout / policy['input_prefix']
        config_record, config_raw = read(base / 'control' / 'CONFIG.json', 1 << 20)
        require(expected_pin(config_record, policy['configuration_original']), 'r3c original CONFIG differs')
        configuration = parse(config_raw)
        require(len(configuration['source_pins']) == 160
                and configuration['components'] == policy['components']
                and configuration['limits'] == policy['limits']
                and configuration['original_cli_ids'] == policy['original_cli_ids']
                and configuration['trace_plan_ids'] == policy['trace_plan_ids'],
                'original source-only denominator/caps differ')
        require(configuration['caller_execution_requested'] is False
                and configuration['trace_execution_requested'] is False
                and configuration['native_executed'] is False, 'original source-only flags differ')
        for name, pin in configuration['source_pins'].items():
            observed, raw = read(base / 'source' / name, 1 << 20)
            require(expected_pin(observed, pin), 'r3c source bytes differ: ' + name)
            subdirectories(root / 'source', Path(name).parent.as_posix() if '/' in name else '')
            report['source'][name] = create(root / 'source' / name, raw)
        require(sum(row['bytes'] for row in report['source'].values()) == 2498584,
                'source total size differs')
        source_namespace(root / 'source', configuration['source_pins'])
        for name, pin in policy['original_controls'].items():
            observed, raw = read(base / 'control' / name)
            require(expected_pin(observed, pin), 'unchanged original control differs: ' + name)
            report['controls'][name] = create(root / 'control' / name, raw)
        configuration['source_root'] = str(root / 'source')
        require(wire({**configuration, 'source_root': parse(config_raw)['source_root']}) == config_raw,
                'remote config changed beyond the exact source_root substitution')
        report['configuration'] = create(root / 'control' / 'CONFIG.json', wire(configuration))
        report['runtime'] = runtime_record()
        python = report['runtime']['executable']['path']
        source_identities = {row['path']: row['sha256'] for row in report['source'].values()}
        source_identities.update({row['path']: row['sha256'] for row in report['controls'].values()})
        source_identities.update({row['path']: row['sha256'] for row in report['authority'].values()})
        source_identities[report['configuration']['path']] = report['configuration']['sha256']
        source_identities[python] = report['runtime']['executable']['sha256']
        if report['runtime']['shared_library'] is not None:
            lib = report['runtime']['shared_library']
            source_identities[lib['path']] = lib['sha256']
        request = {'schema': 'hia-external-guardian-request.v1',
                   'controller_seconds': 180,
                   'command': [python, '-I', '-S', '-B',
                               str(root / 'control' / 'source_authoring_worker.py'),
                               str(root / 'control' / 'CONFIG.json'), str(root / 'actual')],
                   'cwd': str(root / 'source'), 'source_identities': source_identities}
        report['request'] = create(root / 'guardian' / 'REQUEST.json', wire(request))
        report['guardian_command'] = [
            python, '-I', '-S', '-B', str(root / 'control' / 'guardian.py'),
            '--config', report['request']['path'], '--config-sha256', report['request']['sha256'],
            '--implementation', str(root / 'control' / 'process_owner_impl.py')]
        report['environment'] = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
        report['status'] = 'FOUR_COMPONENT_SOURCE_REQUEST_READY_NOT_EXECUTED'
    except BaseException as error:
        report['errors'].append({'type': type(error).__name__, 'message': str(error),
                                 'traceback': traceback.format_exc()})
    create(root / 'SETUP.json', wire(report))
    print(json.dumps({'schema': report['schema'], 'status': report['status'], 'root': str(root)}, sort_keys=True))
    return 0 if not report['errors'] else 1


def read_setup(root):
    record, raw = read(root / 'SETUP.json', 4 << 20, owned=True)
    setup = parse(raw)
    return record, raw, setup


def run(args):
    policy, policy_record, policy_raw, authority, controls, checkout, root, public = context(args)
    setup_record, setup_raw, setup = read_setup(root)
    require(setup['status'] == 'FOUR_COMPONENT_SOURCE_REQUEST_READY_NOT_EXECUTED'
            and not setup['errors'], 'source-only setup was not ready')
    require(setup['policy']['sha256'] == policy_record['sha256']
            and setup['control_commit'] == args.control_commit, 'setup authority differs')
    for group in ('source', 'controls', 'authority'):
        for row in setup[group].values():
            observed, _ = read(row['path'], owned=True)
            require(observed == row, 'setup input changed before launch')
    current_runtime = runtime_record()
    require(current_runtime == setup['runtime'], 'runtime changed before source-only launch')
    require(not os.path.lexists(root / 'RUN.json') and not os.path.lexists(root / 'actual')
            and not os.path.lexists(root / 'guardian' / 'guardian.json'),
            'new operation already has execution evidence; do not replay')
    observed_request, request_raw = read(setup['request']['path'], 1 << 20, owned=True)
    require(observed_request == setup['request'], 'runtime request changed')
    record = {'schema': SCHEMA + '.run', 'status': 'HOLD', 'setup': setup_record,
              'request': observed_request, 'command': setup['guardian_command'],
              'cwd': str(root / 'source'), 'environment': setup['environment'],
              'launch_attempted': False, 'launched_pid': None, 'returned': False,
              'returncode': None, 'started_ns': time.monotonic_ns(), 'errors': []}
    stdout_path = root / 'guardian.stdout.log'
    stderr_path = root / 'guardian.stderr.log'
    create(stdout_path, b'')
    create(stderr_path, b'')
    try:
        with parent_fd(stdout_path) as (out_parent, out_name), parent_fd(stderr_path) as (err_parent, err_name):
            out = os.open(out_name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=out_parent)
            err = os.open(err_name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=err_parent)
            try:
                record['launch_attempted'] = True
                process = subprocess.Popen(record['command'], cwd=record['cwd'],
                                           env=record['environment'], stdin=subprocess.DEVNULL,
                                           stdout=out, stderr=err, close_fds=True)
                record['launched_pid'] = process.pid
                record['returncode'] = process.wait()
                record['returned'] = True
                record['status'] = 'GUARDIAN_PROCESS_RETURNED'
            finally:
                os.fsync(out)
                os.fsync(err)
                os.close(out)
                os.close(err)
    except BaseException as error:
        record['errors'].append({'type': type(error).__name__, 'message': str(error),
                                 'traceback': traceback.format_exc()})
    record['elapsed_ns'] = time.monotonic_ns() - record['started_ns']
    create(root / 'RUN.json', wire(record))
    print(json.dumps({'schema': record['schema'], 'status': record['status'],
                      'returncode': record['returncode']}, sort_keys=True))
    return 0 if record['returned'] and record['returncode'] == 0 and not record['errors'] else 1


def worker_record(record):
    return {key: record[key] for key in ('path', 'bytes', 'sha256', 'identity')}


def original_record(root, value, expected_relative):
    require(type(value) is dict and value.get('path') == str(root / expected_relative),
            'producer evidence path differs: ' + expected_relative)
    observed, raw = read(root / expected_relative, MAX_FILE, owned=True)
    require(worker_record(observed) == value, 'producer record differs: ' + expected_relative)
    return observed, raw


def closed_guard(root, setup):
    request_record, request_raw = read(root / 'guardian' / 'REQUEST.json', 1 << 20, owned=True)
    require(request_record == setup['request'], 'actual guardian request differs')
    request = parse(request_raw)
    expected_identities = {row['path']: row['sha256'] for row in setup['source'].values()}
    expected_identities.update({row['path']: row['sha256'] for row in setup['controls'].values()})
    expected_identities.update({row['path']: row['sha256'] for row in setup['authority'].values()})
    expected_identities[setup['configuration']['path']] = setup['configuration']['sha256']
    runtime = setup['runtime']
    expected_identities[runtime['executable']['path']] = runtime['executable']['sha256']
    if runtime['shared_library'] is not None:
        expected_identities[runtime['shared_library']['path']] = runtime['shared_library']['sha256']
    expected_request = {
        'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
        'command': [runtime['executable']['path'], '-I', '-S', '-B',
                    str(root / 'control' / 'source_authoring_worker.py'),
                    str(root / 'control' / 'CONFIG.json'), str(root / 'actual')],
        'cwd': str(root / 'source'), 'source_identities': expected_identities}
    require(wire(request) == wire(expected_request), 'complete actual guardian request differs')
    require(setup['environment'] == {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'},
            'actual source environment differs')
    expected_guardian_command = [
        runtime['executable']['path'], '-I', '-S', '-B', str(root / 'control' / 'guardian.py'),
        '--config', str(root / 'guardian' / 'REQUEST.json'),
        '--config-sha256', request_record['sha256'],
        '--implementation', str(root / 'control' / 'process_owner_impl.py')]
    require(setup['guardian_command'] == expected_guardian_command, 'actual guardian command differs')
    guard_record, guard_raw = read(root / 'guardian' / 'guardian.json', 4 << 20, owned=True)
    guard = parse(guard_raw)
    require(guard['schema'] == GUARDIAN_SCHEMA
            and guard['command'] == request['command'] and guard['cwd'] == request['cwd']
            and guard['external_controller_seconds'] == request['controller_seconds'] == 180
            and guard['lifecycle_implementation_sha256'] == OWNER_SHA
            and guard['source_identities_before'] == request['source_identities'],
            'guardian schema/command/cwd/input binding differs')
    life = guard['lifecycle']
    cleanup = life.get('cleanup', {})
    require(life.get('schema') == GUARDIAN_SCHEMA + '.lifecycle'
            and life.get('qualification_seconds') == 180 and life.get('cleanup_seconds') == 3
            and life.get('subreaper_enabled') is True
            and cleanup.get('complete') is True and cleanup.get('observed_echild') is True
            and cleanup.get('leader_reaped') is True
            and cleanup.get('remaining_direct_children') == []
            and cleanup.get('errors') == [] and cleanup.get('deadline_exceeded') is False,
            'owned source child closure is not proven')
    # Cleanup may be closed after a failed/terminated child. That allows
    # custody, but this predicate by itself never admits source success.
    return guard_record, guard, request_record, request


def measure_again(document, assembly_bytes, limits):
    rows = []
    for function in document['functions']:
        names = {value['name'] for value in function['params']}
        maximum_parameters = len(function['params'])
        maximum_arguments = maximum_results = operations = 0
        for block in function['blocks']:
            names.update(value['name'] for value in block['params'])
            maximum_parameters = max(maximum_parameters, len(block['params']))
            for op in block['ops']:
                names.update(value['name'] for value in op['out'])
                operations += 1
                maximum_arguments = max(maximum_arguments, len(op['args']))
                maximum_results = max(maximum_results, len(op['out']))
            term = block['term']
            if term['op'] == 'jump':
                maximum_arguments = max(maximum_arguments, len(term['args']))
            elif term['op'] == 'branch':
                maximum_arguments = max(maximum_arguments, len(term['then']['args']),
                                        len(term['else']['args']))
            elif term['op'] == 'ret':
                maximum_arguments = max(maximum_arguments, len(term['values']))
        rows.append({'name': function['name'], 'blocks': len(function['blocks']),
                     'operations': operations, 'ssa_names': len(names),
                     'parameters': maximum_parameters, 'arguments': maximum_arguments,
                     'instruction_results': maximum_results,
                     'function_results': len(function['returns'])})
    require(bool(rows), 'empty source component')
    actual = {
        'source_bytes': assembly_bytes, 'functions': len(rows),
        'blocks_per_function': max(row['blocks'] for row in rows),
        'blocks_total': sum(row['blocks'] for row in rows),
        'parameters_or_arguments': max(max(row['parameters'], row['arguments']) for row in rows),
        'ssa_names_per_function': max(row['ssa_names'] for row in rows),
        'instruction_results': max(row['instruction_results'] for row in rows),
        'function_results': max(row['function_results'] for row in rows),
        'instructions': sum(row['operations'] for row in rows)}
    return {'actual': actual, 'limits': limits, 'functions': rows,
            'within_limits': all(value <= limits[key] for key, value in actual.items())}


def verify_source(root, policy, setup, guard, request):
    result = {'schema': SCHEMA + '.source-acceptance', 'status': 'HOLD',
              'components': [], 'source_files': 160, 'source_bytes': 2498584,
              'original_cli_methods_executed': 0, 'trace_cases_executed': 0,
              'native_executed': False, 'compiler_line_gate_measured': False}
    life = guard['lifecycle']
    require(guard['status'] == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
            and guard['input_identity_preserved'] is True
            and guard['source_identities_after'] == request['source_identities']
            and guard['whole_native_delivery_qualified'] is False
            and guard['qualification'] is None,
            'original guardian did not accept a stable source-only child')
    require(life.get('status') == 'OWNED_PROCESS_COMPLETED' and life.get('returncode') == 0
            and life.get('exit_observed_before_deadline') is True
            and life.get('timed_out') is False and not life.get('interrupted_signals')
            and not life.get('owner_error') and life.get('event_overflow') is False,
            'original source-only owner was not a natural success')
    kinds = [event['kind'] for event in life['events']]
    require(kinds == ['qualification_started', 'owned_child_observed',
                     'qualification_exit_observed', 'owned_child_reaped'],
            'source-only owner had non-natural events')
    run_record, run_raw = read(root / 'RUN.json', 4 << 20, owned=True)
    run_value = parse(run_raw)
    require(run_value['returned'] is True and run_value['returncode'] == 0
            and run_value['launch_attempted'] is True and not run_value['errors']
            and run_value['command'] == setup['guardian_command']
            and run_value['cwd'] == str(root / 'source')
            and run_value['environment'] == setup['environment']
            and run_value['request'] == setup['request'], 'actual guardian launch receipt differs')
    for path, expected in guard['logs'].items():
        require(path in (str(root / 'guardian' / 'child.stdout.log'),
                         str(root / 'guardian' / 'child.stderr.log')),
                'guardian contains an unexpected log path')
        observed, _ = read(path, MAX_FILE, owned=True)
        require(observed['sha256'] == expected, 'guardian raw log differs')
    require(set(guard['logs']) == {str(root / 'guardian' / 'child.stdout.log'),
                                  str(root / 'guardian' / 'child.stderr.log')},
            'guardian log denominator differs')
    for path, digest in request['source_identities'].items():
        record, _ = read(path, 64 << 20)
        require(record['sha256'] == digest, 'final runtime or control input differs')
    source_namespace(root / 'source', policy['source_pins'])
    report_record, report_raw = read(root / 'actual' / 'REPORT.json', 4 << 20, owned=True)
    report = parse(report_raw)
    require(report['schema'] == 'hia.cli-json.source-authoring.r3.v1'
            and report['status'] == 'FOUR_SOURCE_COMPONENTS_PASS_PENDING_OUTER_GUARDIAN'
            and not report['errors'] and report['native_executed'] is False
            and report['product_callers_executed'] is False and report['counts_are_plan_only'] is True
            and report['original_cli_ids'] == policy['original_cli_ids']
            and report['trace_plan_ids'] == policy['trace_plan_ids'],
            'actual worker report scope or source result differs')
    config_record, _ = read(root / 'control' / 'CONFIG.json', 1 << 20, owned=True)
    require(report['configuration'] == worker_record(config_record), 'worker configuration binding differs')
    _, before_raw = original_record(root, report['source_before'], 'actual/source.before.json')
    _, after_raw = original_record(root, report['source_after'], 'actual/source.after.json')
    before, after = parse(before_raw), parse(after_raw)
    expected_sources = {name: worker_record(row) for name, row in setup['source'].items()}
    require(before == after == expected_sources, 'actual complete source snapshots differ')
    for name, row in setup['source'].items():
        record, _ = read(root / 'source' / name, 1 << 20, owned=True)
        require(record == row and expected_pin(record, policy['source_pins'][name]),
                'actual source changed after completed worker')
    require([[row['name'], row['module']] for row in report['components']] == policy['components'],
            'four source components were not run in their original order')
    require(set(module for _, module in policy['components']).issubset(report['actual_repository_modules'])
            and all(relative in policy['source_pins']
                    for relative in report['actual_repository_modules'].values()),
            'actual imported repository closure differs')
    suffixes = {'authoring_source': '.authoring.py.txt', 'document': '.document.json',
                'assembly': '.hiaasm', 'verified_document': '.verified.json', 'caps': '.caps.json'}
    for row in report['components']:
        require(row['status'] == 'SOURCE_CORE_AND_CAPS_PASS_NOT_NATIVE' and row['error'] is None
                and type(row['elapsed_ns']) is int and row['elapsed_ns'] >= 0,
                'source component did not pass its actual original gates')
        raw_files = {}
        records = {}
        for key, suffix in suffixes.items():
            records[key], raw_files[key] = original_record(
                root, row[key], 'actual/' + row['name'] + suffix)
        verified = parse(raw_files['verified_document'])
        caps = parse(raw_files['caps'])
        measured = measure_again(verified, len(raw_files['assembly']), policy['limits'])
        require(wire(caps) == wire(measured) and caps['within_limits'] is True,
                'actual source metrics/unchanged nine caps differ')
        result['components'].append({'name': row['name'], 'module': row['module'],
                                     'elapsed_ns': row['elapsed_ns'],
                                     'records': records, 'actual_caps': caps['actual']})
    result['worker_elapsed_ns'] = report['elapsed_ns']
    result['owner_elapsed_ns'] = life['events'][2]['monotonic_ns'] - life['events'][0]['monotonic_ns']
    result['report'] = report_record
    result['run'] = run_record
    result['status'] = 'FOUR_SOURCE_COMPONENTS_ACCEPTED_NOT_NATIVE'
    return result


def fixed_paths(policy):
    values = ['SETUP.json', 'RUN.json', 'guardian.stdout.log', 'guardian.stderr.log',
              'guardian/REQUEST.json', 'guardian/guardian.json',
              'guardian/child.stdout.log', 'guardian/child.stderr.log',
              'control/CONFIG.json', 'authority/POLICY.json',
              'actual/REPORT.json', 'actual/source.before.json',
              'actual/source.after.json', 'actual/error.txt']
    values += ['authority/' + name for name in policy['controls']]
    values += ['control/' + name for name in policy['original_controls']]
    values += ['source/' + name for name in policy['source_pins']]
    for label, _ in policy['components']:
        values += ['actual/' + label + suffix for suffix in (
            '.authoring.py.txt', '.document.json', '.hiaasm',
            '.verified.json', '.caps.json', '.error.txt')]
    require(len(values) == len(set(values)), 'duplicate fixed original path')
    return sorted(values)


def typed(path):
    with parent_fd(path) as (parent, name):
        item = os.stat(name, dir_fd=parent, follow_symlinks=False)
        result = {'identity': identity(item), 'kind': 'other'}
        if stat.S_ISREG(item.st_mode):
            result['kind'] = 'regular'
        elif stat.S_ISDIR(item.st_mode):
            result['kind'] = 'directory'
        elif stat.S_ISLNK(item.st_mode):
            result['kind'] = 'symlink'
            result['target'] = os.readlink(name, dir_fd=parent)
        elif stat.S_ISFIFO(item.st_mode):
            result['kind'] = 'fifo'
        elif stat.S_ISSOCK(item.st_mode):
            result['kind'] = 'socket'
        return result


def namespace(root):
    stack = [root]
    rows = {}
    while stack:
        current = stack.pop()
        relative = current.relative_to(root).as_posix()
        current_type = typed(current)
        rows[relative] = current_type
        require(len(rows) <= 4096, 'closed original namespace exceeds its custody count')
        if current_type['kind'] != 'directory':
            continue
        require(current_type['identity'][3] == os.geteuid(), 'closed directory has another owner')
        with parent_fd(current / 'unused') as (fd, unused):
            for name in sorted(os.listdir(fd), reverse=True):
                require(name not in ('.', '..') and '\0' not in name, 'invalid original leaf name')
                stack.append(current / name)
    return rows


def capture_closed(root, public, policy):
    original_namespace = namespace(root)
    ledger = {'schema': SCHEMA + '.custody', 'status': 'HOLD', 'owned_children_closed': True,
              'expected_paths': fixed_paths(policy), 'namespace': original_namespace,
              'captured': {}, 'missing': [], 'typed_without_bytes': {}, 'errors': [],
              'raw_bytes': 0, 'file_bytes_limit': MAX_FILE, 'raw_total_limit': MAX_RAW,
              'archive_limit': MAX_ARCHIVE, 'archive': None}
    for relative in ledger['expected_paths']:
        if relative not in original_namespace:
            ledger['missing'].append(relative)
    try:
        archive = public / 'originals.tar'
        create(archive, b'')
        with parent_fd(archive) as (parent, name):
            fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW, dir_fd=parent)
            with os.fdopen(fd, 'w+b', closefd=True) as stream:
                with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as tar:
                    for relative, metadata in sorted(original_namespace.items()):
                        if relative == '.' or metadata['kind'] == 'directory':
                            continue
                        if metadata['kind'] != 'regular':
                            ledger['typed_without_bytes'][relative] = metadata
                            ledger['errors'].append({'path': relative, 'type': 'NonRegular',
                                                     'message': 'typed metadata retained without following/opening'})
                            continue
                        try:
                            size = metadata['identity'][6]
                            require(size <= MAX_FILE and ledger['raw_bytes'] + size <= MAX_RAW,
                                    'complete original exceeds fixed custody byte budget')
                            record, raw = read(root / relative, MAX_FILE, owned=True)
                            require(record['identity'] == metadata['identity'], 'closed original changed before capture')
                            info = tarfile.TarInfo('owned/' + relative)
                            info.size = len(raw)
                            info.mode = 0o600
                            info.uid = info.gid = info.mtime = 0
                            tar.addfile(info, io.BytesIO(raw))
                            ledger['captured'][relative] = record
                            ledger['raw_bytes'] += len(raw)
                        except BaseException as error:
                            ledger['typed_without_bytes'][relative] = metadata
                            ledger['errors'].append({'path': relative, 'type': type(error).__name__,
                                                     'message': str(error)})
                stream.flush()
                os.fsync(stream.fileno())
        archive_record, _ = read(archive, MAX_ARCHIVE, owned=True)
        # Full tar body readback, with no extraction and no use of archive paths.
        with parent_fd(archive) as (parent, name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(fd, 'rb', closefd=True) as stream:
                with tarfile.open(fileobj=stream, mode='r:') as tar:
                    members = tar.getmembers()
                    require([member.name for member in members] ==
                            ['owned/' + name for name in sorted(ledger['captured'])],
                            'captured original tar members differ')
                    for member in members:
                        relative = member.name.removeprefix('owned/')
                        expected = ledger['captured'][relative]
                        require(member.isfile() and member.size == expected['bytes'],
                                'captured original tar type/size differs')
                        body = tar.extractfile(member)
                        digest = sha256()
                        size = 0
                        while True:
                            chunk = body.read(1 << 16)
                            if not chunk:
                                break
                            digest.update(chunk)
                            size += len(chunk)
                        require(size == expected['bytes'] and digest.hexdigest() == expected['sha256'],
                                'captured original tar body differs')
        final_record, _ = read(archive, MAX_ARCHIVE, owned=True)
        require(final_record == archive_record, 'archive changed during independent readback')
        ledger['archive'] = archive_record
        final_namespace = namespace(root)
        require(final_namespace == original_namespace, 'closed original namespace changed while captured')
        for relative, expected in ledger['captured'].items():
            record, _ = read(root / relative, MAX_FILE, owned=True)
            require(record == expected, 'closed original changed after capture')
        # Error.txt files are optional on success and remain explicitly missing.
        if not ledger['errors']:
            ledger['status'] = 'CLOSED_AVAILABLE_ORIGINAL_BYTES_RETAINED'
    except BaseException as error:
        ledger['errors'].append({'phase': 'archive-readback', 'type': type(error).__name__,
                                 'message': str(error), 'traceback': traceback.format_exc()})
        # Closed partial archives remain actual bytes, never a complete seal.
        try:
            ledger['archive_partial_metadata'] = typed(public / 'originals.tar')
            partial_record, _ = read(public / 'originals.tar', MAX_ARCHIVE, owned=True)
            ledger['archive_partial'] = partial_record
        except BaseException as partial_error:
            ledger['errors'].append({'phase': 'partial-archive', 'type': type(partial_error).__name__,
                                     'message': str(partial_error)})
        ledger['status'] = 'HOLD'
    return ledger


def copy_small_originals(root, public, custody, policy):
    order = ['actual/REPORT.json', 'guardian/guardian.json']
    order += ['actual/' + label + '.hiaasm' for label in ('sort', 'text', 'note', 'cgraph')]
    order += ['actual/' + label + '.caps.json' for label, _ in policy['components']]
    order += ['actual/error.txt']
    order += ['actual/' + label + '.error.txt' for label, _ in policy['components']]
    order += ['RUN.json', 'SETUP.json', 'guardian/REQUEST.json',
              'guardian/child.stdout.log', 'guardian/child.stderr.log',
              'guardian.stdout.log', 'guardian.stderr.log']
    private_directory(public / 'small')
    rows = []
    used = 0
    # Reserve 32 KiB for the compact final/selection originals. Optional
    # larger inventories are accounted as whole-file omissions when needed.
    # All captured regular originals remain in the full tar regardless.
    for number, relative in enumerate(order):
        expected = custody.get('captured', {}).get(relative)
        row = {'source': relative, 'status': 'MISSING', 'record': None}
        if expected is None:
            rows.append(row)
            continue
        row['expected'] = {key: expected[key] for key in ('bytes', 'sha256', 'git_blob')}
        if expected['bytes'] > SMALL_RAW - (32 << 10) - used:
            row['status'] = 'OMITTED_WHOLE_FILE_BUDGET'
            rows.append(row)
            continue
        observed, raw = read(root / relative, MAX_FILE, owned=True)
        require(observed == expected, 'selected small original differs from full capture')
        retained = create(public / 'small' / ('%03d.bin' % number), raw)
        row['record'] = retained
        row['status'] = 'CAPTURED'
        used += len(raw)
        rows.append(row)
    return {'schema': SCHEMA + '.small-selection', 'rows': rows,
            'raw_selected_bytes': used, 'whole_files_only': True,
            'raw_limit': SMALL_RAW, 'stdout_limit': SMALL_STDOUT,
            'complete_originals_are_in_artifact_not_all_stdout': True}


def finalize(args):
    policy, policy_record, policy_raw, authority, controls, checkout, root, public = context(args)
    private_directory(public)
    final = {'schema': SCHEMA + '.final', 'status': 'HOLD', 'source_acceptance': None,
             'guardian': None, 'setup': None, 'owned_children_closed': False,
             'parent_originals': {}, 'errors': [], 'custody': None, 'small_selection': None,
             'source_commit': policy['source_commit'], 'source_tree': policy['source_tree'],
             'control_commit': args.control_commit, 'policy_sha256': policy_record['sha256'],
             'original_cli_methods_executed': 0, 'trace_cases_executed': 0,
             'native_executed': False, 'compiler_line_gate_measured': False}
    setup = None
    try:
        setup_record, setup_raw, setup = read_setup(root)
        final['setup'] = setup_record
        # This receipt is written by the completed prepare step, not by the
        # potentially live owned worker. Preserve it even without child closure.
        final['parent_originals']['SETUP.json'] = create(public / 'SETUP.original.json', setup_raw)
        try:
            run_record, run_raw = read(root / 'RUN.json', 4 << 20, owned=True)
            require(parse(run_raw)['schema'] == SCHEMA + '.run', 'parent run receipt schema differs')
            final['parent_originals']['RUN.json'] = create(public / 'RUN.original.json', run_raw)
        except FileNotFoundError:
            pass
        require(setup['policy']['sha256'] == policy_record['sha256']
                and setup['control_commit'] == args.control_commit, 'final setup identity differs')
        guard_record, guard, request_record, request = closed_guard(root, setup)
        final['guardian'] = guard_record
        final['owned_children_closed'] = True
    except BaseException as error:
        final['errors'].append({'phase': 'owned-child-closure', 'type': type(error).__name__,
                                'message': str(error), 'traceback': traceback.format_exc()})
    if final['owned_children_closed']:
        try:
            final['source_acceptance'] = verify_source(root, policy, setup, guard, request)
        except BaseException as error:
            final['errors'].append({'phase': 'source-acceptance', 'type': type(error).__name__,
                                    'message': str(error), 'traceback': traceback.format_exc()})
        try:
            custody = capture_closed(root, public, policy)
            final['custody'] = create(public / 'CUSTODY.json', wire(custody))
            selection = copy_small_originals(root, public, custody, policy)
            final['small_selection'] = create(public / 'SMALL.json', wire(selection))
            if custody['errors']:
                final['errors'].append({'phase': 'custody', 'type': 'IncompleteOriginals',
                                        'message': 'typed refusals or unreadable/oversized originals remain'})
        except BaseException as error:
            final['errors'].append({'phase': 'custody', 'type': type(error).__name__,
                                    'message': str(error), 'traceback': traceback.format_exc()})
    else:
        # No child data is opened when closure is unknown. Fixed metadata only.
        metadata = {}
        for relative in fixed_paths(policy):
            try:
                metadata[relative] = typed(root / relative)
            except BaseException as error:
                metadata[relative] = {'status': 'UNAVAILABLE', 'type': type(error).__name__,
                                      'message': str(error)}
        final['metadata_only'] = create(public / 'UNCLOSED-METADATA.json', wire(metadata))
    if not final['errors'] and final['source_acceptance'] is not None:
        final['status'] = 'REMOTE_FOUR_SOURCE_COMPONENTS_PASS_NOT_NATIVE'
    create(public / 'FINAL.json', wire(final))
    print(json.dumps({'schema': final['schema'], 'status': final['status'],
                      'public': str(public)}, sort_keys=True))
    return 0 if final['status'] == 'REMOTE_FOUR_SOURCE_COMPONENTS_PASS_NOT_NATIVE' else 1


def frames(args):
    policy, policy_record, policy_raw, authority, controls, checkout, root, public = context(args)
    final_record, final_raw = read(public / 'FINAL.json', 4 << 20, owned=True)
    final = parse(final_raw)
    require(final['schema'] == SCHEMA + '.final'
            and final['policy_sha256'] == policy_record['sha256'],
            'final source-only receipt differs')
    selection = None
    custody = None
    derived = [('FINAL.json', final_record, final_raw)]
    for name in ('SMALL.json', 'CUSTODY.json', 'UNCLOSED-METADATA.json',
                 'SETUP.original.json', 'RUN.original.json'):
        try:
            record, raw = read(public / name, 8 << 20, owned=True)
        except FileNotFoundError:
            continue
        derived.append((name, record, raw))
        if name == 'SMALL.json':
            selection = parse(raw)
        if name == 'CUSTODY.json':
            custody = parse(raw)
    selected = []
    omitted = []
    used = 0
    # Actual source bytes precede the optional large inventory metadata in
    # the small channel. The complete inventory itself always remains public.
    candidates = [derived[0]]
    if selection is not None:
        require(selection['raw_limit'] == SMALL_RAW and selection['stdout_limit'] == SMALL_STDOUT
                and selection['whole_files_only'] is True, 'small selection budget differs')
        for row in selection['rows']:
            if row['status'] != 'CAPTURED':
                omitted.append({'name': row['source'], 'reason': row['status'],
                                'expected': row.get('expected')})
                continue
            record, raw = read(row['record']['path'], SMALL_RAW, owned=True)
            require(record == row['record'], 'retained small raw file changed')
            require(expected_pin(record, row['expected']), 'small original byte seal differs')
            candidates.append((row['source'], record, raw))
    candidates += derived[1:]
    for name, record, raw in candidates:
        if used + len(raw) > SMALL_RAW:
            omitted.append({'name': name, 'reason': 'OMITTED_WHOLE_FILE_BUDGET',
                            'expected': {key: record[key] for key in ('bytes', 'sha256', 'git_blob')}})
            continue
        selected.append((name, record, raw))
        used += len(raw)
    archive_pin = None
    all_originals = None
    if custody is not None:
        archive_pin = custody.get('archive')
        all_originals = {
            'expected_paths': custody['expected_paths'],
            'captured': {name: {key: row[key] for key in ('bytes', 'sha256')}
                         for name, row in custody['captured'].items()},
            'missing': custody['missing'],
            'typed_without_bytes': sorted(custody['typed_without_bytes']),
            'errors': custody['errors'],
        }
    index = {'schema': SCHEMA + '.frames-index',
             'source_status': final['status'], 'source_commit': policy['source_commit'],
             'policy_sha256': policy_record['sha256'], 'raw_limit': SMALL_RAW,
             'stdout_limit': SMALL_STDOUT, 'whole_files_only': True,
             'all_available_raw_originals_in_stdout': False,
             'complete_artifact_archive': archive_pin, 'full_original_inventory': all_originals,
             'selected': [{'index': number, 'name': name,
                           **{key: record[key] for key in ('bytes', 'sha256', 'git_blob')}}
                          for number, (name, record, raw) in enumerate(selected)],
             'omitted_or_missing': omitted, 'selected_raw_bytes': used}
    index_raw = wire(index)
    require(len(index_raw) <= 64 << 10, 'bounded frame index exceeds 64 KiB')
    lines = []
    lines.append('HIA_CLI_JSON_SOURCE_INDEX ' + base64.b64encode(index_raw).decode() + '\n')
    for number, (name, record, raw) in enumerate(selected):
        for offset in range(0, len(raw), 8192):
            block = raw[offset:offset + 8192]
            frame = {'file': number, 'offset': offset, 'bytes': len(block),
                     'sha256': sha256(block).hexdigest(), 'base64': base64.b64encode(block).decode()}
            lines.append('HIA_CLI_JSON_SOURCE_CHUNK ' + json.dumps(frame, sort_keys=True, separators=(',', ':')) + '\n')
    prefix = ''.join(lines).encode()
    framing = {'schema': SCHEMA + '.framing', 'status': 'BOUNDED_WHOLE_FILE_CHANNEL_READY',
               'final': final_record, 'index_sha256': sha256(index_raw).hexdigest(),
               'selected_files': len(selected), 'selected_raw_bytes': used,
               'prefix_bytes': len(prefix), 'prefix_sha256': sha256(prefix).hexdigest(),
               'limits': {'raw': SMALL_RAW, 'stdout': SMALL_STDOUT},
               'complete_artifact_archive': archive_pin,
               'omissions_explicit': True, 'native_executed': False}
    # Seal the publication record before emitting any success END.
    framing_record = create(public / 'FRAMING.json', wire(framing))
    check_record, check_raw = read(public / 'FRAMING.json', 1 << 20, owned=True)
    require(check_record == framing_record and parse(check_raw) == framing, 'framing record readback differs')
    end = {'schema': SCHEMA + '.frames-end', 'status': 'BOUNDED_CHANNEL_COMPLETE',
           'index_sha256': framing['index_sha256'], 'prefix_sha256': framing['prefix_sha256'],
           'prefix_bytes': len(prefix), 'selected_files': len(selected),
           'selected_raw_bytes': used, 'framing_sha256': framing_record['sha256'],
           'source_status': final['status']}
    output = prefix + ('HIA_CLI_JSON_SOURCE_END ' + json.dumps(end, sort_keys=True, separators=(',', ':')) + '\n').encode()
    require(len(output) <= SMALL_STDOUT, 'whole bounded output exceeds fixed stdout budget')
    create(public / 'small.frames.txt', output)
    offset = 0
    while offset < len(output):
        written = os.write(1, output[offset:])
        require(written > 0, 'short stdout write')
        offset += written
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'run', 'finalize', 'frames'))
    parser.add_argument('--checkout', type=Path, required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--control-commit', required=True)
    args = parser.parse_args()
    require(len(args.control_commit) == 40
            and all(c in '0123456789abcdef' for c in args.control_commit), 'exact control commit required')
    return {'prepare': prepare, 'run': run, 'finalize': finalize, 'frames': frames}[args.operation](args)


if __name__ == '__main__':
    raise SystemExit(main())
