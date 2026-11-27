"""Separate, explicit inspect generation-only attempt; never the R1 full run.

Authoring this file does not execute it.  The reviewed caller must supply the
exact plan hash and --execute-generation-only.  No test, VM, compiler image,
native loader, cold builder or CLI policy invocation is performed here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import sys
import time
import traceback

HERE = Path(__file__).absolute().parent
KIT = Path('/workspace/scratch/dda74a4fae35/v119-inspect-policy-execution-r1')
BASE = Path('/workspace/scratch/dda74a4fae35/v120-union-r20/source')
KIT_SHA256 = '9e827365eb3c9217486fa569c667825f6c824abbaf7b9df03f43d78206d43d61'
MIB = 1048576
SECONDS, CLEANUP = 180, 3
GENERATED = ('examples/hia_bootstrap/inspect_program.hepta',
             'hepta/hia_inspect_program_ports.py',
             'hepta/hia_inspect_program_data.py')
OUTPUT_NAMES = ('inspect_program.hepta', 'hia_inspect_program_ports.py',
                'hia_inspect_program_data.py')
SCHEMA = 'hepta.hia.inspect-generation-only.v1'
_ATTEMPT = None
_OWNER_ATTEMPTS = 0


def require(value, message):
    if not value:
        raise AssertionError(message)


def pin(raw):
    require(type(raw) is bytes, 'exact bytes required')
    return {'bytes': len(raw), 'mode': '100644',
            'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True,
                       allow_nan=False) + '\n').encode()


def pairs(items):
    result = {}
    for key, value in items:
        require(type(key) is str and key not in result, 'duplicate or nonstring JSON key')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs)


def identity(s):
    # Reads may change atime. Hardlink preparation intentionally changes nlink
    # and ctime; those are recorded and stable-checked after preparation.
    return {'device': s.st_dev, 'inode': s.st_ino, 'mode': stat.S_IMODE(s.st_mode),
            'bytes': s.st_size, 'nlink': s.st_nlink,
            'mtime_ns': s.st_mtime_ns, 'ctime_ns': s.st_ctime_ns}


def read_exact(path, *, maximum, expected=None):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute controlled path required')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum,
                'bounded ordinary file required: ' + str(path))
        require(identity(path.lstat()) == identity(before), 'named/held input differs')
        chunks, remaining = [], before.st_size + 1
        while remaining:
            value = os.read(fd, min(MIB, remaining))
            if not value:
                break
            chunks.append(value)
            remaining -= len(value)
        raw = b''.join(chunks)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
                == identity(path.lstat()), 'input changed during complete read')
    finally:
        os.close(fd)
    if expected is not None:
        require(pin(raw) == expected, 'complete input identity differs: ' + str(path))
    return raw, identity(before)


def create(path, raw, *, mode=0o600):
    require(type(raw) is bytes, 'exact publication bytes required')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            require(count > 0, 'short publication made no progress')
            view = view[count:]
        # Only a newly created private inode is chmodded, never a hardlink.
        require(os.fstat(fd).st_nlink == 1, 'new publication is unexpectedly linked')
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def publish(path, value):
    create(path, encoded(value))


def path_authority(path):
    path = Path(path).absolute()
    require('..' not in path.parts and path.resolve(strict=True) == path,
            'controlled root must have no symlink/relative traversal')
    require(stat.S_ISDIR(path.lstat().st_mode), 'ordinary controlled root required')
    return path


def load_plan(path, sha256):
    require(type(sha256) is str and len(sha256) == 64, 'external reviewed plan hash required')
    path = Path(path).absolute()
    raw, _ = read_exact(path, maximum=MIB)
    require(hashlib.sha256(raw).hexdigest() == sha256, 'reviewed generation-only plan differs')
    plan = decode(raw)
    require(plan['schema'] == SCHEMA + '.plan' and plan['status'] == 'AUTHORED_NOT_EXECUTED'
            and plan['kit']['path'] == str(KIT) and plan['kit']['index_sha256'] == KIT_SHA256
            and plan['base']['path'] == str(BASE)
            and plan['limits'] == {'qualification_seconds': SECONDS, 'cleanup_seconds': CLEANUP}
            and tuple(plan['generated_paths']) == GENERATED,
            'generation-only fixed plan contract differs')
    script, _ = read_exact(Path(__file__).absolute(), maximum=MIB, expected=plan['runner'])
    for name, expected in plan['review_artifacts'].items():
        read_exact(HERE / name, maximum=4*MIB, expected=expected)
    index, _ = read_exact(KIT / 'KIT-PINS.json', maximum=MIB)
    require(hashlib.sha256(index).hexdigest() == KIT_SHA256, 'original R1 kit index differs')
    kit_index = decode(index)
    require(len(kit_index['files']) == 13, 'complete original 14-file kit required')
    for name, expected in kit_index['files'].items():
        read_exact(KIT / name, maximum=max(expected['bytes'], MIB), expected=expected)
    return plan, raw


def helpers():
    sys.path.insert(0, str(KIT))
    import inspect_exec_support as support
    require(Path(support.__file__).absolute() == KIT / 'inspect_exec_support.py',
            'frozen support import came from another directory')
    return support


def storage(path):
    info = os.statvfs(path)
    return {'available_bytes': info.f_bavail * info.f_frsize,
            'available_inodes': info.f_favail, 'block_bytes': info.f_frsize,
            'observed_ns': time.time_ns()}


def storage_gate(attempt, label, minimum, *, inodes=64):
    row = {'label': label, 'minimum_available_bytes': minimum,
           'minimum_available_inodes': inodes, **storage(attempt)}
    publish(attempt / ('SPACE-' + label + '.json'), row)
    require(row['available_bytes'] >= minimum and row['available_inodes'] >= inodes,
            'generation-only storage preflight failed: ' + label)
    return row


def cas(attempt, value):
    raw = encoded(value)
    key = pin(raw)
    path = attempt / 'maps' / (key['sha256'] + '.json')
    if path.exists():
        read_exact(path, maximum=len(raw), expected=key)
    else:
        create(path, raw)
    return {'path': str(path), 'pin': key}


def capture(root, expected):
    """Read every encountered regular input; retain all per-path failures.

    This captures complete identities, not another copy of original sources.
    Original full bytes are already in the frozen repository inputs. Unknown
    large files are rejected without treating them as an unbounded read grant.
    """
    rows, statuses, errors = {}, {}, []

    def visit(directory, prefix):
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except BaseException:
            errors.append({'path': prefix, 'traceback': traceback.format_exc()})
            return
        for entry in entries:
            name = prefix + entry.name
            try:
                s = entry.stat(follow_symlinks=False)
                require(not stat.S_ISLNK(s.st_mode), 'source symlink refused')
                if stat.S_ISDIR(s.st_mode):
                    visit(Path(entry.path), name + '/')
                    continue
                require(stat.S_ISREG(s.st_mode), 'nonregular source refused')
                maximum = max(MIB, expected.get(name, {}).get('bytes', 0))
                raw, actual = read_exact(Path(entry.path), maximum=maximum)
                row = pin(raw)
                row['mode'] = '100755' if actual['mode'] & 0o111 else '100644'
                rows[name], statuses[name] = row, actual
            except BaseException:
                errors.append({'path': name, 'traceback': traceback.format_exc()})
    visit(root, '')
    return {'files': rows, 'stat': statuses, 'errors': errors}


def assert_capture(value, expected, *, stable=None):
    require(not value['errors'] and value['files'] == expected,
            'complete source bytes/Git modes differ or a source read failed')
    require(all(value['stat'][name]['mode'] == (0o755 if row['mode'] == '100755' else 0o644)
                for name, row in expected.items()), 'exact POSIX source permissions differ')
    if stable is not None:
        require(value['stat'] == stable, 'held source inode/metadata changed after preparation')


def pair_capture(attempt, label, root, base_map, source_map, *, stable=None):
    before = capture(BASE, base_map)
    view = capture(root, source_map)
    row = {'label': label, 'base': cas(attempt, before), 'source': cas(attempt, view),
           'all_bytes_read': True, 'exact_posix_modes_required': True}
    publish(attempt / ('GUARD-' + label + '.json'), row)
    assert_capture(before, base_map, stable=None if stable is None else stable[0])
    assert_capture(view, source_map, stable=None if stable is None else stable[1])
    return before, view


def prepare(attempt, base_map, overlay, prepared, support):
    root = attempt / 'source'
    root.mkdir(mode=0o700)
    base_before = capture(BASE, base_map)
    publish(attempt / 'BASE-INITIAL.json', cas(attempt, base_before))
    assert_capture(base_before, base_map)
    require(BASE.stat().st_dev == attempt.stat().st_dev, 'hardlinks require the same filesystem')
    for name in sorted(base_map):
        target = root / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.link(BASE / name, target, follow_symlinks=False)
    overlay_rows = []
    for name, value in sorted(overlay['files'].items()):
        target = root / name
        if value['before'] is not None:
            raw, actual = read_exact(target, maximum=max(MIB, base_map[name]['bytes']))
            require(raw == value['before']['text'].encode()
                    and (actual['device'], actual['inode']) ==
                        (base_before['stat'][name]['device'], base_before['stat'][name]['inode']),
                    'shared existing overlay preimage differs')
            # Never write through or chmod the link to the original source.
            target.unlink()
        else:
            require(not target.exists(), 'new overlay destination already exists')
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        create(target, value['text'].encode(),
               mode=0o755 if value['after']['mode'] == '100755' else 0o644)
        overlay_rows.append({'path': name, 'existing': value['before'] is not None,
                             'new_private_inode': identity(target.lstat())})
    base_after, view = pair_capture(attempt, 'prepared', root, base_map, prepared)
    private = set(overlay['files'])
    for name, old in base_before['stat'].items():
        new = base_after['stat'][name]
        require(all(old[key] == new[key] for key in ('device','inode','mode','bytes','mtime_ns')),
                'original base changed during hardlink preparation')
        require(new['nlink'] == old['nlink'] + (name not in private),
                'original source link count changed by an unexplained amount')
        if name not in private:
            require(view['stat'][name] == new, 'remaining original path is not the expected shared inode')
    base_inodes = {(row['device'], row['inode']) for row in base_after['stat'].values()}
    require(all(view['stat'][name]['nlink'] == 1
                and (view['stat'][name]['device'], view['stat'][name]['inode']) not in base_inodes
                for name in private), 'overlay file is not a distinct private inode')
    require(len(base_map) == 3177 and len(prepared) == 3184
            and len(private) == 8 and len(set(base_map) - private) == 3176,
            'exact shared/overlay inventory differs')
    publish(attempt / 'PREPARATION.json', {
        'schema': SCHEMA + '.preparation', 'status': 'PREPARED',
        'base_tree': support.tree_digest(base_map), 'prepared_tree': support.tree_digest(prepared),
        'base_files': len(base_map), 'prepared_files': len(prepared),
        'shared_original_paths': 3176, 'private_overlays': overlay_rows,
        'intentional_base_metadata_changes': ['nlink during link creation/removal', 'ctime'],
        'base_original_bytes_and_posix_modes_unchanged': True,
        'atime_not_an_identity_field': True,
        'hardlinks_are_not_a_security_sandbox': True,
        'generator_outputs_are_external': True})
    return root, (base_after['stat'], view['stat'])


def check_runtime(runtime, fixed):
    require(sys.version_info[:3] == (3, 14, 4)
            and runtime['launch_executable'] == fixed['interpreter']['argv0']
            and runtime['version'] == fixed['runtime_version'], 'fixed actual interpreter differs')
    for key in ('bytes', 'sha256', 'mode'):
        require(runtime['executable'][key] == fixed['interpreter'][key]
                and runtime['library'] is not None
                and runtime['library'][key] == fixed['actual_library'][key],
                'fixed interpreter/library full bytes differ')
    require(runtime['executable']['path'] == fixed['interpreter']['actual']
            and runtime['library']['path'] == fixed['actual_library']['path'],
            'fixed actual executable/library path differs')


def output_capture(directory):
    result = {'files': {}, 'errors': []}
    actual_names = sorted(p.name for p in directory.iterdir())
    result['actual_names'] = actual_names
    for name in actual_names:
        path = directory / name
        try:
            s = path.lstat()
            require(name in OUTPUT_NAMES and stat.S_ISREG(s.st_mode) and s.st_nlink == 1,
                    'unexpected or nonprivate generated output')
            # The size is actual observed output, not a new language limit.
            raw, current = read_exact(path, maximum=s.st_size)
            result['files'][name] = {'pin': pin(raw), 'stat': current}
        except BaseException:
            result['errors'].append({'path': str(path), 'traceback': traceback.format_exc()})
    return result


def check_outputs(value):
    require(not value['errors'] and set(value['files']) == set(OUTPUT_NAMES)
            and all(value['files'][name]['pin']['bytes'] > 0 for name in OUTPUT_NAMES),
            'complete three generated outputs required')
    require(value['files'][OUTPUT_NAMES[0]]['pin']['bytes'] <= MIB,
            'actual assembly exceeds the unchanged public assembly source bound')


def write_fence(allowed_paths):
    """Cooperative Python-audit write fence for this exact frozen generator.

    It is not a hostile-native-code sandbox. The reviewed generator's only
    writes are its three Path.write_bytes calls; the complete base/view guards
    independently read every source before and after each owned invocation.
    """
    allowed = frozenset(str(Path(path).absolute()) for path in allowed_paths)
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
    mutation_events = frozenset(('os.remove', 'os.rmdir', 'os.rename', 'os.link',
        'os.symlink', 'os.mkdir', 'os.chmod', 'os.chown', 'os.utime', 'os.truncate'))

    def audit(event, arguments):
        if event == 'open':
            path, mode, flags = arguments
            writing = (type(flags) is int and bool(flags & write_flags)) or (
                type(mode) is str and any(c in mode for c in 'wax+'))
            if writing:
                require(type(path) in (str, bytes), 'generator cannot acquire a writable file descriptor')
                actual = os.path.abspath(os.fsdecode(path))
                require(actual in allowed, 'generator write outside explicit external outputs refused')
                try:
                    target = os.lstat(actual)
                except FileNotFoundError:
                    target = None
                require(target is None or (stat.S_ISREG(target.st_mode) and target.st_nlink == 1),
                        'generator output must not be a symlink or shared inode')
        elif event in mutation_events:
            raise AssertionError('generator filesystem mutation refused: ' + event)
        elif event == 'subprocess.Popen' or event in ('os.system', 'os.exec', 'os.posix_spawn', 'os.fork', 'os.forkpty'):
            raise AssertionError('generation-only child cannot launch another product process')
    sys.addaudithook(audit)


def child(request_path, request_sha256):
    raw, _ = read_exact(request_path, maximum=MIB)
    require(hashlib.sha256(raw).hexdigest() == request_sha256, 'generation request bytes differ')
    request = decode(raw)
    plan, _ = load_plan(request['plan'], request['plan_sha256'])
    require(request['schema'] == SCHEMA + '.request'
            and request['kind'] in ('generation-1', 'generation-2', 'generation-check')
            and request['runner'] == plan['runner'], 'unexpected child request')
    source = path_authority(request['source'])
    outputs = [Path(value) for value in request['outputs']]
    output_directory = path_authority(request['output_directory'])
    require(outputs == [output_directory / name for name in OUTPUT_NAMES]
            and not output_directory.is_relative_to(source)
            and not output_directory.is_relative_to(BASE), 'external fixed outputs required')
    result_path = Path(request['child_result'])
    require(result_path.parent == Path(request_path).parent and not result_path.exists(),
            'fresh child result path required')
    support = helpers()
    base_map, overlay, prepared = support.frozen_inputs()
    generator = source / 'tools/generate_hia_inspect_program.py'
    read_exact(generator, maximum=MIB, expected=prepared['tools/generate_hia_inspect_program.py'])
    sys.path.insert(0, str(source))
    from tools.hia_linux_file_roundtrip_cold import capture_runtime_context
    runtime = capture_runtime_context()
    require(runtime == request['runtime_context'], 'child actual runtime differs from selected parent')
    checking = request['kind'] == 'generation-check'
    require(checking or not any(path.exists() for path in outputs), 'generation must use new output paths')
    argv = [str(generator), '--output', str(outputs[0]), '--ports', str(outputs[1]),
            '--identity', str(outputs[2])]
    if checking:
        argv.append('--check')
    require(argv == request['generator_argv'], 'exact generator command differs')
    result = {'schema': SCHEMA + '.child', 'status': 'FAIL', 'request_pin': pin(raw),
              'generator_argv': argv, 'runtime_context': runtime,
              'write_fence': 'EXACT_PYTHON_WRITES_ONLY_NOT_A_NATIVE_SANDBOX',
              'native_compilations': 0, 'vm_frames': 0, 'tests': 0,
              'matching_current_cold': False, 'started_ns': time.monotonic_ns()}
    original_argv = sys.argv
    original_umask = os.umask(0o022)
    # Result publication is the only harness write allowed alongside the
    # generator's three destinations. --check can write no generated file.
    write_fence([result_path] + ([] if checking else outputs))
    try:
        sys.argv = argv
        runpy.run_path(str(generator), run_name='__main__')
        result['status'] = 'PASS'
    except BaseException:
        result['traceback'] = traceback.format_exc()
        raise
    finally:
        sys.argv = original_argv
        os.umask(original_umask)
        result['finished_ns'] = time.monotonic_ns()
        # Plain exclusive open avoids chmod, which the child write fence
        # deliberately refuses. The private result's actual mode is recorded.
        fd = os.open(result_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            pending = memoryview(encoded(result))
            while pending:
                count = os.write(fd, pending)
                require(count > 0, 'child result write made no progress')
                pending = pending[count:]
        finally:
            os.close(fd)


def execute(plan_path, plan_sha256, attempt):
    global _ATTEMPT, _OWNER_ATTEMPTS
    plan, plan_raw = load_plan(plan_path, plan_sha256)
    support = helpers()
    base_map, overlay, prepared = support.frozen_inputs()
    require(support.tree_digest(prepared) == plan['base']['prepared_tree'], 'prepared overlay tree differs')
    path_authority(BASE)
    attempt = Path(attempt).absolute()
    path_authority(attempt.parent)
    require('..' not in attempt.parts and not attempt.is_relative_to(BASE)
            and not BASE.is_relative_to(attempt) and not attempt.exists(), 'fresh independent attempt required')
    free = storage(attempt.parent)
    require(free['available_bytes'] >= 80*MIB and free['available_inodes'] >= 512,
            'separate generation-only preparation needs 80 MiB/512 free inodes')
    attempt.mkdir(mode=0o700)
    _ATTEMPT = attempt
    (attempt / 'maps').mkdir(mode=0o700)
    (attempt / 'results').mkdir(mode=0o700)
    report = {'schema': SCHEMA + '.result', 'status': 'FAIL', 'plan_pin': pin(plan_raw),
              'attempt': str(attempt), 'source': str(attempt / 'source'),
              'scope': 'GENERATION_ONLY_NO_TESTS_NO_COMPILATION_NO_VM_NO_COLD',
              'started_ns': time.monotonic_ns(), 'stages': [],
              'product_tests': 0, 'native_compilations': 0, 'vm_frames': 0,
              'matching_current_cold': False, 'default_activated': False,
              'whole_cli_native': False, 'cli_operation10_connected': False}
    root = attempt / 'source'
    current_map = prepared
    stable = None
    try:
        publish(attempt / 'PLAN-USED.json', plan)
        storage_gate(attempt, 'preparation', 80*MIB, inodes=512)
        root, stable = prepare(attempt, base_map, overlay, prepared, support)
        storage_gate(attempt, 'generation-1', 64*MIB)
        sys.path.insert(0, str(root))
        from tools.hia_selfhost_process_owner import run_owned
        from tools.hia_linux_file_roundtrip_cold import (
            capture_runtime_context, guard_runtime_context, runtime_child_environment)
        runtime = capture_runtime_context()
        fixed = decode((KIT / 'inputs/B3-REUSE-SIZE-PLAN.json').read_bytes())
        check_runtime(runtime, fixed)
        publish(attempt / 'RUNTIME.json', runtime)
        environment = runtime_child_environment({'PATH': '/usr/local/bin:/usr/bin:/bin',
            'HOME': str(attempt), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
            'PYTHONDONTWRITEBYTECODE': '1'}, runtime)
        output_sets = []
        first_size = 0
        for number, label in enumerate(('generation-1', 'generation-2', 'generation-check'), 1):
            directory = attempt / ('%02d-%s' % (number, label))
            directory.mkdir(mode=0o700)
            if number == 2:
                storage_gate(attempt, label, 44*MIB + 2*first_size)
            elif number == 3:
                storage_gate(attempt, label, 40*MIB + first_size)
            load_plan(plan_path, plan_sha256)
            pair_capture(attempt, label + '-before', root, base_map, current_map, stable=stable)
            guard_runtime_context(runtime)
            support.compiler_bytes()  # Identity only; this stage never invokes B3.
            if number < 3:
                output_dir = attempt / 'results' / str(number)
                output_dir.mkdir(mode=0o700)
            else:
                output_dir = attempt / 'results/2'
            outputs = [output_dir / name for name in OUTPUT_NAMES]
            generator_argv = [str(root / 'tools/generate_hia_inspect_program.py'),
                '--output', str(outputs[0]), '--ports', str(outputs[1]), '--identity', str(outputs[2])]
            if number == 3:
                generator_argv.append('--check')
            request = {'schema': SCHEMA + '.request', 'kind': label,
                'source': str(root), 'plan': str(Path(plan_path).absolute()),
                'plan_sha256': plan_sha256, 'runner': plan['runner'],
                'runtime_context': runtime, 'output_directory': str(output_dir),
                'outputs': [str(path) for path in outputs], 'generator_argv': generator_argv,
                'child_result': str(directory / 'CHILD-RESULT.json')}
            request_path = directory / 'REQUEST.json'
            publish(request_path, request)
            command = [sys.executable, '-I', '-B', str(Path(__file__).absolute()),
                '--child', str(request_path), '--request-sha256', pin(encoded(request))['sha256']]
            publish(directory / 'COMMAND.json', {'argv': command, 'cwd': str(root),
                'generator_argv': generator_argv, 'environment': environment,
                'supervisor_environment': environment, 'qualification_seconds': SECONDS,
                'cleanup_seconds': CLEANUP, 'source_tree': support.tree_digest(current_map)})
            row = {'label': label, 'status': 'FAIL', 'directory': str(directory),
                   'started_ns': time.monotonic_ns()}
            report['stages'].append(row)
            returned = None
            try:
                _OWNER_ATTEMPTS += 1
                returned = run_owned(command, cwd=root, env=environment,
                    stdout_path=directory / 'stdout.raw', stderr_path=directory / 'stderr.raw',
                    receipt_path=directory / 'OWNER.json', qualification_seconds=SECONDS,
                    cleanup_seconds=CLEANUP, supervisor_env=environment)
                publish(directory / 'OWNER-RETURNED.json', returned)
                support.complete_receipt(returned, directory / 'OWNER.json')
                child_raw, _ = read_exact(directory / 'CHILD-RESULT.json', maximum=4*MIB)
                child_result = decode(child_raw)
                require(child_result['status'] == 'PASS'
                        and child_result['request_pin'] == pin(encoded(request))
                        and child_result['runtime_context'] == runtime,
                        'actual child result does not attest this exact request/runtime')
                observed = output_capture(output_dir)
                check_outputs(observed)
                row['child_result_pin'] = pin(child_raw)
                row['outputs'] = observed
                if number == 1:
                    first_size = sum((value['pin']['bytes'] + 4095)//4096*4096
                                     for value in observed['files'].values())
                    output_sets.append(observed)
                else:
                    for name in OUTPUT_NAMES:
                        require(observed['files'][name]['pin'] == output_sets[0]['files'][name]['pin'],
                                'second generation/check is not byte exact')
                        first, _ = read_exact(attempt / 'results/1' / name,
                            maximum=output_sets[0]['files'][name]['pin']['bytes'],
                            expected=output_sets[0]['files'][name]['pin'])
                        actual, _ = read_exact(output_dir / name,
                            maximum=observed['files'][name]['pin']['bytes'],
                            expected=observed['files'][name]['pin'])
                        require(actual == first, 'full actual output bytes differ between generations')
                    if number == 2:
                        output_sets.append(observed)
                    else:
                        require(observed == output_sets[1], '--check mutated output content/metadata')
                guard_runtime_context(runtime)
                support.compiler_bytes()
                load_plan(plan_path, plan_sha256)
                row['status'] = 'PASS'
            except BaseException:
                row['traceback'] = traceback.format_exc()
                raise
            finally:
                # Capture both full source maps even after product failure.
                # A source/readback failure changes this stage to FAIL and
                # prevents the next owner, including when an owner returned 0.
                try:
                    pair_capture(attempt, label + '-after', root, base_map, current_map, stable=stable)
                    row['source_guard_pass'] = True
                except BaseException:
                    row['source_guard_pass'] = False
                    row['source_guard_error'] = traceback.format_exc()
                    row['status'] = 'FAIL'
                try:
                    row['actual_partial_outputs'] = output_capture(output_dir)
                    if row['status'] == 'PASS':
                        check_outputs(row['actual_partial_outputs'])
                        require(row['actual_partial_outputs'] == row['outputs'],
                                'actual output changed during final stage readback')
                except BaseException:
                    row['output_capture_error'] = traceback.format_exc()
                    row['status'] = 'FAIL'
                row['owner_returned'] = returned
                row['finished_ns'] = time.monotonic_ns()
                publish(directory / 'STAGE.json', row)
            require(row['status'] == 'PASS', 'stage readback failed; no later owner permitted')
        storage_gate(attempt, 'install', 36*MIB + first_size)
        pair_capture(attempt, 'install-before', root, base_map, current_map, stable=stable)
        install_rows = []
        for relative, name in zip(GENERATED, OUTPUT_NAMES, strict=True):
            target = root / relative
            require(not target.exists(), 'canonical generated destination must still be absent')
            actual, output_stat = read_exact(attempt / 'results/2' / name,
                maximum=output_sets[1]['files'][name]['pin']['bytes'],
                expected=output_sets[1]['files'][name]['pin'])
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            create(target, actual, mode=0o644)
            target_stat = identity(target.lstat())
            require(target_stat['nlink'] == 1
                    and (target_stat['device'], target_stat['inode']) !=
                        (output_stat['device'], output_stat['inode']), 'installed output must be a private copy')
            current_map = {**current_map, relative: pin(actual)}
            install_rows.append({'path': relative, 'pin': pin(actual), 'stat': target_stat})
        final_base, final_source = pair_capture(attempt, 'install-after', root, base_map, current_map)
        require(final_base['stat'] == stable[0]
                and all(final_source['stat'][name] == row for name, row in stable[1].items()),
                'installation changed a prior source inode or metadata')
        require(len(current_map) == 3187 and set(current_map) == set(prepared) | set(GENERATED),
                'final canonical inventory differs')
        publish(attempt / 'INSTALLATION.json', {'status': 'INSTALLED_AFTER_TWO_EXACT_GENERATIONS_AND_CHECK',
            'generated': install_rows, 'source_tree': support.tree_digest(current_map),
            'source_files': len(current_map), 'complete_map': cas(attempt, current_map)})
        report.update(status='GENERATION_ONLY_PASS', generated_paths=list(GENERATED),
            source_final_tree=support.tree_digest(current_map), source_files=len(current_map),
            original_base_bytes_and_posix_modes_unchanged=True,
            generation_invocations=2, check_invocations=1)
    except BaseException:
        report['traceback'] = traceback.format_exc()
        report['halted_after_first_failure'] = True
    finally:
        report['owner_launch_attempts'] = _OWNER_ATTEMPTS
        report['finished_ns'] = time.monotonic_ns()
        # Do not replace earlier artifacts or rerun a failed owner. The maps
        # include the last actual partial state even if preparation/install
        # failed; an absent final capture is an explicit incomplete result.
        try:
            terminal_base = capture(BASE, base_map)
            report['final_base_capture'] = cas(attempt, terminal_base)
            if root.is_dir():
                terminal_source = capture(root, current_map)
                report['final_source_capture'] = cas(attempt, terminal_source)
            if report['status'] == 'GENERATION_ONLY_PASS':
                assert_capture(terminal_base, base_map, stable=final_base['stat'])
                assert_capture(terminal_source, current_map, stable=final_source['stat'])
        except BaseException:
            report['final_capture_error'] = traceback.format_exc()
            report['status'] = 'FAIL'
        publish(attempt / 'RESULT.json', report)
    return 0 if report['status'] == 'GENERATION_ONLY_PASS' else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-generation-only', action='store_true')
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--plan-sha256')
    parser.add_argument('--attempt', type=Path)
    parser.add_argument('--child', type=Path)
    parser.add_argument('--request-sha256')
    args = parser.parse_args(argv)
    if args.child is not None:
        require(not args.execute_generation_only and args.plan is None and args.plan_sha256 is None
                and args.attempt is None and args.request_sha256 is not None,
                'mixed generation parent/child invocation')
        child(args.child, args.request_sha256)
        return 0
    require(args.execute_generation_only and args.plan is not None
            and args.plan_sha256 is not None and args.attempt is not None
            and args.request_sha256 is None, 'explicit reviewed generation-only invocation required')
    try:
        return execute(args.plan, args.plan_sha256, args.attempt)
    except BaseException:
        error = traceback.format_exc()
        sys.stderr.write(error)
        if _ATTEMPT is not None and not (_ATTEMPT / 'RESULT.json').exists():
            publish(_ATTEMPT / 'ENTRY-FAILURE.json', {'status': 'FAIL', 'traceback': error,
                'owner_launch_attempts': _OWNER_ATTEMPTS, 'matching_current_cold': False,
                'partial_artifacts_retained': True})
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
