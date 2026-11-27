"""Reviewed private inspect generation stage; no tests, compile or VM.

The 3,188-file independent source already exists. This stage does not copy or
hardlink a source tree. Two real generations and one check use external paths;
only after all three complete can three new private output inodes be installed.
"""
from __future__ import annotations

import argparse
import ast
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
BASE = Path('/workspace/scratch/dda74a4fae35/v119-inspect-generation-only-r1/attempt-r1/source')
SOURCE = Path('/workspace/scratch/dda74a4fae35/v132-inspect-machine-entry-r1/successor-r2/materialization-attempt-r1/source')
ATTEMPT = HERE.parent / 'generation-attempt-r1'
KIT_SHA256 = '9e827365eb3c9217486fa569c667825f6c824abbaf7b9df03f43d78206d43d61'
MIB = 1048576
MINIMUM_FREE = 1073741824
SECONDS, CLEANUP = 180, 3
GENERATED = ('examples/hia_bootstrap/inspect_program.hepta',
             'hepta/hia_inspect_program_ports.py', 'hepta/hia_inspect_program_data.py')
OUTPUT_NAMES = ('inspect_program.hepta', 'hia_inspect_program_ports.py',
                'hia_inspect_program_data.py')
SCHEMA = 'hepta.hia.inspect-private-class-default-generation.v1'
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

def tree_digest(files):
    tree={}
    for name,row in files.items():
        require(not name.startswith('/') and all(x not in ('','.','..') for x in name.split('/')),
                'unsafe source-map path')
        node=tree
        parts=name.split('/')
        for part in parts[:-1]:node=node.setdefault(part,{})
        require(parts[-1] not in node,'duplicate tree path')
        node[parts[-1]]=(row['mode'],row['git_blob'])
    def digest(node):
        entries=[]
        for name,row in node.items():
            if isinstance(row,dict):
                mode,sha='40000',digest(row);key=name.encode()+b'/'
            else:
                mode,sha=row;key=name.encode()
            entries.append((key,mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(sha)))
        body=b''.join(item[1] for item in sorted(entries))
        return hashlib.sha1(b'tree '+str(len(body)).encode()+b'\0'+body).hexdigest()
    return digest(tree)


def fixed_file(row):
    # Git identity and actual POSIX mode are separate. Evidence files produced
    # as 0600 must never be admitted by a source-only 0644 permission guard.
    require(type(row) is dict and set(row) == {'path', 'pin', 'posix_mode'}
            and type(row['posix_mode']) is int, 'complete fixed file descriptor required')
    raw, observed = read_exact(Path(row['path']), maximum=row['pin']['bytes'], expected=row['pin'])
    require(observed['mode'] == row['posix_mode'], 'actual fixed file permission differs')
    return raw


def load_plan(path, sha256):
    path = Path(path).absolute()
    raw, actual = read_exact(path, maximum=MIB)
    require(type(sha256) is str and len(sha256) == 64
            and hashlib.sha256(raw).hexdigest() == sha256
            and actual['mode'] == 0o644, 'reviewed complete plan bytes/mode differ')
    plan = decode(raw)
    require(plan['schema'] == SCHEMA + '.plan'
            and plan['status'] == 'AUTHORED_NOT_EXECUTED'
            and plan['source'] == str(SOURCE) and plan['base'] == str(BASE)
            and plan['attempt'] == str(ATTEMPT)
            and tuple(plan['generated_paths']) == GENERATED
            and plan['kit'] == {'path': str(KIT), 'index_sha256': KIT_SHA256}
            and encoded(plan['limits']) == encoded({
                'qualification_seconds': SECONDS, 'cleanup_seconds': CLEANUP,
                'minimum_free_bytes': MINIMUM_FREE, 'assembly_source_bytes': MIB})
            and plan['stage_order'] == ['generation-1', 'generation-2', 'generation-check'],
            'fixed generation-only plan contract differs')
    runner, observed = read_exact(Path(__file__).absolute(), maximum=MIB, expected=plan['runner'])
    require(observed['mode'] == 0o644, 'runner mode differs')
    require(set(plan['inputs']) == {
        'contract', 'design', 'overlay', 'materialization_result', 'source_map',
        'source_capture', 'base_capture', 'runtime_capture', 'original_generation_runner'},
        'fixed complete input inventory differs')
    for row in plan['inputs'].values():
        fixed_file(row)
    index, _ = read_exact(KIT / 'KIT-PINS.json', maximum=MIB)
    require(hashlib.sha256(index).hexdigest() == KIT_SHA256, 'complete original kit index differs')
    inventory = decode(index)
    require(len(inventory['files']) == 13, 'all original 14 kit files required')
    for name, expected in inventory['files'].items():
        read_exact(KIT / name, maximum=max(MIB, expected['bytes']), expected=expected)
    return plan, raw


def authorities(plan):
    material = decode(fixed_file(plan['inputs']['materialization_result']))
    source_map = decode(fixed_file(plan['inputs']['source_map']))
    source = decode(fixed_file(plan['inputs']['source_capture']))
    base = decode(fixed_file(plan['inputs']['base_capture']))
    runtime = decode(fixed_file(plan['inputs']['runtime_capture']))
    require(material['status'] == 'PRIVATE_SOURCE_MATERIALIZATION_PASS'
            and material['source'] == str(SOURCE) and material['source_files'] == 3188
            and material['source_tree'] == '36b936c0473844e943d227b99865de776c27834b'
            and material['new_hardlinks'] == 0 and material['no_base_inode_reused'] is True
            and material['all_private_inodes_unique'] is True
            and material['old_all_bytes_modes_seven_stat_fields_unchanged'] is True
            and material['generated_metadata_current'] is False
            and material['generation'] == material['compile'] == material['Source']
                == material['Native'] == material['VM'] == material['product_execution'] == 0,
            'actual non-product private materialization result differs')
    require(material['source_map'] == plan['inputs']['source_map']['pin']
            and material['source_capture'] == plan['inputs']['source_capture']['pin']
            and source['files'] == source_map and not source['errors'] and not base['errors']
            and len(base['files']) == 3187 and len(source_map) == 3188
            and tree_digest(source_map) == material['source_tree']
            and tree_digest(base['files']) == '7df49dd24bbba4ba3210168e639d6ea35a76a475',
            'complete actual source/base authority differs')
    require(runtime['launch_executable'] == plan['runtime']['launch_executable']
            and runtime == plan['runtime'] and runtime['version'] == [3, 14, 4],
            'fixed actual runtime capture differs')
    for name in GENERATED:
        require(source_map[name] == base['files'][name], 'old generated preimage differs')
    return base, source, runtime


def independent(base_capture, source_capture):
    old = {(row['device'], row['inode']) for row in base_capture['stat'].values()}
    current = [(row['device'], row['inode']) for row in source_capture['stat'].values()]
    require(len(current) == len(set(current))
            and all(row['nlink'] == 1 for row in source_capture['stat'].values())
            and not old.intersection(current), 'private source no longer has independent inodes')


def pair_capture(attempt, label, base_expected, source_expected, stable):
    base = capture(BASE, base_expected)
    source = capture(SOURCE, source_expected)
    row = {'label': label, 'base': cas(attempt, base), 'source': cas(attempt, source),
           'all_bytes_read': True, 'all_seven_stat_fields_checked': True}
    publish(attempt / ('GUARD-' + label + '.json'), row)
    assert_capture(base, base_expected, stable=stable[0])
    assert_capture(source, source_expected, stable=stable[1])
    independent(base, source)
    return base, source


def actual_runtime(expected):
    from tools.hia_linux_file_roundtrip_cold import capture_runtime_context
    runtime = capture_runtime_context()
    require(runtime == expected and sys.version_info[:3] == (3, 14, 4),
            'running interpreter/library does not equal frozen actual runtime')
    return runtime


def bind_generated_identity(output_directory, observed, source_map):
    """Read generated data as literal evidence; never manufacture its bytes."""
    raws = {}
    for name in OUTPUT_NAMES:
        raws[name], _ = read_exact(output_directory / name,
            maximum=observed['files'][name]['pin']['bytes'],
            expected=observed['files'][name]['pin'])
    for relative, name in zip(GENERATED[:2], OUTPUT_NAMES[:2], strict=True):
        require(pin(raws[name]) == source_map[relative],
                'policy assembly/ports changed in a connection-layer-only successor')
        previous, _ = read_exact(SOURCE / relative, maximum=source_map[relative]['bytes'],
                                 expected=source_map[relative])
        require(raws[name] == previous, 'complete original assembly/ports bytes differ')
    runtime_raw, _ = read_exact(SOURCE / 'hepta/hia_inspect_program_native.py', maximum=MIB,
        expected=source_map['hepta/hia_inspect_program_native.py'])
    assignments = [node for node in ast.parse(runtime_raw).body
                   if isinstance(node, ast.Assign) and len(node.targets) == 1
                   and isinstance(node.targets[0], ast.Name)
                   and node.targets[0].id == 'HOST_SOURCE_FILES']
    require(len(assignments) == 1, 'one literal host source inventory required')
    names = ast.literal_eval(assignments[0].value)
    require(type(names) is tuple and len(names) == len(set(names)) == 13
            and all(type(name) is str and Path(name).name == name for name in names),
            'complete exact component host inventory required')
    body = ast.parse(raws[OUTPUT_NAMES[2]]).body
    require(body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
            and type(body[0].value.value) is str, 'generated identity docstring required')
    values = {}
    for node in body[1:]:
        require(isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id not in values, 'generated identity must contain unique literal assignments')
        values[node.targets[0].id] = ast.literal_eval(node.value)
    require(set(values) == {'SOURCE_BYTES', 'SOURCE_SHA256', 'HOST_SOURCE_SHA256'}
            and type(values['SOURCE_BYTES']) is int
            and values['SOURCE_BYTES'] == len(raws[OUTPUT_NAMES[0]])
            and values['SOURCE_SHA256'] == hashlib.sha256(raws[OUTPUT_NAMES[0]]).hexdigest(),
            'actual generated assembly identity differs')
    expected_hosts = {}
    for name in names:
        if name == 'hia_inspect_program_ports.py':
            raw = raws[OUTPUT_NAMES[1]]
        else:
            raw, _ = read_exact(SOURCE / 'hepta' / name,
                maximum=source_map['hepta/' + name]['bytes'], expected=source_map['hepta/' + name])
        expected_hosts[name] = hashlib.sha256(raw).hexdigest()
    require(values['HOST_SOURCE_SHA256'] == expected_hosts
            and values['HOST_SOURCE_SHA256']['hia_inspect_program_native.py']
                == '8db7befea61305e52d08abe874ddc252d5cec0072b92e44e55be50a9c439f89d'
            and pin(raws[OUTPUT_NAMES[2]]) != source_map[GENERATED[2]],
            'real generation has not bound the new runtime and all actual host bytes')
    return {'host_source_files': list(names), 'actual_generated_fields': values,
            'assembly_and_ports_full_bytes_unchanged': True,
            'new_runtime_identity_is_actually_generated': True,
            'identity_pin': pin(raws[OUTPUT_NAMES[2]])}


def child(request_path, request_sha256):
    raw, _ = read_exact(request_path, maximum=MIB)
    require(hashlib.sha256(raw).hexdigest() == request_sha256, 'generation request bytes differ')
    request = decode(raw)
    plan, _ = load_plan(request['plan'], request['plan_sha256'])
    require(set(request) == {'schema', 'kind', 'source', 'plan', 'plan_sha256', 'runner',
        'runtime_context', 'output_directory', 'outputs', 'generator_argv', 'child_result'}
        and request['schema'] == SCHEMA + '.request' and request['kind'] in plan['stage_order']
        and request['runner'] == plan['runner'] and request['source'] == str(SOURCE),
        'fixed generation child request differs')
    base, source, expected_runtime = authorities(plan)
    path_authority(SOURCE)
    outputs = [Path(value) for value in request['outputs']]
    output_directory = path_authority(request['output_directory'])
    expected_number = '1' if request['kind'] == 'generation-1' else '2'
    require(output_directory == ATTEMPT / 'results' / expected_number
            and outputs == [output_directory / name for name in OUTPUT_NAMES],
            'only exact external generated output paths are admitted')
    number = plan['stage_order'].index(request['kind']) + 1
    stage_directory = ATTEMPT / ('%02d-%s' % (number, request['kind']))
    require(Path(request_path) == stage_directory / 'REQUEST.json', 'request stage path differs')
    result_path = stage_directory / 'CHILD-RESULT.json'
    require(request['child_result'] == str(result_path) and not result_path.exists(),
            'fresh exact child result path required')
    generator = SOURCE / 'tools/generate_hia_inspect_program.py'
    read_exact(generator, maximum=MIB, expected=source['files']['tools/generate_hia_inspect_program.py'])
    sys.path.insert(0, str(SOURCE))
    runtime = actual_runtime(expected_runtime)
    require(runtime == request['runtime_context'], 'parent/child runtime differs')
    checking = request['kind'] == 'generation-check'
    require(checking or not any(path.exists() for path in outputs), 'new generation outputs required')
    argv = [str(generator), '--output', str(outputs[0]), '--ports', str(outputs[1]),
            '--identity', str(outputs[2])]
    if checking:
        argv.append('--check')
    require(argv == request['generator_argv'], 'exact real generator argv differs')
    result = {'schema': SCHEMA + '.child', 'status': 'FAIL', 'request_pin': pin(raw),
        'generator_argv': argv, 'runtime_context': runtime, 'tests': 0,
        'native_compilations': 0, 'vm_frames': 0, 'matching_current_cold': False,
        'write_fence': 'EXACT_PYTHON_WRITES_ONLY_NOT_A_NATIVE_SANDBOX',
        'started_ns': time.monotonic_ns()}
    original_argv, original_umask = sys.argv, os.umask(0o022)
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
        fd = os.open(result_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            pending = memoryview(encoded(result))
            while pending:
                count = os.write(fd, pending)
                require(count > 0, 'child result write made no progress')
                pending = pending[count:]
        finally:
            os.close(fd)


def install_outputs(attempt, observed, source_map, stable, base_map):
    pair_capture(attempt, 'install-before', base_map, source_map, stable)
    directory = attempt / 'install-staging'
    directory.mkdir(mode=0o700)
    rows = []
    for relative, name in zip(GENERATED, OUTPUT_NAMES, strict=True):
        target = SOURCE / relative
        before, previous = read_exact(target, maximum=source_map[relative]['bytes'],
                                      expected=source_map[relative])
        require(previous == stable[1][relative] and previous['nlink'] == 1,
                'exact private generated preimage changed')
        actual, output_stat = read_exact(attempt / 'results/2' / name,
            maximum=observed['files'][name]['pin']['bytes'], expected=observed['files'][name]['pin'])
        replacement = directory / name
        create(replacement, actual, mode=0o644)
        replacement_stat = identity(replacement.lstat())
        require(replacement_stat['nlink'] == 1
                and replacement_stat['device'] == previous['device']
                and replacement_stat['inode'] != previous['inode']
                and (replacement_stat['device'], replacement_stat['inode'])
                    != (output_stat['device'], output_stat['inode']),
                'replacement must already be a distinct private inode on the same filesystem')
        # The old inode remains present until the new one is already allocated.
        # Replacing the private copy cannot write the retained base inode.
        check, current = read_exact(target, maximum=len(before), expected=source_map[relative])
        require(check == before and current == previous, 'preimage changed before atomic replacement')
        publish(attempt / ('INSTALL-INTENT-' + name + '.json'), {
            'target': str(target), 'before': source_map[relative], 'before_stat': previous,
            'replacement': str(replacement), 'after': pin(actual), 'replacement_stat': replacement_stat})
        os.replace(replacement, target)
        source_map[relative] = pin(actual)
        installed, final_stat = read_exact(target, maximum=len(actual), expected=pin(actual))
        require(installed == actual and final_stat['nlink'] == 1
                and final_stat['mode'] == 0o644
                and (final_stat['device'], final_stat['inode'])
                    == (replacement_stat['device'], replacement_stat['inode']),
                'actual installed new inode differs')
        stable[1][relative] = final_stat
        rows.append({'path': relative, 'before': pin(before), 'after': pin(actual),
                     'before_stat': previous, 'after_stat': final_stat})
    final_base, final_source = pair_capture(attempt, 'install-after', base_map, source_map, stable)
    require(len(source_map) == 3188, 'generation changed the complete source pathname inventory')
    publish(attempt / 'INSTALLATION.json', {'status': 'THREE_NEW_INODES_AFTER_REAL_DOUBLE_GENERATION_AND_CHECK',
        'generated': rows, 'source_tree': tree_digest(source_map), 'source_files': len(source_map),
        'all_base_bytes_modes_seven_stat_fields_unchanged': True,
        'all_nongenerated_private_bytes_modes_seven_stat_fields_unchanged': True,
        'complete_map': cas(attempt, source_map)})
    return final_base, final_source


def execute(plan_path, plan_sha256, attempt):
    global _ATTEMPT, _OWNER_ATTEMPTS
    plan, plan_raw = load_plan(plan_path, plan_sha256)
    base, source, expected_runtime = authorities(plan)
    require(Path(attempt).absolute() == ATTEMPT and not ATTEMPT.exists(), 'one fresh fixed attempt required')
    path_authority(ATTEMPT.parent)
    path_authority(BASE)
    path_authority(SOURCE)
    free = storage(ATTEMPT.parent)
    require(free['available_bytes'] >= MINIMUM_FREE and free['available_inodes'] >= 128,
            'unchanged 1-GiB storage floor and 128 free inodes required')
    ATTEMPT.mkdir(mode=0o700)
    _ATTEMPT = ATTEMPT
    (ATTEMPT / 'maps').mkdir(mode=0o700)
    (ATTEMPT / 'results').mkdir(mode=0o700)
    base_map, current_map = base['files'], dict(source['files'])
    stable = [dict(base['stat']), dict(source['stat'])]
    report = {'schema': SCHEMA + '.result', 'status': 'FAIL', 'plan_pin': pin(plan_raw),
        'attempt': str(ATTEMPT), 'source': str(SOURCE), 'source_initial_tree': tree_digest(current_map),
        'scope': 'GENERATION_ONLY_NO_TESTS_NO_COMPILE_NO_VM_NO_COLD', 'stages': [],
        'product_tests': 0, 'native_compilations': 0, 'vm_frames': 0,
        'source_copies': 0, 'new_hardlinks': 0, 'matching_current_cold': False,
        'default_activated': False, 'whole_cli_native': False, 'cli_operation10_connected': False,
        'generated_metadata_current': False, 'started_ns': time.monotonic_ns()}
    try:
        publish(ATTEMPT / 'PLAN-USED.json', plan)
        pair_capture(ATTEMPT, 'initial', base_map, current_map, stable)
        support = helpers()
        sys.path.insert(0, str(SOURCE))
        from tools.hia_selfhost_process_owner import run_owned
        from tools.hia_linux_file_roundtrip_cold import guard_runtime_context, runtime_child_environment
        runtime = actual_runtime(expected_runtime)
        publish(ATTEMPT / 'RUNTIME.json', runtime)
        environment = runtime_child_environment({'PATH': '/usr/local/bin:/usr/bin:/bin',
            'HOME': str(ATTEMPT), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
            'PYTHONDONTWRITEBYTECODE': '1'}, runtime)
        output_sets = []
        for number, label in enumerate(plan['stage_order'], 1):
            storage_gate(ATTEMPT, label, MINIMUM_FREE, inodes=64)
            directory = ATTEMPT / ('%02d-%s' % (number, label))
            directory.mkdir(mode=0o700)
            load_plan(plan_path, plan_sha256)
            pair_capture(ATTEMPT, label + '-before', base_map, current_map, stable)
            guard_runtime_context(runtime)
            support.compiler_bytes()  # Identity only; the compiler is not invoked.
            output_dir = ATTEMPT / 'results' / ('1' if number == 1 else '2')
            if number < 3:
                output_dir.mkdir(mode=0o700)
            outputs = [output_dir / name for name in OUTPUT_NAMES]
            generator_argv = [str(SOURCE / 'tools/generate_hia_inspect_program.py'),
                '--output', str(outputs[0]), '--ports', str(outputs[1]), '--identity', str(outputs[2])]
            if number == 3:
                generator_argv.append('--check')
            request = {'schema': SCHEMA + '.request', 'kind': label, 'source': str(SOURCE),
                'plan': str(Path(plan_path).absolute()), 'plan_sha256': plan_sha256,
                'runner': plan['runner'], 'runtime_context': runtime, 'output_directory': str(output_dir),
                'outputs': [str(path) for path in outputs], 'generator_argv': generator_argv,
                'child_result': str(directory / 'CHILD-RESULT.json')}
            publish(directory / 'REQUEST.json', request)
            command = [sys.executable, '-I', '-B', str(Path(__file__).absolute()),
                '--child', str(directory / 'REQUEST.json'), '--request-sha256', pin(encoded(request))['sha256']]
            publish(directory / 'COMMAND.json', {'argv': command, 'cwd': str(SOURCE),
                'generator_argv': generator_argv, 'environment': environment,
                'supervisor_environment': environment, 'qualification_seconds': SECONDS,
                'cleanup_seconds': CLEANUP, 'source_tree': tree_digest(current_map)})
            row = {'label': label, 'status': 'FAIL', 'directory': str(directory),
                   'started_ns': time.monotonic_ns()}
            report['stages'].append(row)
            returned = None
            try:
                _OWNER_ATTEMPTS += 1
                returned = run_owned(command, cwd=SOURCE, env=environment,
                    stdout_path=directory / 'stdout.raw', stderr_path=directory / 'stderr.raw',
                    receipt_path=directory / 'OWNER.json', qualification_seconds=SECONDS,
                    cleanup_seconds=CLEANUP, supervisor_env=environment)
                publish(directory / 'OWNER-RETURNED.json', returned)
                support.complete_receipt(returned, directory / 'OWNER.json')
                child_raw, _ = read_exact(directory / 'CHILD-RESULT.json', maximum=4*MIB)
                child_result = decode(child_raw)
                require(child_result['status'] == 'PASS' and child_result['request_pin'] == pin(encoded(request))
                        and child_result['runtime_context'] == runtime,
                        'actual child result does not attest this complete request/runtime')
                observed = output_capture(output_dir)
                check_outputs(observed)
                row['child_result_pin'], row['outputs'] = pin(child_raw), observed
                row['generated_identity'] = bind_generated_identity(output_dir, observed, current_map)
                if number == 1:
                    output_sets.append(observed)
                else:
                    for name in OUTPUT_NAMES:
                        require(observed['files'][name]['pin'] == output_sets[0]['files'][name]['pin'],
                                'actual generation/check output identity differs')
                        first, _ = read_exact(ATTEMPT / 'results/1' / name,
                            maximum=output_sets[0]['files'][name]['pin']['bytes'],
                            expected=output_sets[0]['files'][name]['pin'])
                        actual, _ = read_exact(output_dir / name, maximum=len(first),
                                              expected=output_sets[0]['files'][name]['pin'])
                        require(first == actual, 'full generated output bytes differ')
                    if number == 2:
                        output_sets.append(observed)
                    else:
                        require(observed == output_sets[1], '--check changed generated bytes or metadata')
                guard_runtime_context(runtime)
                support.compiler_bytes()
                load_plan(plan_path, plan_sha256)
                row['status'] = 'PASS'
            except BaseException:
                row['traceback'] = traceback.format_exc()
                raise
            finally:
                try:
                    pair_capture(ATTEMPT, label + '-after', base_map, current_map, stable)
                    row['source_guard_pass'] = True
                except BaseException:
                    row['source_guard_pass'], row['status'] = False, 'FAIL'
                    row['source_guard_error'] = traceback.format_exc()
                try:
                    row['actual_partial_outputs'] = output_capture(output_dir)
                    if row['status'] == 'PASS':
                        check_outputs(row['actual_partial_outputs'])
                        require(row['actual_partial_outputs'] == row['outputs'],
                                'generated output changed during final stage readback')
                except BaseException:
                    row['output_capture_error'], row['status'] = traceback.format_exc(), 'FAIL'
                row['owner_returned'], row['finished_ns'] = returned, time.monotonic_ns()
                publish(directory / 'STAGE.json', row)
            require(row['status'] == 'PASS', 'failed actual stage forbids every later owner')
        storage_gate(ATTEMPT, 'install', MINIMUM_FREE, inodes=64)
        bind_generated_identity(ATTEMPT / 'results/2', output_sets[1], current_map)
        final_base, final_source = install_outputs(ATTEMPT, output_sets[1], current_map, stable, base_map)
        require(_OWNER_ATTEMPTS == 3 and len(report['stages']) == 3
                and all(row['status'] == 'PASS' for row in report['stages']), 'exact three actual owners required')
        report.update(status='GENERATION_ONLY_PASS', source_files=len(current_map),
            source_final_tree=tree_digest(current_map), generated_paths=list(GENERATED),
            generation_invocations=2, check_invocations=1, generated_metadata_current=True,
            original_base_bytes_modes_seven_stat_fields_unchanged=True,
            nongenerated_private_bytes_modes_seven_stat_fields_unchanged=True)
    except BaseException:
        report['traceback'], report['halted_after_first_failure'] = traceback.format_exc(), True
    finally:
        report['owner_launch_attempts'], report['finished_ns'] = _OWNER_ATTEMPTS, time.monotonic_ns()
        try:
            terminal_base = capture(BASE, base_map)
            terminal_source = capture(SOURCE, current_map)
            report['final_base_capture'], report['final_source_capture'] = (
                cas(ATTEMPT, terminal_base), cas(ATTEMPT, terminal_source))
            if report['status'] == 'GENERATION_ONLY_PASS':
                assert_capture(terminal_base, base_map, stable=stable[0])
                assert_capture(terminal_source, current_map, stable=stable[1])
                independent(terminal_base, terminal_source)
        except BaseException:
            report['final_capture_error'], report['status'] = traceback.format_exc(), 'FAIL'
        publish(ATTEMPT / 'RESULT.json', report)
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
                and args.attempt is None and args.request_sha256 is not None, 'mixed parent/child invocation')
        child(args.child, args.request_sha256)
        return 0
    require(args.execute_generation_only and args.plan is not None and args.plan_sha256 is not None
            and args.attempt is not None and args.request_sha256 is None,
            'explicit reviewed generation-only authorization required')
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
