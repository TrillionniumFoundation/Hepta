"""Private entry-layout support. Import performs no product call."""
from pathlib import Path
import ast
import functools
import hashlib
import inspect
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parent
PLAN_PATH = ROOT / 'EXECUTION-PLAN.json'
PLAN_RAW = PLAN_PATH.read_bytes()
PLAN = json.loads(PLAN_RAW)
SOURCE = Path(PLAN['source']['path'])
OUT = Path(PLAN['output'])
DATA = OUT / 'entry.evidence'
CAPACITY = 1 << 20
STAT_KEYS = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')


def require(value, message):
    if not value:
        raise AssertionError(message)


def pin(raw, mode=None):
    value = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
             'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
    if mode is not None:
        value.update(mode=mode, git_mode='100755' if mode & 0o111 else '100644')
    return value


def state(value):
    return {key: getattr(value, key) for key in STAT_KEYS}


def read_regular(path):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), 'nonregular fixed file: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(state(os.fstat(fd)) == state(before), 'opened fixed file differs')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(before.st_size + 1)
        require(len(raw) == before.st_size and state(os.fstat(fd)) == state(before)
                and state(path.lstat()) == state(before), 'fixed file changed during complete read')
    finally:
        os.close(fd)
    return raw, stat.S_IMODE(before.st_mode), state(before)


def identity(path):
    raw, mode, _ = read_regular(path)
    return pin(raw, mode)


def write(path, raw, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, mode)
    observed, actual_mode, _ = read_regular(path)
    require(observed == raw and actual_mode == mode, 'new evidence readback differs')


def dump(path, value):
    write(path, (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode())


def source_snapshot(destination):
    expected = json.loads((ROOT / 'FROZEN-3180-SOURCE.json').read_bytes())
    files, stamps = {}, {}
    for directory, directories, names in os.walk(SOURCE, followlinks=False):
        directories.sort()
        for name in directories:
            require(stat.S_ISDIR((Path(directory) / name).lstat().st_mode), 'source directory symlink')
        for name in sorted(names):
            path = Path(directory) / name
            relative = path.relative_to(SOURCE).as_posix()
            raw, mode, stamp = read_regular(path)
            require(relative in expected, 'unexpected source path: ' + relative)
            files[relative], stamps[relative] = pin(raw, mode), stamp
    require(files == expected and len(files) == 3180, 'full frozen source bytes/modes differ')
    result = {'files': files, 'inode_states': stamps, 'tree': PLAN['source']['tree'],
              'identity_is_complete_frozen_manifest_equality': True}
    dump(destination, result)
    return result


def same_source(before, destination):
    after = source_snapshot(destination)
    require(before is not None and after == before, 'complete source bytes/modes/inodes changed')
    return {'files': len(after['files']), 'tree': after['tree'], 'whole_before_after_equal': True}


def controls():
    observed = {}
    for key, row in PLAN['controls'].items():
        actual = identity(row['path'])
        require(actual == row['identity'], 'fixed control differs: ' + key)
        observed[key] = actual
    require(PLAN_PATH.read_bytes() == PLAN_RAW, 'fixed execution plan changed')
    return observed


def runtime():
    expected = PLAN['runtime']
    require(sys.version_info[:3] == (3, 14, 4) and sys.executable == expected['executable']['path'],
            'actual interpreter is not the fixed 3.14.4 argv executable')
    require(sys.flags.isolated == 1 and sys.flags.ignore_environment == 1
            and sys.flags.no_site == 1 and sys.flags.dont_write_bytecode == 1,
            'fixed isolated non-site no-bytecode launch flags differ')
    resolved = Path(sys.executable).resolve(strict=True)
    require(str(resolved) == expected['executable']['resolved_path']
            and identity(resolved) == expected['executable']['identity'], 'runtime executable differs')
    require(identity(expected['library']['path']) == expected['library']['identity'], 'fixed libpython differs')
    require(dict(os.environ) == PLAN['environment'] and 'LD_PRELOAD' not in os.environ,
            'runtime environment differs from the complete fixed dictionary')
    require(platform.system() == 'Linux' and platform.machine().lower() in ('x86_64', 'amd64'),
            'fixed Linux x86-64 profile required')
    return {'executable': str(resolved), 'argv_executable': sys.executable, 'version': sys.version,
            'isolated': sys.flags.isolated, 'ignore_environment': sys.flags.ignore_environment,
            'no_site': sys.flags.no_site, 'dont_write_bytecode': sys.flags.dont_write_bytecode,
            'environment': dict(os.environ), 'library': expected['library']}


def toolchain():
    observed = {}
    for name, row in PLAN['toolchain'].items():
        selected = shutil.which(name, path=PLAN['environment']['PATH'])
        require(selected == row['selected_path'] and str(Path(selected).resolve(strict=True)) == row['path']
                and identity(row['path']) == row['identity'], 'fixed host tool differs: ' + name)
        observed[name] = row
    return observed


def function_text(path, name):
    text = Path(path).read_text()
    node = next(node for node in ast.parse(text).body if isinstance(node, ast.FunctionDef) and node.name == name)
    return ''.join(text.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])


def projection_guard():
    spec = json.loads((ROOT / 'PROJECTION-SPEC.json').read_bytes())
    original = function_text(SOURCE / spec['original_file'], 'qualify_entry_layout')
    projected = function_text(ROOT / 'entry_projection.py', 'qualify_entry_layout_explicit')
    require(original == spec['original_function'] and projected == spec['proposed_function'],
            'complete original or explicit function differs')
    inverse = projected
    for replacement in reversed(spec['replacements']):
        require(inverse.count(replacement['after']) == 1, 'ambiguous exact function inverse')
        inverse = inverse.replace(replacement['after'], replacement['before'], 1)
    require(inverse == original and ast.dump(ast.parse(inverse), include_attributes=False)
            == ast.dump(ast.parse(original), include_attributes=False), 'whole original function inverse differs')
    loader = PLAN['loader_projection']
    before = Path(loader['original']['path']).read_bytes()
    after = Path(loader['projected']['path']).read_bytes()
    inverse_loader = after.decode()
    for insertion in loader['insertions']:
        require(inverse_loader.count(insertion) == 1, 'private full-frame loader inverse differs')
        inverse_loader = inverse_loader.replace(insertion, '', 1)
    require(inverse_loader.encode() == before and ast.dump(ast.parse(inverse_loader), include_attributes=False)
            == ast.dump(ast.parse(before), include_attributes=False), 'original loader body not preserved')
    return {'entry_whole_inverse_bytes_equal': True, 'entry_whole_inverse_AST_equal': True,
            'loader_whole_inverse_bytes_equal': True, 'loader_whole_inverse_AST_equal': True,
            'ordinary_SOURCE_rebound': False}


def input_guard():
    manifest = json.loads((ROOT / 'ACTUAL-INPUT-MANIFEST.json').read_bytes())
    for row in manifest['files']:
        raw, mode, _ = read_regular(row['local_path'])
        require(pin(raw) == row['identity'] and mode == row['mode'], 'extracted actual input changed')
    for label in ('B3', 'M3'):
        folder = ROOT / 'actual-inputs'
        image = (folder / (label + '.image.bin')).read_bytes()
        output = (folder / (label + '.output.bin')).read_bytes()
        request = json.loads((folder / (label + '.request.json')).read_bytes())
        receipt = json.loads((folder / (label + '.receipt.json')).read_bytes())
        stdout = json.loads((folder / (label + '.stdout.log')).read_bytes())
        require(output[:len(image)] == image and len(output) == CAPACITY
                and receipt['result_u64'] == receipt['core_u32'] == len(image)
                and receipt['abi_status'] == 0 and receipt['status'] == 'returned'
                and request['image_sha256'] == pin(image)['sha256']
                and all(receipt[key] == value for key, value in stdout.items()),
                'actual prefix/request/stdout/receipt binding changed')
    require((SOURCE / PLAN['new_source_relative']).read_bytes()
            == (ROOT / 'actual-inputs/B3.input.bin').read_bytes(), 'actual B3 source binding differs')
    return {'actual_inputs': len(manifest['files']), 'actual_B3_M3_output_prefixes_equal': True,
            'source_tree': PLAN['source']['tree'], 'matching_current_new_cold': False}


def original_functions(modules):
    expected = json.loads((ROOT / 'ORIGINAL-FUNCTIONS.json').read_bytes())
    by_name = {module.__name__: module for module in modules}
    observed = {}
    for key, row in expected.items():
        module = by_name[row['module']]
        require(Path(module.__file__).resolve() == SOURCE / (row['module'].replace('.', '/') + '.py'),
                'original callable came from a different module path')
        raw = inspect.getsource(getattr(module, row['name'])).encode()
        require(raw == row['text'].encode(), 'retained callable body differs: ' + key)
        observed[key] = pin(raw)
    return observed


def owner_return(receipt_path, returned):
    raw = Path(receipt_path).read_bytes()
    expected = json.loads(raw)
    expected.update(supervisor_returncode=returned.get('supervisor_returncode'),
                    receipt_sha256=hashlib.sha256(raw).hexdigest())
    if expected['supervisor_returncode'] != 0 and expected['status'] == 'OWNED_PROCESS_COMPLETED':
        expected['status'] = 'OWNER_EXIT_MISMATCH_HOLD'
    require(returned == expected, 'actual owner receipt plus wrapper fields differ')


def complete_owner(returned, seconds):
    require(returned['status'] == 'OWNED_PROCESS_COMPLETED' and returned['returncode'] == 0
            and returned['supervisor_returncode'] == 0 and returned['qualification_seconds'] == seconds
            and returned['cleanup_seconds'] == 3 and returned['timed_out'] is False
            and returned['exit_observed_before_deadline'] is True
            and returned['cleanup']['complete'] is True and returned['cleanup']['observed_echild'] is True,
            'qualification or complete descendant cleanup did not pass')


class GateJournal:
    """Observe each retained call once; do not replace VM, arguments or results.

    A killed child can leave START only. Missing completion never passes.
    Immutable reference bytes are captured directly from original dataclass fields.
    """
    def __init__(self, qualifier, cli, program):
        self.qualifier, self.cli, self.program = qualifier, cli, program
        self.calls, self.stack, self.originals = [], [], []
        self.counts = {key: 0 for key in ('reference', 'compile', 'invoke', 'tool', 'executable', 'mutation')}

    def event(self, value):
        raw = (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode()
        with (OUT / 'CALLS.jsonl').open('ab') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

    def __enter__(self):
        (OUT / 'calls').mkdir()
        for module, name, kind in ((self.program, 'execute_program', 'reference'),
                (self.qualifier, 'compile_stage', 'compile'), (self.qualifier, 'invoke', 'invoke'),
                (self.qualifier, 'observe_native_tool', 'tool'),
                (self.qualifier, 'mutate_compiler', 'mutation'), (self.cli, 'execute', 'executable')):
            original = getattr(module, name)
            self.originals.append((module, name, original))
            @functools.wraps(original)
            def observed(*args, _kind=kind, _original=original, **kwargs):
                return self.call(_kind, _original, args, kwargs)
            setattr(module, name, observed)
        return self

    def __exit__(self, *exception):
        for module, name, original in reversed(self.originals):
            setattr(module, name, original)
        dump(OUT / 'CALL-INDEX.json', {'calls': self.calls, 'counts': self.counts,
            'all_original_bindings_restored': all(getattr(module, name) is original
                for module, name, original in self.originals), 'missing_results_synthesized': False})

    def call(self, kind, original, args, kwargs):
        index = len(self.calls)
        row = {'index': index, 'kind': kind, 'status': 'STARTED',
               'parent_index': self.stack[-1] if self.stack else None,
               'started_monotonic_ns': time.monotonic_ns()}
        self.calls.append(row)
        self.counts[kind] += 1
        folder = OUT / 'calls' / ('%03d-%s' % (index, kind))
        folder.mkdir()
        self.stack.append(index)
        try:
            if kind == 'reference':
                require(self.counts['compile'] == 0 and self.counts['invoke'] == 0,
                        'resource reference started after native compilation')
                require(len(args) == 3 and type(args[0]) is self.program.VerifiedProgram
                        and args[1] == 'reference_entry' and args[2] == [] and kwargs == {},
                        'original finite reference shape or default fuel differs')
                canonical = args[0].canonical_bytes
                require(type(canonical) is bytes, 'reference canonical bytes absent')
                write(folder / 'program.canonical.json', canonical)
                structured = args[0].structured_bytes
                if structured is not None:
                    require(type(structured) is bytes, 'reference structured bytes type differs')
                    write(folder / 'program.structured.json', structured)
                row.update(program_canonical=pin(canonical), function=args[1], arguments=[],
                           max_steps_default=1000000, explicit_max_steps_not_supplied=True)
            elif kind == 'mutation':
                require(len(args) == 1 and kwargs == {} and type(args[0]) is bytes
                        and args[0] == (ROOT / 'actual-inputs/B3.input.bin').read_bytes(),
                        'original mutation input differs from actual B3 source')
                row['input'] = pin(args[0])
            else:
                row.update(directory=str(args[0]), label=args[1])
                if kind in ('compile', 'invoke', 'executable'):
                    require(len(args) == 4 and type(args[3]) is bytes, 'original call shape changed')
                    row.update(image_path=str(args[2]), image=identity(Path(args[2])), source=pin(args[3]),
                               options={key: value.hex() if isinstance(value, bytes) else value
                                        for key, value in kwargs.items()})
                    if kind == 'compile':
                        require(self.counts['reference'] == 8
                                and all(item['status'] == 'RETURNED' for item in self.calls
                                        if item['kind'] == 'reference'),
                                'all eight references must return before first compile')
                else:
                    require(kind == 'tool' and len(args) == 4 and args[2] == 'ld' and kwargs == {},
                            'unexpected native tool call')
                    row.update(tool=args[2], arguments=[str(value) for value in args[3]])
            dump(folder / 'BEFORE.json', row)
            self.event(dict(event='start', **row))
            returned = original(*args, **kwargs)
            if kind == 'reference':
                dump(folder / 'RETURNED.json', returned)
                row.update(returned_status=returned.get('status'), values=returned.get('values'),
                           resources=returned.get('resources'))
            elif kind == 'mutation':
                require(type(returned) is bytes and returned == (ROOT / 'actual-inputs/M3.input.bin').read_bytes(),
                        'original mutation output differs from actual M3 source')
                write(folder / 'returned.hepta', returned)
                row['output'] = pin(returned)
            elif kind in ('invoke', 'executable'):
                receipt, output = returned
                dump(folder / 'RETURNED-RECEIPT.json', receipt)
                row.update(returned_status=receipt.get('status'), actual_output=pin(output))
            elif kind == 'compile':
                path, receipt = returned
                dump(folder / 'RETURNED-RECEIPT.json', receipt)
                row.update(produced_path=str(path), produced=identity(path))
            else:
                dump(folder / 'RETURNED.json', returned)
            row['status'] = 'RETURNED'
            return returned
        except BaseException as error:
            row.update(status='EXCEPTION', error_type=type(error).__name__, error=str(error),
                       traceback=traceback.format_exc())
            if isinstance(error, subprocess.TimeoutExpired):
                for label, raw in (('stdout', error.stdout), ('stderr', error.stderr)):
                    if raw is not None:
                        require(type(raw) is bytes, 'partial subprocess wire has unexpected type')
                        write(folder / (label + '.partial.bin'), raw)
            raise
        finally:
            row['finished_monotonic_ns'] = time.monotonic_ns()
            dump(folder / 'AFTER.json', row)
            self.event(dict(event='stop', **row))
            require(self.stack.pop() == index, 'call observation stack differs')


def frame_inventory(required_complete):
    """Validate real frame bytes; partial normal/failure artifacts remain intact."""
    rows = []
    for directory in sorted(DATA.glob('*.output.bin.full-frames')):
        label = directory.name[:-len('.output.bin.full-frames')]
        request = json.loads((DATA / (label + '.request.json')).read_bytes())
        row = {'label': label, 'files': {}, 'complete_actual_six_frames': False,
               'missing_frames_synthesized': False}
        metadata = {}
        for phase in ('before', 'after'):
            file = directory / (phase + '.json')
            if file.exists():
                value = json.loads(file.read_bytes())
                require(value['schema'] == 'hepta.selfhost-seed-loader-actual-frames.v1'
                        and value['phase'] == phase and value['request'] == request,
                        'actual full-frame metadata differs from its original request')
                metadata[phase] = value
                row['files'][file.name] = identity(file)
            for region in ('source', 'output', 'workspace'):
                file = directory / (region + '.' + phase + '.bin')
                if file.exists():
                    raw, mode, _ = read_regular(file)
                    require(phase in metadata and metadata[phase]['frames'][region]
                            == {'bytes': len(raw), 'sha256': pin(raw)['sha256']},
                            'actual complete region differs from its frame metadata')
                    row['files'][file.name] = pin(raw, mode)
        if len(row['files']) == 8:
            first, last = metadata['before'], metadata['after']
            receipt = json.loads((DATA / (label + '.receipt.json')).read_bytes())
            stdout = json.loads((DATA / (label + '.stdout.log')).read_bytes())
            source = Path(request['source']).read_bytes()
            output = Path(request['output']).read_bytes()
            require(first['child_pid'] == last['child_pid'] and first['result_u64'] is None
                    and first['native_elapsed_ns'] is None
                    and last['result_u64'] == receipt['result_u64']
                    and last['native_elapsed_ns'] == receipt['native_elapsed_ns'],
                    'actual child/return/elapsed differs')
            extra = {'case', 'input_sha256', 'input_bytes', 'artifact_sha256', 'format',
                     'runner_sha256', 'wall_elapsed_ns'}
            if 'produced_image' in receipt:
                extra.update(('produced_image', 'produced_bytes', 'produced_sha256'))
            if request.get('observe_trap_writes', False):
                extra.add('shared_output_observation')
            require(set(receipt) == set(stdout) | extra
                    and all(receipt[key] == value for key, value in stdout.items())
                    and (DATA / (label + '.stderr.log')).read_bytes() == b'',
                    'actual child stdout/receipt/stderr differ')
            require((directory / 'source.before.bin').read_bytes() == source
                    and (directory / 'source.after.bin').read_bytes() == source
                    and (directory / 'output.after.bin').read_bytes() == output,
                    'actual frame differs from actual original source/output file')
            initial = (bytes.fromhex(request['output_initial_hex']) if 'output_initial_hex' in request
                       else bytes([0xa5]) * request['capacity'])
            workspace_initial = bytes([request.get('workspace_fill', 0)]) * request['workspace_size']
            require((directory / 'output.before.bin').read_bytes() == initial
                    and (directory / 'workspace.before.bin').read_bytes() == workspace_initial,
                    'actual pre-call output/workspace initialization differs')
            require(receipt['limits']['cpu_seconds'] == 10
                    and receipt['limits']['output_capacity'] == request['capacity']
                    and receipt['limits']['workspace_bytes'] == request['workspace_size']
                    and max(request['capacity'], request['workspace_size'], len(source)) <= CAPACITY,
                    'actual original CPU or extent limits differ')
            if receipt.get('produced_image') is not None:
                image = Path(receipt['produced_image']).read_bytes()
                require(image == output[:receipt['produced_bytes']]
                        and len(image) == receipt['core_u32'] == receipt['result_u64']
                        and pin(image)['sha256'] == receipt['produced_sha256'], 'actual image prefix differs')
                row['actual_image_prefix'] = pin(image)
            row.update(complete_actual_six_frames=True, child_pid=first['child_pid'])
        rows.append(row)
    result = {'rows': rows, 'count': len(rows), 'complete_count': sum(row['complete_actual_six_frames'] for row in rows),
              'missing_after_frames_synthesized': False}
    dump(OUT / 'ACTUAL-FRAMES.json', result)
    if required_complete:
        require([row['label'] for row in rows] == sorted(PLAN['expected']['invoke_labels'])
                and result['complete_count'] == 32, '32 complete actual six-frame witnesses required')
    return result


def raw_inventory():
    rows = {}
    for folder, directories, files in os.walk(OUT, followlinks=False):
        for name in directories:
            require(stat.S_ISDIR((Path(folder) / name).lstat().st_mode), 'evidence directory symlink')
        for name in sorted(files):
            path = Path(folder) / name
            require(path.name != 'RAW-INVENTORY.json', 'unique final raw inventory required')
            rows[path.relative_to(OUT).as_posix()] = identity(path)
    dump(OUT / 'RAW-INVENTORY.json', {'files': rows, 'logical_bytes': sum(row['bytes'] for row in rows.values()),
        'mode_authority': 'actual lstat and held descriptor, not ZIP wrapper',
        'this_self_manifest_is_external_to_its_own_file_inventory': True,
        'cleanup_or_missing_frames_do_not_gain_success_from_inventory': True})
    return {'files': len(rows), 'logical_bytes': sum(row['bytes'] for row in rows.values())}
