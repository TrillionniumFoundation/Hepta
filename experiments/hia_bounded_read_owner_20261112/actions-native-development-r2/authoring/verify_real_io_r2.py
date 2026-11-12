"""Exercise the actual two controller IO implementations on real filesystem nodes.

This file does not import Hepta, invoke a compiler, start a guardian, or run any
bounded-read product case.  The original failed helper is a retained control.
"""
from __future__ import annotations
import ast
import errno
from hashlib import sha1, sha256
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time
import traceback

ROOT = Path(__file__).absolute().parent.parent
OLD = ROOT.parent / 'bounded-read-actions-r1'
OUT = ROOT / 'evidence' / 'real-io-controls-r2'
NAMES = ('require', 'wire', 'identity', '_directory_identity', '_checked_parent',
         '_read_extent', '_create_bytes', '_create_directory', 'read', 'create',
         'save', 'clean_environment')


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def persist(path, value):
    with path.open('xb') as stream:
        stream.write(wire(value))
        stream.flush()
        os.fsync(stream.fileno())


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def info(path):
    value = path.lstat()
    return {'path': str(path), 'dev': value.st_dev, 'ino': value.st_ino,
            'mode': value.st_mode, 'uid': value.st_uid, 'gid': value.st_gid,
            'nlink': value.st_nlink, 'bytes': value.st_size,
            'mtime_ns': value.st_mtime_ns, 'ctime_ns': value.st_ctime_ns}


def fd_count():
    return len(os.listdir('/proc/self/fd'))


def fail_call(function, types, fragment=None, error_number=None):
    try:
        function()
    except BaseException as error:
        assert isinstance(error, types), (type(error).__name__, str(error))
        if fragment is not None:
            assert fragment in str(error), str(error)
        if error_number is not None:
            assert error.errno in error_number, error.errno
        return {'exception_class': type(error).__name__, 'message': str(error),
                'errno': getattr(error, 'errno', None),
                'traceback': ''.join(traceback.format_exception(error))}
    raise AssertionError('expected refusal did not occur')


OUT.mkdir(mode=0o700)
fixtures = OUT / 'fixtures'
fixtures.mkdir(mode=0o700)
source_paths = [OLD / 'reference/A72-controller.py', OLD / 'reference/A72-diagnostics.py',
                OLD / 'authoring/controller_io.inc', ROOT / 'authoring/controller_io.inc',
                OLD / 'control/controller.py', OLD / 'control/diagnostics.py',
                ROOT / 'control/controller.py', ROOT / 'control/diagnostics.py']
source_before = {str(path): pin(path.read_bytes()) for path in source_paths}
reference = {node.name: node for node in ast.parse(source_paths[0].read_bytes()).body
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
ast_rows = []
for path in source_paths[1:]:
    nodes = {node.name: node for node in ast.parse(path.read_bytes()).body
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for name in NAMES:
        if name not in nodes:
            # The historical diagnostics has only the read-side subset.  It is
            # not the original source of the twelve-function copied fragment.
            assert path == OLD / 'reference/A72-diagnostics.py'
            continue
        original, observed = reference[name], nodes[name]
        row = {'path': str(path), 'function': name,
               'expected_decorators': [ast.dump(x) for x in original.decorator_list],
               'observed_decorators': [ast.dump(x) for x in observed.decorator_list],
               'function_body_equal': ast.dump(ast.Module(body=original.body, type_ignores=[]))
                    == ast.dump(ast.Module(body=observed.body, type_ignores=[])),
               'complete_function_AST_equal': ast.dump(original) == ast.dump(observed)}
        is_failed_copy = path in (OLD / 'authoring/controller_io.inc',
                                 OLD / 'control/controller.py', OLD / 'control/diagnostics.py')
        expected_equal = not (is_failed_copy and name == '_checked_parent')
        assert row['function_body_equal'], row
        assert row['complete_function_AST_equal'] is expected_equal, row
        ast_rows.append(row)
assert (ROOT / 'authoring/controller_io.inc').read_bytes() == (
    OLD / 'authoring/controller_io.inc').read_bytes().replace(
        b'def _checked_parent(path):', b'@contextmanager\ndef _checked_parent(path):', 1)
persist(OUT / 'full-function-decorator-audit.json', {
    'schema': 'hia.bounded-read-controller-full-function-audit.v1',
    'function_names': list(NAMES), 'rows': ast_rows,
    'single_runtime_repair': '@contextmanager on _checked_parent',
    'earlier_body_only_review_did_not_prove_decorator_preservation': True})

rows = []


def run_case(label, method):
    before = fd_count()
    started = time.monotonic_ns()
    result = {'id': label, 'status': 'HOLD', 'fd_before': before}
    try:
        result['observations'] = method()
        result['fd_after'] = fd_count()
        assert result['fd_after'] == before, result
        result['status'] = 'PASS'
    except BaseException as error:
        result['error'] = {'class': type(error).__name__, 'message': str(error),
                           'traceback': ''.join(traceback.format_exception(error))}
        result['fd_after'] = fd_count()
    result['elapsed_ns'] = time.monotonic_ns() - started
    persist(OUT / (label + '.json'), result)
    rows.append(result)


for module_name in ('controller', 'diagnostics'):
    module = load(ROOT / 'control' / (module_name + '.py'), 'fixed_' + module_name)
    old_module = load(OLD / 'control' / (module_name + '.py'), 'old_' + module_name)
    base = fixtures / module_name
    base.mkdir(mode=0o700)
    regular = base / 'regular.bin'
    content = b'owned original\x00\xff\n'
    regular.write_bytes(content)
    regular.chmod(0o400)
    empty = base / 'empty.bin'
    empty.write_bytes(b'')
    empty.chmod(0o400)

    def case(name, function):
        run_case(module_name + '--' + name, function)

    case('old-original-typeerror', lambda: fail_call(
        lambda: old_module.read(regular), TypeError, 'context manager protocol'))

    def positive():
        before = info(regular)
        raw, record = module.read(regular, len(content))
        assert raw == content
        assert record['bytes'] == len(content)
        assert record['sha256'] == sha256(content).hexdigest()
        assert record['identity'] == list(module.identity(regular.lstat()))
        assert before == info(regular)
        return {'input': before, 'record': record, 'raw_sha256': sha256(raw).hexdigest()}
    case('owned-real-read', positive)

    def zero():
        raw, record = module.read(empty, 0)
        assert raw == b'' and record['bytes'] == 0
        return record
    case('zero-byte-read', zero)

    def create():
        path = base / 'created.bin'
        record = module.create(path, content)
        assert path.read_bytes() == content
        assert stat.S_IMODE(path.lstat().st_mode) == 0o400
        return record
    case('create-readback', create)
    case('exclusive-existing-refusal', lambda: fail_call(
        lambda: module.create(base / 'created.bin', b'replacement'),
        FileExistsError, error_number=(errno.EEXIST,)))

    def save():
        path = base / 'saved.json'
        value = {'unicode': '\u96ea', 'count': 3}
        record = module.save(path, value)
        assert json.loads(path.read_bytes()) == value
        return record
    case('save-json-readback', save)

    def directory():
        path = base / 'private-directory'
        module._create_directory(path)
        assert stat.S_IMODE(path.lstat().st_mode) == 0o700
        return info(path)
    case('private-directory', directory)

    leaf_link = base / 'leaf-symlink'
    leaf_link.symlink_to(regular)
    case('leaf-symlink-refusal', lambda: fail_call(
        lambda: module.read(leaf_link), OSError, error_number=(errno.ELOOP,)))
    parent_link = base / 'parent-symlink'
    parent_link.symlink_to(base, target_is_directory=True)
    case('parent-symlink-refusal', lambda: fail_call(
        lambda: module.read(parent_link / regular.name), OSError,
        error_number=(errno.ENOTDIR, errno.ELOOP)))

    hard = base / 'hard-original'
    hard.write_bytes(content)
    hard.chmod(0o400)
    hard_alias = base / 'hard-alias'
    os.link(hard, hard_alias)
    case('hardlink-refusal', lambda: fail_call(
        lambda: module.read(hard), RuntimeError, 'owned single-link input required'))

    fifo = base / 'fifo'
    os.mkfifo(fifo, 0o600)
    case('fifo-nonblocking-refusal', lambda: fail_call(
        lambda: module.read(fifo), RuntimeError, 'regular input required'))
    case('directory-as-file-refusal', lambda: fail_call(
        lambda: module.read(base), RuntimeError, 'regular input required'))
    case('extent-bound-refusal', lambda: fail_call(
        lambda: module.read(regular, len(content) - 1), RuntimeError, 'bounded original input required'))
    case('negative-bound-refusal', lambda: fail_call(
        lambda: module.read(regular, -1), RuntimeError, 'bounded original input required'))
    case('relative-path-refusal', lambda: fail_call(
        lambda: module.read(Path('relative.bin')), RuntimeError, 'noncanonical controlled IO path'))
    case('dotdot-path-refusal', lambda: fail_call(
        lambda: module.read(base / '..' / module_name / regular.name),
        RuntimeError, 'noncanonical controlled IO path'))

    nonowned = Path('/etc/hostname')
    external = info(nonowned)
    assert external['uid'] != os.geteuid(), external

    def unowned():
        result = fail_call(lambda: module.read(nonowned), RuntimeError,
                           'owned single-link input required')
        assert info(nonowned) == external
        return {'lstat_only_external_fixture': external, 'contents_not_read': True, **result}
    case('real-nonowned-refusal', unowned)

    def unexpected_system_owner():
        assert external['uid'] not in (0, os.geteuid()), external
        result = fail_call(lambda: module.read(nonowned, system_binary=True), RuntimeError,
                           'runner tool is writable or has unexpected ownership')
        assert info(nonowned) == external
        return {'lstat_only_external_fixture': external, 'contents_not_read': True, **result}
    case('real-system-unexpected-owner-refusal', unexpected_system_owner)

    system_file = base / 'system-fixture'
    system_file.write_bytes(content)
    system_file.chmod(0o555)

    def system_ok():
        raw, record = module.read(system_file, system_binary=True)
        assert raw == content
        return record
    case('system-immutable-read', system_ok)

    writable_system = base / 'writable-system-fixture'
    writable_system.write_bytes(content)
    writable_system.chmod(0o664)
    case('system-mutable-refusal', lambda: fail_call(
        lambda: module.read(writable_system, system_binary=True), RuntimeError,
        'runner tool is writable or has unexpected ownership'))

    def changed_parent():
        parent = base / 'change-parent'
        held = base / 'changed-original-parent'
        parent.mkdir(mode=0o700)
        (parent / 'input').write_bytes(content)
        expected = info(parent)
        def operation():
            with module._checked_parent(parent / 'input') as (_, _, stable):
                parent.rename(held)
                parent.mkdir(mode=0o700)
                stable()
        refusal = fail_call(operation, RuntimeError, 'controlled IO directory chain changed')
        assert held.stat().st_ino == expected['ino']
        assert parent.stat().st_ino != expected['ino']
        return {'original_parent': expected, 'held_original_after': info(held),
                'replacement_parent': info(parent), **refusal}
    case('actual-parent-replacement-refusal', changed_parent)

    def body_exception():
        sentinel = RuntimeError('original controlled body sentinel')
        try:
            with module._checked_parent(regular):
                raise sentinel
        except RuntimeError as caught:
            assert caught is sentinel
            return {'same_exception_object': True, 'message': str(caught)}
        raise AssertionError('original body exception disappeared')
    case('context-body-exception-cleanup', body_exception)

    def short_extent():
        descriptor = os.open(regular, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            return fail_call(lambda: module._read_extent(descriptor, len(content) + 1),
                             RuntimeError, 'original ended before its declared extent')
        finally:
            os.close(descriptor)
    case('actual-short-extent-refusal', short_extent)

source_after = {str(path): pin(path.read_bytes()) for path in source_paths}
assert source_before == source_after
assert len(rows) == 46, len(rows)
report = {'schema': 'hia.bounded-read-controller-real-io-controls.v1',
          'status': 'PASS' if all(row['status'] == 'PASS' for row in rows) else 'HOLD',
          'python': sys.version, 'euid': os.geteuid(), 'scope': 'actual controller and diagnostics filesystem IO only',
          'expected_cases': 46, 'executed_cases': len(rows),
          'expected_ids': [row['id'] for row in rows], 'executed_ids': [row['id'] for row in rows],
          'PASS': sum(row['status'] == 'PASS' for row in rows),
          'HOLD': sum(row['status'] != 'PASS' for row in rows),
          'cases': [{'id': row['id'], 'status': row['status'],
                     'original': pin((OUT / (row['id'] + '.json')).read_bytes())} for row in rows],
          'source_before': source_before, 'source_after': source_after,
          'source_stable': source_before == source_after,
          'product_imported': False, 'native_compilation_or_execution': False,
          'original_product_cases_executed': 0, 'guardian_started': False,
          'failed_remote_run_replayed': False,
          'historical_runtime_failure_control': 'two actual old-module reads must raise original TypeError',
          'external_fixture_boundary': '/etc/hostname lstat then refusal before data reading; never written',
          'full_source_Actions_preparation_or_fixed_Python314_executed': False}
persist(OUT / 'report.json', report)
print(json.dumps({key: report[key] for key in ('status', 'expected_cases', 'executed_cases', 'PASS', 'HOLD')}))
raise SystemExit(0 if report['status'] == 'PASS' else 1)
