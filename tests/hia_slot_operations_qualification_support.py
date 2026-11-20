"""Pure-data admission and owned supervision for complete Slot observations.

This module does not import product code. All declared finite inputs remain
immutable. In particular, numeric type checks reject bools and JSON floats.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import time

ORACLE_PREFIX = 'tests/fixtures/hia_slot_operations_original_r1'
DERIVED_FILE = 'tests/fixtures/hia_slot_operations_derived_r1/inputs.json'
ORACLE_FREEZE_SHA256 = 'b8e6a95992609dabf8ea87fe7974a123a9a5e5260c00b231b1f070eea36e0953'
ORACLE_SHA256 = 'b915a9636794e6ad80af094d64664e753fe149c8b70dc25f854ce70cf14ea444'
CASES_SHA256 = 'e468605ae03d4b3d06c2d526767231ca29c1d9fe3bb9fa2de73d9ef34a1b3a68'
DERIVED_SHA256 = '5f86f5c3f6af81694cbb24a597c27880b5cc5b27cfef5dcc647bdf6f4ee86cbf'
NAMES = ('__init__', '_execute', '_call', 'snapshot', 'validate_u64', 'conditional',
         '_begin', 'admit_evaluation', 'admit_net_benefit', 'adopt', 'rollback',
         '_lease_value', 'acquire', 'lease', 'release')
ORIGINAL_SECONDS, CANDIDATE_SECONDS, TOTAL_SECONDS, CLEANUP_SECONDS = 180, 1800, 1800, 5
JSON_KW = dict(ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)


def canonical(value):
    return json.dumps(value, **JSON_KW).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    Path(path).write_bytes(canonical(value) + b'\n')


def unique_pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('duplicate JSON key: ' + name)
        result[name] = value
    return result


def read_json(path):
    return json.loads(regular_bytes(path), object_pairs_hook=unique_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def regular_bytes(path):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or path.is_symlink():
        raise ValueError('expected regular immutable input: ' + str(path))
    raw = path.read_bytes()
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError('input changed while reading: ' + str(path))
    if len(raw) != after.st_size:
        raise ValueError('short source read')
    return raw


def pin(path):
    raw = regular_bytes(path)
    return {'bytes': len(raw), 'sha256': sha(raw)}


def checked_int(value, expected=None):
    if type(value) is not int or (expected is not None and value != expected):
        raise ValueError('integer identity differs: ' + repr(value))
    return value


def admit_originals(oracle_root):
    oracle_root = Path(oracle_root)
    raw = regular_bytes(oracle_root / 'source-freeze.json')
    if sha(raw) != ORACLE_FREEZE_SHA256:
        raise ValueError('original 36-file freeze differs')
    manifest = json.loads(raw, object_pairs_hook=unique_pairs)
    if len(manifest['files']) != 36:
        raise ValueError('complete original 36-file inventory differs')
    before = {}
    for relative, expected in manifest['files'].items():
        if Path(relative).is_absolute() or '..' in Path(relative).parts:
            raise ValueError('unsafe source relative path')
        actual = pin(oracle_root / relative)
        if canonical(actual) != canonical(expected):
            raise ValueError('original input changed: ' + relative)
        before[relative] = actual
    if before['observe_originals.py']['sha256'] != ORACLE_SHA256:
        raise ValueError('original observer differs')
    return before


def admit_cases(oracle_root, derived_path, group):
    admit_originals(oracle_root)
    if group == 'original248':
        path, digest, count = Path(oracle_root) / 'cases.json', CASES_SHA256, 248
    elif group == 'derived7574':
        path, digest, count = Path(derived_path), DERIVED_SHA256, 7574
    else:
        raise ValueError('undeclared complete Slot observation group')
    raw = regular_bytes(path)
    if sha(raw) != digest:
        raise ValueError('independent finite input bytes differ')
    manifest = json.loads(raw, object_pairs_hook=unique_pairs)
    checked_int(manifest['finite_case_count'], count)
    cases = manifest['cases']
    if type(cases) is not list or len(cases) != count:
        raise ValueError('complete finite case count differs')
    identities = [case['id'] for case in cases]
    if any(type(value) is not str for value in identities) or len(set(identities)) != count:
        raise ValueError('invalid/duplicate finite case identities')
    if group == 'derived7574' and (
            manifest['candidate_observations_used'] is not False
            or manifest['original_248_unchanged'] is not True):
        raise ValueError('derived inputs are not independent original-trace inputs')
    return cases, {'path': str(path.resolve()), 'bytes': len(raw), 'sha256': digest}


def product_snapshot(root, paths):
    root = Path(root)
    result = {}
    for relative in paths:
        if Path(relative).is_absolute() or '..' in Path(relative).parts:
            raise ValueError('unsafe product source path')
        result[relative] = pin(root / relative)
    return result


def admit_product(root, freeze_path, freeze_sha256):
    raw = regular_bytes(freeze_path)
    if sha(raw) != freeze_sha256:
        raise ValueError('supervisor product freeze differs')
    value = json.loads(raw, object_pairs_hook=unique_pairs)
    if value.get('schema') != 'hepta.slot-operations.qualification-source-freeze.v1':
        raise ValueError('unknown product source freeze schema')
    files = value['files']
    if type(files) is not dict or not files:
        raise ValueError('empty product source freeze')
    actual = product_snapshot(root, files)
    if canonical(actual) != canonical(files):
        raise ValueError('product source differs from supervising freeze')
    return actual


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if not key.startswith(('HEPTA_HIA', 'PYTHON'))}


def group_members(group):
    found = []
    for directory in Path('/proc').iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            raw = (directory / 'stat').read_text()
            parts = raw[raw.rfind(')') + 2:].split()
            if int(parts[2]) == group and int(parts[3]) == group:
                found.append({'pid': int(directory.name), 'pgid': int(parts[2]),
                              'sid': int(parts[3]), 'state': parts[0],
                              'start_ticks': int(parts[19])})
        except (FileNotFoundError, ProcessLookupError):
            continue
    return sorted(found, key=lambda row: row['pid'])


def stop_owned(process):
    start = time.monotonic()
    before, signals = group_members(process.pid), []
    if before:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            signals.append('SIGTERM')
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=max(.001, CLEANUP_SECONDS / 2 - (time.monotonic() - start)))
    except subprocess.TimeoutExpired:
        pass
    middle = group_members(process.pid)
    if middle:
        try:
            os.killpg(process.pid, signal.SIGKILL)
            signals.append('SIGKILL')
        except ProcessLookupError:
            pass
    reaped = True
    try:
        process.wait(timeout=max(.001, CLEANUP_SECONDS - (time.monotonic() - start)))
    except subprocess.TimeoutExpired:
        reaped = False
    return {'before': before, 'middle': middle, 'after': group_members(process.pid),
            'signals': signals, 'reaped': reaped,
            'cleanup_elapsed_seconds': time.monotonic() - start}


def run_owned(command, *, cwd, directory, timeout_seconds, environment=None, stdin=None, deadline=None):
    checked_int(timeout_seconds)
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    environment = clean_environment() if environment is None else environment
    start, process, timed_out, interruption = time.monotonic(), None, False, None
    stdout_path, stderr_path = directory / 'stdout.log', directory / 'stderr.log'
    spec = {'argv': list(map(str, command)), 'cwd': str(Path(cwd).resolve()),
            'timeout_seconds': timeout_seconds, 'cleanup_seconds': CLEANUP_SECONDS,
            'new_session': True, 'parent_pid': os.getpid(),
            'environment': {key: value for key, value in environment.items()
                            if key in ('PATH', 'LD_LIBRARY_PATH', 'CLANG', 'HEPTA_CLANG')
                            or key.startswith(('HEPTA_HIA', 'PYTHON'))}}
    write_json(directory / 'command.json', spec)
    cleanup = None
    try:
        with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
            process = subprocess.Popen(spec['argv'], cwd=cwd, env=environment,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                spec.update({'pid': process.pid, 'pgid': process.pid,
                             'owned_initial_members': group_members(process.pid)})
                write_json(directory / 'command.json', spec)
                effective = timeout_seconds if deadline is None else min(timeout_seconds, max(.001, deadline - time.monotonic()))
                spec['effective_timeout_seconds'] = effective
                write_json(directory / 'command.json', spec)
                process.communicate(stdin, timeout=effective)
            except subprocess.TimeoutExpired:
                timed_out = True
            except BaseException as error:
                interruption = {'type': type(error).__module__ + '.' + type(error).__qualname__,
                                'message': str(error)}
                raise
            finally:
                cleanup = stop_owned(process)
    finally:
        result = {'command': spec, 'pid': None if process is None else process.pid,
                  'exit_code': None if process is None else process.returncode,
                  'timed_out': timed_out, 'interruption': interruption,
                  'elapsed_seconds': time.monotonic() - start, 'owned_cleanup': cleanup,
                  'stdout': pin(stdout_path) if stdout_path.exists() else None,
                  'stderr': pin(stderr_path) if stderr_path.exists() else None}
        write_json(directory / 'result.json', result)
    return result


def successful_exit(result):
    cleanup = result.get('owned_cleanup')
    return (type(result.get('exit_code')) is int and result['exit_code'] == 0
            and result.get('timed_out') is False and result.get('interruption') is None
            and type(cleanup) is dict and cleanup.get('reaped') is True
            and cleanup.get('after') == [] and cleanup.get('signals') == [])
