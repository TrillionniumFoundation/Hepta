"""Opt-in evidence for the original artifact-publication tests.

This module changes no native policy, timeout, input or process termination
decision.  The test runner installs the observer explicitly.  Ordinary unittest
execution still uses TemporaryDirectory and Popen directly.  Offered stdin is
retained before launch; it is not a claim that a failed child consumed it.
"""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import stat
import subprocess
import tempfile
import time
import traceback


OPERATIONS = frozenset(('publish', 'verify', 'withdraw', 'store-put', 'store-get', 'store-hash'))
_REAL_RUN = subprocess.run
_REAL_POPEN = subprocess.Popen
# Evidence durability belongs to this explicit observer.  The original tests
# poison the shared os.fsync attribute to forbid hosted product publication;
# that poison must remain effective for the product, while observer records
# still use the genuine primitive captured before the tests are installed.
_EVIDENCE_FSYNC = os.fsync
_ACTIVE = None


def identity(value):
    return {name: getattr(value, 'st_' + name) for name in
            ('dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtime_ns', 'ctime_ns')}


@contextmanager
def parent_fd(path):
    """Hold and recheck every directory link; never traverse a symlink."""
    path = Path(path)
    if not path.is_absolute() or any(p in ('.', '..') for p in path.parts[1:]):
        raise ValueError('absolute ordinary path required')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fds = [os.open('/', flags)]
    links = []
    try:
        for part in path.parts[1:-1]:
            before = os.stat(part, dir_fd=fds[-1], follow_symlinks=False)
            child = os.open(part, flags, dir_fd=fds[-1])
            fds.append(child)
            observed = os.fstat(child)
            if (before.st_dev, before.st_ino, before.st_mode) != (observed.st_dev, observed.st_ino, observed.st_mode):
                raise ValueError('parent directory changed while opening')
            links.append((part, before.st_dev, before.st_ino, before.st_mode))
        yield fds[-1], path.name
        for index, (part, dev, ino, mode) in enumerate(links):
            linked = os.stat(part, dir_fd=fds[index], follow_symlinks=False)
            held = os.fstat(fds[index + 1])
            if any((s.st_dev, s.st_ino, s.st_mode) != (dev, ino, mode) for s in (linked, held)):
                raise ValueError('parent directory identity changed')
    finally:
        for fd in reversed(fds):
            os.close(fd)


def create_directory(path):
    path = Path(path)
    with parent_fd(path) as (fd, name):
        os.mkdir(name, 0o700, dir_fd=fd)
        value = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o700:
            raise ValueError('private evidence directory required')
    return path


def write_new(path, data):
    if type(data) is not bytes:
        raise TypeError('evidence bytes required')
    with parent_fd(path) as (fd, name):
        leaf = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        try:
            view = memoryview(data)
            while view:
                count = os.write(leaf, view)
                if count <= 0:
                    raise OSError('short evidence write')
                view = view[count:]
            _EVIDENCE_FSYNC(leaf)
            os.lseek(leaf, 0, os.SEEK_SET)
            digest = sha256()
            size = 0
            while chunk := os.read(leaf, 1 << 20):
                digest.update(chunk)
                size += len(chunk)
            if size != len(data) or digest.hexdigest() != sha256(data).hexdigest():
                raise ValueError('evidence write readback differs')
            observed = identity(os.fstat(leaf))
            if identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) != observed:
                raise ValueError('evidence name changed')
        finally:
            os.close(leaf)
        _EVIDENCE_FSYNC(fd)
    return {'path': str(path), 'bytes': len(data), 'sha256': sha256(data).hexdigest(), 'identity': observed}


def write_json(path, value):
    return write_new(path, (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode())


def read_file(path, maximum=None):
    with parent_fd(path) as (fd, name):
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or (maximum is not None and before.st_size > maximum):
            raise ValueError('bounded regular evidence input required: ' + str(path))
        leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        try:
            if identity(os.fstat(leaf)) != identity(before):
                raise ValueError('input changed while opening')
            chunks = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(leaf, min(1 << 20, remaining))
                if not chunk:
                    raise ValueError('short input read')
                chunks.append(chunk)
                remaining -= len(chunk)
            if identity(os.fstat(leaf)) != identity(before):
                raise ValueError('input changed while reading')
            if identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) != identity(before):
                raise ValueError('input name changed while reading')
        finally:
            os.close(leaf)
    return b''.join(chunks), identity(before)


@contextmanager
def _cold_evidence_input(path, maximum, expected_bytes=None):
    """Bound one immutable regular cold-evidence input by its actual size."""
    if type(maximum) is not int or maximum < 0:
        raise ValueError('nonnegative cold-evidence byte budget required')
    if expected_bytes is not None and (type(expected_bytes) is not int or expected_bytes < 0):
        raise ValueError('integer cold-evidence size required')
    with parent_fd(path) as (parent, name):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_size > maximum or
                (expected_bytes is not None and before.st_size != expected_bytes)):
            raise ValueError('cold evidence must be regular, single-link and within its byte budget: '
                             + str(path) + '; size=' + str(before.st_size)
                             + '; maximum=' + str(maximum))
        leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            if identity(os.fstat(leaf)) != identity(before):
                raise ValueError('cold evidence changed while opening')
            yield leaf, identity(before)
            if (identity(os.fstat(leaf)) != identity(before) or
                    identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity(before)):
                raise ValueError('cold evidence identity or name changed while reading')
        finally:
            os.close(leaf)


def observe_cold_evidence(path, maximum, *, expected_bytes=None, expected_sha256=None):
    """Read all actual bytes in fixed chunks, including an explicit EOF check."""
    with _cold_evidence_input(path, maximum, expected_bytes) as (leaf, before):
        digest = sha256()
        remaining = before['size']
        while remaining:
            chunk = os.read(leaf, min(1 << 20, remaining))
            if not chunk:
                raise ValueError('short cold evidence read')
            remaining -= len(chunk)
            digest.update(chunk)
        if os.read(leaf, 1):
            raise ValueError('cold evidence grew beyond its admitted size')
        actual = digest.hexdigest()
        if expected_sha256 is not None and actual != expected_sha256:
            raise ValueError('cold evidence SHA256 differs')
    return {'path': str(path), 'bytes': before['size'], 'sha256': actual, 'identity': before}


def copy_cold_evidence(source, destination, maximum, *, expected_bytes=None, expected_sha256=None):
    """Retain full bytes with bounded memory; failed partial output is preserved.

    This is evidence custody, not a product input/output limit. The source and
    new destination are held by descriptor, their complete byte hashes are
    joined, and every named link is rechecked before success can be returned.
    """
    with _cold_evidence_input(source, maximum, expected_bytes) as (incoming, before):
        with parent_fd(destination) as (parent, name):
            target = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
            try:
                os.fchmod(target, 0o600)
                digest = sha256()
                remaining = before['size']
                while remaining:
                    chunk = os.read(incoming, min(1 << 20, remaining))
                    if not chunk:
                        raise ValueError('short cold evidence copy')
                    remaining -= len(chunk)
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        count = os.write(target, view)
                        if count <= 0:
                            raise OSError('short cold evidence write')
                        view = view[count:]
                if os.read(incoming, 1):
                    raise ValueError('cold evidence grew beyond its admitted size')
                _EVIDENCE_FSYNC(target)
                copied = identity(os.fstat(target))
                actual = digest.hexdigest()
                if (copied['size'] != before['size'] or copied['nlink'] != 1 or
                        copied['uid'] != os.geteuid() or stat.S_IMODE(copied['mode']) != 0o600):
                    raise ValueError('cold evidence destination identity differs')
                os.lseek(target, 0, os.SEEK_SET)
                readback = sha256()
                remaining = copied['size']
                while remaining:
                    chunk = os.read(target, min(1 << 20, remaining))
                    if not chunk:
                        raise ValueError('short cold evidence readback')
                    remaining -= len(chunk)
                    readback.update(chunk)
                if (os.read(target, 1) or readback.hexdigest() != actual or
                        identity(os.fstat(target)) != copied or
                        identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != copied):
                    raise ValueError('cold evidence retained bytes or name differ')
                if expected_sha256 is not None and actual != expected_sha256:
                    raise ValueError('cold evidence SHA256 differs')
                _EVIDENCE_FSYNC(parent)
            finally:
                os.close(target)
    return {'source': str(source), 'original_identity': before,
            'retained': {'path': str(destination), 'bytes': before['size'],
                         'sha256': actual, 'identity': copied},
            'stream_copy': {'chunk_bytes': 1 << 20, 'maximum_bytes': maximum,
                            'expected_bytes': expected_bytes, 'expected_sha256': expected_sha256,
                            'complete_source_and_destination_readback': True}}


def process_identity(pid):
    """Linux PID identity only; no assertion of a full process-tree owner."""
    try:
        raw = Path('/proc/' + str(pid) + '/stat').read_bytes()
    except FileNotFoundError:
        return None
    fields = raw[raw.rindex(b')') + 2:].split()
    return {'pid': int(pid), 'ppid': int(fields[1]), 'pgrp': int(fields[2]),
            'session': int(fields[3]), 'starttime': int(fields[19]), 'state': fields[0].decode('ascii')}


def descendants(pid):
    table = {}
    for entry in Path('/proc').iterdir():
        if entry.name.isdecimal():
            try:
                observed = process_identity(int(entry.name))
            except (OSError, ValueError):
                continue
            if observed is not None:
                table[observed['pid']] = observed
    selected = []
    parents = {pid}
    while True:
        extra = [row for row in table.values() if row['ppid'] in parents and row['pid'] not in parents]
        if not extra:
            return selected
        selected.extend(extra)
        parents.update(row['pid'] for row in extra)


def child_usage():
    value = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {name: getattr(value, name) for name in
            ('ru_utime', 'ru_stime', 'ru_maxrss', 'ru_minflt', 'ru_majflt', 'ru_inblock', 'ru_oublock', 'ru_nvcsw', 'ru_nivcsw')}


def native_command(argv):
    return (isinstance(argv, (list, tuple)) and len(argv) >= 4 and
            all(isinstance(item, (str, os.PathLike)) for item in argv) and argv[-3] in OPERATIONS)


class _Call:
    def __init__(self, session, argv, wire, timeout, origin, kwargs):
        self.session = session
        self.index = len(session.calls)
        self.root = session.root / 'calls' / ('%05d' % self.index)
        self.test_id = session.test_id
        self.argv = None
        self.events = []
        self.flushed = 0
        self.process = None
        self.launch_attempted = False
        self.launch_completed = False
        self.launched_pid = None
        self.pid_identity = None
        self.pid_identity_error = None
        self.seen = {}
        self.returncode = None
        self.closed_observed = False
        self.record_errors = []
        self.origin = origin
        self.input = self.code = self.request = None
        self.root_created = self.request_written = self.preflight_complete = False
        self.preflight_stage = 'INITIALIZED'
        self.preflight_error = None
        # All fields used by summary/finish are initialized before the first
        # evidence operation.  A failed preflight is a real call attempt record,
        # not a launch, and must not erase the original unittest failure.
        session.calls.append(self)
        try:
            self.preflight_stage = 'DIRECTORY'
            create_directory(self.root)
            self.root_created = True
            self.preflight_stage = 'ARGUMENTS'
            self.argv = [os.fspath(v) for v in argv]
            if type(wire) is not bytes:
                raise TypeError('test native stdin must be exact bytes')
            self.preflight_stage = 'STDIN'
            self.input = write_new(self.root / 'stdin.offered.bin', wire)
            self.preflight_stage = 'EXECUTABLE_READ'
            executable = self.argv[-4]
            if executable.startswith('/proc/self/fd/'):
                source_fd = int(executable.rsplit('/', 1)[1])
                before = identity(os.fstat(source_fd))
                if not stat.S_ISREG(before['mode']) or before['size'] > 1 << 20:
                    raise ValueError('bounded sealed executable required')
                code = os.pread(source_fd, before['size'], 0)
                if len(code) != before['size'] or identity(os.fstat(source_fd)) != before:
                    raise ValueError('sealed executable changed')
            else:
                code, before = read_file(Path(executable).absolute(), 1 << 20)
            self.preflight_stage = 'EXECUTABLE_WRITE'
            self.code = write_new(self.root / 'executable.bin', code)
            self.request = {'schema': 'hepta.hia.publication-test-call.v1', 'ordinal': self.index,
                            'test_id': self.test_id, 'origin': origin, 'argv': self.argv,
                            'cwd': os.getcwd(), 'env': kwargs.get('env'), 'timeout': timeout,
                            'capture_output': kwargs.get('capture_output'),
                            'pass_fds': list(kwargs.get('pass_fds', ())),
                            'stdin': self.input, 'executable': self.code, 'executable_original_identity': before,
                            'stdin_scope': 'full bytes offered by the test; consumed byte count is not inferred',
                            'timeout_scope': 'unchanged original subprocess timeout, after evidence preflight'}
            self.preflight_stage = 'REQUEST_WRITE'
            write_json(self.root / 'request.json', self.request)
            self.request_written = self.preflight_complete = True
            self.preflight_stage = 'READY'
        except BaseException as exc:
            self.preflight_error = {'stage': self.preflight_stage, 'type': type(exc).__name__}
            try:
                self.preflight_error.update(message=str(exc), traceback=traceback.format_exc())
            except BaseException as rendering:
                self.preflight_error['rendering_error_type'] = type(rendering).__name__
            text = 'PREFLIGHT: ' + self.preflight_stage + ': ' + type(exc).__name__
            self.record_errors.append(text)
            session.errors.append('call %d %s' % (self.index, text))
            self.event('PREFLIGHT_EXCEPTION', failure=self.preflight_error)
            raise

    def event(self, kind, **values):
        # No filesystem I/O, payload hashing or /proc traversal occurs between
        # an original communicate timeout and the original caller's kill/wait.
        # These references are serialized only after the test's cleanups.
        row = {'kind': kind, 'monotonic_ns': time.monotonic_ns(), **values}
        self.events.append(row)

    def flush(self):
        while self.flushed < len(self.events):
            index = self.flushed
            row = dict(self.events[index])
            for name in ('stdout', 'stderr'):
                if name in row:
                    raw = row[name]
                    row[name] = None if raw is None else write_new(self.root / ('%03d-%s.bin' % (index, name)), raw)
            write_json(self.root / ('%03d-event.json' % index), row)
            self.events[index] = row
            self.flushed += 1

    def see_descendants(self):
        if self.process is not None:
            for row in descendants(self.process.pid):
                self.seen[(row['pid'], row['starttime'])] = row

    def summary(self):
        if self.process is not None:
            self.returncode = getattr(self.process, 'returncode', None)
            self.closed_observed = self.returncode is not None
        return {'ordinal': self.index, 'path': str(self.root), 'test_id': self.test_id,
                'request': str(self.root / 'request.json'), 'process': self.pid_identity,
                'launch_attempted': self.launch_attempted, 'launch_completed': self.launch_completed,
                'launched_pid': self.launched_pid, 'pid_identity_error': self.pid_identity_error,
                'descendants_seen': list(self.seen.values()), 'returncode': self.returncode,
                'direct_child_reaped_observed': self.closed_observed,
                'events': len(self.events), 'record_errors': self.record_errors,
                'preflight': {'stage': self.preflight_stage, 'complete': self.preflight_complete,
                              'root_created': self.root_created, 'request_written': self.request_written,
                              'error': self.preflight_error, 'stdin': self.input, 'executable': self.code,
                              'unwritten_request_data': None if self.request_written else self.request},
                'full_process_tree_cleanup_claimed': False}


def direct_child_custody_closed(row):
    """An absent identity cannot stand for a launch that never happened."""
    keys = {'launch_attempted', 'launch_completed', 'launched_pid', 'process',
            'pid_identity_error', 'returncode', 'direct_child_reaped_observed'}
    if not keys <= row.keys() or type(row['launch_attempted']) is not bool or type(row['launch_completed']) is not bool:
        return False
    if not row['launch_attempted']:
        return (row['launch_completed'] is False and row['launched_pid'] is None
                and row['process'] is None and row['pid_identity_error'] is None
                and row['returncode'] is None and row['direct_child_reaped_observed'] is False)
    observed = row['process']
    return (row['launch_completed'] is True and type(row['launched_pid']) is int and row['launched_pid'] > 0
            and type(observed) is dict and type(observed.get('pid')) is int
            and observed['pid'] == row['launched_pid'] and type(observed.get('starttime')) is int
            and observed['starttime'] >= 0 and row['pid_identity_error'] is None
            and type(row['returncode']) is int and row['direct_child_reaped_observed'] is True)


class _ObservedPopen(_REAL_POPEN):
    def __init__(self, call, *args, **kwargs):
        self._custody_call = call
        call.launch_attempted = True
        call.event('LAUNCH_BEGIN', usage=child_usage())
        try:
            super().__init__(*args, **kwargs)
        except BaseException as exc:
            # A constructor exception may follow creation of an OS child.
            # Record any exposed PID, without new termination/wait behavior.
            pid = getattr(self, 'pid', None)
            if type(pid) is int and pid > 0:
                call.process = self
                call.launched_pid = pid
            call.event('LAUNCH_EXCEPTION', exception_type=type(exc).__name__, exception=repr(exc))
            raise
        call.process = self
        call.launch_completed = True
        call.launched_pid = self.pid
        try:
            call.pid_identity = process_identity(self.pid)
        except BaseException as exc:
            text = type(exc).__name__ + ': ' + str(exc)
            call.pid_identity_error = text
            call.record_errors.append('PID_IDENTITY: ' + text)
            call.session.errors.append('call %d PID_IDENTITY: %s' % (call.index, text))
            call.event('PID_IDENTITY_EXCEPTION', exception_type=type(exc).__name__, exception=repr(exc),
                       launched_pid=call.launched_pid)
            raise
        if call.pid_identity is None:
            call.pid_identity_error = 'process_identity returned no identity after launch'
            call.record_errors.append('PID_IDENTITY: ' + call.pid_identity_error)
            call.session.errors.append('call %d PID_IDENTITY: %s' % (call.index, call.pid_identity_error))
        call.event('LAUNCH_RETURN', process=call.pid_identity)

    def communicate(self, input=None, timeout=None):
        call = self._custody_call
        call.event('COMMUNICATE_BEGIN', timeout=timeout,
                   input_argument_bytes=None if input is None else len(input))
        try:
            out, err = super().communicate(input=input, timeout=timeout)
        except BaseException as exc:
            call.event('COMMUNICATE_EXCEPTION', exception_type=type(exc).__name__, exception=repr(exc),
                       stdout=getattr(exc, 'output', None), stderr=getattr(exc, 'stderr', None),
                       returncode=self.returncode, usage=child_usage(), output_may_be_partial=True)
            raise
        call.event('COMMUNICATE_RETURN', stdout=out, stderr=err, returncode=self.returncode,
                   usage=child_usage(), output_may_be_partial=False)
        return out, err

    def kill(self):
        self._custody_call.event('ORIGINAL_CALLER_KILL_REQUEST')
        return super().kill()


class Session:
    def __init__(self, root):
        self.root = create_directory(Path(root).absolute())
        for name in ('calls', 'fixtures', 'inputs'):
            create_directory(self.root / name)
        self.calls = []
        self.fixtures = []
        self.test_id = None
        self.tests = []
        self.errors = []
        self.runner = process_identity(os.getpid())
        self._run_hook = self.run
        write_json(self.root / 'START.json', {'schema': 'hepta.hia.publication-test-custody.v1',
                   'status': 'RUNNING', 'runner': self.runner, 'created_ns': time.time_ns(),
                   'native_operations': sorted(OPERATIONS), 'full_process_tree_owner_added': False})

    def install(self):
        global _ACTIVE
        if _ACTIVE is not None or subprocess.run is not _REAL_RUN:
            raise ValueError('one explicit publication test observer required')
        _ACTIVE = self
        subprocess.run = self._run_hook

    def restore(self):
        global _ACTIVE
        if subprocess.run is not self._run_hook:
            self.errors.append('subprocess.run observer was not restored by a test')
        subprocess.run = _REAL_RUN
        _ACTIVE = None

    def run(self, *popenargs, **kwargs):
        argv = popenargs[0] if popenargs else kwargs.get('args')
        if not native_command(argv):
            return _REAL_RUN(*popenargs, **kwargs)
        call = _Call(self, argv, kwargs.get('input', b''), kwargs.get('timeout'), 'subprocess.run', kwargs)
        original_popen = subprocess.Popen
        def launch(*args, **options):
            actual = args[0] if args else options.get('args')
            if [os.fspath(v) for v in actual] != call.argv:
                raise ValueError('observed Popen argv differs from original run')
            return _ObservedPopen(call, *args, **options)
        subprocess.Popen = launch
        try:
            result = _REAL_RUN(*popenargs, **kwargs)
        except BaseException as exc:
            call.event('RUN_EXCEPTION', exception_type=type(exc).__name__, exception=repr(exc),
                       stdout=getattr(exc, 'output', None), stderr=getattr(exc, 'stderr', None),
                       returncode=None if call.process is None else call.process.returncode)
            raise
        else:
            call.event('RUN_RETURN', returncode=result.returncode)
            return result
        finally:
            subprocess.Popen = original_popen

    def popen(self, argv, *, offered_input, **kwargs):
        if not native_command(argv):
            raise ValueError('explicit test Popen must be a native publication command')
        call = _Call(self, argv, offered_input, None, 'test direct Popen', kwargs)
        return _ObservedPopen(call, argv, **kwargs)

    def temporary_directory(self, prefix):
        # Preserve TemporaryDirectory's original filesystem, prefix and random
        # basename. Retention must not move the measured workload to RUNNER_TEMP.
        folder = Path(tempfile.mkdtemp(prefix=prefix)).absolute()
        with parent_fd(folder) as (fd, name):
            value = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o700:
                raise ValueError('private original temporary directory required')
            observed = identity(value)
        self.fixtures.append({'path': str(folder), 'prefix': prefix, 'test_id': self.test_id,
                              'root_identity_at_creation': observed,
                              'allocation': 'stdlib tempfile.mkdtemp(prefix), no dir override'})
        write_json(self.root / ('fixture-%03d.json' % (len(self.fixtures) - 1)), self.fixtures[-1])
        return _RetainedDirectory(folder)

    def finish(self, result):
        self.flush_calls()
        rows = [call.summary() for call in self.calls]
        known_closed = all(direct_child_custody_closed(row) for row in rows)
        body = {'schema': 'hepta.hia.publication-test-custody.v1', 'runner': self.runner,
                'status': 'TESTS_PASS' if result.wasSuccessful() and not self.errors and known_closed else 'TESTS_FAIL_OR_CUSTODY_HOLD',
                'test_result_successful': result.wasSuccessful(), 'tests_run': result.testsRun,
                'tests': self.tests, 'calls': rows, 'fixtures': self.fixtures, 'errors': self.errors,
                'known_direct_children_reaped': known_closed,
                'original_timeouts_changed': False, 'full_process_tree_cleanup_claimed': False,
                'end_ns': time.time_ns()}
        write_json(self.root / 'RUN.json', body)
        return body

    def flush_calls(self):
        for call in self.calls:
            if call.flushed != len(call.events):
                try:
                    call.flush()
                except BaseException as exc:
                    text = type(exc).__name__ + ': ' + str(exc)
                    call.record_errors.append(text)
                    self.errors.append('call %d evidence flush: %s' % (call.index, text))


class _RetainedDirectory:
    def __init__(self, path):
        self.name = str(path)
    def __enter__(self):
        return self.name
    def __exit__(self, *args):
        return False
    def cleanup(self):
        # Explicit retention keeps the original fixture bytes and all types.
        return None


def temporary_directory(*, prefix):
    if _ACTIVE is None:
        return tempfile.TemporaryDirectory(prefix=prefix)
    return _ACTIVE.temporary_directory(prefix)


def observed_popen(argv, *, offered_input, **kwargs):
    if _ACTIVE is None:
        return subprocess.Popen(argv, **kwargs)
    return _ACTIVE.popen(argv, offered_input=offered_input, **kwargs)
