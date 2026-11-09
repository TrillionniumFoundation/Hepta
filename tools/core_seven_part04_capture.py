"""Bounded, nonaccepting Linux PTY diagnostic capture; never proof admission.

Only stdout uses a PTY. All raw bytes are retained under finite budgets; only markers create trace events.
No subprocess is used for platform detection and no pipe fallback is provided.
"""
from copy import deepcopy
import errno
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import platform
import re
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import termios
import time

TARGET = 'SevenCertificatePart04'
TRACE = 'p04-markers-v2'
PREFIX = 'HIA_SEVEN_DIAG_v1_P04_'
DIAGNOSTIC_FILES = tuple(TARGET + suffix for suffix in ('.stdout', '.stderr', '.events.jsonl'))
START_LIMIT = 2368
MARKER_LIMIT = 224
TERMINAL_LIMIT = 3584
EVENT_STREAM_LIMIT = 8416

def target_configuration(target=TARGET):
    require(type(target) is str and target == TARGET, 'fixed Part04 diagnostic target required')
    return DIAGNOSTIC_FILES, PREFIX


PROCESS_SECONDS = 60
CLEANUP_SECONDS = 2
PENDING_EIO_SECONDS = 0.050
TOTAL = 1048576
DISPLAY_LABEL_RESERVE = 1024
DURABLE_TOTAL = (TOTAL - DISPLAY_LABEL_RESERVE) // 2
METADATA_LIMIT = 16384
INTERNAL_METADATA_LIMIT = METADATA_LIMIT - 4096
RAW_LIMIT = DURABLE_TOTAL - METADATA_LIMIT
TERMINAL_RESERVE = 4096
READ_CHUNK = 16384
MAX_MARKERS = 11


class CaptureFailure(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise CaptureFailure(message)


def platform_observation():
    """Parse standard quoted os-release values, never shell-evaluate them."""
    with open('/etc/os-release', 'rb') as stream:
        raw = stream.read(16385)
    require(len(raw) <= 16384, 'os-release byte cap')
    values = {}
    for line in raw.decode('utf-8', errors='strict').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        require(separator and re.fullmatch(r'[A-Z_][A-Z0-9_]*', key), 'ambiguous os-release field')
        tokens = shlex.split(value, comments=True, posix=True)
        require(len(tokens) == 1, 'ambiguous os-release value')
        if key in ('ID', 'VERSION_ID'):
            require(key not in values, 'duplicate os-release identity')
            values[key] = tokens[0]
    return {'sys_platform': sys.platform, 'machine': platform.machine(),
            'os_release': values, 'libc': os.confstr('CS_GNU_LIBC_VERSION')}


def require_platform(observed):
    require(observed == {'sys_platform': 'linux', 'machine': 'x86_64',
                         'os_release': {'ID': 'ubuntu', 'VERSION_ID': '24.04'},
                         'libc': 'glibc 2.39'}, 'unsupported diagnostic platform')


def safe_error(value, limit=128):
    return ''.join(c if 32 <= ord(c) <= 126 and c not in '\\"' else '?' for c in str(value))[:limit]


def validate_path(value):
    require(type(value) is str and len(value) <= 128 and
            re.fullmatch(r'/[A-Za-z0-9_./-]+', value) is not None and
            str(Path(value)) == value and '..' not in Path(value).parts,
            'bounded safe absolute path required')
    return value


def validate_elapsed(value):
    require(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 600,
            'bounded elapsed seconds required')
    return round(value, 6)


def validate_settings(value):
    require(type(value) is list and len(value) == 7 and
            all(type(v) is int and 0 <= v <= 0xffffffff for v in value[:6]) and
            type(value[6]) is list and len(value[6]) == 32 and
            all(type(v) is int and 0 <= v <= 255 for v in value[6]), 'bounded termios shape required')
    return value


def _settings(value):
    require(type(value) is list and len(value) == 7 and type(value[6]) is list,
            'bounded termios shape required')
    converted = value[:6] + [[v if type(v) is int else v[0]
                             if type(v) is bytes and len(v) == 1 else None for v in value[6]]]
    return validate_settings(converted)


def validate_signed(value):
    require(value is None or (type(value) is int and -(2**63) <= value < 2**63),
            'signed64 process value required')
    return value


def _record_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


class _Sink:
    """Exclusive single-link descriptors, continuously bound to their directory entry."""
    def __init__(self, safe_root, root_path, *, target=TARGET):
        self.names, _ = target_configuration(target)
        self.root = safe_root
        self.path = Path(root_path).absolute()
        require(self.path == Path(safe_root.path).absolute(), 'safe root path mismatch')
        for path in (self.path, *self.path.parents):
            require(not path.is_symlink(), 'diagnostic root symlink')
        safe_root.unchanged()
        self.files = {}
        self.raw_written = 0
        self.metadata_written = 0
        try:
            for name in self.names:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND |
                             os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=safe_root.fd)
                self.files[name] = {'fd': fd, 'identity': os.fstat(fd), 'bytes': 0, 'hash': sha256()}
                self.files[name]['stamp'] = (os.fstat(fd).st_mtime_ns, os.fstat(fd).st_ctime_ns)
                self._check(name)
        except BaseException:
            self.close()
            raise

    def _check(self, name, after_write=False):
        self.root.unchanged()
        item = self.files[name]
        fdstat = os.fstat(item['fd'])
        current = os.stat(name, dir_fd=self.root.fd, follow_symlinks=False)
        same = lambda s: (s.st_dev, s.st_ino, s.st_nlink, s.st_size)
        require(stat.S_ISREG(fdstat.st_mode) and stat.S_ISREG(current.st_mode) and
                fdstat.st_nlink == 1 and same(fdstat) == same(current) and
                (fdstat.st_dev, fdstat.st_ino) ==
                (item['identity'].st_dev, item['identity'].st_ino) and
                fdstat.st_size == item['bytes'] and
                (after_write or (fdstat.st_mtime_ns, fdstat.st_ctime_ns) == item['stamp']),
                'diagnostic append file identity changed')
        item['stamp'] = (fdstat.st_mtime_ns, fdstat.st_ctime_ns)

    def append(self, name, data, terminal=False):
        require(type(data) is bytes, 'diagnostic bytes required')
        metadata = name == self.names[2]
        remaining = (INTERNAL_METADATA_LIMIT - self.metadata_written - (0 if terminal else TERMINAL_RESERVE)
                     if metadata else RAW_LIMIT - self.raw_written)
        if metadata:
            remaining = min(remaining, EVENT_STREAM_LIMIT - self.metadata_written)
        require(len(data) <= remaining, 'diagnostic metadata budget' if metadata else 'diagnostic raw write budget')
        self._check(name)
        item = self.files[name]
        view = memoryview(data)
        while view:
            count = os.write(item['fd'], view)
            require(count > 0, 'diagnostic append made no progress')
            chunk = view[:count]
            item['bytes'] += count
            item['hash'].update(chunk)
            if metadata:
                self.metadata_written += count
            else:
                self.raw_written += count
            view = view[count:]
        self._check(name, after_write=True)
        os.fsync(item['fd'])

    def record(self, value, terminal=False):
        data = _record_bytes(value)
        limit = TERMINAL_LIMIT if terminal else START_LIMIT if value.get('kind') == 'start' else MARKER_LIMIT
        require(len(data) <= limit and self.metadata_written + len(data) <= EVENT_STREAM_LIMIT,
                'diagnostic metadata budget')
        self.append(self.names[2], data, terminal=terminal)

    def identities(self):
        return {name: {'path': name, 'bytes': item['bytes'], 'sha256': item['hash'].hexdigest()}
                for name, item in self.files.items()}

    def close(self):
        for item in self.files.values():
            if item['fd'] is not None:
                os.close(item['fd'])
                item['fd'] = None


class MarkerObserver:
    """Bounded line scanner. Marker-like lines, including partial EOF, fail closed."""
    def __init__(self, markers, *, target=TARGET):
        target_configuration(target)
        require(type(markers) in (list, tuple) and len(markers) == MAX_MARKERS, 'planned marker cap/type')
        self.markers = []
        for index, marker in enumerate(markers):
            require(type(marker) is dict and marker.get('id') == PREFIX + '%03d' % index,
                    'planned marker IDs/order')
            require(all(type(marker.get(k)) is int and 0 <= marker[k] <= 2 * 1024 * 1024
                        for k in ('original_offset', 'instrumented_offset')), 'planned marker offsets')
            self.markers.append({k: marker[k] for k in ('id', 'original_offset', 'instrumented_offset')})
        self.next_index = 0
        self.last_elapsed = 0
        self.pending = {'stdout': bytearray(), 'stderr': bytearray()}
        self.line_start = {'stdout': 0, 'stderr': 0}
        self.offsets = {'stdout': 0, 'stderr': 0}
        self.markerlike = {'stdout': False, 'stderr': False}
        self.tail = {'stdout': b'', 'stderr': b''}

    def __call__(self, stream, data, stream_offset, elapsed):
        require(stream in self.offsets and type(data) is bytes and stream_offset == self.offsets[stream],
                'noncontiguous marker observation')
        validate_elapsed(elapsed)
        require(elapsed >= self.last_elapsed, 'nonmonotone observation clock')
        self.last_elapsed = elapsed
        self.offsets[stream] += len(data)
        result = []
        for index, byte in enumerate(data):
            tail = (self.tail[stream] + bytes([byte]))[-16:]
            self.tail[stream] = tail
            if b'HIA_' in tail:
                self.markerlike[stream] = True
            if byte == 10:
                line = bytes(self.pending[stream])
                if self.markerlike[stream]:
                    require(stream == 'stdout' and re.fullmatch(
                        rb'"HIA_SEVEN_DIAG_v1_P04_[0-9]{3}" : String', line) is not None,
                        'malformed/foreign diagnostic marker namespace')
                    ident = line.split(b'"')[1].decode('ascii')
                    require(self.next_index < len(self.markers) and
                            ident == self.markers[self.next_index]['id'], 'unexpected/duplicate/reordered marker')
                    result.append({**self.markers[self.next_index], 'stream': stream,
                                   'byte_offset': self.line_start[stream], 'received_seconds': elapsed})
                    self.next_index += 1
                self.pending[stream].clear()
                self.markerlike[stream] = False
                self.tail[stream] = b''
                self.line_start[stream] = stream_offset + index + 1
            elif len(self.pending[stream]) < 257:
                self.pending[stream].append(byte)
        return result

    def finish(self, stream):
        require(not self.markerlike[stream], 'partial diagnostic marker at EOF')


def capture_result(executable, source, output, root_path, *, safe_root, markers=(),
                   manifest_reference=None, observer=None, target=TARGET, started_reference=None):
    """Return bounded metadata; raw logs never appear in the returned dictionary.

    The fixed observer emits at most eleven ordered marker records. Custom
    observers are forbidden. The caller independently replays raw evidence and
    budgets every additional copy of the returned metadata.
    """
    names, _ = target_configuration(target)
    validate_path(str(root_path))
    validate_path(str(executable))
    validate_path(str(Path(executable).parent.parent))
    require(str(source) == str(root_path) + '/HiaSyntaxResearch/CertPart04.lean' and
            str(output) == str(root_path) + '/HiaSyntaxResearch/CertPart04.olean', 'fixed Part04 derived paths required')
    require(observer is None, 'custom Part04 observer forbidden')
    default_observer = MarkerObserver(markers, target=target)
    observer = default_observer
    started = time.monotonic()
    process = None
    sink = None
    master = slave = None
    selector = None
    streams = {}
    observed_bytes = {'stdout': 0, 'stderr': 0}
    group_signalled = False
    terminal_written = False
    status = 'diagnostic_infrastructure_failed'
    reason = None
    marker_count = 0
    last_marker = None
    cleanup_deadline = None
    eof = set()
    raw_limit_hit = False
    metadata_limit_hit = False
    collect_enabled = True
    pending_eio = None

    class PendingEIOTimeout(CaptureFailure):
        pass

    class CleanupDeadlineExceeded(CaptureFailure):
        pass
    result = {'trace': TRACE, 'process_started': False, 'returncode': None, 'signal': None,
              'timeout_seconds': PROCESS_SECONDS, 'platform': None, 'pty': None,
              'leader_reaped': False, 'group_kill_sent': False, 'drain_complete': False,
              'cleanup_deadline_exceeded': False,
              'kernel_core_syntax_connection_checked': False, 'authority': 'DENY_ALL',
              'metadata_written_bytes': 0, 'metadata_remaining_bytes': METADATA_LIMIT,
              'raw_written_bytes': 0, 'compact_receipt_reference': None}
    result['started_reference'] = started_reference
    argv = [str(executable), '--root=' + str(root_path), '-o', str(output), str(source)]
    result.update(argv=argv, cwd=str(root_path), search_path=str(root_path),
                  sysroot=str(Path(executable).parent.parent), manifest_reference=manifest_reference)

    def leader_exit():
        # WNOWAIT preserves our leader PID/PGID until group signalling is done.
        observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        check_active_deadline(check_process=observed is not None)
        return observed

    def check_active_deadline(*, check_process=True):
        # Admission uses observation time, including a syscall that began in
        # budget but returned late. Cleanup has its own fixed, unrenewed limit.
        now = time.monotonic()
        if cleanup_deadline is not None and now >= cleanup_deadline:
            result['cleanup_deadline_exceeded'] = True
            raise CleanupDeadlineExceeded('cleanup observation deadline exceeded')
        if (check_process and cleanup_deadline is None and status == 'diagnostic_completed' and
                now >= started + PROCESS_SECONDS):
            raise PendingEIOTimeout('60-second process deadline')

    def kill_group():
        nonlocal group_signalled
        if process is None or group_signalled:
            return
        try:
            os.killpg(process.pid, signal.SIGKILL)
            group_signalled = True
            result['group_kill_sent'] = True
        except ProcessLookupError:
            group_signalled = True
        except OSError as error:
            group_signalled = True
            result['group_cleanup_error'] = safe_error(type(error).__name__ + ': ' + str(error))
            # The leader is still unreaped, so its PID cannot have been reused.
            try:
                os.kill(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as leader_error:
                result['leader_cleanup_error'] = safe_error(type(leader_error).__name__, 32)

    def close_stream(fd):
        if selector is not None:
            try:
                selector.unregister(fd)
            except (KeyError, ValueError, OSError):
                pass
        stream = streams.pop(fd, None)
        if stream == 'stderr':
            process.stderr.close()
        elif stream == 'stdout':
            os.close(fd)

    def check_pending_deadline():
        # Check after waitid/read as well: neither syscall may admit a late EOF.
        now = time.monotonic()
        if now >= started + PROCESS_SECONDS:
            raise PendingEIOTimeout('60-second process deadline')
        require(now < pending_eio[1], 'pending stdout EIO grace expired')
        require(not group_signalled and cleanup_deadline is None and
                status == 'diagnostic_completed', 'pending stdout EIO after cleanup')

    def confirm_pending_eio():
        nonlocal pending_eio
        check_pending_deadline()
        exited = leader_exit()
        check_pending_deadline()
        if exited is None:
            return
        fd = pending_eio[0]
        remaining = RAW_LIMIT - sum(observed_bytes.values())
        require(remaining > 0, 'pending stdout EIO raw budget exhausted')
        try:
            data = os.read(fd, min(READ_CHUNK, remaining))
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            data = b''
        # A reopened stream's data is observed but never persisted or interpreted.
        observed_bytes['stdout'] += len(data)
        check_pending_deadline()
        require(not data, 'pending stdout EIO confirmation returned data')
        observer.finish('stdout')
        eof.add('stdout')
        close_stream(fd)
        pending_eio = None

    def collect(fd, stream):
        nonlocal marker_count, last_marker, raw_limit_hit, pending_eio
        remaining = RAW_LIMIT - sum(observed_bytes.values())
        if remaining <= 0:
            raw_limit_hit = True
            return
        try:
            data = os.read(fd, min(READ_CHUNK, remaining))
        except BlockingIOError:
            return
        except OSError as error:
            if error.errno != errno.EIO or stream != 'stdout':
                raise
            first_eio = time.monotonic() if target == TARGET else None
            if result['group_kill_sent'] or leader_exit() is not None:
                data = b''
            elif target == TARGET and not group_signalled:
                # Unregister, but retain ownership for exactly-once final closure.
                # This deadline is fixed at the first EIO and never refreshed.
                pending_eio = (fd, min(first_eio + PENDING_EIO_SECONDS,
                                       started + PROCESS_SECONDS,
                                       cleanup_deadline if cleanup_deadline is not None else float('inf')))
                selector.unregister(fd)
                check_pending_deadline()
                return
            else:
                raise
        offset = observed_bytes[stream]
        observed_bytes[stream] += len(data)
        check_active_deadline()
        if not data:
            observer.finish(stream)
            eof.add(stream)
            close_stream(fd)
            return
        elapsed = validate_elapsed(time.monotonic() - started)
        # Reserve the complete replay batch before persisting any of this read.
        # A rejected read still consumes observed_bytes; collection then stops.
        # This preflight is not an I/O transaction: partial writes remain failures.
        batch = bytearray()
        metadata_remaining = INTERNAL_METADATA_LIMIT - sink.metadata_written - TERMINAL_RESERVE
        require(len(batch) <= metadata_remaining, 'diagnostic metadata budget')
        next_count, next_marker = marker_count, last_marker
        if observer is not None:
            events = observer(stream, data, offset, elapsed)
            if events is not None:
                for event in events:
                    require(next_count < MAX_MARKERS and type(event) is dict, 'marker event bound/type')
                    record = _record_bytes({'kind': 'marker', 'event': event, 'received_seconds': elapsed})
                    require(len(record) <= MARKER_LIMIT and len(batch) + len(record) <= metadata_remaining and
                            sink.metadata_written + len(batch) + len(record) + TERMINAL_LIMIT <= EVENT_STREAM_LIMIT,
                            'diagnostic metadata budget')
                    batch.extend(record)
                    next_count += 1
                    next_marker = event
        sink.append(names[0 if stream == 'stdout' else 1], data)
        sink.append(names[2], bytes(batch))
        marker_count, last_marker = next_count, next_marker
        if sum(observed_bytes.values()) == RAW_LIMIT:
            raw_limit_hit = True

    try:
        sink = _Sink(safe_root, root_path, target=target)
        if manifest_reference is not None:
            require(type(manifest_reference) is dict and set(manifest_reference) == {'path', 'sha256'} and
                    manifest_reference['path'] == 'diagnostic-manifest.json' and
                    type(manifest_reference['sha256']) is str and
                    re.fullmatch(r'[0-9a-f]{64}', manifest_reference['sha256']) is not None,
                    'compact manifest reference required')
            original = safe_root.read(manifest_reference['path'], 8 * 1024 * 1024)
            require(sha256(original).hexdigest() == manifest_reference['sha256'], 'manifest reference changed')
        if target == TARGET:
            require(type(started_reference) is dict and set(started_reference) == {'path', 'sha256'} and
                    started_reference['path'] == 'SevenCertificatePart04.started.json' and
                    type(started_reference['sha256']) is str and
                    re.fullmatch(r'[0-9a-f]{64}', started_reference['sha256']) is not None,
                    'fixed target started reference required')
            require(sha256(safe_root.read(started_reference['path'], METADATA_LIMIT)).hexdigest() ==
                    started_reference['sha256'], 'target started reference changed')
        observed = platform_observation()
        require_platform(observed)
        result['platform'] = observed
        master, slave = os.openpty()
        before = termios.tcgetattr(slave)
        changed = deepcopy(before)
        changed[1] = 0
        termios.tcsetattr(slave, termios.TCSANOW, changed)
        after = termios.tcgetattr(slave)
        tty = os.isatty(slave)
        result['pty'] = {'before': _settings(before), 'after': _settings(after), 'isatty': tty}
        require(after[1] == 0 and tty is True, 'PTY output flags/isatty verification failed')
        sink.record({'kind': 'start', 'process': result, 'planned_markers': len(markers),
                     'raw_limit': RAW_LIMIT, 'metadata_limit': METADATA_LIMIT,
                     'session': 'new session; no controlling terminal'})
        environment = dict(os.environ)
        environment['LEAN_PATH'] = str(root_path)
        environment.pop('LEAN_SRC_PATH', None)
        environment['LEAN_SYSROOT'] = str(Path(executable).parent.parent)
        os.set_blocking(master, False)
        process = subprocess.Popen(argv, cwd=root_path, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=slave, stderr=subprocess.PIPE, start_new_session=True,
                                   close_fds=True)
        result['process_started'] = True
        result['pid'] = validate_signed(process.pid)
        os.close(slave)
        slave = None
        selector = selectors.DefaultSelector()
        streams[master] = 'stdout'
        streams[process.stderr.fileno()] = 'stderr'
        master = None  # owned by streams even if selector registration fails
        for fd, stream in streams.items():
            os.set_blocking(fd, False)
            selector.register(fd, selectors.EVENT_READ, stream)
        status = 'diagnostic_completed'
        while streams or leader_exit() is None:
            now = time.monotonic()
            if cleanup_deadline is None and now - started >= PROCESS_SECONDS:
                status, reason = 'diagnostic_timeout', '60-second process deadline'
                kill_group()
                cleanup_deadline = now + CLEANUP_SECONDS
                if pending_eio is not None:
                    collect_enabled = False
                    break
            if pending_eio is not None:
                confirm_pending_eio()
            if pending_eio is None and leader_exit() is not None and cleanup_deadline is None:
                # Kill any descendant still inheriting our descriptors. Never wait
                # for it to perform more computation after the leader exits.
                kill_group()
                cleanup_deadline = now + CLEANUP_SECONDS
            if cleanup_deadline is not None and now >= cleanup_deadline:
                break
            if raw_limit_hit:
                status, reason = 'diagnostic_output_limit', 'combined raw read budget exhausted'
                kill_group()
                break
            wait = min(0.05, max(0, (cleanup_deadline if cleanup_deadline is not None
                                   else started + PROCESS_SECONDS) - now))
            if pending_eio is not None:
                wait = min(wait, 0.001, max(0, pending_eio[1] - time.monotonic()))
            ready = selector.select(wait)
            if cleanup_deadline is None and time.monotonic() >= started + PROCESS_SECONDS:
                # No read or exit observation is being accepted. Enter the
                # normal timeout transition, then drain under its fixed budget.
                continue
            check_active_deadline()
            for key, _ in ready:
                collect(key.fd, key.data)
                if raw_limit_hit:
                    break
        exit_info = leader_exit()
        if status == 'diagnostic_completed' and exit_info is not None and (
                exit_info.si_code != os.CLD_EXITED or exit_info.si_status != 0):
            status, reason = 'diagnostic_failed', 'nonzero diagnostic process exit'
    except BaseException as error:
        result['interrupted'] = isinstance(error, (KeyboardInterrupt, SystemExit))
        status = 'diagnostic_failed' if result['interrupted'] else 'diagnostic_infrastructure_failed'
        collect_enabled = False
        reason = safe_error(type(error).__name__ + ': ' + str(error))
        if isinstance(error, PendingEIOTimeout):
            status, reason = 'diagnostic_timeout', '60-second process deadline'
        if target == TARGET and process is not None and isinstance(error, CaptureFailure) and str(error) == 'diagnostic metadata budget':
            metadata_limit_hit = True
            status = 'diagnostic_output_limit'
        kill_group()
        if cleanup_deadline is None:
            cleanup_deadline = time.monotonic() + CLEANUP_SECONDS
    finally:
        if process is not None:
            kill_group()
            if cleanup_deadline is None:
                cleanup_deadline = time.monotonic() + CLEANUP_SECONDS
            # Drain only already available output; never regain raw/metadata quota.
            while streams and collect_enabled and not raw_limit_hit and time.monotonic() < cleanup_deadline:
                try:
                    ready = selector.select(0)
                    check_active_deadline()
                    if not ready:
                        break
                    for key, _ in ready:
                        collect(key.fd, key.data)
                        if raw_limit_hit:
                            break
                except BaseException as error:
                    status = 'diagnostic_infrastructure_failed'
                    reason = 'cleanup capture: ' + safe_error(type(error).__name__ + ': ' + str(error))
                    if target == TARGET and process is not None and isinstance(error, CaptureFailure) and str(error) == 'diagnostic metadata budget':
                        metadata_limit_hit = True
                    break
            try:
                process.wait(timeout=max(0, cleanup_deadline - time.monotonic()))
                result['leader_reaped'] = True
                check_active_deadline()
            except CleanupDeadlineExceeded:
                reason = (reason or '') + '; leader reap observation after cleanup deadline'
                status = 'diagnostic_infrastructure_failed'
            except subprocess.TimeoutExpired:
                result['cleanup_deadline_exceeded'] = True
                reason = (reason or '') + '; leader reap deadline exceeded'
                status = 'diagnostic_infrastructure_failed'
            result['returncode'] = validate_signed(process.returncode)
            result['signal'] = validate_signed(-process.returncode if process.returncode is not None and process.returncode < 0 else None)
        result['drain_complete'] = eof == {'stdout', 'stderr'}
        for fd in list(streams):
            close_stream(fd)
        if selector is not None:
            selector.close()
        for fd in (slave, master):
            if fd is not None:
                os.close(fd)
        if 'group_cleanup_error' in result or 'leader_cleanup_error' in result:
            status, reason = 'diagnostic_infrastructure_failed', 'process group cleanup incomplete'
        if raw_limit_hit:
            status, reason = 'diagnostic_output_limit', 'combined raw read budget exhausted'
        if status == 'diagnostic_completed' and (not result['leader_reaped'] or not result['drain_complete'] or result['cleanup_deadline_exceeded']):
            status, reason = 'diagnostic_infrastructure_failed', 'incomplete cleanup or output drain'
        if process is not None and process.stderr is not None and not process.stderr.closed:
            process.stderr.close()
        if metadata_limit_hit:
            status, reason = 'diagnostic_output_limit', 'diagnostic metadata budget exhausted'
        if status == 'diagnostic_completed' and marker_count != MAX_MARKERS:
            status, reason = 'diagnostic_infrastructure_failed', 'incomplete planned markers'
        clock_valid = True
        try:
            elapsed_seconds = validate_elapsed(time.monotonic() - started)
            require(elapsed_seconds >= observer.last_elapsed, 'nonmonotone final process clock')
        except CaptureFailure as error:
            clock_valid = False
            elapsed_seconds = 0  # Ineligible sentinel: no terminal can be persisted.
            status, reason = 'diagnostic_infrastructure_failed', str(error)
        result.update(status=status, error=safe_error(reason) if reason is not None else None, observed_bytes=observed_bytes,
                      output_truncated=raw_limit_hit or metadata_limit_hit, marker_count=marker_count, last_observed_marker=last_marker,
                      next_planned_marker_id=(markers[marker_count]['id'] if marker_count < len(markers) else None),
                      cleanup_incomplete=process is not None and not (result['leader_reaped'] and result['drain_complete'] and not result['cleanup_deadline_exceeded'] and 'group_cleanup_error' not in result),
                      elapsed_seconds=elapsed_seconds)
        if sink is not None:
            result['raw_files'] = {name: row for name, row in sink.identities().items()
                                   if name != names[2]}
            # A terminal record cannot truthfully contain its own final serialized
            # byte count/hash. Persist explicit prefix accounting instead. The
            # returned object receives final accounting only after this append.
            terminal_process = {key: value for key, value in result.items()
                                if key not in ('metadata_written_bytes', 'metadata_remaining_bytes',
                                               'raw_written_bytes', 'compact_receipt_reference')}
            before_terminal = {'raw_written_bytes': sink.raw_written,
                               'metadata_written_bytes': sink.metadata_written}
            try:
                require(clock_valid, 'invalid process clock; terminal refused')
                sink.record({'kind': 'terminal', 'process': terminal_process,
                             'accounting_before_terminal': before_terminal}, terminal=True)
                terminal_written = True
            except BaseException as error:
                result['status'] = 'diagnostic_infrastructure_failed'
                result['error'] = safe_error('terminal persistence: ' + type(error).__name__ + ': ' + str(error))
            result.update(metadata_written_bytes=sink.metadata_written,
                          metadata_remaining_bytes=METADATA_LIMIT - sink.metadata_written,
                          raw_written_bytes=sink.raw_written,
                          files=sink.identities())
            sink.close()
        result['terminal_record_persisted'] = terminal_written
        if sink is not None:
            result['compact_receipt_reference'] = sink.identities()[names[2]]
    return result
