"""Bounded, nonaccepting Linux PTY diagnostic capture; never proof admission.

Only stdout uses a PTY. All raw reads and append-only writes share finite budgets.
No subprocess is used for platform detection and no pipe fallback is provided.
"""
from copy import deepcopy
import errno
from hashlib import sha256
import json
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

DIAGNOSTIC_FILES = ('LinearTransport.stdout', 'LinearTransport.stderr', 'LinearTransport.events.jsonl')
def target_configuration(target):
    require(type(target) is str and target in ('LinearTransport', 'CertPart02'),
            'fixed diagnostic target required')
    return (tuple(target + suffix for suffix in ('.stdout', '.stderr', '.events.jsonl')),
            'HIA_DIAG_v1_' + ('LIN_' if target == 'LinearTransport' else 'P02_'))


PROCESS_SECONDS = 60
CLEANUP_SECONDS = 2
TOTAL = 1048576
DISPLAY_LABEL_RESERVE = 1024
DURABLE_TOTAL = (TOTAL - DISPLAY_LABEL_RESERVE) // 2
METADATA_LIMIT = 16384
INTERNAL_METADATA_LIMIT = METADATA_LIMIT - 4096
RAW_LIMIT = DURABLE_TOTAL - METADATA_LIMIT
TERMINAL_RESERVE = 4096
READ_CHUNK = 16384
MAX_MARKERS = 24


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


def _settings(value):
    return [list(x if isinstance(x, int) else x[0] for x in part)
            if isinstance(part, list) else part for part in value]


class _Sink:
    """Exclusive single-link descriptors, continuously bound to their directory entry."""
    def __init__(self, safe_root, root_path, *, target="LinearTransport"):
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
        data = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
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
    """Recognize only complete, ordered, exact stdout records; pending bytes <=256."""
    def __init__(self, markers, *, target="LinearTransport"):
        require(type(markers) in (list, tuple) and len(markers) <= MAX_MARKERS, 'planned marker cap/type')
        _, prefix = target_configuration(target)
        self.pattern = rb'"(' + re.escape(prefix.encode()) + rb'[0-9]{3})" : String'
        self.markers = []
        for index, marker in enumerate(markers):
            require(type(marker) is dict and marker.get('id') == prefix + '%03d' % index,
                    'planned marker IDs/order')
            require(all(type(marker.get(k)) is int and marker[k] >= 0
                        for k in ('original_offset', 'instrumented_offset')) and
                    all(marker[k] <= 2 * 1024 * 1024 for k in ('original_offset', 'instrumented_offset')),
                    'planned marker offsets')
            self.markers.append({k: marker[k] for k in ('id', 'original_offset', 'instrumented_offset')})
        self.next_index = 0
        self.pending = bytearray()
        self.discarding = False
        self.line_start = 0

    def __call__(self, stream, data, stream_offset, elapsed):
        if stream != 'stdout':
            return []
        result = []
        for index, byte in enumerate(data):
            if byte == 10:
                if not self.discarding:
                    match = re.fullmatch(self.pattern, bytes(self.pending))
                    if match:
                        ident = match[1].decode('ascii')
                        require(self.next_index < len(self.markers) and
                                ident == self.markers[self.next_index]['id'], 'unexpected/duplicate/reordered marker')
                        result.append({**self.markers[self.next_index], 'stream': stream,
                                       'byte_offset': self.line_start, 'received_seconds': elapsed})
                        self.next_index += 1
                self.pending.clear()
                self.discarding = False
                self.line_start = stream_offset + index + 1
            elif not self.discarding:
                if len(self.pending) < 256:
                    self.pending.append(byte)
                else:
                    self.pending.clear()
                    self.discarding = True
        return result


def capture_result(executable, source, output, root_path, *, safe_root, markers=(),
                   manifest_reference=None, observer=None, target="LinearTransport"):
    """Return bounded metadata; raw logs never appear in the returned dictionary.

    observer(stream, chunk, stream_offset, elapsed_seconds) may return up to 24
    compact event dictionaries cumulatively; any observer failure kills/reaps the group. The caller owns marker
    grammar and must budget any additional copy of the returned metadata.
    """
    names, _ = target_configuration(target)
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
    collect_enabled = True
    result = {'process_started': False, 'returncode': None, 'signal': None,
              'timeout_seconds': PROCESS_SECONDS, 'platform': None, 'pty': None,
              'leader_reaped': False, 'group_kill_sent': False, 'drain_complete': False,
              'kernel_core_syntax_connection_checked': False, 'authority': 'DENY_ALL',
              'metadata_written_bytes': 0, 'metadata_remaining_bytes': METADATA_LIMIT,
              'raw_written_bytes': 0, 'compact_receipt_reference': None}
    argv = [str(executable), '--root=' + str(root_path), '-o', str(output), str(source)]
    result.update(argv=argv, cwd=str(root_path), search_path=str(root_path),
                  sysroot=str(Path(executable).parent.parent), manifest_reference=manifest_reference)

    def leader_exit():
        # WNOWAIT preserves our leader PID/PGID until group signalling is done.
        return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)

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
            result['group_cleanup_error'] = type(error).__name__ + ': ' + str(error)[:160]
            # The leader is still unreaped, so its PID cannot have been reused.
            try:
                os.kill(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as leader_error:
                result['leader_cleanup_error'] = type(leader_error).__name__

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

    def collect(fd, stream):
        nonlocal marker_count, last_marker, raw_limit_hit
        remaining = RAW_LIMIT - sum(observed_bytes.values())
        if remaining <= 0:
            raw_limit_hit = True
            return
        try:
            data = os.read(fd, min(READ_CHUNK, remaining))
        except BlockingIOError:
            return
        except OSError as error:
            if error.errno == errno.EIO and stream == 'stdout' and (
                    result['group_kill_sent'] or leader_exit() is not None):
                data = b''
            else:
                raise
        if not data:
            eof.add(stream)
            close_stream(fd)
            return
        offset = observed_bytes[stream]
        observed_bytes[stream] += len(data)
        elapsed = round(time.monotonic() - started, 6)
        sink.append(names[0 if stream == 'stdout' else 1], data)
        sink.record({'kind': 'receive', 'stream': stream, 'offset': offset,
                     'bytes': len(data), 'received_seconds': elapsed})
        if observer is not None:
            events = observer(stream, data, offset, elapsed)
            if events is not None:
                for event in events:
                    require(marker_count < MAX_MARKERS and type(event) is dict, 'marker event bound/type')
                    sink.record({'kind': 'marker', 'event': event, 'received_seconds': elapsed})
                    marker_count += 1
                    last_marker = event
        if sum(observed_bytes.values()) == RAW_LIMIT:
            raw_limit_hit = True

    try:
        sink = _Sink(safe_root, root_path, target=target)
        default_observer = MarkerObserver(markers, target=target)
        if observer is None:
            observer = default_observer
        if manifest_reference is not None:
            require(type(manifest_reference) is dict and set(manifest_reference) == {'path', 'sha256'} and
                    re.fullmatch(r'[0-9a-f]{64}', manifest_reference['sha256']) is not None,
                    'compact manifest reference required')
            original = safe_root.read(manifest_reference['path'], 8 * 1024 * 1024)
            require(sha256(original).hexdigest() == manifest_reference['sha256'], 'manifest reference changed')
        observed = platform_observation()
        result['platform'] = observed
        require_platform(observed)
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
        result['pid'] = process.pid
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
            if leader_exit() is not None and cleanup_deadline is None:
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
            for key, _ in selector.select(wait):
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
        reason = type(error).__name__ + ': ' + str(error)[:256]
        kill_group()
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
                    if not ready:
                        break
                    for key, _ in ready:
                        collect(key.fd, key.data)
                        if raw_limit_hit:
                            break
                except BaseException as error:
                    status = 'diagnostic_infrastructure_failed'
                    reason = 'cleanup capture: ' + type(error).__name__ + ': ' + str(error)[:160]
                    break
            try:
                process.wait(timeout=max(0, cleanup_deadline - time.monotonic()))
                result['leader_reaped'] = True
            except subprocess.TimeoutExpired:
                reason = (reason or '') + '; leader reap deadline exceeded'
                status = 'diagnostic_infrastructure_failed'
            result['returncode'] = process.returncode
            result['signal'] = -process.returncode if process.returncode is not None and process.returncode < 0 else None
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
        if status == 'diagnostic_completed' and (not result['leader_reaped'] or not result['drain_complete']):
            status, reason = 'diagnostic_infrastructure_failed', 'incomplete cleanup or output drain'
        if process is not None and process.stderr is not None and not process.stderr.closed:
            process.stderr.close()
        result.update(status=status, error=reason, observed_bytes=observed_bytes,
                      output_truncated=raw_limit_hit, marker_count=marker_count, last_observed_marker=last_marker,
                      next_planned_marker_id=(markers[marker_count]['id'] if marker_count < len(markers) else None),
                      cleanup_incomplete=process is not None and not (result['leader_reaped'] and result['drain_complete'] and 'group_cleanup_error' not in result),
                      elapsed_seconds=round(time.monotonic() - started, 6))
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
                sink.record({'kind': 'terminal', 'process': terminal_process,
                             'accounting_before_terminal': before_terminal}, terminal=True)
                terminal_written = True
            except BaseException as error:
                result['status'] = 'diagnostic_infrastructure_failed'
                result['error'] = 'terminal persistence: ' + type(error).__name__ + ': ' + str(error)[:160]
            result.update(metadata_written_bytes=sink.metadata_written,
                          metadata_remaining_bytes=METADATA_LIMIT - sink.metadata_written,
                          raw_written_bytes=sink.raw_written,
                          files=sink.identities())
            sink.close()
        result['terminal_record_persisted'] = terminal_written
        if sink is not None:
            result['compact_receipt_reference'] = sink.identities()[names[2]]
    return result
