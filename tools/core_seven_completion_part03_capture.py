"""Fixed nonaccepting completion-barrier Part03 PTY capture and independent raw replay.

The original session/group alone is contained. A detached descendant is outside
this contract. No leader is reaped before the single original-group SIGKILL.
"""
from __future__ import annotations

import codecs
import errno
import hashlib
import json
import os
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

from tools import core_seven_acceptance_capture as hardened
from tools import core_seven_relocation_acceptance_plan as inherited
from tools import core_seven_completion_part03_sources as sources

TARGET = 'CompletionPart03'
PREFIX = 'HIA_SEVEN_COMP_v1_P03_'
CAPTURE_PROTOCOL = 'p03-completion-pty-hardened-v1'
PROCESS_NS = 60_000_000_000
CLEANUP_NS = 2_000_000_000
OUTER_NS = 600_000_000_000
PENDING_EIO_NS = 50_000_000
RAW_STAGE = 507392
RAW_GLOBAL = 819891
START_LIMIT = 2368
MARKER_LIMIT = 272
SENTINEL_LIMIT = 208
TERMINAL_LIMIT = 3584
EVENT_STREAM_LIMIT = 8416
PRETERMINAL_LIMIT = 8192
INTERNAL_LIMIT = 12288
TERMINAL_RESERVE = 4096
MAX_MARKERS = 12
MAX_EVENTS = 13
SENTINEL = b"'True.intro' does not depend on any axioms\n"
STREAMS = ('stdout', 'stderr')
EVENTS = TARGET + '.events.jsonl'
PLATFORM = dict(sys_platform='linux', machine='x86_64',
                os_release=dict(ID='ubuntu', VERSION_ID='24.04'), libc='glibc 2.39')


class CaptureFailure(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise CaptureFailure(message)


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def integer(value, maximum=OUTER_NS, minimum=0):
    require(type(value) is int and minimum <= value <= maximum, 'bounded integer')
    return value


def record(raw):
    return dict(bytes=len(raw), sha256=digest(raw))


def marker_fields(index):
    return dict(id=sources.MARKER_IDS[index], original_offset=sources.OFFSETS[index],
                instrumented_offset=sources.MARKER_OFFSETS[index])


def marker_line(index):
    return ('"' + sources.MARKER_IDS[index] + '" : String\n').encode()


def observation(index, offset):
    """Closed thirteen-record observation grammar, before receipt timestamp."""
    if index == 9:
        return dict(kind='sentinel', id='True.intro', stdout_offset=offset,
                    stdout_length=len(SENTINEL), stdout_sha256=digest(SENTINEL))
    marker_index = index if index < 9 else index - 1
    result = dict(kind='marker', **marker_fields(marker_index), stdout_offset=offset)
    if marker_index == 9:
        raw = marker_line(marker_index)
        result.update(stdout_length=len(raw), stdout_sha256=digest(raw))
    return result


def remaining_event_reserve(count):
    return sum(len(encode(dict(observation(i, RAW_STAGE), received_ns=OUTER_NS)))
               for i in range(count, MAX_EVENTS))


def validate_markers(markers):
    require(type(markers) in (tuple, list) and len(markers) == MAX_MARKERS, 'fixed markers')
    for i, marker in enumerate(markers):
        require(type(marker) is dict, 'marker record')
        for key, value in marker_fields(i).items():
            require(type(marker.get(key)) is type(value) and marker[key] == value, 'fixed marker topology')


def parse_raw(stdout, stderr, source_stage, markers, events=None, complete=False):
    """Reparse raw bytes. Only the exact reserved sentinel is excluded once.

    A valid observation proves checked-chain resolution, possibly error/fallback,
    not proof success. Missing observation is censored and inconclusive.
    """
    require(type(stdout) is bytes and type(stderr) is bytes and type(complete) is bool, 'raw bytes')
    require(len(stdout) + len(stderr) <= RAW_STAGE, 'raw cap')
    stdout.decode('utf-8', 'strict'); stderr.decode('utf-8', 'strict')
    validate_markers(markers)
    expected = inherited.seven._qualified_prints(source_stage.source)
    require(len(expected) == 1655, 'fixed inventory subjects')
    row_re = re.compile(rb"'([^'\r\n]+)' (?:depends on axioms: \[([^\]\r\n]*)\]|does not depend on any axioms)\n")
    def claims(line):
        return (b'depends on axioms' in line or b'does not depend on any axioms' in line
                or line.lstrip().startswith(b"'"))
    for line in stderr.splitlines(keepends=True):
        require(b'HIA_' not in line and not claims(line), 'stderr marker/inventory')
    found, marker_rows, filtered, inventory = [], [], [], {}
    sentinel = None
    offset = 0
    for line in stdout.splitlines(keepends=True):
        if b'HIA_' in line:
            index = len(marker_rows)
            require(index < MAX_MARKERS and line == marker_line(index), 'foreign/malformed/reordered marker')
            boundary = 0 if index <= 9 else 828 if index == 10 else 1655
            require(len(inventory) == boundary, 'marker inventory interleaving')
            require(index != 9 or sentinel is not None, 'completion marker without sentinel')
            event = observation(len(found), offset)
            require(event['kind'] == 'marker', 'missing sentinel')
            found.append(event); marker_rows.append(event)
        elif line == SENTINEL:
            require(len(marker_rows) == 9 and sentinel is None and not inventory,
                    'sentinel reserved boundary')
            sentinel = observation(9, offset)
            found.append(sentinel)
        else:
            filtered.append(line)
            match = row_re.fullmatch(line)
            if match:
                subject = match[1].decode('utf-8')
                require(len(marker_rows) >= 10 and len(inventory) < 1655 and
                        subject == expected[len(inventory)], 'inventory ordered prefix')
                require(len(inventory) < 828 or len(marker_rows) == 11, 'missing inventory boundary marker')
                axioms = [] if match[2] is None else [v.strip() for v in match[2].decode().split(',') if v.strip()]
                require(set(axioms) <= {'propext', 'Classical.choice', 'Quot.sound'}, 'inventory axioms')
                inventory[subject] = axioms
            else:
                require(not claims(line), 'malformed inventory claim')
        offset += len(line)
    if events is not None:
        require(type(events) is list and len(events) == len(found), 'raw/event count')
        for actual, event in zip(found, events):
            require(type(event) is dict and set(event) == set(actual) | {'received_ns'} and
                    all(type(event[k]) is type(v) and event[k] == v for k, v in actual.items()), 'raw/event binding')
            integer(event['received_ns'])
    filtered = b''.join(filtered)
    full = None
    if complete:
        require(len(marker_rows) == 12 and sentinel is not None and len(inventory) == 1655,
                'incomplete marker/inventory')
        full = inherited.inventory(filtered, stderr, source_stage)
        require(full == inventory, 'full inventory differs')
    return dict(markers=marker_rows, events=found, sentinel=sentinel, inventory=full,
                subject_count=len(inventory), stdout=filtered)


def platform_observation():
    with open('/etc/os-release', 'rb') as stream:
        raw = stream.read(16385)
    require(len(raw) <= 16384, 'platform cap')
    values = {}
    for line in raw.decode('utf-8', 'strict').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        require(sep and re.fullmatch('[A-Z_][A-Z0-9_]*', key), 'platform field')
        tokens = shlex.split(value, comments=True)
        require(len(tokens) == 1, 'platform value')
        if key in ('ID', 'VERSION_ID'):
            require(key not in values, 'duplicate platform field')
            values[key] = tokens[0]
    return dict(sys_platform=sys.platform, machine=platform.machine(), os_release=values,
                libc=os.confstr('CS_GNU_LIBC_VERSION'))


def settings(value):
    require(type(value) is list and len(value) == 7 and type(value[6]) is list and len(value[6]) == 32,
            'termios shape')
    result = value[:6] + [[v if type(v) is int else v[0] if type(v) is bytes and len(v) == 1 else None
                          for v in value[6]]]
    for v in result[:6]: integer(v, 2**32 - 1)
    for v in result[6]: integer(v, 255)
    return result


class _Sink:
    """Exclusive descriptor ownership; partial writes remain charged forever."""
    def __init__(self, root, raw_limit):
        self.root, self.raw_limit = root, raw_limit
        self.files, self.raw_written, self.metadata_written = {}, 0, 0
        self.ancestors = {}
        self._ancestors()
        try:
            for name in (TARGET + '.stdout', TARGET + '.stderr', EVENTS):
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK,
                             0o600, dir_fd=root.fd)
                info = os.fstat(fd)
                self.files[name] = dict(fd=fd, inode=(info.st_dev, info.st_ino), count=0,
                                        hash=hashlib.sha256(), stamp=(info.st_mtime_ns, info.st_ctime_ns))
                self.check(name)
        except BaseException:
            self.close()
            raise

    def _ancestors(self):
        self.root.unchanged()
        for path in (self.root.path, *self.root.path.parents):
            info = os.stat(path, follow_symlinks=False)
            identity = (info.st_dev, info.st_ino)
            require(stat.S_ISDIR(info.st_mode) and self.ancestors.get(str(path), identity) == identity, 'ancestor changed')
            self.ancestors[str(path)] = identity

    def check(self, name, after=False):
        self._ancestors()
        item = self.files[name]
        info = os.fstat(item['fd']); current = os.stat(name, dir_fd=self.root.fd, follow_symlinks=False)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(stat.S_ISREG(info.st_mode) and stat.S_ISREG(current.st_mode) and info.st_nlink == 1 and
                fields(info) == fields(current) and (info.st_dev, info.st_ino) == item['inode'] and
                info.st_size == item['count'] and (after or (info.st_mtime_ns, info.st_ctime_ns) == item['stamp']), 'sink changed')
        item['stamp'] = (info.st_mtime_ns, info.st_ctime_ns)

    def reserve(self, size, metadata=False, terminal=False):
        if metadata:
            require(self.metadata_written + size <= EVENT_STREAM_LIMIT and
                    self.metadata_written + size <= INTERNAL_LIMIT - (0 if terminal else TERMINAL_RESERVE) and
                    (terminal or self.metadata_written + size + TERMINAL_LIMIT <= EVENT_STREAM_LIMIT) and
                    (terminal or self.metadata_written + size <= PRETERMINAL_LIMIT), 'event budget')
        else:
            require(self.raw_written + size <= self.raw_limit, 'raw budget')

    def append(self, name, raw, terminal=False):
        metadata = name == EVENTS
        self.reserve(len(raw), metadata, terminal)
        self.check(name)
        item = self.files[name]
        view = memoryview(raw)
        while view:
            count = os.write(item['fd'], view)
            require(count > 0, 'short sink write')
            item['count'] += count; item['hash'].update(view[:count])
            if metadata: self.metadata_written += count
            else: self.raw_written += count
            view = view[count:]
        self.check(name, after=True)

    def event(self, value):
        raw = encode(value)
        cap = TERMINAL_LIMIT if value['kind'] == 'terminal' else START_LIMIT if value['kind'] == 'start' else SENTINEL_LIMIT if value['kind'] == 'sentinel' else MARKER_LIMIT
        require(len(raw) <= cap, 'event subcap')
        self.append(EVENTS, raw, terminal=value['kind'] == 'terminal')

    def persist(self):
        for name, item in self.files.items():
            self.check(name); os.fsync(item['fd']); self.check(name)

    def logs(self):
        return {stream: dict(bytes=self.files[TARGET + '.' + stream]['count'],
                             sha256=self.files[TARGET + '.' + stream]['hash'].hexdigest()) for stream in STREAMS}

    def close(self):
        for item in self.files.values():
            fd, item['fd'] = item['fd'], None
            if fd is not None: os.close(fd)


class MarkerObserver:
    """Online marker framing only; independent parse_raw authenticates inventory."""
    def __init__(self):
        self.pending = {s: b'' for s in STREAMS}
        self.offsets = {s: 0 for s in STREAMS}
        self.events = []

    def feed(self, stream, raw, received_ns):
        self.pending[stream] += raw
        while b'\n' in self.pending[stream]:
            line, self.pending[stream] = self.pending[stream].split(b'\n', 1)
            line += b'\n'
            if b'HIA_' in line or line == SENTINEL:
                index = len(self.events)
                expected = SENTINEL if index == 9 else marker_line(index if index < 9 else index - 1) if index < MAX_EVENTS else None
                require(stream == 'stdout' and index < MAX_EVENTS and line == expected, 'marker framing')
                event = dict(observation(index, self.offsets[stream]), received_ns=received_ns)
                # Yield before advancing the committed prefix. The collector
                # persists each record before requesting the next one, so a
                # later malformed line in this same read cannot invent events.
                yield event
                self.events.append(event)
            self.offsets[stream] += len(line)

    def eof(self, stream):
        require(b'HIA_' not in self.pending[stream] and b'True.intro' not in self.pending[stream], 'partial marker')


def reportable(process, logs, observed):
    return (process['spawned'] and process['leader_reaped'] and process['leader_start_ticks'] is not None and
            process['stdout_eof'] and process['stderr_eof'] and process['original_group_empty'] and
            process['post_reap_group_probe'] == 'esrch' and process['leader_reap_observed'] and
            process['pre_reap_group_signal'] in ('sigkill_sent', 'sigkill_no_signalable_group') and
            not process['incomplete'] and not process['output_truncated'] and
            all(logs[s]['bytes'] == observed[s] for s in STREAMS))


def collect(root, plan, run, started, *, launch_deadline_ns, outer_deadline_ns):
    """One fixed target launch. No injected command, observer, reader or finalizer.

    Preparation, source identity and prior parent admission are caller-owned.
    All target terminal verification and persistence are collector-owned.
    """
    from tools import core_seven_completion_part03_plan as p
    # Prove all reserved event bytes fit existing caps before any launch.
    require(START_LIMIT + remaining_event_reserve(0) + TERMINAL_LIMIT <= EVENT_STREAM_LIMIT,
            'static event reserve')
    entered = time.monotonic_ns()
    integer(launch_deadline_ns, 2**63-1); integer(outer_deadline_ns, 2**63-1)
    result = dict(process=hardened.unspawned_process(), logs=None, error_code=None,
                  status='no_launch', launch_state='not_attempted', terminal=None, events_sha256=None)
    process = result['process']
    sink = child = selector = None
    master = slave = None
    origin = cleanup_origin = spawn_offset = None
    attempted = False
    observed = dict(stdout=0, stderr=0)
    eof = dict(stdout='not_observed', stderr='not_observed')
    eio_first = eio_confirmed = None
    observer = MarkerObserver()
    decoders = {s: codecs.getincrementaldecoder('utf-8')('strict') for s in STREAMS}
    streams = {}
    start_event = None
    io_broken = False

    def clock():
        now = time.monotonic_ns()
        require(entered <= now < outer_deadline_ns, 'outer/monotonic clock')
        return integer(now - entered)

    def fail(code, status=None):
        if result['error_code'] is None:
            result['error_code'] = code
            result['status'] = status or {'process_timeout': 'target_timeout', 'process_failed': 'target_nonzero',
                'output_limit': 'raw_overflow', 'cleanup_failed': 'cleanup_uncertain',
                'launch_deadline': 'no_launch', 'platform_invalid': 'no_launch', 'pty_invalid': 'no_launch',
                'marker_invalid': 'target_invalid', 'target_inventory_invalid': 'target_invalid',
                'target_module_invalid': 'target_invalid'}.get(code, 'capture_incomplete')

    def terminate():
        nonlocal cleanup_origin
        if child is None or cleanup_origin is not None:
            return
        cleanup_origin = time.monotonic_ns()
        process['elapsed_ns'] = cleanup_origin - origin
        process['timed_out'] = process['elapsed_ns'] >= PROCESS_NS
        if process['timed_out']: fail('process_timeout')
        try:
            os.killpg(child.pid, signal.SIGKILL)
            process['pre_reap_group_signal'] = 'sigkill_sent'
        except ProcessLookupError:
            process['pre_reap_group_signal'] = 'sigkill_no_signalable_group'
        except OSError:
            process['pre_reap_group_signal'] = 'failed'
            fail('cleanup_failed')

    def window():
        now = time.monotonic_ns()
        if child is not None and cleanup_origin is None and now >= origin + PROCESS_NS:
            terminate()
        if child is not None and cleanup_origin is not None and now >= cleanup_origin + CLEANUP_NS:
            process['incomplete'] = True
            fail('cleanup_failed')
            return False
        if now >= outer_deadline_ns or now < entered:
            process['incomplete'] = child is not None
            fail('clock_invalid')
            terminate()
            return False
        return True

    def observe_exit():
        if child is not None and not process['leader_reaped'] and process['leader_start_ticks'] is not None:
            observation = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if observation is not None:
                process['terminal_observation'] = 'waitid_wnowait'
                return True
        return process['terminal_observation'] == 'waitid_wnowait'

    def end_stream(name, evidence):
        decoders[name].decode(b'', final=True)
        observer.eof(name)
        process[name + '_eof'] = True; eof[name] = evidence
        selector.unregister(streams[name])

    def read_stream(name):
        nonlocal eio_first, eio_confirmed, io_broken
        if not window() or io_broken:
            return
        # Reserve worst read-driven markers plus a full terminal before I/O.
        sink.reserve(remaining_event_reserve(len(observer.events)), metadata=True)
        remaining = min(RAW_STAGE, raw_remaining) - sum(observed.values())
        if remaining < 0:
            return
        try:
            data = os.read(streams[name], min(16384, remaining + 1))
        except BlockingIOError:
            return
        except OSError as exc:
            if name != 'stdout' or exc.errno != errno.EIO:
                raise
            now = time.monotonic_ns()
            if eio_first is None: eio_first = clock()
            require(now - entered - eio_first < PENDING_EIO_NS, 'expired pending EIO')
            authenticated = observe_exit() or cleanup_origin is not None
            if not authenticated:
                return
            # A second no-data read is mandatory, before both fixed cutoffs.
            require(window(), 'EIO cutoff')
            try:
                confirmation = os.read(streams[name], 1)
            except OSError as confirm:
                if confirm.errno != errno.EIO: raise
                confirmation = b''
            if confirmation:
                observed[name] += len(confirmation)
                allowance = min(RAW_STAGE, raw_remaining) - sink.raw_written
                if allowance: sink.append(TARGET + '.' + name, confirmation[:allowance])
                raise CaptureFailure('reopened pending EIO')
            confirmed = clock()
            require(confirmed - eio_first < PENDING_EIO_NS and window(), 'EIO confirmation cutoff')
            end_stream(name, 'eio_after_waitid' if process['terminal_observation'] == 'waitid_wnowait' else 'eio_after_kill')
            # Strict decoder/framing finalization must succeed before a
            # confirmed EIO can be committed as authenticated EOF.
            eio_confirmed = confirmed
            return
        if data:
            observed[name] += len(data)
        received = clock()
        if data:
            allowance = min(RAW_STAGE, raw_remaining) - sink.raw_written
            retained = data[:max(0, allowance)]
            if retained:
                sink.append(TARGET + '.' + name, retained)
                decoders[name].decode(retained, final=False)
                for event in observer.feed(name, retained, received):
                    sink.event(event)
            if eio_first is not None and name == 'stdout':
                raise CaptureFailure('reopened pending EIO')
            if len(data) > allowance:
                process['output_truncated'] = True
                fail('output_limit'); terminate()
                io_broken = True
            window()
        else:
            if name == 'stdout' and eio_first is not None:
                require(received - eio_first < PENDING_EIO_NS and (observe_exit() or cleanup_origin is not None),
                        'unconfirmed pending EIO')
                end_stream(name, 'eio_after_waitid' if process['terminal_observation'] == 'waitid_wnowait' else 'eio_after_kill')
                eio_confirmed = received
            else:
                end_stream(name, 'read_zero')

    def drain():
        if not window(): return
        cutoff = cleanup_origin + CLEANUP_NS if cleanup_origin is not None else origin + PROCESS_NS
        if eio_first is not None and eio_confirmed is None:
            cutoff = min(cutoff, entered + eio_first + PENDING_EIO_NS)
            require(time.monotonic_ns() < cutoff, 'expired pending EIO')
        timeout = max(0, min(.005, (cutoff - time.monotonic_ns()) / 1e9))
        for key, _ in selector.select(timeout):
            read_stream(key.data)

    try:
        require(plan['target']['name'] == TARGET and plan['target']['capture_protocol'] == CAPTURE_PROTOCOL, 'fixed target')
        require(plan['process_spec']['root'] == str(root.path), 'fixed root')
        snapshot = p.Snapshot(root)
        require(snapshot.read(TARGET + '.started.json') == encode(started), 'persisted start')
        require(snapshot.read('PLAN.json') == encode(plan) and snapshot.read('RUN.json') == encode(run), 'persisted plan/run')
        raw_used = sum(len(snapshot.read(n + '.' + s)) for n in ('Baseline', 'SyntaxData', 'CertPart01', 'CertPart02') for s in STREAMS)
        raw_remaining = RAW_GLOBAL - raw_used
        integer(raw_remaining, RAW_GLOBAL)
        observed_platform = platform_observation()
        if observed_platform != PLATFORM:
            fail('platform_invalid'); return result
        master, slave = os.openpty()
        before_raw = termios.tcgetattr(slave)
        before = settings(before_raw)
        after_raw = before_raw[:]; after_raw[1] = 0
        termios.tcsetattr(slave, termios.TCSANOW, after_raw)
        after = settings(termios.tcgetattr(slave))
        require(after == before[:1] + [0] + before[2:] and os.isatty(master) and os.isatty(slave), 'PTY setup')
        sink = _Sink(root, min(raw_remaining, RAW_STAGE))
        selector = selectors.DefaultSelector()
        start_now = time.monotonic_ns()
        require(entered <= start_now < outer_deadline_ns, 'outer/monotonic clock')
        remaining = launch_deadline_ns - start_now
        if remaining <= 0:
            fail('launch_deadline'); return result
        integer(remaining, 540_000_000_000, 1)
        start_event = dict(kind='start', run_sha256=digest(encode(run)), started_sha256=digest(encode(started)),
            diagnostic_manifest_sha256=plan['target']['diagnostic_manifest_sha256'],
            process_spec_sha256=digest(encode(plan['process_spec'])), capture_protocol=CAPTURE_PROTOCOL,
            planned_markers=12, raw_limit=RAW_STAGE, raw_remaining=raw_remaining, process_ns=PROCESS_NS,
            cleanup_ns=CLEANUP_NS, remaining_launch_ns=remaining, received_ns=integer(start_now - entered), platform=observed_platform,
            pty=dict(before=before, after=after, isatty=True), session='new session; no controlling terminal')
        sink.event(start_event)
        spec, target = plan['process_spec'], plan['target']
        argv = [spec['executable'], '--root=' + spec['root'], '-o',
                str(root.path / target['module_path']), str(root.path / target['source_path'])]
        env = dict(os.environ, LEAN_PATH=spec['root'], LEAN_SYSROOT=spec['sysroot'])
        env.pop('LEAN_SRC_PATH', None)
        origin = time.monotonic_ns()
        if origin >= launch_deadline_ns or origin >= outer_deadline_ns:
            fail('launch_deadline')
        else:
            spawn_offset = integer(origin - entered)
            attempted = True; result['launch_state'] = 'spawn_outcome_uncertain'
            child = subprocess.Popen(argv, cwd=root.path, env=env, stdin=subprocess.DEVNULL,
                                     stdout=slave, stderr=subprocess.PIPE, start_new_session=True,
                                     close_fds=True, bufsize=0)
            # A returned child is a confirmed spawn even if the immediately
            # adjacent deadline observation raises. Never lose that identity.
            result['launch_state'] = 'spawned'
            process.update(spawned=True, leader_pid=child.pid, original_pgid=child.pid)
            post_spawn = time.monotonic_ns()
            if post_spawn >= launch_deadline_ns or post_spawn >= outer_deadline_ns:
                process['incomplete'] = True; fail('capture_incomplete'); terminate()
            # Close our slave immediately; otherwise it would mask EOF.
            os.close(slave); slave = None
            streams.update(stdout=master, stderr=child.stderr.fileno())
            for name, fd in streams.items():
                os.set_blocking(fd, False); selector.register(fd, selectors.EVENT_READ, name)
            process['leader_start_ticks'] = hardened._leader_identity(child.pid)
            if time.monotonic_ns() >= launch_deadline_ns:
                process['incomplete'] = True; fail('capture_incomplete'); terminate()
            while cleanup_origin is None and window():
                if observe_exit(): terminate(); break
                drain()
    except (Exception, KeyboardInterrupt) as exc:
        process['incomplete'] = child is not None
        if isinstance(exc, CaptureFailure) and str(exc) in ('event budget', 'event subcap'):
            fail('evidence_limit', 'event_overflow')
        elif isinstance(exc, CaptureFailure) and str(exc) in ('marker framing', 'partial marker'):
            fail('marker_invalid')
        elif isinstance(exc, CaptureFailure) and str(exc) == 'outer/monotonic clock':
            fail('clock_invalid')
        else:
            fail('capture_incomplete' if attempted else 'pty_invalid')
        terminate()
    finally:
        if child is not None:
            terminate()
            # A setup exception still must preserve the original cleanup origin.
            if slave is not None:
                os.close(slave); slave = None
            for name, fd in (('stdout', master), ('stderr', child.stderr.fileno() if child.stderr else None)):
                if fd is not None:
                    streams[name] = fd
                    try:
                        os.set_blocking(fd, False)
                        if fd not in selector.get_map(): selector.register(fd, selectors.EVENT_READ, name)
                    except (OSError, ValueError, KeyError): process['incomplete'] = True
            while time.monotonic_ns() < cleanup_origin + CLEANUP_NS:
                try:
                    if not process['leader_reaped']:
                        pid, status = os.waitpid(child.pid, os.WNOHANG)
                        if pid == child.pid:
                            process.update(returncode=os.waitstatus_to_exitcode(status), leader_reaped=True, leader_reap_observed=True)
                            child.returncode = process['returncode']
                    if process['leader_reaped']:
                        process['original_group_empty'] = False
                        try:
                            os.killpg(child.pid, 0); process['post_reap_group_probe'] = 'group_exists'
                        except ProcessLookupError:
                            process['post_reap_group_probe'] = 'esrch'; process['original_group_empty'] = True
                        except OSError:
                            process['post_reap_group_probe'] = 'unknown_or_permission_error'; break
                    if all(process[k] for k in ('leader_reaped', 'stdout_eof', 'stderr_eof', 'original_group_empty')): break
                    drain()
                except (Exception, KeyboardInterrupt):
                    process['incomplete'] = True; fail('capture_incomplete'); io_broken = True
                    # Still attempt bounded reap/probe, never refresh deadlines.
                    time.sleep(min(.005, max(0, (cleanup_origin + CLEANUP_NS - time.monotonic_ns()) / 1e9)))
            if not all(process[k] for k in ('leader_reaped', 'stdout_eof', 'stderr_eof', 'original_group_empty')):
                process['incomplete'] = True; fail('cleanup_failed')
            if process['returncode'] != 0: fail('process_failed')
        if selector is not None: selector.close()
        if slave is not None: os.close(slave)
        if master is not None: os.close(master)
        if child is not None and child.stderr is not None: child.stderr.close()
        if sink is not None:
            try:
                sink.persist()
            except (Exception, KeyboardInterrupt):
                process['incomplete'] = child is not None; fail('filesystem_invalid')
            if cleanup_origin is not None:
                elapsed = time.monotonic_ns() - cleanup_origin
                process['cleanup_ns'] = min(CLEANUP_NS, elapsed)
                if elapsed >= CLEANUP_NS:
                    process['incomplete'] = True
                    result.update(error_code='cleanup_failed', status='cleanup_uncertain')
            result['logs'] = sink.logs()
            try:
                if start_event is not None:
                    inventory = module = None
                    if result['error_code'] is None and child is not None:
                        inherited.validate_process(process, success=True)
                        from tools.core_seven_completion_part03_replay import verify_target_capture
                        verified = verify_target_capture(root, plan, run, started, observer.events,
                                                         process, result['logs'], observed)
                        inventory, module = verified['inventory'], verified['olean']
                        result['status'] = 'diagnostic_completed'
                    elif result['error_code'] is None:
                        fail('launch_deadline')
            except (Exception, KeyboardInterrupt) as exc:
                inventory = module = None
                code = 'target_module_invalid' if isinstance(exc, CaptureFailure) and str(exc) == 'target_module_invalid' else 'target_inventory_invalid'
                result.update(error_code=code, status='target_invalid')
            try:
                if start_event is not None:
                    count = sum(e['kind'] == 'marker' for e in observer.events)
                    terminal = dict(kind='terminal', run_sha256=digest(encode(run)), started_sha256=digest(encode(started)),
                        status=result['status'], error_code=result['error_code'], receipt_elapsed_ns=clock(),
                        spawn_offset_ns=spawn_offset, process=process, logs=result['logs'], observed_bytes=observed,
                        marker_count=count, last_marker_id=sources.MARKER_IDS[count-1] if count else None,
                        next_marker_id=sources.MARKER_IDS[count] if count < 12 else None, inventory=inventory, olean=module,
                        accounting_before_terminal=dict(raw_written_bytes=sink.raw_written, metadata_written_bytes=sink.metadata_written),
                        eof_evidence=eof, pending_eio_ns=PENDING_EIO_NS, eio_first_ns=eio_first, eio_confirmed_ns=eio_confirmed)
                    inherited.validate_process(process)
                    sink.event(terminal); sink.persist()
                    # No patch/retry after persistence. An overrun is a fragment.
                    clock()
                    result['terminal'] = terminal
                    result['events_sha256'] = sink.files[EVENTS]['hash'].hexdigest()
            except (Exception, KeyboardInterrupt):
                result.update(error_code='finalization_failed', status='finalization_failed', terminal=None, events_sha256=None)
            finally:
                sink.close()
        if not attempted: result['launch_state'] = 'not_spawned'
    return result


capture = collect


def validate_events(raw, plan, run, started, raw_remaining):
    """Closed event grammar and algebraic lifecycle replay, independent of capture."""
    from tools import core_seven_completion_part03_plan as p
    require(type(raw) is bytes and len(raw) <= EVENT_STREAM_LIMIT and raw.endswith(b'\n'), 'event bytes')
    lines = raw.splitlines(keepends=True)
    require(2 <= len(lines) <= 15, 'event count')
    events = [p.parse(line) for line in lines]
    require(all(type(e) is dict for e in events), 'event objects')
    start, terminal = events[0], events[-1]
    start_keys = {'kind','run_sha256','started_sha256','diagnostic_manifest_sha256','process_spec_sha256',
                  'capture_protocol','planned_markers','raw_limit','raw_remaining','process_ns','cleanup_ns',
                  'remaining_launch_ns','received_ns','platform','pty','session'}
    require(set(start) == start_keys and len(lines[0]) <= START_LIMIT, 'start shape/cap')
    fixed = dict(kind='start', run_sha256=digest(encode(run)), started_sha256=digest(encode(started)),
                 diagnostic_manifest_sha256=plan['target']['diagnostic_manifest_sha256'],
                 process_spec_sha256=digest(encode(plan['process_spec'])), capture_protocol=CAPTURE_PROTOCOL,
                 planned_markers=12, raw_limit=RAW_STAGE, raw_remaining=raw_remaining,
                 process_ns=PROCESS_NS, cleanup_ns=CLEANUP_NS, platform=PLATFORM,
                 session='new session; no controlling terminal')
    for k, value in fixed.items():
        require(encode(start[k]) == encode(value), 'start binding')
    integer(raw_remaining, RAW_GLOBAL)
    integer(start['remaining_launch_ns'], 540_000_000_000, 1)
    require(start['remaining_launch_ns'] <= started['remaining_launch_ns'], 'start remaining deadline')
    integer(start['received_ns'])
    tty = start['pty']
    require(type(tty) is dict and set(tty) == {'before','after','isatty'} and tty['isatty'] is True, 'PTY record')
    require(settings(tty['before']) == tty['before'] and settings(tty['after']) == tty['after'] and
            tty['after'] == tty['before'][:1] + [0] + tty['before'][2:], 'PTY settings binding')
    keys = {'kind','run_sha256','started_sha256','status','error_code','receipt_elapsed_ns','spawn_offset_ns',
            'process','logs','observed_bytes','marker_count','last_marker_id','next_marker_id','inventory','olean',
            'accounting_before_terminal','eof_evidence','pending_eio_ns','eio_first_ns','eio_confirmed_ns'}
    require(set(terminal) == keys and len(lines[-1]) <= TERMINAL_LIMIT and terminal['kind'] == 'terminal', 'terminal shape/cap')
    require(terminal['run_sha256'] == fixed['run_sha256'] and terminal['started_sha256'] == fixed['started_sha256'], 'terminal binding')
    integer(terminal['receipt_elapsed_ns']); integer(terminal['marker_count'], 12)
    require(type(terminal['status']) is str and terminal['status'] in (
        'diagnostic_completed','target_timeout','target_nonzero','capture_incomplete','cleanup_uncertain',
        'raw_overflow','event_overflow','target_invalid','no_launch'), 'terminal status')
    allowed_codes = {
        'diagnostic_completed': {None}, 'target_timeout': {'process_timeout'}, 'target_nonzero': {'process_failed'},
        'capture_incomplete': {'capture_incomplete','filesystem_invalid','clock_invalid','evidence_limit'},
        'cleanup_uncertain': {'cleanup_failed'}, 'raw_overflow': {'output_limit'},
        'event_overflow': {'evidence_limit'}, 'target_invalid': {'marker_invalid','clock_invalid','target_inventory_invalid','target_module_invalid'},
        'no_launch': {'launch_deadline','platform_invalid','pty_invalid','receipt_failed'}}
    require(terminal['error_code'] in allowed_codes[terminal['status']], 'terminal code/status')
    process = inherited.validate_process(terminal['process'], success=terminal['status'] == 'diagnostic_completed')
    spawn = terminal['spawn_offset_ns']
    if spawn is not None: integer(spawn)
    require(not process['spawned'] or spawn is not None, 'spawn offset missing')
    require(start['received_ns'] <= terminal['receipt_elapsed_ns'], 'receipt clock order')
    if spawn is not None:
        require(spawn - start['received_ns'] < start['remaining_launch_ns'], 'spawn after launch cutoff')
        require(start['received_ns'] <= spawn <= terminal['receipt_elapsed_ns'] and
                spawn + process['elapsed_ns'] + process['cleanup_ns'] <= terminal['receipt_elapsed_ns'], 'process receipt clocks')
    for name in ('logs','observed_bytes'):
        require(type(terminal[name]) is dict and set(terminal[name]) == set(STREAMS), 'stream keys')
    for stream in STREAMS:
        item = terminal['logs'][stream]
        require(type(item) is dict and set(item) == {'bytes','sha256'}, 'log record')
        integer(item['bytes'], RAW_STAGE); p.hash_value(item['sha256'])
        integer(terminal['observed_bytes'][stream], RAW_STAGE + 1)
        require(item['bytes'] <= terminal['observed_bytes'][stream], 'observed/written order')
    observed_total = sum(terminal['observed_bytes'].values())
    written_total = sum(item['bytes'] for item in terminal['logs'].values())
    require(observed_total <= min(RAW_STAGE, raw_remaining) + 1 and written_total <= min(RAW_STAGE, raw_remaining), 'raw allowance')
    require(not process['output_truncated'] or observed_total > written_total, 'truncation without loss')
    accounting = terminal['accounting_before_terminal']
    require(type(accounting) is dict and set(accounting) == {'raw_written_bytes','metadata_written_bytes'}, 'accounting keys')
    integer(accounting['raw_written_bytes'], RAW_STAGE); integer(accounting['metadata_written_bytes'], PRETERMINAL_LIMIT)
    require(accounting == dict(raw_written_bytes=written_total, metadata_written_bytes=sum(map(len,lines[:-1]))), 'actual accounting')
    require(sum(map(len, lines[:-1])) + TERMINAL_RESERVE <= INTERNAL_LIMIT, 'terminal reserve')
    observations = events[1:-1]
    count = sum(e.get('kind') == 'marker' for e in observations)
    require(terminal['marker_count'] == count, 'marker count')
    last_time, last_offset = max(start['received_ns'], spawn or 0), -1
    for index, (event, line) in enumerate(zip(observations, lines[1:-1])):
        expected = observation(index, event.get('stdout_offset'))
        require(set(event) == set(expected) | {'received_ns'} and
                all(type(event[k]) is type(v) and event[k] == v for k, v in expected.items()) and
                len(line) <= (SENTINEL_LIMIT if event['kind'] == 'sentinel' else MARKER_LIMIT), 'observation shape/cap')
        integer(event['stdout_offset'], RAW_STAGE); integer(event['received_ns'])
        length = len(SENTINEL) if index == 9 else len(marker_line(index if index < 9 else index - 1))
        require(spawn is not None and
                last_time <= event['received_ns'] <= min(terminal['receipt_elapsed_ns'],
                    spawn + process['elapsed_ns'] + process['cleanup_ns']) and
                last_offset < event['stdout_offset'] and
                event['stdout_offset'] + length <= terminal['logs']['stdout']['bytes'], 'marker clock/offset')
        last_time, last_offset = event['received_ns'], event['stdout_offset']
    require(terminal['last_marker_id'] == (sources.MARKER_IDS[count-1] if count else None) and
            terminal['next_marker_id'] == (sources.MARKER_IDS[count] if count < 12 else None), 'marker endpoints')
    evidence = terminal['eof_evidence']
    require(type(evidence) is dict and set(evidence) == set(STREAMS) and
            evidence['stdout'] in ('read_zero','eio_after_waitid','eio_after_kill','not_observed') and
            evidence['stderr'] in ('read_zero','not_observed'), 'EOF shape')
    require(all(process[s + '_eof'] == (evidence[s] != 'not_observed') for s in STREAMS), 'EOF observations')
    require(type(terminal['pending_eio_ns']) is int and terminal['pending_eio_ns'] == PENDING_EIO_NS, 'EIO grace')
    first, confirmed = terminal['eio_first_ns'], terminal['eio_confirmed_ns']
    for value in (first, confirmed):
        if value is not None: integer(value)
    require(confirmed is None or first is not None, 'EIO confirmation without first')
    if first is not None:
        require(spawn is not None and spawn <= first <= terminal['receipt_elapsed_ns'], 'first EIO clock')
        require(evidence['stdout'] != 'read_zero', 'pending EIO bypass')
    if confirmed is not None:
        require(first <= confirmed <= terminal['receipt_elapsed_ns'] and confirmed - first < PENDING_EIO_NS and
                confirmed < spawn + process['elapsed_ns'] + CLEANUP_NS, 'EIO bounded confirmation')
        require(evidence['stdout'] in ('eio_after_waitid','eio_after_kill'), 'EIO confirmation evidence')
    if evidence['stdout'].startswith('eio_'):
        require(first is not None and confirmed is not None, 'missing EIO clocks')
        if evidence['stdout'] == 'eio_after_waitid':
            require(process['terminal_observation'] == 'waitid_wnowait', 'EIO without exit observation')
        else:
            require(process['pre_reap_group_signal'] in ('sigkill_sent','sigkill_no_signalable_group') and
                    confirmed >= spawn + process['elapsed_ns'], 'EIO without original kill')
    if process['stdout_eof'] and first is not None:
        require(confirmed is not None, 'unconfirmed EIO cannot be EOF')
    if not process['spawned']:
        require(count == 0 and written_total == observed_total == 0 and
                terminal['inventory'] is None and terminal['olean'] is None and
                first is None and confirmed is None, 'unspawned artifacts')
    if terminal['status'] == 'diagnostic_completed':
        require(count == 12 and len(observations) == 13 and reportable(process, terminal['logs'], terminal['observed_bytes']), 'unsafe completion')
        inv, module = terminal['inventory'], terminal['olean']
        require(type(inv) is dict and set(inv) == {'subject_count','inventory_sha256'} and
                type(inv['subject_count']) is int and inv['subject_count'] == 1655, 'full inventory record')
        p.hash_value(inv['inventory_sha256'])
        require(type(module) is dict and set(module) == {'bytes','sha256','source_sha256'}, 'module record')
        integer(module['bytes'], 33554432, 1); p.hash_value(module['sha256'])
        require(module['source_sha256'] == plan['target']['source_sha256'], 'module source binding')
    else:
        require(terminal['inventory'] is None and terminal['olean'] is None, 'failure cannot carry inventory/module authority')
    if terminal['status'] == 'target_timeout': require(process['timed_out'], 'timeout status')
    if terminal['status'] == 'target_nonzero':
        require(process['leader_reaped'] and process['returncode'] != 0 and not process['timed_out'], 'nonzero status')
    if terminal['status'] == 'no_launch':
        require(not process['spawned'] and spawn is None, 'no-launch process')
    if terminal['status'] == 'cleanup_uncertain':
        require(process['spawned'] and (process['incomplete'] or
                process['pre_reap_group_signal'] == 'failed' or
                not all(process[k] for k in ('leader_reaped','stdout_eof','stderr_eof','original_group_empty'))),
                'cleanup failure must have an unsafe observation')
    if terminal['status'] == 'raw_overflow':
        require(process['spawned'] and process['output_truncated'] and
                written_total == min(RAW_STAGE, raw_remaining) and observed_total == written_total + 1,
                'overflow requires full retained allowance and one unretained sentinel')
    if terminal['status'] in ('capture_incomplete', 'event_overflow'):
        require((process['spawned'] and (process['incomplete'] or observed_total != written_total)) or
                (not process['spawned'] and spawn is not None), 'incomplete capture needs incomplete observations')
    return events
