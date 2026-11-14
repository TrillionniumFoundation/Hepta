"""Finite qualification IPC only; not a Pager, provider, or SQL implementation.

This draft has never been executed. Only Root's later frozen owner may call it.
Children receive fixed pipes and an immutable directory capability. Database
bytes are obtained only from the HIA ELF or the complete original SQLite oracle.
No pread, file-lock policy, WAL selection, or HIA execution occurs in Python.
"""
from __future__ import annotations
import base64
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import stat
import struct
import threading
import time

from pager_audit_stream_r3 import (
    PhysicalBudget, capture_pipe, canonical, INDEX_RESERVE, PART, require,
)

ENV = {'LANG': 'C', 'LC_ALL': 'C', 'PATH': ''}
NATIVE_PROFILE = 'native-owner-v2'
C_PROFILE = 'sqlite-reference-v2'
EVENT_MAGIC = int.from_bytes(b'HIAPGEV2', 'little')
OUTPUT_MAGIC = int.from_bytes(b'HIAPGOT2', 'little')
C_COMMAND_MAGIC = int.from_bytes(b'HIAPGCE2', 'little')
C_OUTPUT_MAGIC = int.from_bytes(b'HIAPGCO2', 'little')
NATIVE_RAW_MAX = 75 * 353664 + 16 * 148160
NATIVE_RECORD_MAX = 5 * (75 + 75 + 16)
C_COMMAND_RAW = 131888


class CommandJournal:
    """Complete finite IPC bytes, charged to the SAME 256MiB trace budget."""
    def __init__(self, root, budget):
        require(type(budget) is PhysicalBudget, 'shared physical budget')
        self.root = Path(root)
        self.root.mkdir(mode=0o700)
        self.budget = budget
        self.budget.reserve_index()
        self.path = self.root / 'IPC.jsonl'
        self.stream = self.path.open('xb')
        os.fchmod(self.stream.fileno(), 0o600)
        self.bytes = 0
        self.rows = 0
        self.digest = hashlib.sha256()

    def append(self, value):
        body = canonical(dict(value, ordinal=self.rows + 1))
        # This finite journal is one <=4MiB file, with its index included.
        require(len(body) <= 1024 * 1024, 'IPC row bound')
        require(self.bytes + len(body) <= PART - INDEX_RESERVE, 'IPC file bound')
        self.budget.take(len(body))
        require(self.stream.write(body) == len(body), 'IPC short write')
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.bytes += len(body)
        self.rows += 1
        self.digest.update(body)

    def close(self, status):
        require(status in ('CLOSED', 'HOLD'), 'journal status')
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.stream.close()
        value = {'schema': 'hia.sqlite-pager.finite-ipc.v1', 'status': status,
                 'rows': self.rows, 'bytes': self.bytes,
                 'sha256': self.digest.hexdigest(),
                 'path': 'IPC.jsonl', 'physical_budget_token': self.budget.token}
        raw = canonical(value)
        require(len(raw) <= INDEX_RESERVE, 'journal index bound')
        self.budget.commit_index(len(raw))
        with (self.root / 'INDEX.json').open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            require(stream.write(raw) == len(raw), 'journal index short write')
            stream.flush()
            os.fsync(stream.fileno())
        return value


def executable_pin(path, expected):
    """One exact already-built input, never a build or a system search."""
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            'executable must be an owned regular input')
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(path, flags)
    digest = hashlib.sha256()
    count = 0
    try:
        opened = os.fstat(fd)
        require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino),
                'executable path changed')
        while True:
            piece = os.read(fd, 65536)
            if not piece:
                break
            count += len(piece)
            digest.update(piece)
        after = os.fstat(fd)
        require((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
                 opened.st_ctime_ns, opened.st_mode, opened.st_nlink) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                 after.st_ctime_ns, after.st_mode, after.st_nlink),
                'executable changed during complete read')
    finally:
        os.close(fd)
    require(count == expected['bytes'] and digest.hexdigest() == expected['sha256'],
            'exact executable input differs')
    return {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest()}


def _high_fd(fd):
    # Descriptor mechanics only. No SQLite fcntl lock is issued by Python.
    return fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 10)


class Process:
    def __init__(self, *, executable, executable_identity, argv, directory_fd,
                 nonce, profile, name, root, budget, journal, deadline,
                 c_commands=0):
        require(type(nonce) is int and 0 < nonce < 2**64, 'nonce')
        require(profile in (NATIVE_PROFILE, C_PROFILE), 'finite process profile')
        require(type(name) is str and name and '/' not in name, 'process label')
        require(stat.S_ISDIR(os.fstat(directory_fd).st_mode), 'directory capability')
        self.name, self.nonce, self.profile = name, nonce, profile
        self.deadline, self.journal = deadline, journal
        self.sequence = 0
        self.pid = None
        self.reaped = False
        self.capture = None
        self.capture_exception = None
        self.last_partial = b''
        self.root = Path(root) / name
        self.root.mkdir(mode=0o700)
        pin = executable_pin(executable, executable_identity)
        command_read, command_write = os.pipe2(os.O_CLOEXEC)
        reply_read, reply_write = os.pipe2(os.O_CLOEXEC)
        audit_read, audit_write = os.pipe2(os.O_CLOEXEC)
        stderr_fd = os.open(self.root/'stderr.bin',
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        high = []
        try:
            # All dup sources are >=10. No mapping can overwrite a later source.
            for descriptor in (command_read, reply_write, stderr_fd,
                               directory_fd, audit_write):
                high.append(_high_fd(descriptor))
            actions = [(os.POSIX_SPAWN_DUP2, descriptor, target)
                       for descriptor, target in zip(high, (0, 1, 2, 3, 4))]
            actions += [(os.POSIX_SPAWN_CLOSE, descriptor) for descriptor in high]
            journal.append({'kind': 'spawn_intent', 'process': name, 'nonce': nonce,
                            'profile': profile, 'executable': pin,
                            'argv': [str(executable)] + list(argv), 'env': ENV})
            self.pid = os.posix_spawn(str(executable), [str(executable)] + list(argv),
                                     ENV, file_actions=actions)
        except BaseException:
            for descriptor in (command_write, reply_read, audit_read):
                os.close(descriptor)
            raise
        finally:
            for descriptor in high + [command_read, reply_write, audit_write, stderr_fd]:
                os.close(descriptor)
        self.command_fd, self.reply_fd = command_write, reply_read
        if profile == NATIVE_PROFILE:
            max_raw, max_records = NATIVE_RAW_MAX, NATIVE_RECORD_MAX
            require(c_commands == 0, 'native has no C command denominator')
        else:
            require(type(c_commands) is int and 1 <= c_commands <= 7, 'frozen C commands')
            max_raw, max_records = c_commands * C_COMMAND_RAW, c_commands * 6
        self.bounds = {'max_raw_bytes': max_raw, 'max_records': max_records}
        def drain():
            try:
                self.capture = capture_pipe(
                    audit_read, self.root/'audit', nonce=nonce, budget=budget,
                    profile=profile, **self.bounds)
            except BaseException as exc:
                self.capture_exception = {'type': type(exc).__name__, 'message': str(exc)}
                # capture_pipe may reject before entering its own finally. Close
                # this read end as well so a failed sink cannot leave the child
                # indefinitely blocked on a pipe with no draining reader.
                try:
                    os.close(audit_read)
                except OSError as close_error:
                    if close_error.errno != errno.EBADF:
                        self.capture_exception['close_error'] = str(close_error)
        self.thread = threading.Thread(target=drain, name='audit-'+name, daemon=False)
        self.thread.start()
        journal.append({'kind': 'spawn_ack', 'process': name, 'pid': self.pid,
                        'nonce': nonce, 'profile': profile, 'bounds': self.bounds})

    def _ready(self, descriptor, *, write=False):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, 'original finite owner deadline reached')
        if write:
            ready = select.select([], [descriptor], [], remaining)[1]
        else:
            ready = select.select([descriptor], [], [], remaining)[0]
        require(bool(ready), 'original finite owner deadline reached')

    def _write(self, body):
        view = memoryview(body)
        while view:
            self._ready(self.command_fd, write=True)
            try:
                count = os.write(self.command_fd, view)
            except InterruptedError:
                continue
            require(count > 0, 'command pipe closed')
            view = view[count:]

    def _read(self, size):
        require(type(size) is int and 0 <= size <= 65536, 'bounded IPC read')
        parts = []
        self.last_partial = b''
        left = size
        while left:
            self._ready(self.reply_fd)
            try:
                piece = os.read(self.reply_fd, min(left, 65536))
            except InterruptedError:
                continue
            if not piece:
                self.last_partial = b''.join(parts)
                raise EOFError('child reply ended inside a fixed field')
            parts.append(piece)
            left -= len(piece)
            self.last_partial = b''.join(parts)
        return b''.join(parts)

    def command(self, operation, argument=0):
        require(not self.reaped, 'dead process command')
        self.sequence += 1
        if self.profile == NATIVE_PROFILE:
            words = [EVENT_MAGIC, 2, self.nonce, operation, 0, 0, 0, 0,
                     argument, 0, 0, 0, 0, 0, 0, 0]
        else:
            words = [C_COMMAND_MAGIC, 2, self.nonce, self.sequence,
                     operation, argument] + [0]*10
        raw = struct.pack('<16Q', *words)
        identity = {'process': self.name, 'nonce': self.nonce,
                    'command': self.sequence, 'operation': operation}
        self.journal.append(dict(identity, kind='command', bytes=raw.hex()))
        self._write(raw)
        stage = 'reply'
        try:
            reply = self._read(128)
            self.journal.append(dict(identity, kind='reply', bytes=reply.hex()))
            out = struct.unpack('<16Q', reply)
            if self.profile == NATIVE_PROFILE:
                stage = 'state'
                state = self._read(1024)
                self.journal.append(dict(identity, kind='state', bytes=state.hex()))
                require(out[:3] == (OUTPUT_MAGIC, 2, self.nonce), 'native reply identity')
                size = out[9] if out[3] == 129 else 0
                require(0 <= size <= 65536, 'native result page bound')
                stage = 'payload'
                payload = self._read(size)
                self.journal.append(dict(identity, kind='payload', bytes=payload.hex()))
                return {'words': out, 'state': state, 'payload': payload}
            stage = 'snapshot'
            snapshot = self._read(48)
            self.journal.append(dict(identity, kind='snapshot', bytes=snapshot.hex()))
            require(out[:5] == (C_OUTPUT_MAGIC, 2, self.nonce,
                                self.sequence, operation), 'C reply identity')
            require(out[8] in (3046000, 3053002), 'C version domain')
            require(out[14:] == (0, 0), 'C reserved words')
            require(out[6] <= 65536, 'C active result bound')
            stage = 'payload'
            payload = self._read(out[6])
            self.journal.append(dict(identity, kind='payload', bytes=payload.hex()))
            return {'words': out, 'snapshot': snapshot, 'payload': payload}
        except BaseException as exc:
            self.journal.append(dict(identity, kind='reply_failure', stage=stage,
                                     partial=self.last_partial.hex(),
                                     error=type(exc).__name__, detail=str(exc)))
            raise

    def finish(self, expected_exit=0):
        if self.command_fd is not None:
            os.close(self.command_fd)
            self.command_fd = None
        status = None
        while status is None:
            pid, candidate = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                status = candidate
                break
            require(time.monotonic() < self.deadline, 'child exit deadline')
            select.select([], [], [], min(0.01, self.deadline-time.monotonic()))
        self.reaped = True
        code = os.waitstatus_to_exitcode(status)
        # Only after observed waitpid closure are child stderr/EOF/INDEX used.
        unexpected = os.read(self.reply_fd, 1)
        os.close(self.reply_fd)
        self.reply_fd = None
        self.thread.join(max(0, self.deadline-time.monotonic()))
        self.journal.append({'kind': 'child_waitpid', 'process': self.name,
                             'pid': self.pid, 'raw_status': status, 'exit_code': code,
                             'unexpected_reply': unexpected.hex(),
                             'collector_alive': self.thread.is_alive(),
                             'collector_error': self.capture_exception,
                             'capture': self.capture})
        require(not self.thread.is_alive(), 'audit collector did not reach terminal')
        require(self.capture_exception is None and self.capture is not None,
                'audit collector failed')
        require(self.capture['status'] == 'CAPTURE_CLOSED_PIPE', 'audit incomplete')
        require(not unexpected and code == expected_exit, 'child unexpected terminal')
        if self.profile == C_PROFILE:
            require(self.capture['complete_records'] == 6*self.sequence,
                    'C complete PRE/POST population')
        return {'process': self.name, 'pid': self.pid, 'exit_code': code,
                'commands': self.sequence, 'audit': self.capture}

    def abort_input(self):
        # Failure retention only. This never manufactures HIA CLOSE/SQL END.
        # The original outer process owner remains responsible for all children.
        if self.command_fd is not None:
            os.close(self.command_fd)
            self.command_fd = None
