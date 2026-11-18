"""Transport the Agent's existing Store operations to an installed HIA engine.

This is a fixed vocabulary, not a SQL interpreter. The ELF owns transactions,
ordering, predicates, constraints, projection, and durable publication. The
hosted Agent still owns tool methods and translates their typed bindings.
"""
from contextlib import contextmanager
from hashlib import sha256
import fcntl
import os
from pathlib import Path
import select
import stat
import struct
import subprocess
import time
from threading import RLock

from .hia_native_helpers import _read

RELEASE_IMAGES = (
    ('hia-agent-store', 16 << 20),
    ('hia-artifact', 1 << 20),
    ('hia-agent-artifact-capture', 1 << 20),
)

_COLUMNS = {
    'artifacts': ('id', 'sha256', 'uri', 'kind', 'metadata', 'content_key'),
    'contexts': ('id', 'sha256', 'artifact', 'created_ns', 'attempts'),
    'costs': ('sequence', 'context_id', 'tool', 'request_id', 'wall_ns', 'status', 'details'),
    'cursors': ('id', 'artifact_id', 'sha256', 'offset'),
    'execution_budgets': ('context_id', 'used_native_ns', 'owner'),
    'leases': ('id', 'slot', 'generation', 'artifact', 'active'),
    'requests': ('key', 'digest', 'tool', 'state', 'response', 'started_ns'),
    'slots': ('name', 'context_id', 'generation', 'epoch', 'abi_sha256'),
    'profiles': ('id', 'sha256', 'artifact'),
    'versions': ('slot', 'generation', 'artifact'),
}
# Statement order is the native operation number minus one; keep it independent
# of call order. Projection is per table's physical column order.
_SELECTS = (
    ('SELECT * FROM artifacts WHERE content_key=?', 1, 'artifacts', 63),
    ('SELECT * FROM artifacts WHERE id=?', 1, 'artifacts', 63),
    ('SELECT * FROM artifacts WHERE uri=?', 1, 'artifacts', 63),
    ('SELECT * FROM contexts WHERE id=?', 1, 'contexts', 31),
    ('SELECT * FROM costs WHERE context_id=? OR context_id IS NULL ORDER BY sequence LIMIT 10001', 1, 'costs', 127),
    ('SELECT * FROM cursors WHERE id=?', 1, 'cursors', 15),
    ('SELECT * FROM execution_budgets WHERE context_id=?', 1, 'execution_budgets', 7),
    ('SELECT * FROM leases WHERE id=?', 1, 'leases', 31),
    ('SELECT * FROM requests WHERE key=?', 1, 'requests', 63),
    ('SELECT * FROM slots WHERE name=?', 1, 'slots', 31),
    ('SELECT COUNT(*) FROM leases WHERE slot=? AND active=1', 1, 'leases', 0),
    ('SELECT artifact FROM profiles WHERE id=? AND sha256=?', 2, 'profiles', 4),
    ('SELECT artifact FROM versions WHERE slot=? AND generation=?', 2, 'versions', 4),
    ('SELECT context_id,used_native_ns,owner FROM main.execution_budgets WHERE context_id=?', 1, 'execution_budgets', 7),
    ('SELECT created_ns FROM contexts WHERE id=?', 1, 'contexts', 8),
    ('SELECT generation FROM versions WHERE slot=?', 1, 'versions', 2),
    ('SELECT id,attempts FROM main.contexts WHERE id=?', 1, 'contexts', 17),
)
_INSERTS = (
    ('INSERT INTO contexts VALUES (?,?,?,?,0)', 4),
    ('INSERT INTO costs (context_id,tool,request_id,wall_ns,status,details) VALUES (?,?,?,?,?,?)', 6),
    ("INSERT INTO execution_budgets VALUES (?,'0',NULL)", 1),
    ('INSERT INTO leases VALUES (?,?,?,?,1)', 4),
    ('INSERT INTO main.execution_budgets(context_id,used_native_ns,owner) VALUES (?,?,NULL)', 2),
    ('INSERT INTO requests VALUES (?,?,?,?,?,?)', 6),
    ('INSERT INTO slots VALUES (?,?,?,?,?)', 5),
    ('INSERT INTO versions VALUES (?,?,?)', 3),
    ('INSERT OR IGNORE INTO artifacts VALUES (?,?,?,?,?,?)', 6),
    ('INSERT OR IGNORE INTO cursors VALUES (?,?,?,?)', 4),
    ('INSERT OR IGNORE INTO profiles VALUES (?,?,?)', 3),
)
_UPDATES = (
    ("UPDATE requests SET state='completed',response=? WHERE key=?", 2),
    ('UPDATE slots SET generation=?,epoch=?,context_id=? WHERE name=?', 4),
    ('UPDATE leases SET active=0 WHERE id=?', 1),
    ('UPDATE execution_budgets SET owner=NULL,used_native_ns=? WHERE context_id=? AND owner=?', 3),
    ('UPDATE execution_budgets SET owner=? WHERE context_id=?', 2),
    ('UPDATE main.execution_budgets SET owner=? WHERE context_id=? AND used_native_ns=? AND owner IS NULL', 3),
    ('UPDATE main.execution_budgets SET owner=NULL,used_native_ns=? WHERE context_id=? AND used_native_ns=? AND owner=?', 4),
    ('UPDATE main.contexts SET attempts=? WHERE id=? AND attempts=?', 3),
    ('UPDATE contexts SET attempts=attempts+1 WHERE id=? AND attempts<?', 2),
)
_STATEMENTS = {
    **{sql: (i + 3, i, count, table, mask)
       for i, (sql, count, table, mask) in enumerate(_SELECTS, 1)},
    **{sql: (1, i, count, b'HIAINS01', 0)
       for i, (sql, count) in enumerate(_INSERTS, 1)},
    **{sql: (1, i, count, b'HIAUPB01', 0)
       for i, (sql, count) in enumerate(_UPDATES, 1)},
}
_TABLE_IDS = ('artifacts', 'profiles', 'contexts', 'requests', 'costs',
              'cursors', 'slots', 'versions', 'leases', 'execution_budgets')
_MAX_FRAME = 8128
_MAX_VALUE = 1000000032
_TIMEOUT = 10.0


class StoreProtocolError(OSError):
    """No exact transport reply, or the admission state can no longer be used."""


class StoreCommitUnknown(StoreProtocolError):
    """A commit was sent but was not conclusively acknowledged."""


class StoreRefusal(Exception):
    """A typed statement or transaction was refused without losing transport custody."""


class _Row(tuple):
    def __new__(cls, values, names):
        row = super().__new__(cls, values)
        row.names = names
        return row

    def __getitem__(self, key):
        if isinstance(key, str):
            try:
                key = self.names.index(key)
            except ValueError:
                raise IndexError('No item with that key') from None
        return super().__getitem__(key)

    def keys(self):
        return list(self.names)


class _Cursor:
    def __init__(self, rows=(), rowcount=-1):
        self.rows = iter(rows)
        self.rowcount = rowcount

    def fetchone(self):
        return next(self.rows, None)

    def fetchall(self):
        return list(self.rows)

    def __iter__(self):
        return self.rows


def _parameters(values, statement, magic):
    if magic is None:
        offset = 32 + 24 * len(values)
    else:
        offset = 40 + 24 * len(values)
    directory, contents = [], []
    for value in values:
        if value is None:
            kind, payload = 0, b''
        elif isinstance(value, int):
            kind, payload = 1, struct.pack('<q', value)
        elif isinstance(value, float):
            kind, payload = 2, struct.pack('<d', value)
        elif isinstance(value, str):
            kind, payload = 3, value.encode('utf-8')
        elif isinstance(value, bytes):
            kind, payload = 4, value
        else:
            raise TypeError('unsupported Agent Store binding')
        directory.append(struct.pack('<3Q', kind, offset, len(payload)))
        contents.append(payload)
        offset += len(payload)
    if offset > _MAX_VALUE:
        raise ValueError('Agent Store binding exceeds native extent')
    if magic is None:
        header = struct.pack('<8s3Q', b'HIAQPA01', 1, len(values), offset)
    else:
        header = struct.pack('<8s4Q', magic, 1, statement, 0, len(values))
    return b''.join((header, *directory, *contents))


def _row(data, table_id, columns):
    if len(data) < 32:
        raise StoreProtocolError('truncated native row header')
    magic, version, table, count = struct.unpack_from('<8s3Q', data)
    offset = 32 + 24 * count
    if (magic, version, table, count) != (b'HIAROW01', 1, table_id, columns) or len(data) < offset:
        raise StoreProtocolError('unexpected native row header')
    values = []
    for i in range(count):
        kind, at, size = struct.unpack_from('<3Q', data, 32 + i * 24)
        if at != offset or size > len(data) - offset:
            raise StoreProtocolError('native row cell outside its extent')
        payload = data[at:at + size]
        if kind == 0 and size == 0:
            value = None
        elif kind == 1 and size == 8:
            value, = struct.unpack('<q', payload)
        elif kind == 2 and size == 8:
            value, = struct.unpack('<d', payload)
        elif kind == 3:
            value = payload.decode('utf-8')
        elif kind == 4:
            value = bytes(payload)
        else:
            raise StoreProtocolError('unexpected native row cell type')
        values.append(value)
        offset += size
    if offset != len(data):
        raise StoreProtocolError('trailing bytes after native row')
    return values


@contextmanager
def _sealed_image(code):
    fd = os.memfd_create('hia-agent-store', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        # Direct argv mode requires fd 3 through 36 to be free on entry.
        child_fd = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 37)
        try:
            payload = memoryview(code)
            while payload:
                size = os.write(child_fd, payload)
                if size <= 0:
                    raise StoreProtocolError('cannot write the admitted native Store image')
                payload = payload[size:]
            seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
            fcntl.fcntl(child_fd, fcntl.F_ADD_SEALS, seals)
            if (fcntl.fcntl(child_fd, fcntl.F_GET_SEALS) != seals
                    or os.fstat(child_fd).st_size != len(code)
                    or os.pread(child_fd, len(code), 0) != code):
                raise StoreProtocolError('native Store executable changed before sealing')
            yield child_fd
        finally:
            os.close(child_fd)
    finally:
        os.close(fd)


def release_identity(release):
    info = release.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o500 or release.resolve() != release):
        raise StoreProtocolError('native Store release must be an owned sealed directory')
    return info.st_dev, info.st_ino, info.st_ctime_ns


def capture_release_image(release, name, limit, digest):
    captured = _read(release / name, limit)
    code = captured.raw
    if (sha256(code).hexdigest() != digest or len(code) < 176
            or code[:7] != b'\x7fELF\x02\x01\x01' or struct.unpack_from('<2H', code, 16) != (2, 62)):
        raise StoreProtocolError(f'native Store executable identity differs: {name}')
    return captured


class NativeStoreConnection:
    """A serialized connection to an explicitly installed, already initialized Store."""

    def __init__(self, state_root, release, digest, artifact_digest, capture_digest, *, lock=None):
        self.lock = lock if lock is not None else RLock()
        self.root = Path(state_root)
        self.release = Path(release).absolute()
        release_identity(self.release)
        # The module loader independently authenticates every module against this
        # pinned executable. It never interprets a path from a public request.
        pins = (digest, artifact_digest, capture_digest)
        self.code, self.artifact_code, self.capture_code = (
            capture_release_image(self.release, name, limit, pin).raw
            for (name, limit), pin in zip(RELEASE_IMAGES, pins, strict=True)
        )
        self.creator = os.getpid()
        self.namespace = self._namespace_files()
        self.process = None
        self.request = 0
        self.in_transaction = False
        self.generation = None
        self.failed = False
        self.closed = False

    def _namespace_files(self):
        namespace = self.root / 'store'
        roles = ((self.root, stat.S_ISDIR), (namespace, stat.S_ISDIR),
                 (namespace / 'namespace.bin', stat.S_ISREG),
                 (namespace / 'wal.lock', stat.S_ISREG), (namespace / 'wal.data', stat.S_ISREG))
        identity = []
        for path, correct_type in roles:
            info = path.lstat()
            if not correct_type(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise StoreProtocolError('native Store namespace is not owned ordinary state')
            identity.append((info.st_dev, info.st_ino))
            if path.name == 'namespace.bin':
                identity.append((info.st_size, info.st_mtime_ns, info.st_ctime_ns))
        return tuple(identity)

    def check_custody(self):
        if self.creator != os.getpid() or self.closed or self.failed:
            raise StoreProtocolError('native Store connection no longer has custody')
        if self._namespace_files() != self.namespace:
            raise StoreProtocolError('native Store namespace identity changed')

    def _open(self):
        with _sealed_image(self.code) as fd:
            image = f'/proc/self/fd/{fd}'
            self.process = subprocess.Popen(
                [image, self.root, 'store', self.release],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                bufsize=0, pass_fds=(fd,), env={'PATH': ''})
        self.request = 0
        os.set_blocking(self.process.stdin.fileno(), False)
        os.set_blocking(self.process.stdout.fileno(), False)
        status, _, self.generation, *_ = self._ack(0, 0, self._deadline())
        if status != 0:
            raise StoreProtocolError('native Store rejected connection readiness')

    @staticmethod
    def _deadline():
        return time.monotonic() + _TIMEOUT

    @staticmethod
    def _wait(fd, deadline, writing=False):
        remaining = deadline - time.monotonic()
        if remaining > 0:
            poller = select.poll()
            poller.register(fd, select.POLLOUT if writing else select.POLLIN)
            if poller.poll(max(1, int(1000 * remaining))):
                return
        raise StoreProtocolError('native Store transport deadline exceeded')

    def _send(self, kind, deadline, target=0, body=b''):
        self.request += 1
        fd = self.process.stdin.fileno()
        header = struct.pack('<8s5Q', b'HIATCM01', 1, self.request, kind, target, len(body))
        for chunk in (header, body):
            view = memoryview(chunk)
            while view:
                self._wait(fd, deadline, writing=True)
                try:
                    size = os.write(fd, view)
                except BlockingIOError:
                    continue
                if size <= 0:
                    raise StoreProtocolError('native Store command pipe made no progress')
                view = view[size:]

    def _exact(self, extent, deadline):
        fd = self.process.stdout.fileno()
        output = bytearray()
        while len(output) < extent:
            self._wait(fd, deadline)
            try:
                chunk = os.read(fd, extent - len(output))
            except BlockingIOError:
                continue
            if not chunk:
                raise StoreProtocolError('native Store exited before a complete reply')
            output.extend(chunk)
        return bytes(output)

    def _ack(self, request, kind, deadline, magic=None):
        if magic is None:
            magic = self._exact(8, deadline)
        if magic != b'HIATXR01':
            raise StoreProtocolError('native Store reply was not an acknowledgement')
        version, actual_request, actual_kind, *result = struct.unpack('<9Q', self._exact(72, deadline))
        if (version, actual_request, actual_kind) != (1, request, kind):
            raise StoreProtocolError('misordered native Store acknowledgement')
        return result

    def _results(self, plan, table, mask, deadline):
        table_id = _TABLE_IDS.index(table) + 1
        columns = _COLUMNS[table]
        names = tuple(name for i, name in enumerate(columns) if mask & (1 << i))
        rows, pending, summary = [], None, None
        while True:
            magic = self._exact(8, deadline)
            if magic == b'HIATXR01':
                status, *_ = self._ack(self.request, 27, deadline, magic)
                if status or pending is not None or summary is None:
                    raise StoreProtocolError('native Store query did not finish')
                return rows
            if magic != b'HIAQRF01' or summary is not None:
                raise StoreProtocolError('unexpected native Store query frame')
            kind, observed_table, rowid, offset, size, _, reserved = struct.unpack('<7Q', self._exact(56, deadline))
            if observed_table != table_id or reserved != 0 or size > _MAX_FRAME:
                raise StoreProtocolError('invalid native Store query frame header')
            data = self._exact(size, deadline)
            if kind == 1 and pending is None and size == 128 and offset == 0:
                pending, pending_id = bytearray(), rowid
            elif kind == 2 and pending is not None and rowid == pending_id and offset == len(pending):
                if size == 0 or size > _MAX_VALUE - len(pending):
                    raise StoreProtocolError('native Store row exceeds its extent')
                pending.extend(data)
            elif kind == 3 and pending is not None and rowid == pending_id and offset == len(pending) and size == 0:
                values = _row(pending, table_id, len(columns))
                rows.append(_Row((value for i, value in enumerate(values) if mask & (1 << i)), names))
                pending = None
            elif kind == 4 and pending is None and len(data) == 416:
                observed_plan, observed_mask, total, delivered = struct.unpack_from('<4Q', data, 384)
                if (observed_plan, observed_mask, delivered) != (plan, mask, len(rows)):
                    raise StoreProtocolError('native Store query projection differs')
                if plan == 11:
                    rows.append(_Row((total,), ('COUNT(*)',)))
                summary = total
            else:
                raise StoreProtocolError('misordered native Store query frames')

    def _begin(self):
        if self.in_transaction:
            raise StoreRefusal('cannot start a transaction within a transaction')
        self.check_custody()
        if self.process is None:
            self._open()
        else:
            deadline = self._deadline()
            self._send(21, deadline)
            status, _, generation, *_ = self._ack(self.request, 21, deadline)
            if status or generation < self.generation:
                raise StoreProtocolError('native Store rejected transaction readiness')
            self.generation = generation
        self.in_transaction = True

    def _finish(self, commit):
        if not self.in_transaction:
            raise StoreRefusal('no Agent Store transaction is active')
        deadline = self._deadline()
        command = 2 if commit else 3
        try:
            self._send(command, deadline)
            magic = self._exact(8, deadline)
            receipt = None
            if magic == b'HIAWTA01' and commit:
                receipt = self._exact(248, deadline)
                magic = self._exact(8, deadline)
            status, count, generation, *_ = self._ack(self.request, command, deadline, magic)
            expected_generation = self.generation + int(commit and count != 0)
            if status or generation != expected_generation or bool(receipt) != (generation != self.generation):
                raise StoreProtocolError('native Store transaction confirmation differs')
            if receipt and struct.unpack_from('<8s2Q', receipt, 120) != (b'HIAWAK01', 1, generation):
                raise StoreProtocolError('native Store receipt names a different anchor')
        except OSError as error:
            if commit:
                raise StoreCommitUnknown('native Store commit result is unknown; reopen before observing it') from error
            raise
        self.generation = generation
        self.in_transaction = False

    def execute(self, sql, values=()):
        with self.lock:
            return self._execute(sql, values)

    def _execute(self, sql, values):
        if self.creator != os.getpid() or self.closed or self.failed:
            raise StoreProtocolError('native Store connection is no longer usable')
        if sql in ('BEGIN IMMEDIATE', 'COMMIT', 'ROLLBACK'):
            try:
                if sql == 'BEGIN IMMEDIATE':
                    self._begin()
                else:
                    self._finish(sql == 'COMMIT')
            except OSError:
                self._abort()
                raise
            return _Cursor()
        specification = _STATEMENTS.get(sql)
        if specification is None:
            raise StoreRefusal('not an Agent Store statement')
        command, plan, arity, table, mask = specification
        if len(values) != arity:
            raise StoreRefusal('incorrect Agent Store bindings')
        payload = _parameters(values, plan, table if command == 1 else None)
        local = not self.in_transaction
        try:
            if local:
                self._begin()
            deadline = self._deadline()
            self._send(27, deadline, command, payload)
            if command == 1:
                status, _, _, skipped, _, _ = self._ack(self.request, 27, deadline)
                if status in (5, 22):
                    raise StoreRefusal('native Agent Store constraint failed')
                if status or skipped not in (0, 1):
                    raise StoreProtocolError('native Agent Store refused write')
                result = _Cursor(rowcount=1 - skipped)
            else:
                result = _Cursor(self._results(plan, table, mask, deadline))
            if local:
                self._finish(command == 1)
            return result
        except (OSError, UnicodeError):
            self._abort()
            raise
        except StoreRefusal:
            if local:
                try:
                    self._finish(False)
                except OSError:
                    self._abort()
                    raise
            raise

    def _abort(self):
        self.failed = True
        self.close()

    def close(self):
        if self.creator != os.getpid():
            raise StoreProtocolError('native Store connection belongs to its creator process')
        with self.lock:
            self._close()

    def _close(self):
        if self.closed:
            return
        self.closed = True
        self.in_transaction = False
        process = self.process
        if process is None:
            return
        process.stdin.close()
        if self.failed:
            process.kill()
        try:
            status = process.wait(timeout=_TIMEOUT)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait()
            raise StoreProtocolError('native Store did not close') from error
        finally:
            process.stdout.close()
        if status and not self.failed:
            raise StoreProtocolError('native Store did not close cleanly')
