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

from .hia_execution_budget import INSERT_CONTEXT
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
    (INSERT_CONTEXT, 4),
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


def _query_plan(index):
    _, count, table, mask = _SELECTS[index - 1]
    return index + 3, index, count, table, mask


def _write_plan(index, operations, magic):
    _, count = operations[index - 1]
    return 1, index, count, magic, 0


# Typed transport shares the stored operation numbers with the compatibility
# path without entering its SQL-shaped dispatch table.
_JOURNAL_LOOKUP = _query_plan(9)
_JOURNAL_RESERVE = _write_plan(6, _INSERTS, b'HIAINS01')
_JOURNAL_COMPLETE = _write_plan(1, _UPDATES, b'HIAUPB01')
_JOURNAL_COST = _write_plan(2, _INSERTS, b'HIAINS01')
_CONTEXT_LOOKUP = _query_plan(4)
_CONTEXT_CREATED = _query_plan(15)
_CONTEXT_COSTS = _query_plan(5)
_ATTEMPT_LOOKUP = _query_plan(17)
_ATTEMPT_SET = _write_plan(8, _UPDATES, b'HIAUPB01')
_WALL_BUDGET_LOOKUP = _query_plan(14)
_WALL_BUDGET_CREATE = _write_plan(5, _INSERTS, b'HIAINS01')
_WALL_BUDGET_CLAIM = _write_plan(6, _UPDATES, b'HIAUPB01')
_WALL_BUDGET_FINISH = _write_plan(7, _UPDATES, b'HIAUPB01')
_CONTEXT_CREATE = _write_plan(1, _INSERTS, b'HIAINS01')
_ARTIFACT_BY_CONTENT = _query_plan(1)
_ARTIFACT_BY_ID = _query_plan(2)
_ARTIFACT_BY_URI = _query_plan(3)
_ARTIFACT_RETAIN = _write_plan(9, _INSERTS, b'HIAINS01')
_PROFILE_LOOKUP = _query_plan(12)
_PROFILE_RETAIN = _write_plan(11, _INSERTS, b'HIAINS01')
_CURSOR_LOOKUP = _query_plan(6)
_CURSOR_ROW_LIMIT = 512
_CURSOR_RETAIN = _write_plan(10, _INSERTS, b'HIAINS01')
_SLOT_LOOKUP = _query_plan(10)
_VERSION_LOOKUP = _query_plan(13)
_SLOT_LEASE_COUNT = _query_plan(11)
_SLOT_CREATE = _write_plan(7, _INSERTS, b'HIAINS01')
_VERSION_RETAIN = _write_plan(8, _INSERTS, b'HIAINS01')
_SLOT_GENERATIONS = _query_plan(16)
_SLOT_MOVE = _write_plan(2, _UPDATES, b'HIAUPB01')
_LEASE_LOOKUP = _query_plan(8)
_LEASE_RETAIN = _write_plan(4, _INSERTS, b'HIAINS01')
_LEASE_RELEASE = _write_plan(3, _UPDATES, b'HIAUPB01')
_STATEMENTS = {
    **{row[0]: _query_plan(i) for i, row in enumerate(_SELECTS, 1)},
    **{row[0]: _write_plan(i, _INSERTS, b'HIAINS01') for i, row in enumerate(_INSERTS, 1)},
    **{row[0]: _write_plan(i, _UPDATES, b'HIAUPB01') for i, row in enumerate(_UPDATES, 1)},
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


def _parameter_cells(values):
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
        yield kind, payload


def _parameters(values, statement, magic):
    if magic is None:
        offset = 32 + 24 * len(values)
    else:
        offset = 40 + 24 * len(values)
    directory, contents = [], []
    for kind, payload in _parameter_cells(values):
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


_NATIVE_ROW_ERRORS = {
    2: 'truncated native row header',
    3: 'unexpected native row header',
    4: 'native row cell outside its extent',
    5: 'unexpected native row cell type',
    6: 'trailing bytes after native row',
}


def _native_row(codec, data, table_id, columns):
    decision = codec.row_values(table_id, columns, data)
    if decision is None:
        raise StoreProtocolError('invalid HIA Store row response')
    status, admitted = decision
    if admitted > columns or (status == 1 and admitted != columns):
        raise StoreProtocolError('invalid HIA Store row response')
    values = []
    # Decode admitted cells before reporting later wire faults, as the older
    # reader did when invalid UTF-8 preceded any later malformed cell.
    for index in range(admitted):
        kind, at, size = struct.unpack_from('<3Q', data, 32 + index * 24)
        if kind == 0:
            value = None
        elif kind == 1:
            value, = struct.unpack_from('<q', data, at)
        elif kind == 2:
            value, = struct.unpack_from('<d', data, at)
        elif kind == 3:
            value = data[at:at + size].decode('utf-8')
        else:
            value = bytes(data[at:at + size])
        values.append(value)
    if status != 1:
        raise StoreProtocolError(_NATIVE_ROW_ERRORS.get(status, 'invalid HIA Store row response'))
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


def initialize_store(root, parent, code):
    """Publish the first native namespace with the held selection lock."""
    try:
        entries = set(os.listdir(parent))
        if entries - {'artifacts'}:
            raise StoreProtocolError('native Store cannot initialize a nonempty state root')
        if 'artifacts' in entries:
            artifacts = os.open('artifacts', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                dir_fd=parent)
            try:
                info = os.fstat(artifacts)
                if info.st_uid != os.geteuid() or info.st_mode & 0o022 or os.listdir(artifacts):
                    raise StoreProtocolError('native Store cannot initialize over retained artifacts')
            finally:
                os.close(artifacts)
        with _sealed_image(code) as fd:
            image = f'/proc/self/fd/{fd}'
            receipt = subprocess.run([image, root, 'store'], stdin=subprocess.DEVNULL, capture_output=True,
                                     pass_fds=(fd,), env={'PATH': ''}, timeout=_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        raise StoreProtocolError('native Store initialization did not confirm publication') from exc
    if (receipt.returncode or receipt.stderr or len(receipt.stdout) != 256
            or struct.unpack_from('<8sQ', receipt.stdout) != (b'HIAWNA01', 1)):
        raise StoreProtocolError('native Store initialization did not confirm publication')


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
        from .hia_agent_store_transport_native import selected_store_transport
        self.codec = selected_store_transport()
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
        status, count, self.generation, *_ = self._ack(0, 0, self._deadline())
        if self.codec is None:
            admitted = status == 0
        else:
            admitted = self.codec.transaction(0, status, count, 0, self.generation) == (1, self.generation)
        if not admitted:
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
        if self.codec is None:
            header = struct.pack('<8s5Q', b'HIATCM01', 1, self.request, kind, target, len(body))
        else:
            header = self.codec.command(self.request, kind, target, len(body))
            if header is None:
                raise StoreProtocolError('native HIA Store command header refused')
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
        header = self._exact(72, deadline)
        if self.codec is not None:
            result = self.codec.acknowledgement(request, kind, magic + header)
            if result is not None:
                return list(result)
        else:
            version, actual_request, actual_kind, *result = struct.unpack('<9Q', header)
            if (version, actual_request, actual_kind) == (1, request, kind):
                return result
        raise StoreProtocolError('misordered native Store acknowledgement')

    @staticmethod
    def _reference_query_event(kind, rowid, offset, data, *, pending_id, pending_size,
                               limit, rows, unique, plan, mask):
        size = len(data)
        if kind == 1 and pending_size is None and size == 128 and offset == 0:
            return 1, 0
        if pending_size is not None and rowid == pending_id and offset == pending_size:
            if kind == 2:
                return (101 if size == 0 or size > limit - pending_size else 2), 0
            if kind == 3 and size == 0:
                return (102 if unique and rows else 3), 0
        if kind == 4 and pending_size is None and size == 416:
            observed_plan, observed_mask, total, delivered = struct.unpack_from('<4Q', data, 384)
            if (observed_plan, observed_mask, delivered) != (plan, mask, rows):
                return 103, 0
            return 4, total
        return 104, 0

    def _results(self, plan, table, mask, deadline, *, raw_row_limit=None):
        table_id = _TABLE_IDS.index(table) + 1
        columns = _COLUMNS[table]
        names = tuple(name for i, name in enumerate(columns) if mask & (1 << i))
        rows, pending, pending_id, summary = [], None, None, None
        limit = _MAX_VALUE if raw_row_limit is None else raw_row_limit
        route = self._reference_query_event if self.codec is None else self.codec.query_event
        while True:
            magic = self._exact(8, deadline)
            if magic == b'HIATXR01':
                status, *_ = self._ack(self.request, 27, deadline, magic)
                if status or pending is not None or summary is None:
                    raise StoreProtocolError('native Store query did not finish')
                return rows
            if magic != b'HIAQRF01' or summary is not None:
                raise StoreProtocolError('unexpected native Store query frame')
            header = self._exact(56, deadline)
            if self.codec is None:
                fields = struct.unpack('<7Q', header)
                if fields[1] != table_id or fields[4] > _MAX_FRAME or fields[6] != 0:
                    raise StoreProtocolError('invalid native Store query frame header')
            else:
                fields = self.codec.query_header(table_id, _MAX_FRAME, magic + header)
                if fields is None:
                    raise StoreProtocolError('invalid native Store query frame header')
            kind, _, rowid, offset, size, _, _ = fields
            data = self._exact(size, deadline)
            result = route(kind, rowid, offset, data, pending_id=pending_id,
                           pending_size=None if pending is None else len(pending),
                           limit=limit, rows=len(rows), unique=raw_row_limit is not None,
                           plan=plan, mask=mask)
            if result is None:
                raise StoreProtocolError('invalid HIA Store continuation response')
            event, total = result
            if event == 1:
                pending, pending_id = bytearray(), rowid
            elif event == 2:
                pending.extend(data)
            elif event == 3:
                if raw_row_limit is None:
                    if self.codec is None:
                        values = _row(pending, table_id, len(columns))
                    else:
                        values = _native_row(self.codec, pending, table_id, len(columns))
                    rows.append(_Row((value for i, value in enumerate(values) if mask & (1 << i)), names))
                else:
                    rows.append(bytes(pending))
                pending, pending_id = None, None
            elif event == 4:
                if plan == 11:
                    rows.append(_Row((total,), ('COUNT(*)',)))
                summary = total
            elif event == 101:
                raise StoreProtocolError('native Store row exceeds its extent')
            elif event == 102:
                raise StoreProtocolError('native Store returned two records for one key')
            elif event == 103:
                raise StoreProtocolError('native Store query projection differs')
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
            status, count, generation, *_ = self._ack(self.request, 21, deadline)
            if self.codec is None:
                admitted = status == 0 and generation >= self.generation
            else:
                admitted = self.codec.transaction(21, status, count, self.generation, generation) == (1, generation)
            if not admitted:
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
            receipt = b''
            if magic == b'HIAWTA01' and commit:
                receipt = magic + self._exact(248, deadline)
                magic = self._exact(8, deadline)
            status, count, generation, *_ = self._ack(self.request, command, deadline, magic)
            if self.codec is None:
                expected_generation = self.generation + int(commit and count != 0)
                if status or generation != expected_generation or bool(receipt) != (generation != self.generation):
                    raise StoreProtocolError('native Store transaction confirmation differs')
                if receipt and struct.unpack_from('<8s2Q', receipt, 128) != (b'HIAWAK01', 1, generation):
                    raise StoreProtocolError('native Store receipt names a different anchor')
            else:
                decision = self.codec.transaction(command, status, count, self.generation, generation, receipt)
                if decision == (4, 0):
                    raise StoreProtocolError('native Store receipt names a different anchor')
                if decision != (1, generation):
                    raise StoreProtocolError('native Store transaction confirmation differs')
        except OSError as error:
            if commit:
                raise StoreCommitUnknown('native Store commit result is unknown; reopen before observing it') from error
            raise
        self.generation = generation
        self.in_transaction = False

    def execute(self, sql, values=()):
        with self.lock:
            return self._execute(sql, values)

    def _check_live(self):
        if self.creator != os.getpid() or self.closed or self.failed:
            raise StoreProtocolError('native Store connection is no longer usable')

    def journal_lookup(self, key):
        return self._typed_operation(_JOURNAL_LOOKUP, (key,)).fetchone()

    def journal_reserve(self, key, digest, tool, started_ns):
        self._typed_operation(_JOURNAL_RESERVE, (key, digest, tool, 'running', None, started_ns))

    def journal_complete(self, key, response):
        self._typed_operation(_JOURNAL_COMPLETE, (response, key))

    def journal_cost(self, context, tool, request_id, wall_ns, status, details):
        self._typed_operation(_JOURNAL_COST, (context, tool, request_id, wall_ns, status, details))

    def context_lookup(self, context):
        return self._typed_operation(_CONTEXT_LOOKUP, (context,)).fetchone()

    def context_created(self, context):
        return self._typed_operation(_CONTEXT_CREATED, (context,)).fetchone()

    def context_costs(self, context):
        return self._typed_operation(_CONTEXT_COSTS, (context,)).fetchall()

    def attempt_lookup(self, context):
        return self._typed_operation(_ATTEMPT_LOOKUP, (context,)).fetchone()

    def attempt_set(self, updated, context, previous):
        return self._typed_operation(_ATTEMPT_SET, (updated, context, previous)).rowcount

    def wall_budget_lookup(self, context):
        return self._typed_operation(_WALL_BUDGET_LOOKUP, (context,)).fetchone()

    def wall_budget_create(self, context, used):
        return self._typed_operation(_WALL_BUDGET_CREATE, (context, used)).rowcount

    def wall_budget_claim(self, owner, context, used):
        return self._typed_operation(_WALL_BUDGET_CLAIM, (owner, context, used)).rowcount

    def wall_budget_finish(self, updated, context, used, owner):
        return self._typed_operation(_WALL_BUDGET_FINISH, (updated, context, used, owner)).rowcount

    def context_create(self, context, digest, artifact, started_ns):
        return self._typed_operation(_CONTEXT_CREATE, (context, digest, artifact, started_ns)).rowcount

    def artifact_by_content(self, key):
        return self._typed_operation(_ARTIFACT_BY_CONTENT, (key,)).fetchone()

    def artifact_by_id(self, identity):
        return self._typed_operation(_ARTIFACT_BY_ID, (identity,)).fetchone()

    def artifact_lookup_frame(self, payload):
        return self._lookup_frame(_ARTIFACT_BY_ID, payload, 192, _MAX_VALUE)

    def artifact_by_uri(self, uri):
        return self._typed_operation(_ARTIFACT_BY_URI, (uri,)).fetchone()

    def resource_lookup_frame(self, payload):
        return self._lookup_frame(_ARTIFACT_BY_URI, payload, 208, _MAX_VALUE)

    def artifact_retain(self, identity, digest, uri, kind, metadata, key):
        self._typed_operation(_ARTIFACT_RETAIN, (identity, digest, uri, kind, metadata, key))

    def profile_lookup(self, identity, digest):
        return self._typed_operation(_PROFILE_LOOKUP, (identity, digest)).fetchone()

    def profile_retain(self, identity, digest, artifact):
        self._typed_operation(_PROFILE_RETAIN, (identity, digest, artifact))

    def cursor_lookup(self, identity):
        return self._typed_operation(_CURSOR_LOOKUP, (identity,)).fetchone()

    def cursor_lookup_frame(self, payload):
        return self._lookup_frame(_CURSOR_LOOKUP, payload, 2048, _CURSOR_ROW_LIMIT)

    def _lookup_frame(self, specification, payload, key_limit, row_limit):
        if (not 56 < len(payload) <= 56 + key_limit
                or struct.unpack_from('<8s6Q', payload)
                != (b'HIAQPA01', 1, 1, len(payload), 3, 56, len(payload) - 56)):
            raise StoreProtocolError('invalid HIA Agent read lookup frame')
        with self.lock:
            self._check_live()
            return self._perform(specification, (), raw_row_limit=row_limit,
                                 payload=payload).fetchone()

    def cursor_retain_frame(self, payload):
        if (not 278 <= len(payload) <= 533
                or struct.unpack_from('<8s4Q', payload) != (b'HIAINS01', 1, 10, 0, 4)):
            raise StoreProtocolError('invalid HIA Agent cursor retain frame')
        with self.lock:
            self._check_live()
            self._perform(_CURSOR_RETAIN, (), payload=payload)

    def cursor_retain(self, identity, artifact, digest, offset):
        self._typed_operation(_CURSOR_RETAIN, (identity, artifact, digest, offset))

    def slot_lookup(self, slot):
        return self._typed_operation(_SLOT_LOOKUP, (slot,)).fetchone()

    def version_lookup(self, slot, generation):
        return self._typed_operation(_VERSION_LOOKUP, (slot, generation)).fetchone()

    def slot_lease_count(self, slot):
        return self._typed_operation(_SLOT_LEASE_COUNT, (slot,)).fetchone()[0]

    def slot_create(self, slot, context, generation, epoch, abi):
        self._typed_operation(_SLOT_CREATE, (slot, context, generation, epoch, abi))

    def version_retain(self, slot, generation, artifact):
        self._typed_operation(_VERSION_RETAIN, (slot, generation, artifact))

    def slot_generations(self, slot):
        return self._typed_operation(_SLOT_GENERATIONS, (slot,))

    def slot_move(self, generation, epoch, context, slot):
        self._typed_operation(_SLOT_MOVE, (generation, epoch, context, slot))

    def lease_lookup(self, identity):
        return self._typed_operation(_LEASE_LOOKUP, (identity,)).fetchone()

    def lease_retain(self, identity, slot, generation, artifact):
        self._typed_operation(_LEASE_RETAIN, (identity, slot, generation, artifact))

    def lease_release(self, identity):
        self._typed_operation(_LEASE_RELEASE, (identity,))

    def _typed_operation(self, specification, values, *, raw_row_limit=None):
        with self.lock:
            self._check_live()
            return self._perform(specification, values, raw_row_limit=raw_row_limit)

    def begin_immediate(self):
        self._transaction_command(begin=True)

    def commit(self):
        self._transaction_command(commit=True)

    def rollback(self):
        self._transaction_command()

    def _transaction_command(self, *, begin=False, commit=False):
        with self.lock:
            self._check_live()
            try:
                if begin:
                    self._begin()
                else:
                    self._finish(commit)
            except OSError:
                self._abort()
                raise

    def _execute(self, sql, values):
        self._check_live()
        if sql in ('BEGIN IMMEDIATE', 'COMMIT', 'ROLLBACK'):
            self._transaction_command(begin=sql == 'BEGIN IMMEDIATE', commit=sql == 'COMMIT')
            return _Cursor()
        specification = _STATEMENTS.get(sql)
        if specification is None:
            raise StoreRefusal('not an Agent Store statement')
        return self._perform(specification, values)

    def _perform(self, specification, values, *, raw_row_limit=None, payload=None):
        command, plan, arity, table, mask = specification
        if payload is None:
            if len(values) != arity:
                raise StoreRefusal('incorrect Agent Store bindings')
            form = table if command == 1 else None
            if self.codec is None:
                payload = _parameters(values, plan, form)
            else:
                payload = self.codec.parameters(plan, form, tuple(_parameter_cells(values)), _MAX_VALUE)
                if payload is None:
                    raise ValueError('Agent Store binding exceeds native extent')
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
                result = _Cursor(self._results(plan, table, mask, deadline,
                                               raw_row_limit=raw_row_limit))
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
