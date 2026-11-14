"""HIA-owned AgentStore lifecycle with fixed Python object/SQLite effects.

The native image selects every branch, effect, cleanup and rethrow. The driver
implements only the continuation protocol and CPython's active-exception
mechanism. SQLite, Path, stat, object protocols and the budget provider remain
foreign dependencies; this is not a native SQLite implementation.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import struct
import threading

from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/store_lifecycle.hepta')
SCHEMA = 'hepta.hia.store-lifecycle-native.v1'
SELECTOR = 'HEPTA_HIA_STORE_LIFECYCLE_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIASLRQ1', 'little')
RESULT_MAGIC = int.from_bytes(b'HIASLRS1', 'little')
STATE_BYTES = 128
OUTPUT_BYTES = 80
_FRAME_CUSTODY = {}
_CUSTODY_LOCK = threading.Lock()
_CUSTODY_PID = os.getpid()
SCHEMA_SQL = '\n            CREATE TABLE IF NOT EXISTS artifacts (\n                id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, uri TEXT UNIQUE NOT NULL,\n                kind TEXT NOT NULL, metadata TEXT NOT NULL, content_key TEXT UNIQUE NOT NULL\n            );\n            CREATE TABLE IF NOT EXISTS profiles (\n                id TEXT NOT NULL, sha256 TEXT NOT NULL, artifact TEXT NOT NULL,\n                PRIMARY KEY (id,sha256)\n            );\n            CREATE TABLE IF NOT EXISTS contexts (\n                id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, artifact TEXT NOT NULL,\n                created_ns TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0\n            );\n            CREATE TABLE IF NOT EXISTS requests (\n                key TEXT PRIMARY KEY, digest TEXT NOT NULL, tool TEXT NOT NULL,\n                state TEXT NOT NULL, response TEXT, started_ns TEXT NOT NULL\n            );\n            CREATE TABLE IF NOT EXISTS costs (\n                sequence INTEGER PRIMARY KEY AUTOINCREMENT, context_id TEXT,\n                tool TEXT NOT NULL, request_id TEXT NOT NULL, wall_ns TEXT NOT NULL,\n                status TEXT NOT NULL, details TEXT NOT NULL\n            );\n            CREATE TABLE IF NOT EXISTS cursors (\n                id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL,\n                sha256 TEXT NOT NULL, offset INTEGER NOT NULL\n            );\n            CREATE TABLE IF NOT EXISTS slots (\n                name TEXT PRIMARY KEY, context_id TEXT NOT NULL,\n                generation TEXT NOT NULL, epoch TEXT NOT NULL, abi_sha256 TEXT NOT NULL\n            );\n            CREATE TABLE IF NOT EXISTS versions (\n                slot TEXT NOT NULL, generation TEXT NOT NULL, artifact TEXT NOT NULL,\n                PRIMARY KEY (slot,generation)\n            );\n            CREATE TABLE IF NOT EXISTS leases (\n                id TEXT PRIMARY KEY, slot TEXT NOT NULL, generation TEXT NOT NULL,\n                artifact TEXT NOT NULL, active INTEGER NOT NULL\n            );\n            CREATE TABLE IF NOT EXISTS execution_budgets (\n                context_id TEXT PRIMARY KEY, used_native_ns TEXT NOT NULL,\n                owner TEXT\n            );\n            '


class StoreLifecycleUnknown(RuntimeError):
    """A claim or observation is unconfirmed; the frame cannot be replayed."""


def _after_fork_child():
    global _CUSTODY_LOCK, _CUSTODY_PID
    # A vanished parent thread may have held the old lock at fork. Replacing
    # this representation lock does not retire or close any inherited owner.
    _CUSTODY_LOCK = threading.Lock()
    _CUSTODY_PID = os.getpid()


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_after_fork_child)


def _custody_lock():
    # Check before acquiring: even a failed at-fork callback must not make a
    # child wait forever on a lock held by a vanished thread.
    if os.getpid() != _CUSTODY_PID:
        raise StoreLifecycleUnknown('lifecycle custody lock was not established in this process')
    return _CUSTODY_LOCK


class NativeStoreLifecycleImage(NativeHiaJsonImage):
    pass


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('duplicate store-lifecycle manifest field')
        value[key] = item
    return value


def _regular_bytes(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb', buffering=8192) as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError('store-lifecycle input must be a bounded ordinary file')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields):
        raise ValueError('store-lifecycle input changed while being read')
    return raw


@lru_cache(maxsize=3)
def _mapped_lifecycle(raw, expected):
    return NativeStoreLifecycleImage(raw, expected)


def installed_store_lifecycle(manifest_path):
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeStoreLifecycleImage)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid store-lifecycle manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or Path(name).name != name or any(ord(char) < 32 for char in name)):
        raise ValueError('store-lifecycle image must be a sibling basename')
    source = _regular_bytes(SOURCE, 8 << 20)
    image_path = path.parent / name
    image = _regular_bytes(image_path, 1 << 20)
    if sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('store-lifecycle source identity mismatch')
    if sha256(image).hexdigest() != value['image_sha256']:
        raise ValueError('store-lifecycle image identity mismatch')
    if selected is None:
        selected = _mapped_lifecycle(image, value['image_sha256'])
    elif type(selected) is not NativeStoreLifecycleImage or selected.image_sha256 != value['image_sha256']:
        raise ValueError('store-lifecycle selection differs from pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source
            or _regular_bytes(image_path, 1 << 20) != image):
        raise ValueError('store-lifecycle selection changed during admission')
    return selected


@dataclass(frozen=True)
class LifecycleReceipt:
    port: int
    sequence: int
    phase: int
    mode: int
    suffix: int
    depth: int


class LifecycleFrame:
    def __init__(self, image, mode, store, root=None, *, namespace=None):
        if type(image) is not NativeStoreLifecycleImage or type(mode) is not int or mode not in (1, 2):
            raise StoreLifecycleUnknown('lifecycle image or public mode differs')
        if namespace is None:
            from . import hia_agent_store
            namespace = vars(hia_agent_store)
        self.image, self.mode, self.namespace = image, mode, namespace
        self.store, self.root_argument = store, root
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.creator, self.thread = os.getpid(), threading.get_ident()
        self.buffer = ctypes.create_string_buffer(STATE_BYTES)
        self.receipt = None
        self.fenced = False
        self.unconfirmed = False
        self.errors = []
        # Grow custody before the first possible foreign effect. Allocation
        # failure cannot occur after an unrecorded effect, and no fixed count
        # excludes otherwise admitted parallel/reentrant Store lifetimes.
        # An unconfirmed
        # continuation keeps its actual Python/SQLite owners until process
        # termination, rather than letting GC invent an unrecorded close.
        with _custody_lock():
            _FRAME_CUSTODY[id(self)] = self
        self.call(0)

    def call(self, event, observation=0):
        if self.fenced or os.getpid() != self.creator or threading.get_ident() != self.thread:
            raise StoreLifecycleUnknown('lifecycle frame cannot be resumed or inherited')
        try:
            sequence, port = (0, 0) if self.receipt is None else (self.receipt.sequence, self.receipt.port)
            numbers = (REQUEST_MAGIC, event, sequence, port, observation, self.mode, *self.identity, 0, 0)
            if any(type(value) is not int or not 0 <= value < 1 << 64 for value in numbers):
                raise StoreLifecycleUnknown('lifecycle observation is not an exact ABI integer')
            raw = struct.pack('<10Q', *numbers)
            source = ctypes.create_string_buffer(raw, len(raw))
            output = ctypes.create_string_buffer(OUTPUT_BYTES)
            code = self.image._entry(source, len(raw), output, OUTPUT_BYTES, self.buffer, STATE_BYTES)
            if type(code) is not int or code != OUTPUT_BYTES or source.raw != raw:
                raise StoreLifecycleUnknown('lifecycle machine return is unconfirmed')
            words = struct.unpack('<10Q', output.raw)
            state = struct.unpack('<16Q', self.buffer.raw)
            if (words[0] != RESULT_MAGIC or words[1] > 1
                    or words[2:8] != (state[3], state[4], state[5], state[2], state[8], state[9])
                    or words[8:10] != self.identity or tuple(state[6:8]) != self.identity
                    or words[5] != self.mode or not 1 <= words[3] <= 128
                    or not 1 <= words[4] <= 6 or words[6] > 1 or words[7] > 3):
                raise StoreLifecycleUnknown('lifecycle receipt differs from its issued state')
            if words[1] or words[4] == 6:
                raise StoreLifecycleUnknown('lifecycle native claim or observation refused')
            receipt = LifecycleReceipt(*words[2:8])
            self.receipt = receipt
            return receipt
        except BaseException:
            self.fenced = True
            self.unconfirmed = True
            raise

    def drive(self):
        """The protocol's POP/PROPAGATE instructions use real except regions.

        A cleanup operation executes with the original exception active. A
        note operation executes with the cleanup exception active. POP exits
        exactly that handler before PROPAGATE reraises the original identity.
        No Python branch here chooses a Store policy or cleanup operation.
        """
        while True:
            phase = self.receipt.phase
            if phase in (3, 4, 5):
                return phase
            if phase != 1:
                self.fenced = True
                self.unconfirmed = True
                raise StoreLifecycleUnknown('lifecycle continuation was already claimed')
            self.call(1)
            try:
                observed = self.effect(self.receipt.port)
            except BaseException as error:
                self.errors.append(error)
                self.call(3)
                outcome = self.drive()
                if outcome == 3:
                    self.call(4)
                    self.errors.pop()
                    continue
                if outcome == 5:
                    self.errors.pop()
                    raise
                self.fenced = True
                self.unconfirmed = True
                raise StoreLifecycleUnknown('lifecycle exception continuation returned normally')
            else:
                self.call(2, 0 if observed is None else observed)

    def finish(self):
        returned = False
        try:
            if self.drive() != 4 or self.errors:
                self.unconfirmed = True
                raise StoreLifecycleUnknown('lifecycle public continuation did not return')
            returned = True
        finally:
            # Failure while retaining a foreign exception or delivering its
            # observation is also unknown, even if no native call raised.
            # Only an actual native terminal can retire effect custody.
            if self.receipt is None or self.receipt.phase not in (4, 5):
                self.unconfirmed = True
            self.fenced = True
            if not self.unconfirmed:
                # A native return/propagate terminal confirms the original
                # policy. Only this path retires representation ownership.
                with _custody_lock():
                    if _FRAME_CUSTODY.get(id(self)) is self:
                        del _FRAME_CUSTODY[id(self)]
                # On an ordinary exception its traceback keeps the original
                # object locals alive, as the retained Python body does.
                # Successful returns can release those locals immediately.
                if returned:
                    self.store = self.root_argument = None
                self.errors.clear()

    def effect(self, port):
        """Execute one fixed foreign operation, with no lifecycle decisions."""
        ns = self.namespace
        if port == 1:
            from .hia_execution_budget import admitted_execution_budget, execution_budget_store
            self.budget_factory = execution_budget_store
            self.budget_admission = admitted_execution_budget()
        elif port == 2:
            self.supplied = ns['Path'](self.root_argument).absolute()
        elif port == 3:
            self.supplied.mkdir(mode=0o700, parents=True, exist_ok=True)
        elif port == 4:
            return int(bool(self.supplied.is_symlink()))
        elif port == 5:
            self.store.root = self.supplied.resolve()
        elif port == 6:
            self.info = self.store.root.stat()
        elif port == 7 or port == 14 or port == 21:
            return int(bool(self.info.st_uid != ns['os'].geteuid()))
        elif port == 8 or port == 15 or port == 22:
            return int(bool(self.info.st_mode & 0o022))
        elif port == 9:
            self.store.artifacts = self.store.root / 'artifacts'
        elif port == 10:
            self.store.artifacts.mkdir(mode=0o700, exist_ok=True)
        elif port == 11:
            return int(bool(self.store.artifacts.is_symlink()))
        elif port == 12:
            self.info = self.store.artifacts.lstat()
        elif port == 13:
            return int(bool(ns['stat'].S_ISDIR(self.info.st_mode)))
        elif port == 16:
            self.database = self.store.root / 'state.sqlite3'
        elif port == 17:
            return int(bool(self.database.exists()))
        elif port == 18:
            return int(bool(self.database.is_symlink()))
        elif port == 19:
            self.info = self.database.lstat()
        elif port == 20:
            return int(bool(ns['stat'].S_ISREG(self.info.st_mode)))
        elif port == 23:
            self.store.db = ns['sqlite3'].connect(self.database, isolation_level=None, timeout=10, check_same_thread=False)
        elif port == 24:
            ns['os'].chmod(self.database, 0o600)
        elif port == 25:
            self.store.database = self.database
        elif port == 26:
            self.database_info = self.database.lstat()
        elif port == 27:
            return int(bool(ns['stat'].S_ISREG(self.database_info.st_mode)))
        elif port == 28:
            self.store.database_identity = (self.database_info.st_dev, self.database_info.st_ino)
        elif port == 29:
            self.store.db.row_factory = ns['sqlite3'].Row
        elif port == 30:
            self.store.db.execute('PRAGMA journal_mode=WAL')
        elif port == 31:
            self.store.db.execute('PRAGMA synchronous=FULL')
        elif port == 32:
            self.store.lock = ns['threading'].RLock()
        elif port == 33:
            self.store.db.executescript(SCHEMA_SQL)
        elif port == 34:
            self.store.database_sidecars = None
        elif port == 35:
            return int(self.budget_admission is not None)
        elif port == 36:
            self.store.db.execute('SELECT name FROM sqlite_master LIMIT 1').fetchone()
        elif port == 37:
            self.sidecars = {}
        elif port == 38:
            self.suffix = ('-wal', '-shm')[self.receipt.suffix]
            self.sidecar = ns['Path'](str(self.database) + self.suffix).lstat()
        elif port == 39:
            return int(bool(ns['stat'].S_ISREG(self.sidecar.st_mode)))
        elif port == 40:
            return int(bool(self.sidecar.st_uid != ns['os'].geteuid()))
        elif port == 41:
            return int(bool(self.sidecar.st_mode & 0o022))
        elif port == 42:
            self.sidecars[self.suffix] = (self.sidecar.st_dev, self.sidecar.st_ino)
        elif port == 43:
            self.store.database_sidecars = self.sidecars
        elif port == 44:
            self.store.execution_budgets = self.budget_factory(self.store, self.budget_admission)
        elif port == 60:
            ns['reject']('E_HIA_STORE', 'state directory cannot be a symbolic link')
        elif port == 61:
            ns['reject']('E_HIA_STORE', 'state directory must be owned and not writable by other users')
        elif port == 62:
            ns['reject']('E_HIA_STORE', 'artifact directory cannot be a symbolic link')
        elif port == 63:
            ns['reject']('E_HIA_STORE', 'artifact directory must be owned and not writable by other users')
        elif port == 64:
            ns['reject']('E_HIA_STORE', 'journal must be an owned private ordinary file')
        elif port == 65:
            ns['reject']('E_HIA_STORE', 'journal must remain an ordinary file after opening')
        elif port == 66:
            ns['reject']('E_HIA_STORE', 'journal sidecar must be an owned private ordinary file')
        elif port == 70:
            self.store.execution_budgets.close()
        elif port == 71 or port == 80:
            self.store.db.close()
        elif port == 81:
            self.errors[0].add_note('AgentStore construction cleanup failed: ' + type(self.errors[-1]).__name__)
        else:
            raise StoreLifecycleUnknown('lifecycle image issued an unknown fixed operation')


@dataclass(frozen=True)
class NativeStoreLifecycleOwner:
    image: NativeStoreLifecycleImage

    def __post_init__(self):
        if type(self.image) is not NativeStoreLifecycleImage:
            raise TypeError('lifecycle owner requires an admitted native image')

    def prepare(self, mode, store, root=None):
        self.check_store(store)
        return LifecycleFrame(self.image, mode, store, root)

    def check_store(self, store):
        with _custody_lock():
            if any(frame.unconfirmed and frame.store is store for frame in _FRAME_CUSTODY.values()):
                raise StoreLifecycleUnknown('Store has an unconfirmed lifecycle; it cannot be reopened or closed in this worker')

    def finish(self, frame):
        if type(frame) is not LifecycleFrame or frame.image is not self.image:
            raise StoreLifecycleUnknown('lifecycle frame belongs to a different owner')
        return frame.finish()


def unconfirmed_lifecycle_count():
    """Observation only; unknown continuations have no in-process replay/close."""
    with _custody_lock():
        return sum(frame.unconfirmed for frame in _FRAME_CUSTODY.values())
