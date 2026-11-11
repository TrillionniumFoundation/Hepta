"""Retained HIA slot/version/lease policy with fixed same-database effects.

The request owner commits adoption and rollback. The namespace owner commits
direct lease transactions. This bridge cannot grant or reconstruct either
owner's authority, and never retries an unconfirmed effect.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import os
import struct
import threading

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/slot_ledger.hiaasm')
SCHEMA = 'hepta.hia.slot-ledger-native.v1'
SELECTOR = 'HEPTA_HIA_SLOT_LEDGER_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIASLQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIASLR01', 'little')
PREFIX = 4096
MAX_ABI = 8 << 20
MAX_STATE = PREFIX + MAX_ABI


class SlotLedgerUnknown(RuntimeError):
    """Nonterminal custody failure, outside the service rejection formatter."""


class _DirectCustodyError(SlotLedgerUnknown):
    """Fixed transport refused a missing or unclaimed local object handle."""


class NativeSlotLedgerImage(NativeHiaJsonImage):
    pass


def admitted_slot_ledger(*, namespace_admission, request_admission):
    selected = os.environ.get(SELECTOR)
    if not selected:
        return None
    image = _installed_json_image(selected, SOURCE, SCHEMA, NativeSlotLedgerImage)
    if namespace_admission is None or request_admission is None:
        raise SlotLedgerUnknown('selected slot ledger requires admitted native namespace and request journal owners')
    return image


def slot_ledger_store(store, admission):
    return None if admission is None else NativeSlotLedgerStore(store, admission)


@dataclass(frozen=True)
class LedgerBinding:
    operation: tuple[int, int]
    official: tuple[int, int]
    connection: tuple[int, int]
    scope_kind: int
    scope_epoch: int
    scope_nonce: tuple[int, int]
    callback_token: int
    operation_kind: int
    scope_owner: tuple[int, int]


@dataclass(frozen=True)
class LedgerReceipt:
    status: int
    words: tuple[int, ...]
    raw: bytes

    @property
    def sequence(self):
        return self.words[2]

    @property
    def phase(self):
        return self.words[3]

    @property
    def action(self):
        return self.words[5]

    @property
    def pending(self):
        return self.words[6]

    def field(self, offset, size):
        if type(offset) is not int or type(size) is not int or not 0 <= offset <= offset + size <= len(self.raw):
            raise SlotLedgerUnknown('native ledger byte extent differs')
        return self.raw[offset:offset + size]

    def text(self, offset, size):
        return self.field(offset, size).decode('utf-8')

    def reference(self, offset):
        # HIA checked every byte of the canonical three-field wire form.
        return {'id': self.text(offset + 7, 34), 'sha256': self.text(offset + 53, 64),
                'uri': self.text(offset + 126, 48)}

    def snapshot(self):
        present = bool(self.words[20])
        return {'target_slot': self.text(512, self.words[24]),
                'current': {'generation': str(self.words[21]), 'epoch': str(self.words[22])},
                'active_artifact': self.reference(1872) if present else None,
                'context': self.text(1616, self.words[23]) if present else None,
                'in_flight_leases': self.words[33], 'snapshot_is_adoption_authority': False}

    def current(self):
        return {'generation': str(self.words[29]), 'epoch': str(self.words[30])}

    def lease(self):
        return {'id': self.text(1248, self.words[34]), 'slot': self.text(512, self.words[24]),
                'generation': str(self.words[29]), 'artifact': self.reference(2224)}


def _field(value, kind='text'):
    """Only object/byte transport tags; HIA admits values and comparisons."""
    from .hia_agent_store import wire
    if kind == 'text':
        return (1, value.encode('utf-8')) if type(value) is str else (0, b'')
    if kind == 'integer':
        return (3, str(value).encode('ascii')) if type(value) is int else (0, b'')
    if kind == 'reference':
        return (2, wire(value)) if type(value) is dict else (0, b'')
    if kind == 'bytes':
        return (4, value) if type(value) is bytes else (0, b'')
    raise SlotLedgerUnknown('unknown ledger field transport')


class LedgerState:
    """An operation owns its HIA buffer before any initialization or effect."""
    def __init__(self, image, binding):
        self.image, self.binding = image, binding
        self.creator, self.thread = os.getpid(), threading.get_ident()
        self.buffer = ctypes.create_string_buffer(PREFIX)
        self.receipt = None
        self.fenced = None
        self.returned = None
        self.foreign_error = None
        self.cursor = None

    def check(self):
        if os.getpid() != self.creator or threading.get_ident() != self.thread:
            raise SlotLedgerUnknown('ledger operation belongs to its original process and thread')
        if self.fenced is not None:
            raise SlotLedgerUnknown('ledger operation is fenced; no implicit retry is permitted')

    def fence(self, error):
        if self.fenced is None:
            try:
                message = str(error)[:1024]
            except BaseException:
                message = '<unavailable>'
            self.fenced = {'type': type(error).__name__, 'message': message}

    def reserve(self, size):
        self.check()
        if type(size) is not int or not PREFIX <= size <= MAX_STATE:
            raise SlotLedgerUnknown('ledger state exceeds its bounded capacity')
        if size > len(self.buffer):
            grown = ctypes.create_string_buffer(size)
            ctypes.memmove(grown, self.buffer, len(self.buffer))
            self.buffer = grown

    def _packet(self, event, fields, known, token, shape, count):
        b = self.binding
        sequence = 0 if self.receipt is None or event == 90 else self.receipt.sequence
        words = [REQUEST_MAGIC, event, sequence, token, *b.operation, *b.official,
                 *b.connection, b.scope_kind, b.scope_epoch, *b.scope_nonce,
                 b.callback_token, b.operation_kind, known, len(fields), shape, count,
                 *b.scope_owner, *([0] * 10)]
        if (len(words) != 32 or any(type(v) is not int or not 0 <= v < 1 << 64 for v in words)
                or len(fields) > 11):
            raise SlotLedgerUnknown('invalid ledger transport header')
        encoded = []
        for tag, raw in fields:
            if type(tag) is not int or not 0 <= tag <= 4 or type(raw) is not bytes:
                raise SlotLedgerUnknown('invalid ledger field transport')
            encoded.append(struct.pack('<2Q', tag, len(raw)) + raw)
        return struct.pack('<32Q', *words) + b''.join(encoded)

    def call(self, event, *, fields=(), known=0, token=0, shape=0, count=0):
        self.check()
        try:
            raw = self._packet(event, fields, known, token, shape, count)
            source = ctypes.create_string_buffer(raw, len(raw))
            output = ctypes.create_string_buffer(len(self.buffer) + 32)
            size = self.image._entry(source, len(raw), output, len(output), self.buffer, len(self.buffer))
            self.check()
            if not 32 <= size <= len(output):
                raise SlotLedgerUnknown('native ledger rejected its bounded ABI')
            returned = ctypes.string_at(output, size)
            magic, status, sequence, extent = struct.unpack('<4Q', returned[:32])
            if (magic != RESULT_MAGIC or status > 22 or extent < PREFIX or extent > len(self.buffer)
                    or size != extent + 32):
                raise SlotLedgerUnknown('native ledger has no exact retained receipt')
            owned = ctypes.string_at(self.buffer, extent)
            if owned != returned[32:]:
                raise SlotLedgerUnknown('ledger receipt differs from retained native state')
            words = struct.unpack('<64Q', owned[:512])
            b = self.binding
            if (sequence != words[2] or extent != words[55]
                    or tuple(words[8:19]) != (*b.operation, *b.official, *b.connection,
                        b.scope_kind, b.scope_epoch, *b.scope_nonce, b.callback_token)
                    or words[4] != b.operation_kind or tuple(words[43:45]) != b.scope_owner):
                raise SlotLedgerUnknown('ledger receipt belongs to another operation or transaction')
            receipt = LedgerReceipt(status, words, owned)
            self.receipt = receipt
            return receipt
        except BaseException as error:
            self.fence(error)
            raise


class DirectLedgerState(LedgerState):
    """Operation-local opaque custody; no coercion or slot byte ceiling.

    A handle is allocated only for the next result expected by retained HIA.
    HIA preclaims each transfer out of the registry before a foreign primitive.
    Borrowed fields remain rooted; consumed temporaries retain the original
    Python expression lifetime. Python/SQLite behavior is foreign; HIA owns
    the order, branches and one-shot transfer authority.
    """
    def __init__(self, image, binding, original):
        super().__init__(image, binding)
        self.objects = {1: original}

    def object(self, handle):
        if type(handle) is not int or handle not in self.objects:
            raise _DirectCustodyError('direct ledger object handle has no retained custody')
        return self.objects[handle]

    def take(self, word):
        """Move exactly one HIA-preclaimed reference into its fixed expression.

        Do not first assign the object to a Python local: its refcount must
        leave the registry at the expression's operand boundary. A lost return
        cannot restore the consumed native preclaim or authorize another pop.
        """
        r = self.receipt
        if r is None or r.phase != 2 or not 22 <= word < 36:
            raise _DirectCustodyError('direct object transfer has no native preclaim')
        handle = r.words[word]
        if not 1 <= handle <= 64 or not (r.words[45] & (1 << (handle - 1))) or handle not in self.objects:
            raise _DirectCustodyError('direct object transfer is absent, consumed or unclaimed')
        return self.objects.pop(handle)

    def drop_claimed(self):
        """Release completed row scopes in original local-creation order."""
        r = self.receipt
        if r is None or r.phase != 2 or r.action not in (240, 241):
            raise _DirectCustodyError('direct row release has no native preclaim')
        for handle in range(1, r.words[20] + 1):
            if r.words[45] & (1 << (handle - 1)):
                if handle not in self.objects:
                    raise _DirectCustodyError('direct row scope was already released')
                del self.objects[handle]

    def result(self):
        r = self.receipt
        if r.status or r.phase not in (3, 4):
            raise SlotLedgerUnknown('direct ledger result has no terminal native receipt')
        if r.words[40] == 1:
            return {'target_slot': self.object(1), 'current': {'generation': '0', 'epoch': '0'},
                'active_artifact': None, 'context': None, 'in_flight_leases': 0,
                'snapshot_is_adoption_authority': False}
        if r.words[40] == 2:
            return {'target_slot': self.object(1),
                'current': {'generation': self.object(r.words[25]), 'epoch': self.object(r.words[26])},
                'active_artifact': self.object(r.words[28]), 'context': self.object(r.words[27]),
                'in_flight_leases': self.object(r.words[24]), 'snapshot_is_adoption_authority': False}
        if r.words[40] == 3:
            return {'id': self.object(r.words[29]), 'slot': self.object(r.words[30]),
                'generation': self.object(r.words[31]), 'artifact': self.object(r.words[32])}
        raise SlotLedgerUnknown('direct ledger result shape was not admitted by HIA')


@dataclass(frozen=True)
class LedgerCompletion:
    """A completed diagnostic retains no foreign input, result or traceback."""
    binding: LedgerBinding
    receipt: LedgerReceipt
    fenced: None = None


class NativeSlotLedgerStore:
    def __init__(self, store, image):
        from .hia_artifact_namespace_native import NativeArtifactNamespaceStore
        from .hia_request_journal_native import NativeRequestJournalStore
        if (type(store.artifact_namespace) is not NativeArtifactNamespaceStore
                or type(store.request_journal) is not NativeRequestJournalStore
                or store.artifact_namespace.lock is not store.lock
                or store.request_journal.lock is not store.lock):
            raise SlotLedgerUnknown('ledger dependencies lack the exact shared native transaction custody')
        self.store, self.image = store, image
        self.namespace, self.requests = store.artifact_namespace, store.request_journal
        self.creator, self.lock = os.getpid(), store.lock
        self.pending = None
        self.last = None
        self.fenced = None
        self.closed = False
        self.check()
        self.requests.check()

    def check(self):
        if self.closed or self.fenced is not None or os.getpid() != self.creator:
            raise SlotLedgerUnknown('ledger owner is closed, fenced or belongs to another process')
        if self.store.artifact_namespace is not self.namespace or self.store.request_journal is not self.requests:
            raise SlotLedgerUnknown('ledger transaction owners changed')
        self.namespace.check()

    def _binding(self, operation, connection, nonce):
        observed = self.namespace._binding(operation, connection, nonce)
        owner = self.namespace.state.identity if connection is None else connection.state.identity
        return LedgerBinding(nonce, self.namespace.connection_identity, observed.connection,
            observed.scope_kind, observed.scope_epoch, observed.scope_nonce,
            observed.callback_token, operation, owner)

    def _check_operation(self, state, connection):
        self.check()
        state.check()
        if state.binding.operation_kind in (2, 3, 4, 6, 9, 11):
            self.requests.check()
        if self.pending is not state:
            raise SlotLedgerUnknown('ledger operation custody changed')
        if self._binding(state.binding.operation_kind, connection, state.binding.operation) != state.binding:
            raise SlotLedgerUnknown('ledger request or transaction capability was revoked')

    def _execute(self, connection, statement, parameters=()):
        return (self.store.db if connection is None else connection).execute(statement, parameters)

    def _begin(self, operation, *, slot=None, context=None, expected=None, candidate=None,
               baseline=None, retained=None, lease=None, abi=None, connection=None):
        self.check()
        if operation in (2, 3, 4, 6):
            self.requests.check()
        if self.pending is not None:
            raise SlotLedgerUnknown('ledger already owns a pending operation')
        nonce = struct.unpack('<2Q', os.urandom(16))
        binding = self._binding(operation, connection, nonce)
        state = LedgerState(self.image, binding)
        # Strong custody is established before HIA can authorize the first effect.
        self.pending = state
        try:
            absent = (0, b'')
            fields = [absent] * 11
            shape = count = 0
            if operation in (5, 6):
                shape = int(type(lease) is dict)
                if type(lease) is dict:
                    count = len(lease)
                    for bit, name in enumerate(('id', 'slot', 'generation', 'artifact'), 1):
                        shape |= int(name in lease) << bit
                    slot = lease.get('slot')
                    fields[7] = _field(lease.get('id'))
                    fields[8] = _field(lease.get('generation'))
                    fields[9] = _field(lease.get('artifact'), 'reference')
            fields[0] = _field(slot)
            if operation in (2, 3, 7):
                shape = int(type(expected) is dict)
                if type(expected) is dict:
                    count = len(expected)
                    shape |= int('generation' in expected) << 1
                    shape |= int('epoch' in expected) << 2
                    fields[2], fields[3] = _field(expected.get('generation')), _field(expected.get('epoch'))
            if operation in (2, 3):
                fields[1] = _field(context)
            if operation == 2:
                fields[4], fields[5], fields[10] = (_field(candidate, 'reference'),
                    _field(baseline, 'reference'), _field(abi, 'bytes'))
                state.reserve(PREFIX + len(fields[10][1]))
            if operation == 3:
                fields[6] = _field(retained)
            state.call(0, fields=tuple(fields), shape=shape, count=count)
            return state
        except BaseException as error:
            self._fence(state, error)
            raise SlotLedgerUnknown('ledger admission has no confirmed receipt') from error

    def _fence(self, state, error):
        state.fence(error)
        if self.fenced is None:
            self.fenced = state

    def _reject(self, state):
        from .hia_agent_store import AgentRejected
        receipt, operation = state.receipt, state.binding.operation_kind
        status = receipt.status
        if status in (1, 2, 3):
            label = {1: 'generation', 2: 'epoch', 3: 'retained_generation'}[status]
            raise AgentRejected('E_HIA_RANGE', label + ' must be a canonical u64 decimal string')
        if status == 4:
            error = AgentRejected('E_HIA_GENERATION_STALE',
                'slot changed; read the retained current snapshot and choose a fresh conditional request',
                'adoption', retry_action='refresh_context')
            error.pending_slot_snapshot = receipt.snapshot()
            raise error
        if status == 5:
            raise AgentRejected('E_HIA_SLOT', 'slot has no active generation' if operation in (4, 9) else
                                'slot has no retained generation', 'admission' if operation in (4, 9) else 'adoption')
        if status == 6:
            raise AgentRejected('E_HIA_GENERATION', 'requested generation is not retained', 'adoption')
        if status == 7:
            raise AgentRejected('E_HIA_ABI', 'retained generation is not ABI compatible' if operation == 3
                                else 'candidate changes the live slot ABI', 'adoption')
        if status == 8:
            raise AgentRejected('E_HIA_BASELINE', 'evaluation baseline is not the currently active image', 'adoption')
        if status == 9:
            raise AgentRejected('E_HIA_GENERATION_EXHAUSTED', 'u64 epoch space is exhausted' if operation == 3
                                else 'u64 generation or epoch space is exhausted', 'adoption')
        if status == 10:
            raise AgentRejected('E_HIA_LEASE', 'lease is released, unknown or modified')
        if status == 11:
            raise AgentRejected('E_HIA_FIELDS', 'generation lease has missing or unknown fields')
        if status == 12:
            raise AgentRejected('E_HIA_SLOT', 'slot identifier is outside the selected 192-byte ledger profile')
        if status in (21, 22) and state.foreign_error is not None:
            raise state.foreign_error
        raise SlotLedgerUnknown('native ledger custody, row, sequence or effect outcome is unconfirmed')

    def _complete_owner(self, state):
        if self.pending is not state or state.receipt.phase not in (3, 4, 5):
            raise SlotLedgerUnknown('ledger cannot discharge a pending effect')
        self.last = LedgerCompletion(state.binding, state.receipt)
        self.pending = None

    def _report_failure(self, state, error):
        from .hia_agent_store import AgentRejected
        if (isinstance(state, DirectLedgerState) and state.fenced is None
                and state.receipt is not None and state.receipt.phase == 5
                and state.receipt.status == 22 and state.foreign_error is error):
            self._complete_owner(state)
            raise error
        if isinstance(error, AgentRejected) and state.receipt is not None and state.receipt.phase == 5:
            self._complete_owner(state)
            raise error
        self._fence(state, error)
        raise SlotLedgerUnknown('ledger effect or completion has no confirmed matching receipt') from error

    def _outcome(self, state, connection, fields=(), *, known=1, token=None):
        self._check_operation(state, connection)
        return state.call(3, fields=fields, known=known,
                          token=state.receipt.pending if token is None else token)

    def _drive(self, state, service, connection):
        from .hia_agent_store import AgentRejected, wire
        while True:
            receipt = state.receipt
            if receipt.status:
                self._reject(state)
            if receipt.phase in (3, 4):
                return receipt
            self._check_operation(state, connection)
            action, token = receipt.action, receipt.pending
            claimed = state.call(2, token=token)
            if claimed.status or claimed.phase != 2 or claimed.action != action or claimed.pending != token:
                raise SlotLedgerUnknown('ledger effect preclaim was not confirmed')
            self._check_operation(state, connection)
            r = state.receipt
            slot = r.text(512, r.words[24])
            if action in (1, 10, 18):
                state.returned = self._execute(connection, 'SELECT * FROM main.slots WHERE name=?', (slot,)).fetchone()
                row = state.returned
                fields = () if row is None else tuple(_field(row[name]) for name in
                    ('name', 'context_id', 'generation', 'epoch', 'abi_sha256'))
                self._outcome(state, connection, fields, known=int(row is not None))
            elif action in (2, 11, 12):
                generation = r.words[21] if action == 2 else r.words[28] if action == 12 else (0 if r.words[39] == 3 else r.words[29])
                state.returned = self._execute(connection,
                    'SELECT artifact FROM main.versions WHERE slot=? AND generation=?', (slot, str(generation))).fetchone()
                row = state.returned
                fields = () if row is None else ((2, row['artifact'].encode('utf-8')) if type(row['artifact']) is str else (0, b''),)
                self._outcome(state, connection, fields, known=int(row is not None))
            elif action == 3:
                state.returned = self._execute(connection,
                    'SELECT COUNT(*) FROM main.leases WHERE slot=? AND active=1', (slot,)).fetchone()
                self._outcome(state, connection, (_field(state.returned[0], 'integer'),))
            elif action == 4:
                at = 2048 if r.words[4] == 3 else 1872
                try:
                    state.returned = service._native(r.reference(at),
                        **({} if connection is None else {'_connection': connection}))
                except AgentRejected as error:
                    state.foreign_error = error
                    self._check_operation(state, connection)
                    refused = state.call(5, known=1, token=token)
                    if refused.status != 21 or refused.phase != 5:
                        raise SlotLedgerUnknown('native-image refusal has no matching ledger authority') from error
                    self._reject(state)
                fields = ()
                if r.words[4] == 3:
                    raw = wire(state.returned[1]['signatures'])
                    state.reserve(PREFIX + len(raw))
                    fields = (_field(raw, 'bytes'),)
                elif r.words[4] == 4:
                    # The fixed entropy transport supplies bytes. HIA applies
                    # UUID v4/version bits and formats the retained lease ID.
                    fields = (_field(os.urandom(16), 'bytes'),)
                self._outcome(state, connection, fields)
            elif action == 5:
                state.cursor = self._execute(connection, 'SELECT generation FROM main.versions WHERE slot=?', (slot,))
                while True:
                    self._check_operation(state, connection)
                    state.returned = state.cursor.fetchone()
                    row = state.returned
                    updated = self._outcome(state, connection, () if row is None else (_field(row['generation']),),
                        known=int(row is not None), token=token)
                    if updated.status or row is None:
                        break
            elif action in (6, 7, 8, 9, 14, 15):
                if action == 6:
                    statement, parameters = 'INSERT INTO main.slots VALUES (?,?,?,?,?)', (
                        slot, r.text(704, r.words[25]), '0', '0', r.text(2400, 64))
                elif action in (7, 8):
                    at, generation = (1072, 0) if action == 7 else (896, r.words[29])
                    statement, parameters = 'INSERT INTO main.versions VALUES (?,?,?)', (
                        slot, str(generation), r.text(at, 176))
                elif action == 9:
                    statement = ('UPDATE main.slots SET generation=?,epoch=?,context_id=? WHERE name=? '
                                 'AND generation=? AND epoch=? AND context_id=? AND abi_sha256=?')
                    parameters = (str(r.words[29]), str(r.words[30]), r.text(704, r.words[25]), slot,
                        str(r.words[21]), str(r.words[22]), r.text(1616, r.words[23]), r.text(1808, 64))
                elif action == 14:
                    statement, parameters = 'INSERT INTO main.leases VALUES (?,?,?,?,1)', (
                        r.text(1248, r.words[34]), slot, str(r.words[29]), r.text(2224, 176))
                else:
                    statement = ('UPDATE main.leases SET active=0 WHERE id=? AND active=1 '
                                 'AND slot=? AND generation=? AND artifact=?')
                    parameters = (r.text(1248, r.words[34]), slot, str(r.words[35]), r.text(1440, 176))
                state.returned = self._execute(connection, statement, parameters)
                self._outcome(state, connection, (_field(state.returned.rowcount, 'integer'),))
            elif action in (13, 16):
                state.returned = self._execute(connection, 'SELECT * FROM main.leases WHERE id=?',
                    (r.text(1248, r.words[34]),)).fetchone()
                row = state.returned
                fields = () if row is None else (*(_field(row[name]) for name in ('id', 'slot', 'generation')),
                    (2, row['artifact'].encode('utf-8')) if type(row['artifact']) is str else (0, b''),
                    _field(row['active'], 'integer'))
                self._outcome(state, connection, fields, known=int(row is not None))
            elif action == 17:
                from .hia_agent_store import _native_artifact_admission, _native_artifact_file
                admission = _native_artifact_admission()
                if admission is None:
                    raise SlotLedgerUnknown('ledger ABI hash requires its selected native byte owner')
                state.returned = _native_artifact_file('store-hash', self.store.artifacts,
                    data=r.field(PREFIX, r.words[56]), _admission=admission)
                self._outcome(state, connection, (_field(state.returned['sha256']),
                    _field(state.returned['bytes'], 'integer')))
            else:
                raise SlotLedgerUnknown('native ledger requested an unknown fixed effect')

    def operate(self, operation, service, **inputs):
        connection = inputs.get('connection')
        with self.lock:
            state = self._begin(operation, **inputs)
            try:
                receipt = self._drive(state, service, connection)
                self._complete_owner(state)
                return receipt
            except BaseException as error:
                self._report_failure(state, error)

    def _direct_begin(self, operation, original, connection):
        self.check()
        if operation in (9, 11):
            self.requests.check()
        if self.pending is not None:
            raise SlotLedgerUnknown('ledger already owns a pending operation')
        nonce = struct.unpack('<2Q', os.urandom(16))
        state = DirectLedgerState(self.image, self._binding(operation, connection, nonce), original)
        self.pending = state
        try:
            state.call(0)
            return state
        except BaseException as error:
            self._fence(state, error)
            raise SlotLedgerUnknown('direct ledger admission has no confirmed receipt') from error

    def _direct_effect(self, state, service, connection, action):
        """Fixed foreign primitives only; no row/result admission decisions."""
        from .hia_agent_store import decode_data, wire
        r = state.receipt
        at = lambda word: state.object(r.words[word])
        original = state.object(1)
        if action == 100:
            return self._execute(connection, 'SELECT * FROM main.slots WHERE name=?', (original,))
        if action in (101, 105, 107, 208):
            return state.take(35).fetchone()
        if action in (102, 209):
            return at(22) is None
        if action in (103, 109, 217, 228):
            return at(22)['generation']
        if action == 104:
            return self._execute(connection,
                'SELECT artifact FROM main.versions WHERE slot=? AND generation=?', (original, state.take(33)))
        if action == 106:
            return self._execute(connection,
                'SELECT COUNT(*) FROM main.leases WHERE slot=? AND active=1', (original,))
        if action == 108:
            return state.take(33)[0]
        if action == 110:
            return at(22)['epoch']
        if action == 111:
            return at(23)['artifact']
        if action in (112, 222, 230):
            return decode_data(state.take(33))
        if action == 113:
            return at(22)['context_id']
        if action == 114:
            return at(28) is None
        if action == 120:
            service._native(at(28), **({} if connection is None else {'_connection': connection}))
            return None
        if action == 121:
            return os.urandom(16)
        if action == 122:
            return r.field(1248, 38).decode('ascii')
        if action == 123:
            return wire(at(28)).decode()
        if action == 124:
            self._execute(connection, 'INSERT INTO main.leases VALUES (?,?,?,?,1)',
                (at(29), original, at(25), state.take(33)))
            return None
        if action == 200:
            return type(original) is dict
        if action in (201, 203):
            return set(original)
        if action == 202:
            if set(('id', 'slot', 'generation', 'artifact')) <= state.take(33):
                return True
            return False
        if action == 204:
            return state.take(33) - set(('id', 'slot', 'generation', 'artifact')) - set(())
        if action == 205:
            if state.take(33):
                return True
            return False
        if action == 206:
            return original['id']
        if action == 207:
            return self._execute(connection, 'SELECT * FROM main.leases WHERE id=?', (state.take(33),))
        if action == 210:
            return at(22)['active']
        if action == 211:
            if state.take(33) != 1:
                return True
            return False
        if action in (213, 227):
            return at(22)['slot']
        if action == 214:
            return original['slot']
        if action in (215, 219, 224):
            # One fixed conditional comparison preserves CPython's operand,
            # rich-result and truth-conversion lifetimes. HIA owns which field
            # is compared and whether the next comparison may run.
            if state.take(33) != state.take(34):
                return True
            return False
        if action == 218:
            return original['generation']
        if action in (221, 229):
            return at(22)['artifact']
        if action == 223:
            return original['artifact']
        if action == 226:
            return at(22)['id']
        if action == 231:
            self._execute(connection, 'UPDATE main.leases SET active=0 WHERE id=?', (at(29),))
            return None
        if action in (240, 241):
            state.drop_claimed()
            return None
        raise SlotLedgerUnknown('direct ledger requested an unknown fixed primitive')

    def _direct_drive(self, state, service, connection):
        predicates = (102, 114, 200, 202, 205, 209, 211, 215, 219, 224)
        voids = (120, 124, 231, 240, 241)
        while True:
            receipt = state.receipt
            if receipt.status:
                self._reject(state)
            if receipt.phase in (3, 4):
                return receipt
            self._check_operation(state, connection)
            action, token = receipt.action, receipt.pending
            claim = state.call(2, token=token)
            if claim.status or claim.phase != 2 or claim.action != action or claim.pending != token:
                raise SlotLedgerUnknown('direct ledger primitive preclaim was not confirmed')
            self._check_operation(state, connection)
            try:
                state.returned = self._direct_effect(state, service, connection, action)
            except _DirectCustodyError:
                raise
            except Exception as error:
                # This is a returned foreign exception, not a reconstructed
                # absence of an effect. BaseException/receipt loss stays unknown.
                state.foreign_error = error
                self._check_operation(state, connection)
                refused = state.call(5, known=1, token=token)
                if refused.status != 22 or refused.phase != 5:
                    raise SlotLedgerUnknown('direct foreign exception has no matching native receipt') from error
                self._reject(state)
            self._check_operation(state, connection)
            if action in predicates:
                if type(state.returned) is not bool:
                    raise SlotLedgerUnknown('direct predicate did not return an exact bool')
                payload = struct.pack('<Q', int(state.returned))
            elif action == 121:
                if type(state.returned) is not bytes or len(state.returned) != 16:
                    raise SlotLedgerUnknown('direct entropy did not return sixteen bytes')
                payload = state.returned
            elif action in voids:
                if state.returned is not None:
                    raise SlotLedgerUnknown('direct discarded result did not return its void receipt')
                payload = struct.pack('<Q', 0)
            else:
                handle = state.receipt.words[20] + 1
                if handle in state.objects:
                    raise SlotLedgerUnknown('direct object result slot was already consumed')
                state.objects[handle] = state.returned
                payload = struct.pack('<Q', handle)
            # Object results now have their sole transport reference in the
            # registry; predicates/entropy/void have an immutable payload. Do
            # not keep a second result reference through a later native take.
            state.returned = None
            state.call(3, known=1, token=token, fields=((4, payload),))

    def direct(self, operation, service, original, *, connection=None):
        with self.lock:
            state = self._direct_begin(operation, original, connection)
            try:
                self._direct_drive(state, service, connection)
                result = state.result()
                self._complete_owner(state)
                return result
            except BaseException as error:
                self._report_failure(state, error)

    def direct_transaction(self, operation, service, original):
        with self.lock:
            self.check()
            if self.pending is not None:
                raise SlotLedgerUnknown('ledger already owns a pending operation')
            state = None
            try:
                with self.namespace.transaction():
                    state = self._direct_begin(operation, original, None)
                    self._direct_drive(state, service, None)
                self._committed(state)
                result = state.result()
                self._complete_owner(state)
                return result
            except BaseException as error:
                if state is None:
                    raise
                self._report_failure(state, error)

    def _committed(self, state):
        from .hia_artifact_namespace_native import NamespaceBinding
        self.check()
        if self.pending is not state or self.namespace._scope is not None or self.store.db.in_transaction:
            raise SlotLedgerUnknown('lease transaction did not return its original committed scope')
        receipt = self.namespace.state.call(90, NamespaceBinding((0, 0), self.namespace.connection_identity))
        words = receipt.words
        certificate = struct.pack('<12Q', *self.namespace.state.identity, words[41],
            *words[42:44], words[40], words[44], words[45], words[47], words[46], words[59], words[2])
        committed = state.call(4, known=1, fields=(_field(certificate, 'bytes'),))
        if committed.status or committed.phase != 4:
            raise SlotLedgerUnknown('lease commit does not match its original native epoch')
        return committed

    def lease_transaction(self, operation, service, **inputs):
        # Keep the common lock through COMMIT attestation, never through a child.
        with self.lock:
            self.check()
            if self.pending is not None:
                raise SlotLedgerUnknown('ledger already owns a pending operation')
            state = None
            try:
                with self.namespace.transaction():
                    state = self._begin(operation, **inputs)
                    self._drive(state, service, None)
                receipt = self._committed(state)
                self._complete_owner(state)
                return receipt
            except BaseException as error:
                if state is None:
                    raise
                self._report_failure(state, error)

    def snapshot(self):
        with self.lock:
            state = self.pending if self.pending is not None else self.last
            receipt = None if state is None else state.receipt
            return {'fenced': self.fenced is not None,
                    'pending': self.pending is not None,
                    'operation': None if state is None else state.binding.operation_kind,
                    'sequence': None if receipt is None else receipt.sequence,
                    'phase': None if receipt is None else receipt.phase,
                    'action': None if receipt is None else receipt.action,
                    'effect_token': None if receipt is None else receipt.pending,
                    'scope_epoch': None if state is None else state.binding.scope_epoch,
                    'state_fenced': None if state is None else state.fenced,
                    'diagnostic_only': True, 'historical_completion_reconstructed': False}

    def close(self):
        if os.getpid() != self.creator:
            raise SlotLedgerUnknown('ledger close belongs to its creator process')
        self.closed = True
