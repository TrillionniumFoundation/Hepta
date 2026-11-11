"""HIA-owned request journal on the original SQLite database and WAL.

The retained native state decides request admission, replay, dispatch and exact
terminal-response custody. This module transports fixed SQL and passes an
explicit guarded connection through existing atomic tool helpers. It never
changes AgentStore.db or turns an uncertain commit into a terminal rejection.
"""
from __future__ import annotations

import copy
import ctypes
from dataclasses import dataclass
import os
from pathlib import Path
import sqlite3
import stat
import struct
import threading
import time

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/request_journal.hiaasm')
SCHEMA = 'hepta.hia.request-journal-native.v1'
SELECTOR = 'HEPTA_HIA_REQUEST_JOURNAL_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIAJRQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAJRS01', 'little')
CLEANUP_MAGIC = int.from_bytes(b'HIAJCL01', 'little')
MAX_RESPONSE = 8 * 1024 * 1024
STATE_PREFIX = 1024
OUTPUT_PREFIX = 448


class RequestJournalUnknown(RuntimeError):
    """Nonterminal transport failure; the service must not journal a rejection."""


def _reject(status, message=None):
    from .hia_agent_store import AgentRejected
    descriptions = {
        1: ('E_HIA_REQUEST_CORRUPT', 'request journal has an invalid bounded record', 'observe_original'),
        2: ('E_HIA_REQUEST_CUSTODY', 'native request journal custody failed', 'observe_original'),
        3: ('E_HIA_REQUEST_CONFLICT', 'request key is already bound to different arguments', 'correct_input'),
        4: ('E_HIA_REQUEST_UNKNOWN', 'original request has durable intent but no confirmed terminal result', 'observe_original'),
        5: ('E_HIA_REQUEST_EXHAUSTED', 'native request journal sequence or byte capacity is exhausted', 'stop'),
        6: ('E_HIA_REQUEST_UNKNOWN', 'request journal transition has no confirmed terminal result', 'observe_original'),
        7: ('E_HIA_REQUEST_CUSTODY', 'request journal effect token or phase does not match', 'observe_original')}
    code, text, retry = descriptions[status]
    raise AgentRejected(code, message or text, retry_action=retry)


class NativeRequestJournalImage(NativeHiaJsonImage):
    pass


def admitted_request_journal():
    selected = os.environ.get(SELECTOR)
    return (_installed_json_image(selected, SOURCE, SCHEMA, NativeRequestJournalImage)
            if selected else None)


def request_journal_store(store, admission, *, shared_lock=None):
    if admission is None:
        return None
    return (NativeRequestJournalStore(store, admission) if shared_lock is None else
            NativeRequestJournalStore(store, admission, shared_lock=shared_lock))


@dataclass(frozen=True)
class RequestToken:
    owner: tuple[int, int]
    connection: tuple[int, int]
    sequence: int


@dataclass(frozen=True)
class RequestReceipt:
    status: int
    action: int
    token: RequestToken
    phase: int
    keyed: bool
    mode: int
    atomic_kind: int
    pending_token: int
    dispatch_count: int
    key_characters: int
    replay_validated: bool
    key: bytes
    digest: bytes
    tool: bytes
    started: bytes
    response: bytes


class RequestState:
    """One retained HIA owner, with no reconstruction from hosted booleans."""
    def __init__(self, image, connection, tool, request_digest, candidate_key,
                 *, started=None, response_capacity=MAX_RESPONSE):
        from .hia_agent_store import digest
        if type(response_capacity) is not int or not 1 <= response_capacity <= MAX_RESPONSE:
            _reject(1)
        self.image, self.connection = image, connection
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.creator = os.getpid()
        self.lock = threading.RLock()
        self.capacity = response_capacity
        self.buffer = ctypes.create_string_buffer(STATE_PREFIX + response_capacity)
        self.receipt = None
        self.fenced = None
        raw_tool = self._text(tool, 128)
        raw_digest = self._text(request_digest, 64)
        raw_started = self._text(str(time.time_ns()) if started is None else started, 64)
        # Transport kinds are distinct from eligibility. HIA counts Unicode
        # scalars and decides whether the original 1..192-character rule holds.
        raw_key, raw_key_digest, kind = b'', b'', 0
        if type(candidate_key) is str:
            encoded = candidate_key.encode('utf-8')
            if len(encoded) <= 768:
                kind, raw_key = 1, encoded
                raw_key_digest = digest({'tool': tool, 'key': candidate_key}).encode('ascii')
            else:
                kind = 2
        self.call(0, values=(len(raw_tool), len(raw_started), kind, len(raw_key), len(raw_key_digest)),
            payload=raw_tool + raw_digest + raw_started + raw_key + raw_key_digest)

    @staticmethod
    def _text(value, maximum):
        if type(value) is not str:
            _reject(1)
        raw = value.encode('utf-8')
        if len(raw) > maximum:
            _reject(1)
        return raw

    def fence(self, error):
        if self.fenced is None:
            try:
                message = str(error)[:1024]
            except BaseException:
                message = '<unavailable>'
            self.fenced = {'type': type(error).__name__, 'message': message}

    def check(self):
        if os.getpid() != self.creator:
            raise RequestJournalUnknown('request journal state belongs to its creator process')
        if self.fenced is not None:
            raise RequestJournalUnknown('request journal state is fenced; observe its original durable row')

    def call(self, event, *, values=(), payload=b'', effect_token=0, token=None):
        self.check()
        with self.lock:
            self.check()
            try:
                sequence = 0 if self.receipt is None else self.receipt.token.sequence
                selected = token or RequestToken(self.identity, self.connection, sequence)
                numbers = [REQUEST_MAGIC, event, selected.sequence, effect_token, *values]
                if len(numbers) > 12 or any(type(v) is not int or not 0 <= v < 1 << 64 for v in numbers):
                    _reject(1)
                numbers += [0] * (12 - len(numbers))
                raw = struct.pack('<16Q', *numbers, *selected.owner, *selected.connection) + payload
                source = ctypes.create_string_buffer(raw, len(raw))
                capacity = OUTPUT_PREFIX + self.capacity
                output = ctypes.create_string_buffer(capacity)
                count = self.image._entry(source, len(raw), output, capacity, self.buffer, len(self.buffer))
                self.check()
                if not 128 <= count <= capacity:
                    _reject(2, 'native request journal rejected its bounded ABI')
                returned = ctypes.string_at(output, count)
                h = struct.unpack('<16Q', returned[:128])
                magic, status, action, serial, phase, keyed, mode, atomic, pending, dispatches, tool_size, started_size, response_size, characters, validated, reserved = h
                if (magic != RESULT_MAGIC or status > 7 or action > 8 or phase > 12 or keyed > 1
                        or mode > 3 or atomic > 2 or dispatches > 1 or tool_size > 128
                        or started_size > 64 or response_size > self.capacity or characters > 768
                        or validated > 1 or reserved or status != 0 and action != 0):
                    _reject(2, 'invalid native request journal receipt')
                if phase == 0:
                    _reject(status or 2)
                if count != 256 + tool_size + started_size + response_size:
                    _reject(2, 'invalid native request journal byte extent')
                words = struct.unpack('<32Q', ctypes.string_at(self.buffer, 256))
                if ((words[5], words[6]) != self.identity or (words[7], words[8]) != self.connection
                        or words[24] != self.capacity
                        or (status, action, serial, phase, keyed, mode, atomic, pending, dispatches,
                            tool_size, started_size, response_size, characters, validated)
                        != tuple(words[i] for i in (17, 16, 3, 2, 4, 12, 15, 13, 14, 9, 10, 11, 22, 23))):
                    _reject(2, 'native request journal receipt does not bind its retained state')
                at, fields = 128, []
                for length, offset in ((64, 256), (64, 320), (tool_size, 384),
                                       (started_size, 512), (response_size, 1024)):
                    field = returned[at:at + length]
                    if field != ctypes.string_at(ctypes.addressof(self.buffer) + offset, length):
                        _reject(2, 'native request journal bytes differ from retained custody')
                    fields.append(field); at += length
                receipt = RequestReceipt(status, action, RequestToken(self.identity, self.connection, serial),
                    phase, bool(keyed), mode, atomic, pending, dispatches, characters, bool(validated), *fields)
                self.receipt = receipt
                if status:
                    _reject(status)
                return receipt
            except BaseException as error:
                self.fence(error)
                raise

    def row(self, row):
        if row is None:
            return self.call(2, values=(0, 0, 0, 0, 0, 0, 0, 0))
        key = self._text(row['key'], 64)
        digest = self._text(row['digest'], 64)
        tool = self._text(row['tool'], 128)
        state = self._text(row['state'], 16)
        started = self._text(row['started_ns'], 64)
        response = b'' if row['response'] is None else self._text(row['response'], self.capacity)
        return self.call(2, values=(1, len(state), len(tool), len(started),
            int(row['response'] is not None), len(response), len(key), len(digest)),
            payload=key + digest + tool + state + started + response)

    def claim_rollback(self):
        """Consume one native cleanup claim, including after a fenced handoff.

        This entry cannot dispatch or complete a request. The consumed native
        epoch survives loss of the Python return value or error diagnostics.
        """
        if os.getpid() != self.creator:
            raise RequestJournalUnknown('request cleanup belongs to its creator process')
        with self.lock:
            raw = struct.pack('<16Q', REQUEST_MAGIC, 91, *([0] * 10), *self.identity, *self.connection)
            source = ctypes.create_string_buffer(raw, len(raw))
            output = ctypes.create_string_buffer(32)
            count = self.image._entry(source, len(raw), output, 32, self.buffer, len(self.buffer))
            if count != 32:
                raise RequestJournalUnknown('native request rollback preclaim has no valid receipt')
            magic, status, granted, epoch = struct.unpack('<4Q', output.raw)
            if magic != CLEANUP_MAGIC or status != 0 or granted > 1 or epoch == 0:
                raise RequestJournalUnknown('native request rollback preclaim was refused')
            words = struct.unpack('<32Q', ctypes.string_at(self.buffer, 256))
            if words[19] != epoch or words[25] != epoch:
                raise RequestJournalUnknown('native request rollback claim differs from its retained epoch')
            return bool(granted)

    def snapshot(self):
        receipt = self.receipt
        result = {'key': receipt.key.decode('ascii') if receipt.keyed else None,
            'request_digest': receipt.digest.decode('ascii'), 'tool': receipt.tool.decode('ascii'),
            'started_ns': receipt.started.decode('ascii'), 'phase': receipt.phase,
            'sequence': receipt.token.sequence, 'mode': receipt.mode,
            'dispatch_count': receipt.dispatch_count, 'pending_effect_token': receipt.pending_token,
            'response_bytes': len(receipt.response), 'replay_validated': receipt.replay_validated,
            'observation_grants_execution': False}
        if self.fenced is not None:
            result['native_policy_error'] = copy.deepcopy(self.fenced)
            result['native_fields_are_last_attested'] = True
        return result


# These are the complete literal SQL statements on the transitive atomic
# adopt/rollback and replay-validation helper path. The default connection
# still uses its original statements. Explicit effect connections bind every
# selected statement to main, including in the presence of a TEMP shadow.
_EFFECT_SQL = {
    'SELECT * FROM contexts WHERE id=?': 'SELECT * FROM main.contexts WHERE id=?',
    'SELECT * FROM slots WHERE name=?': 'SELECT * FROM main.slots WHERE name=?',
    'SELECT artifact FROM versions WHERE slot=? AND generation=?': 'SELECT artifact FROM main.versions WHERE slot=? AND generation=?',
    'SELECT COUNT(*) FROM leases WHERE slot=? AND active=1': 'SELECT COUNT(*) FROM main.leases WHERE slot=? AND active=1',
    'INSERT INTO slots VALUES (?,?,?,?,?)': 'INSERT INTO main.slots VALUES (?,?,?,?,?)',
    'INSERT INTO versions VALUES (?,?,?)': 'INSERT INTO main.versions VALUES (?,?,?)',
    'SELECT generation FROM versions WHERE slot=?': 'SELECT generation FROM main.versions WHERE slot=?',
    'UPDATE slots SET generation=?,epoch=?,context_id=? WHERE name=?': 'UPDATE main.slots SET generation=?,epoch=?,context_id=? WHERE name=?',
    'SELECT * FROM artifacts WHERE content_key=?': 'SELECT * FROM main.artifacts WHERE content_key=?',
    'INSERT OR IGNORE INTO artifacts VALUES (?,?,?,?,?,?)': 'INSERT OR IGNORE INTO main.artifacts VALUES (?,?,?,?,?,?)',
    'SELECT * FROM artifacts WHERE id=?': 'SELECT * FROM main.artifacts WHERE id=?',
    'SELECT artifact FROM profiles WHERE id=? AND sha256=?': 'SELECT artifact FROM main.profiles WHERE id=? AND sha256=?',
    # The namespace owner emits the same four fixed statements already
    # qualified with main. These aliases add no new SQL effect authority.
    'SELECT * FROM main.artifacts WHERE content_key=?': 'SELECT * FROM main.artifacts WHERE content_key=?',
    'INSERT OR IGNORE INTO main.artifacts VALUES (?,?,?,?,?,?)': 'INSERT OR IGNORE INTO main.artifacts VALUES (?,?,?,?,?,?)',
    'SELECT * FROM main.artifacts WHERE id=?': 'SELECT * FROM main.artifacts WHERE id=?',
    'SELECT artifact FROM main.profiles WHERE id=? AND sha256=?': 'SELECT artifact FROM main.profiles WHERE id=? AND sha256=?',
    # Slot-ledger aliases keep the same exact request connection. The one
    # conditional update additionally binds the original row observed by HIA.
    'SELECT * FROM main.slots WHERE name=?': 'SELECT * FROM main.slots WHERE name=?',
    'SELECT artifact FROM main.versions WHERE slot=? AND generation=?': 'SELECT artifact FROM main.versions WHERE slot=? AND generation=?',
    'SELECT COUNT(*) FROM main.leases WHERE slot=? AND active=1': 'SELECT COUNT(*) FROM main.leases WHERE slot=? AND active=1',
    'INSERT INTO main.slots VALUES (?,?,?,?,?)': 'INSERT INTO main.slots VALUES (?,?,?,?,?)',
    'INSERT INTO main.versions VALUES (?,?,?)': 'INSERT INTO main.versions VALUES (?,?,?)',
    'SELECT generation FROM main.versions WHERE slot=?': 'SELECT generation FROM main.versions WHERE slot=?',
    ('UPDATE main.slots SET generation=?,epoch=?,context_id=? WHERE name=? '
     'AND generation=? AND epoch=? AND context_id=? AND abi_sha256=?'):
    ('UPDATE main.slots SET generation=?,epoch=?,context_id=? WHERE name=? '
     'AND generation=? AND epoch=? AND context_id=? AND abi_sha256=?'),
}


class _EffectRows:
    """A fetch-only view; a retained cursor cannot bypass effect revocation."""
    def __init__(self, authority, cursor):
        self._authority, self._cursor = authority, cursor

    @property
    def rowcount(self):
        self._authority.check()
        return self._cursor.rowcount

    def fetchone(self):
        self._authority.check()
        return self._cursor.fetchone()

    def fetchall(self):
        self._authority.check()
        return self._cursor.fetchall()


class _EffectConnection:
    def __init__(self, store, state, *, readonly):
        self.store, self.state, self.readonly = store, state, readonly
        self.thread = threading.get_ident()
        self.token = state.receipt.pending_token

    def check(self):
        self.state.check()
        if threading.get_ident() != self.thread:
            raise RequestJournalUnknown('request effect connection belongs to its original thread')
        self.store.check()
        receipt = self.state.call(90)
        expected = (11, 3, 8) if self.readonly else (7, 2, 7)
        if ((receipt.phase, receipt.mode, receipt.action) != expected
                or receipt.pending_token != self.token or self.store._transaction_owner is not self.state
                or not self.store.db.in_transaction):
            raise RequestJournalUnknown('request effect connection has been revoked')

    def execute(self, sql, parameters=()):
        self.check()
        statement = _EFFECT_SQL.get(sql)
        if statement is None or self.readonly and not statement.startswith('SELECT '):
            raise RequestJournalUnknown('statement is outside the fixed request effect vocabulary')
        return _EffectRows(self, self.store._execute_effect(statement, parameters))


class _SemanticRefusal(Exception):
    def __init__(self, error):
        self.error = error


class NativeRequestJournalStore:
    """Fixed SQLite effect transport to the same retained main database."""
    def __init__(self, store, image, *, shared_lock=None):
        self.store, self.image = store, image
        self.official = store.db
        self.path = Path(store.database)
        self.identity = store.database_identity
        self.sidecars = dict(store.database_sidecars)
        self.creator = os.getpid()
        self.connection_identity = struct.unpack('<2Q', os.urandom(16))
        # A selected namespace uses the same lock before both the original
        # and private SQLite transaction. This fixes lock order without
        # borrowing, replacing or committing the other connection's scope.
        self.lock = threading.RLock() if shared_lock is None else shared_lock
        self._db = None
        self._transaction_owner = None
        self.closed = False
        self.poisoned = None
        self.check()
        main = [row for row in self.official.execute('PRAGMA database_list') if row['name'] == 'main']
        if len(main) != 1 or main[0]['file'] != str(self.path):
            raise RequestJournalUnknown('request journal path differs from the official main database')
        connection = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True,
            isolation_level=None, timeout=10, check_same_thread=False)
        try:
            connection.row_factory = sqlite3.Row
            if connection.execute('PRAGMA main.journal_mode').fetchone()[0].lower() != 'wal':
                raise RequestJournalUnknown('request journal requires the original WAL')
            connection.execute('PRAGMA main.synchronous=FULL')
            connection.execute('SELECT name FROM main.sqlite_master LIMIT 1').fetchone()
            self.check()
        except BaseException:
            connection.close()
            raise
        self._db = connection

    @property
    def db(self):
        return self._db

    @staticmethod
    def _file_identity(path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise RequestJournalUnknown('request journal is not an owned private ordinary file')
        return info.st_dev, info.st_ino

    def check(self):
        if os.getpid() != self.creator:
            raise RequestJournalUnknown('request journal connection belongs to its creator process')
        if self.closed or self.poisoned is not None:
            raise RequestJournalUnknown('request journal connection is closed or fenced')
        if self.store.db is not self.official:
            raise RequestJournalUnknown('official request journal connection changed')
        self.official.in_transaction
        if self._file_identity(self.path) != self.identity:
            raise RequestJournalUnknown('official request journal file changed')
        for suffix, identity in self.sidecars.items():
            if self._file_identity(Path(str(self.path) + suffix)) != identity:
                raise RequestJournalUnknown('official request journal WAL identity changed')

    def _execute(self, sql, parameters=()):
        return self.db.execute(sql, parameters)

    def _execute_effect(self, sql, parameters=()):
        return self.db.execute(sql, parameters)

    def _rollback_once(self, state):
        if os.getpid() != self.creator or self._transaction_owner is not state:
            raise RequestJournalUnknown('request rollback lacks this connection transaction owner')
        if not state.claim_rollback():
            raise RequestJournalUnknown('request rollback epoch was already claimed; no retry is permitted')
        return self._execute('ROLLBACK')

    def _cleanup(self, state, error):
        state.fence(error)
        if self._transaction_owner is state:
            if self.poisoned is not None:
                raise RequestJournalUnknown('request journal cleanup is already fenced') from error
            try:
                if self.db.in_transaction:
                    self._rollback_once(state)
                if self.db.in_transaction:
                    raise RequestJournalUnknown('request journal rollback was not confirmed')
                self._transaction_owner = None
            except BaseException as cleanup_error:
                self.poisoned = {'type': type(cleanup_error).__name__, 'message': str(cleanup_error)[:1024]}
                raise RequestJournalUnknown('request journal cleanup outcome is unknown') from cleanup_error

    def _drive(self, state, *, admission=False):
        """Drive only native-emitted fixed SQL; caller owns the connection lock."""
        from .hia_agent_store import AgentRejected
        try:
            state.check()
            receipt = state.receipt
            while receipt.action not in (0, 7, 8):
                self.check()
                action = receipt.action
                key, digest, tool, started = (value.decode('ascii') for value in
                    (receipt.key, receipt.digest, receipt.tool, receipt.started))
                if action == 1:
                    if self.db.in_transaction or self.official.in_transaction or self._transaction_owner is not None:
                        raise RequestJournalUnknown('request journal cannot borrow an existing transaction')
                    self._transaction_owner = state
                    self._execute('BEGIN IMMEDIATE')
                    receipt = state.call(1, values=(1,))
                    continue
                if self._transaction_owner is not state:
                    raise RequestJournalUnknown('request journal transaction custody differs')
                if action == 2:
                    row = self._execute('SELECT key,digest,tool,state,response,started_ns FROM main.requests WHERE key=?',
                                        (key,)).fetchone()
                    try:
                        receipt = state.row(row)
                    except AgentRejected as error:
                        if admission:
                            raise _SemanticRefusal(error) from error
                        raise
                elif action == 3:
                    changed = self._execute('INSERT INTO main.requests(key,digest,tool,state,response,started_ns) VALUES (?,?,?,\'running\',NULL,?)',
                        (key, digest, tool, started)).rowcount
                    receipt = state.call(3, values=(changed,))
                elif action == 4:
                    changed = self._execute('UPDATE main.requests SET state=\'completed\',response=? WHERE key=? AND digest=? AND tool=? AND state=\'running\' AND response IS NULL AND started_ns=?',
                        (receipt.response.decode('utf-8'), key, digest, tool, started)).rowcount
                    receipt = state.call(3, values=(changed,))
                elif action == 5:
                    self._execute('COMMIT')
                    self.check()
                    receipt = state.call(4, values=(int(not self.db.in_transaction),))
                    self._transaction_owner = None
                elif action == 6:
                    self._rollback_once(state)
                    receipt = state.call(8, values=(int(not self.db.in_transaction),))
                    self._transaction_owner = None
                else:
                    raise RequestJournalUnknown('native request journal emitted an unknown SQL action')
            if receipt.action == 0 and self._transaction_owner is state:
                raise RequestJournalUnknown('request journal returned with an unconfirmed transaction')
            return receipt
        except _SemanticRefusal as refused:
            self._cleanup(state, refused.error)
            raise
        except BaseException as error:
            self._cleanup(state, error)
            raise RequestJournalUnknown('request journal effect or acknowledgement is unconfirmed') from error

    def admit(self, tool, request_digest, candidate_key, replay_validator):
        self.check()
        state = RequestState(self.image, self.connection_identity, tool, request_digest, candidate_key)
        ticket = NativeRequestTicket(self, state)
        with self.lock:
            try:
                receipt = self._drive(state, admission=True)
            except _SemanticRefusal as refused:
                raise refused.error
            if receipt.action == 8:
                authority = _EffectConnection(self, state, readonly=True)
                try:
                    replay_validator(receipt.response, authority)
                except BaseException as error:
                    ticket._abort_callback(error)
                    raise
                try:
                    state.call(9, effect_token=receipt.pending_token, values=(1,))
                    receipt = self._drive(state)
                except BaseException as error:
                    self._cleanup(state, error)
                    raise RequestJournalUnknown('request replay commit acknowledgement is unconfirmed') from error
                if receipt.phase != 8 or not receipt.replay_validated:
                    raise RequestJournalUnknown('request replay lacks confirmed native validation')
            return ticket

    def close(self):
        if os.getpid() != self.creator:
            raise RequestJournalUnknown('request journal connection belongs to its creator process')
        with self.lock:
            if not self.closed:
                self.closed = True
                self.db.close()


class NativeRequestTicket:
    def __init__(self, store, state):
        self.store, self.state = store, state

    @property
    def replayed(self):
        self.state.check()
        receipt = self.state.receipt
        return receipt.mode == 3 and receipt.phase == 8 and receipt.replay_validated

    @property
    def replay_bytes(self):
        if not self.replayed:
            raise RequestJournalUnknown('request ticket is not a confirmed replay')
        return self.state.receipt.response

    @property
    def atomic_kind(self):
        self.state.check()
        return self.state.receipt.atomic_kind

    def dispatch(self):
        self.state.check()
        with self.store.lock, self.state.lock:
            try:
                self.store.check()
                self.state.call(5)
                receipt = self.store._drive(self.state)
                if receipt.action != 7:
                    raise RequestJournalUnknown('request has no native dispatch preclaim')
                return receipt
            except BaseException as error:
                self.store._cleanup(self.state, error)
                raise RequestJournalUnknown('request dispatch authority is unconfirmed') from error

    def finish(self, response):
        self.state.check()
        with self.store.lock, self.state.lock:
            try:
                self.store.check()
                if type(response) is not bytes:
                    _reject(1)
                pending = self.state.receipt.pending_token
                self.state.call(6, effect_token=pending, values=(len(response), 1), payload=response)
                receipt = self.store._drive(self.state)
                if receipt.phase != 8:
                    raise RequestJournalUnknown('request completion lacks confirmed commit')
                return receipt.response
            except BaseException as error:
                self.store._cleanup(self.state, error)
                raise RequestJournalUnknown('request terminal response is unconfirmed') from error

    def _abort_callback(self, error):
        known = isinstance(error, (ValueError, TypeError, OSError, OverflowError, RecursionError, sqlite3.Error))
        try:
            self.state.call(7, effect_token=self.state.receipt.pending_token, values=(int(known),))
            self.store._drive(self.state)
        except BaseException as cleanup_error:
            self.store._cleanup(self.state, cleanup_error)
            raise RequestJournalUnknown('request callback rollback acknowledgement is unconfirmed') from cleanup_error
        if not known:
            self.state.fence(error)
            raise RequestJournalUnknown('request callback has no confirmed terminal result') from error

    def run(self, invoke, encode_response, encode_error):
        """A returned/rejected callback is attested before terminal SQL is legal."""
        receipt = self.dispatch()
        if receipt.mode == 2:
            self.store._cleanup(self.state, RequestJournalUnknown('atomic request used ordinary dispatch'))
            raise RequestJournalUnknown('atomic request used ordinary dispatch')
        try:
            try:
                response = encode_response(invoke())
            except (ValueError, TypeError, OSError, OverflowError, RecursionError, sqlite3.Error) as error:
                response = encode_error(error)
            from .hia_agent_store import wire
            raw = wire(response)
            self.state.call(12, effect_token=receipt.pending_token, values=(len(raw), 1), payload=raw)
            return response
        except BaseException as error:
            self.state.fence(error)
            raise RequestJournalUnknown('request callback result acknowledgement is unconfirmed') from error

    def atomic(self, invoke, encode_response):
        self.state.check()
        with self.store.lock, self.state.lock:
            receipt = self.dispatch()
            if receipt.mode != 2:
                self.store._cleanup(self.state, RequestJournalUnknown('request is not an atomic slot effect'))
                raise RequestJournalUnknown('request is not an atomic slot effect')
            authority = _EffectConnection(self.store, self.state, readonly=False)
            try:
                response = encode_response(invoke(authority))
            except BaseException as error:
                self._abort_callback(error)
                raise
            from .hia_agent_store import wire
            try:
                raw = wire(response)
                self.state.call(12, effect_token=receipt.pending_token, values=(len(raw), 1), payload=raw)
                self.finish(raw)
            except BaseException as error:
                self.store._cleanup(self.state, error)
                raise RequestJournalUnknown('atomic request result acknowledgement is unconfirmed') from error
            return response

    def snapshot(self):
        return self.state.snapshot()
