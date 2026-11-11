"""HIA-owned execution budgets over the original SQLite journal.

The foreign adapter transports exact rows and executes a fixed SQL vocabulary.
It owns a dedicated connection to the same observed database/WAL, never another
budget store. Native claims retain their state and cannot resume after an
unconfirmed transition, commit or child outcome.
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

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/execution_budget.hepta')
SCHEMA = 'hepta.hia.execution-budget-native.v1'
SELECTOR = 'HEPTA_HIA_EXECUTION_BUDGET_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIAEBRQ1', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAEBRS1', 'little')
STATE_BYTES = 13568
OUTPUT_BYTES = 13312
MAX_DECIMAL = 4300


def _reject(status, message=None):
    from .hia_agent_store import AgentRejected
    names = {
        1: ('E_HIA_BUDGET_CORRUPT', 'execution budget has an invalid bounded record', 'stop'),
        2: ('E_HIA_BUDGET_NATIVE_CUSTODY', 'native execution budget state or image custody failed', 'stop'),
        3: ('E_HIA_BUDGET', 'context lacks an execution budget record', 'correct_input'),
        4: ('E_HIA_BUDGET_BUSY', 'context native budget has a live or uncertain owner; observe that operation', 'stop'),
        5: ('E_HIA_BUDGET_CONFLICT', 'execution budget changed or its outcome token does not match', 'observe_original'),
        6: ('E_HIA_BUDGET_EXHAUSTED', 'execution budget state or canonical decimal capacity is exhausted', 'stop'),
        7: ('E_HIA_BUDGET_UNKNOWN', 'execution budget has an unconfirmed transition or native outcome', 'observe_original'),
        8: ('E_HIA_BUDGET_EXISTS', 'context already has an execution budget record', 'stop')}
    code, text, retry = names[status]
    raise AgentRejected(code, message or text, 'execution', retry_action=retry)


class NativeExecutionBudgetImage(NativeHiaJsonImage):
    pass


def selected_execution_budget():
    selected = os.environ.get(SELECTOR)
    return (_installed_json_image(selected, SOURCE, SCHEMA, NativeExecutionBudgetImage)
            if selected else None)


@dataclass(frozen=True)
class BudgetToken:
    owner: tuple[int, int]
    connection: tuple[int, int]
    sequence: int


@dataclass(frozen=True)
class BudgetReceipt:
    status: int
    action: int
    token: BudgetToken
    remaining_ms: int
    phase: int
    kind: int
    context: bytes
    used: bytes
    owner: bytes
    updated: bytes
    native: bytes
    owner_present: bool
    row_exists: bool


class BudgetState:
    """One retained native command/claim, never rebuilt from hosted flags."""
    def __init__(self, image, connection, kind, context, owner='', maximum=0, started=0):
        self.image = image
        self.connection = connection
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.creator = os.getpid()
        self.lock = threading.RLock()
        self.buffer = ctypes.create_string_buffer(STATE_BYTES)
        self.receipt = None
        self.fenced = None
        context_raw, owner_raw = self._text(context, 192), self._text(owner, 64)
        self.call(0, values=(kind, maximum, started, len(context_raw), len(owner_raw)),
                  payload=context_raw + owner_raw)

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
            self.fenced = {'type': type(error).__name__, 'message': str(error)[:1024]}

    def check(self):
        if os.getpid() != self.creator:
            _reject(2, 'execution budget claim belongs to its creator process')
        if self.fenced is not None:
            _reject(7, 'execution budget claim is fenced; no implicit replay or refund is permitted')

    def call(self, event, *, values=(), payload=b'', now=0, token=None):
        self.check()
        with self.lock:
            self.check()
            try:
                current = 0 if self.receipt is None else self.receipt.token.sequence
                selected = token or BudgetToken(self.identity, self.connection, current)
                numbers = [REQUEST_MAGIC, event, selected.sequence, now, *values]
                if len(numbers) > 12 or any(type(v) is not int or not 0 <= v < 1 << 64 for v in numbers):
                    _reject(1)
                numbers.extend([0] * (12 - len(numbers)))
                raw = struct.pack('<16Q', *numbers, *selected.owner, *selected.connection) + payload
                source = ctypes.create_string_buffer(raw, len(raw))
                output = ctypes.create_string_buffer(OUTPUT_BYTES)
                returned = self.image._entry(source, len(raw), output, OUTPUT_BYTES, self.buffer, STATE_BYTES)
                self.check()
                if not 128 <= returned <= OUTPUT_BYTES:
                    _reject(2, 'native execution budget rejected its bounded ABI')
                header = struct.unpack('<16Q', output.raw[:128])
                magic, status, action, claimed, remaining, phase, sequence, kind, *tail = header
                lengths, held, found, reserved = tail[:5], tail[5], tail[6], tail[7]
                if (magic != RESULT_MAGIC or status > 8 or action > 7 or phase > 9 or kind > 2
                        or claimed != sequence or remaining > 86400000 or held > 1 or found > 1 or reserved
                        or lengths[0] > 192 or lengths[2] > 64
                        or any(lengths[i] > MAX_DECIMAL for i in (1, 3, 4))
                        or returned != 128 + sum(lengths) or status != 0 and action != 0):
                    _reject(2, 'invalid native execution budget transition receipt')
                words = struct.unpack('<32Q', self.buffer.raw[:256])
                if phase == 0:
                    _reject(status or 2)
                if (words[4] != sequence or words[2] != kind or words[3] != phase or words[18] != action
                        or (words[5], words[6]) != self.identity or (words[22], words[23]) != self.connection
                        or tuple(lengths) != (words[7], words[9], words[8], words[11], words[10])
                        or (held, found) != (words[20], words[21])):
                    _reject(2, 'native execution budget receipt does not bind its retained state')
                at, fields = 128, []
                for size in lengths:
                    fields.append(output.raw[at:at + size]); at += size
                receipt = BudgetReceipt(status, action, BudgetToken(self.identity, self.connection, claimed),
                    remaining, phase, kind, *fields, bool(held), bool(found))
                self.receipt = receipt
                if status:
                    _reject(status)
                return receipt
            except BaseException as error:
                self.fence(error)
                raise

    def row(self, row):
        if row is None:
            return self.call(2, values=(0, 0, 0, 0, 0))
        context = self._text(row['context_id'], 192)
        used = self._text(row['used_native_ns'], MAX_DECIMAL)
        owner = b'' if row['owner'] is None else self._text(row['owner'], 64)
        return self.call(2, values=(1, int(row['owner'] is not None), len(context), len(used), len(owner)),
                         payload=context + used + owner)

    def observation(self):
        row = self.receipt
        result = {'context_id': row.context.decode('utf-8'), 'phase': row.phase,
            'native_child_wall_ns': row.native.decode('ascii'), 'remaining_ms': row.remaining_ms,
            'historical_completion_receipt': False, 'execution_authority_granted': False}
        if row.kind == 1:
            # These bind the original claim. They are deliberately not named
            # as a current-row observation after completion or a later owner.
            result.update(claim_owner=row.owner.decode('utf-8'),
                captured_used_native_ns=row.used.decode('ascii') if row.used else None,
                proposed_used_native_ns=row.updated.decode('ascii') if row.updated else None)
        else:
            result.update(used_native_ns=row.used.decode('ascii') if row.used else None,
                owner=row.owner.decode('utf-8') if row.owner_present else None,
                record_exists=row.row_exists)
        if self.fenced is not None:
            result['native_policy_error'] = copy.deepcopy(self.fenced)
            result['native_fields_are_last_attested'] = True
        return result


class NativeExecutionBudgetStore:
    """Fixed SQLite effects on a dedicated connection to the original WAL."""
    def __init__(self, store, image):
        self.store, self.image = store, image
        self.official = store.db
        self.path = Path(store.database)
        self.identity = store.database_identity
        self.creator = os.getpid()
        self.lock = threading.RLock()
        self.connection_identity = struct.unpack('<2Q', os.urandom(16))
        self._db = None
        self.closed = False
        self.poisoned = None
        self.sidecars = dict(store.database_sidecars)
        self.check()
        main = [row for row in self.official.execute('PRAGMA database_list') if row['name'] == 'main']
        if len(main) != 1 or main[0]['file'] != str(self.path):
            _reject(2, 'execution budget path does not identify the official main database')
        # mode=rw is deliberate: a missing/replaced official database can never
        # silently become a newly created independent budget namespace.
        connection = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True,
                                     isolation_level=None, timeout=10, check_same_thread=False)
        try:
            connection.row_factory = sqlite3.Row
            if connection.execute('PRAGMA journal_mode').fetchone()[0].lower() != 'wal':
                _reject(2, 'execution budget requires the original WAL journal')
            connection.execute('PRAGMA synchronous=FULL')
            connection.execute('SELECT name FROM sqlite_master LIMIT 1').fetchone()
            self.check()
        except BaseException:
            connection.close()
            raise
        self._db = connection

    @property
    def db(self):
        return self._db

    def _execute(self, sql, parameters=()):
        """Fixed foreign statement boundary, used by fault qualification."""
        return self._db.execute(sql, parameters)

    @staticmethod
    def _file_identity(path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            _reject(2, 'execution budget journal identity is not an owned private ordinary file')
        return info.st_dev, info.st_ino

    def _check_main(self):
        if os.getpid() != self.creator:
            _reject(2, 'execution budget connection belongs to its creator process')
        # The original connection remains a live identity custodian. Closing
        # it or replacing AgentStore.db cannot transfer this authority.
        if self.store.db is not self.official:
            _reject(2, 'official execution budget database connection changed')
        self.official.in_transaction
        if self._file_identity(self.path) != self.identity:
            _reject(2, 'official execution budget database file changed')

    def check(self):
        self._check_main()
        if self.closed or self.poisoned is not None:
            _reject(2, 'execution budget connection is closed or fenced')
        for suffix, identity in self.sidecars.items():
            if self._file_identity(Path(str(self.path) + suffix)) != identity:
                _reject(2, 'execution budget WAL identity changed')

    def _state(self, kind, context, owner='', maximum=0, started=0):
        self.check()
        return BudgetState(self.image, self.connection_identity, kind, context, owner, maximum, started)

    def _drive(self, state):
        state.check()
        with self.lock:
            owned_transaction = False
            try:
                self.check()
                if self.db.in_transaction or self.official.in_transaction:
                    _reject(2, 'execution budget cannot borrow a caller-owned transaction')
                receipt = state.receipt
                while receipt.action:
                    self.check()
                    action = receipt.action
                    context = receipt.context.decode('utf-8')
                    if action == 1:
                        # This dedicated connection starts unowned and remains
                        # exclusively held until COMMIT/ROLLBACK. The flag is
                        # foreign transaction custody, never an execution right.
                        owned_transaction = True
                        self._execute('BEGIN IMMEDIATE')
                        receipt = state.call(1, values=(1,))
                    elif action == 2:
                        row = self._execute('SELECT context_id,used_native_ns,owner FROM main.execution_budgets WHERE context_id=?',
                                              (context,)).fetchone()
                        receipt = state.row(row)
                    elif action == 3:
                        if not owned_transaction:
                            _reject(2)
                        changed = self._execute('INSERT INTO main.execution_budgets(context_id,used_native_ns,owner) VALUES (?,?,NULL)',
                            (context, receipt.used.decode('ascii'))).rowcount
                        receipt = state.call(3, values=(changed,))
                    elif action == 4:
                        if not owned_transaction:
                            _reject(2)
                        changed = self._execute('UPDATE main.execution_budgets SET owner=? WHERE context_id=? AND used_native_ns=? AND owner IS NULL',
                            (receipt.owner.decode('ascii'), context, receipt.used.decode('ascii'))).rowcount
                        receipt = state.call(3, values=(changed,))
                    elif action == 5:
                        if not owned_transaction:
                            _reject(2)
                        changed = self._execute('UPDATE main.execution_budgets SET owner=NULL,used_native_ns=? WHERE context_id=? AND used_native_ns=? AND owner=?',
                            (receipt.updated.decode('ascii'), context, receipt.used.decode('ascii'),
                             receipt.owner.decode('ascii'))).rowcount
                        receipt = state.call(3, values=(changed,))
                    elif action == 6:
                        if not owned_transaction:
                            _reject(2)
                        self.check()
                        self._execute('COMMIT')
                        self.check()
                        receipt = state.call(4, values=(int(not self.db.in_transaction),))
                        owned_transaction = False
                    else:
                        _reject(2, 'native execution request reached the SQL effect transport')
                if owned_transaction or self.db.in_transaction:
                    _reject(2, 'native execution budget ended without a confirmed commit')
                return receipt
            except BaseException as error:
                state.fence(error)
                if owned_transaction:
                    try:
                        # A rollback of this uncommitted private connection
                        # cannot clear a previously committed execution owner.
                        # After a successful but lost COMMIT the flag is false
                        # in SQLite, so no compensating write is attempted.
                        if self.db.in_transaction:
                            self._execute('ROLLBACK')
                    except BaseException as cleanup_error:
                        self.poisoned = {'type': type(cleanup_error).__name__,
                                         'message': str(cleanup_error)[:1024]}
                raise

    def create(self, context):
        state = self._state(0, context)
        self._drive(state)

    def claim(self, context, owner, maximum, started):
        state = self._state(1, context, owner, maximum, started)
        self._drive(state)
        return NativeBudgetClaim(self, state)

    def observe(self, context):
        state = self._state(2, context)
        self._drive(state)
        return state.observation()

    def close(self):
        if os.getpid() != self.creator:
            _reject(2, 'execution budget connection belongs to its creator process')
        with self.lock:
            if not self.closed:
                self.closed = True
                self.db.close()


class NativeBudgetClaim:
    def __init__(self, store, state):
        self.store, self.state = store, state

    @property
    def native_ns(self):
        return self.state.receipt.native.decode('ascii')

    def run(self, runner, *args, now, total_ms, **kwargs):
        self.state.check()
        with self.state.lock:
            try:
                self.store.check()
                receipt = self.state.call(5, values=(total_ms,), now=now)
                if receipt.action != 7:
                    _reject(2)
                outcome = runner(*args, timeout_ms=receipt.remaining_ms, **kwargs)
                # These are exact observations from the fixed foreign runner,
                # not user authorization. HIA validates their semantic content.
                cost = self.state._text(outcome['wall_ns'], MAX_DECIMAL)
                self.state.call(6, token=receipt.token,
                    values=(int(outcome.get('termination_confirmed') is True), len(cost)), payload=cost)
                return outcome
            except BaseException as error:
                self.state.fence(error)
                raise

    def complete(self):
        self.state.check()
        with self.state.lock:
            try:
                self.store.check()
                self.state.call(10)
                self.store._drive(self.state)
            except BaseException as error:
                self.state.fence(error)
                raise

    def snapshot(self):
        return self.state.observation()
