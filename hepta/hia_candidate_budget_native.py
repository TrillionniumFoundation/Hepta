"""Native candidate-attempt policy over the original AgentStore contexts.

The inherited connection is the existing bounded SQLite effect transport, not
a second budget namespace. HIA owns count admission, increment, exact readback
and commit acknowledgement. Request identity and replay stay with the original
ordinary or explicitly selected native request journal.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import os
from pathlib import Path
import sqlite3
import struct

from .hia_execution_budget_native import NativeExecutionBudgetStore
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/candidate_budget.hepta')
SCHEMA = 'hepta.hia.candidate-budget-native.v1'
SELECTOR = 'HEPTA_HIA_CANDIDATE_BUDGET_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIACBRQ1', 'little')
RESULT_MAGIC = int.from_bytes(b'HIACBRS1', 'little')
STATE_BYTES = 384
OUTPUT_BYTES = 272


def _reject(status, message=None):
    from .hia_agent_store import AgentRejected
    values = {
        1: ('E_HIA_CANDIDATE_BUDGET_RECORD', 'candidate attempt record is not a bounded integer', 'stop'),
        2: ('E_HIA_CANDIDATE_BUDGET_CONFLICT', 'candidate attempt transition or readback differs', 'observe_original'),
        3: ('E_HIA_BUDGET', 'candidate attempt budget exhausted', 'correct_input'),
        4: ('E_HIA_CANDIDATE_BUDGET_UNKNOWN', 'candidate attempt commit is not confirmed; observe the original request', 'observe_original'),
        5: ('E_HIA_CANDIDATE_BUDGET_CUSTODY', 'candidate attempt native custody failed', 'stop'),
    }
    code, text, retry = values[status]
    raise AgentRejected(code, message or text, 'context', retry_action=retry)


class NativeCandidateBudgetImage(NativeHiaJsonImage):
    pass


def selected_candidate_budget():
    if SELECTOR not in os.environ:
        return None
    # A present but empty/invalid explicit selection is an error, not a request
    # to silently reenter the hosted policy.
    source = SOURCE.read_bytes()
    image = _installed_json_image(os.environ[SELECTOR], SOURCE, SCHEMA, NativeCandidateBudgetImage)
    if SOURCE.read_bytes() != source:
        _reject(5, 'candidate attempt source changed during selection')
    return image, source


@dataclass(frozen=True)
class AttemptReceipt:
    status: int
    action: int
    sequence: int
    phase: int
    maximum: int
    original: int
    updated: int
    context: bytes


class AttemptState:
    def __init__(self, image, connection, context, maximum):
        self.image = image
        self.connection = connection
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.creator = os.getpid()
        self.buffer = ctypes.create_string_buffer(STATE_BYTES)
        self.receipt = None
        self.fenced = False
        if type(context) is not str:
            _reject(1)
        raw = context.encode('utf-8')
        self.call(0, a=maximum, payload=raw)

    def call(self, event, *, a=0, b=0, c=0, payload=b'', sequence=None):
        if self.fenced or os.getpid() != self.creator:
            _reject(5, 'candidate attempt session cannot be resumed or inherited')
        try:
            serial = 0 if self.receipt is None else self.receipt.sequence
            if sequence is not None:
                serial = sequence
            numbers = (REQUEST_MAGIC, event, serial, a, b, c, *self.identity, *self.connection, len(payload), 0)
            if (type(payload) is not bytes or len(payload) > 192
                    or any(type(v) is not int or not 0 <= v < 1 << 64 for v in numbers)):
                _reject(1)
            raw = struct.pack('<12Q', *numbers) + payload
            source = ctypes.create_string_buffer(raw, len(raw))
            output = ctypes.create_string_buffer(OUTPUT_BYTES)
            size = self.image._entry(source, len(raw), output, OUTPUT_BYTES, self.buffer, STATE_BYTES)
            if not 80 <= size <= OUTPUT_BYTES or source.raw != raw:
                _reject(5)
            magic, status, action, sequence, phase, maximum, original, updated, extent, reserved = struct.unpack('<10Q', output.raw[:80])
            words = struct.unpack('<16Q', self.buffer.raw[:128])
            if (magic != RESULT_MAGIC or status > 4 or action > 4 or not 1 <= sequence <= 7
                    or not 1 <= phase <= 7 or not 1 <= maximum <= 4096 or reserved
                    or not 1 <= extent <= 192 or size != 80 + extent
                    or (phase, sequence, maximum, original, updated, extent, action)
                    != (words[2], words[3], words[8], words[9], words[10], words[11], words[12])
                    or tuple(words[4:6]) != self.identity or tuple(words[6:8]) != self.connection
                    or output.raw[80:size] != self.buffer.raw[128:128 + extent]
                    or status and (action != 0 or phase != 7)):
                _reject(5, 'candidate attempt receipt does not bind its native state')
            receipt = AttemptReceipt(status, action, sequence, phase, maximum, original, updated, output.raw[80:size])
            self.receipt = receipt
            if status:
                _reject(status)
            return receipt
        except BaseException:
            self.fenced = True
            raise

    def row(self, value):
        if value is None:
            return self.call(2)
        context, attempts = value['id'], value['attempts']
        if type(context) is not str:
            _reject(1)
        # SQLite's signed INTEGER wire representation is transported without
        # performing the native nonnegative/maximum/increment policy here.
        kind = 0 if type(attempts) is int and -(1 << 63) <= attempts < (1 << 63) else 1
        raw = attempts & ((1 << 64) - 1) if kind == 0 else 0
        return self.call(2, a=1, b=kind, c=raw, payload=context.encode('utf-8'))


class NativeCandidateBudgetStore(NativeExecutionBudgetStore):
    """Reuse original-WAL connection custody; never call execution-budget SQL."""
    def __init__(self, store, admission):
        image, source = admission
        if type(source) is not bytes or SOURCE.read_bytes() != source:
            _reject(5, 'candidate attempt source changed after admission')
        # Candidate selection can be enabled independently of native wall-cost
        # budgets. Capture the already open official WAL before creating the
        # private effect connection, without enabling or altering that policy.
        store.db.execute('SELECT name FROM sqlite_master LIMIT 1').fetchone()
        sidecars = {suffix: self._file_identity(Path(str(store.database) + suffix))
                    for suffix in ('-wal', '-shm')}
        super().__init__(store, image, sidecars=sidecars)
        self.source_bytes = source

    def consume(self, context, maximum):
        self.check()
        if SOURCE.read_bytes() != self.source_bytes:
            _reject(5, 'candidate attempt source changed after selection')
        state = AttemptState(self.image, self.connection_identity, context, maximum)
        with self.lock:
            owned = False
            committed = False
            commit_attempted = False
            try:
                self.check()
                if self.db.in_transaction or self.official.in_transaction:
                    _reject(5, 'candidate attempt cannot borrow an existing transaction')
                receipt = state.receipt
                while receipt.action:
                    self.check()
                    context = receipt.context.decode('utf-8')
                    if receipt.action == 1:
                        owned = True
                        self._execute('BEGIN IMMEDIATE')
                        receipt = state.call(1, a=1)
                    elif receipt.action == 2:
                        row = self._execute('SELECT id,attempts FROM main.contexts WHERE id=?', (context,)).fetchone()
                        receipt = state.row(row)
                    elif receipt.action == 3:
                        if not owned:
                            _reject(5)
                        changed = self._execute('UPDATE main.contexts SET attempts=? WHERE id=? AND attempts=?',
                                                (receipt.updated, context, receipt.original)).rowcount
                        receipt = state.call(3, a=changed)
                    elif receipt.action == 4:
                        if not owned:
                            _reject(5)
                        self.check()
                        commit_attempted = True
                        self._execute('COMMIT')
                        committed = True
                        self.check()
                        receipt = state.call(4, a=int(not self.db.in_transaction))
                        owned = False
                    else:
                        _reject(5)
                if owned or self.db.in_transaction or not committed or receipt.phase != 6:
                    _reject(4)
                return receipt.updated
            except BaseException as error:
                state.fenced = True
                if owned and self.db.in_transaction:
                    try:
                        self._execute('ROLLBACK')
                    except BaseException as cleanup:
                        self.poisoned = {'type': type(cleanup).__name__, 'message': str(cleanup)[:1024]}
                # A commit that reached SQLite but lost its acknowledgment is
                # never compensated. The original request journal prevents
                # replay; its counter remains consumed if the commit happened.
                if commit_attempted and isinstance(error, (ValueError, OSError, sqlite3.Error)):
                    _reject(4)
                raise
