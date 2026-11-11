"""Explicit HIA slot, version and lease decisions on the original SQLite store.

This adapter moves bytes and performs a fixed SQL vocabulary on store.db.
The selected HIA image owns conditional comparison, generation/epoch arithmetic,
live/retained compatibility decisions and complete lease descriptor admission.
Existing proof, evaluation, native image execution and JSON bridges remain in
their ordinary callers. This module never starts or commits a SQL transaction.
"""
from __future__ import annotations
import ctypes
from dataclasses import dataclass
from hashlib import sha256
import os
import struct
import uuid

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/slot_ledger.hepta')
SCHEMA = 'hepta.hia.slot-ledger-native.v1'
SELECTOR = 'HEPTA_HIA_SLOT_LEDGER_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIASLRQ1', 'little')
RESULT_MAGIC = int.from_bytes(b'HIASLRS1', 'little')
STATE_MAGIC = int.from_bytes(b'HIASLST1', 'little')
STATE_BYTES = 128
MAX_U64 = (1 << 64) - 1


def _custody(message):
    from .hia_agent_store import AgentRejected
    raise AgentRejected('E_HIA_SLOT_NATIVE_CUSTODY', message, 'adoption', retry_action='stop')


def request_packet(opcode, fields=(), *, flags=0, a=0, b=0, token=(0, 0, 0, 0)):
    fields = tuple(fields)
    numbers = (REQUEST_MAGIC, opcode, len(fields), flags, a, b, 0, 0, *token, 0, 0, 0, 0)
    if (len(numbers) != 16 or len(fields) > 7
            or any(type(v) is not int or not 0 <= v <= MAX_U64 for v in numbers)
            or any(type(v) is not bytes for v in fields)):
        _custody('invalid foreign slot protocol frame')
    return struct.pack('<16Q', *numbers) + struct.pack('<' + str(len(fields)) + 'Q',
        *(len(v) for v in fields)) + b''.join(fields)


@dataclass(frozen=True)
class SlotLedgerReceipt:
    status: int
    action: int
    values: tuple[int, int]
    fields: tuple[bytes, ...]
    raw: bytes


class NativeSlotLedger(NativeHiaJsonImage):
    """Immutable admitted code; each caller supplies private operation state."""
    def transition(self, request: bytes, state=None) -> SlotLedgerReceipt:
        if type(request) is not bytes:
            _custody('slot input is not immutable bytes')
        workspace = ctypes.create_string_buffer(STATE_BYTES) if state is None else state
        if not isinstance(workspace, ctypes.Array) or ctypes.sizeof(workspace) != STATE_BYTES:
            _custody('slot operation workspace has the wrong extent')
        source = ctypes.create_string_buffer(request, len(request)) if request else ctypes.create_string_buffer(1)
        capacity = max(256, len(request) + 128)
        output = ctypes.create_string_buffer(capacity)
        returned = self._entry(source, len(request), output, capacity, workspace, STATE_BYTES)
        if not 64 <= returned <= capacity:
            _custody('native slot image refused the byte protocol')
        raw = bytes(output.raw[:returned])
        magic, status, action, count, a, b, payload, echoed = struct.unpack('<8Q', raw[:64])
        opcode = struct.unpack_from('<Q', request, 8)[0] if len(request) >= 16 else 0
        if magic != RESULT_MAGIC or echoed != opcode or count > 4 or returned < 64 + count * 8:
            _custody('native slot result header is invalid')
        lengths = struct.unpack_from('<' + str(count) + 'Q', raw, 64)
        at = 64 + count * 8
        remaining = len(raw) - at
        if payload != remaining:
            _custody('native slot result payload extent is invalid')
        fields = []
        for length in lengths:
            if length > remaining:
                _custody('native slot field exceeds the remaining result')
            fields.append(raw[at:at + length])
            at += length
            remaining -= length
        if remaining:
            _custody('native slot result contains unclaimed bytes')
        allowed_errors = {1: {2}, 3: {3}, 4: {4}, 5: {5}, 6: {8, 9},
            7: {2}, 8: {2}, 9: {6, 7}, 10: {10}, 11: {13},
            13: {11}, 14: {11}, 15: {8}, 16: {11}}
        if status:
            if (status not in allowed_errors.get(opcode, set()) | {12} or action or count or b
                    or (status == 2 and a not in {1, 2}) or (status != 2 and a)):
                _custody('native slot refusal has an invalid operation shape')
        else:
            if opcode not in range(1, 17):
                _custody('native slot result admits an unknown operation')
            expected_action, expected_fields = 0, 0
            if opcode == 2:
                if action not in {0, 1}:
                    _custody('native slot snapshot action is invalid')
                expected_action, expected_fields = action, 4 if action else 0
                if b or not action and a:
                    _custody('native slot snapshot scalars are invalid')
            elif opcode == 9:
                expected_fields = 2
                if tuple(fields) != (str(a).encode('ascii'), str(b).encode('ascii')):
                    _custody('native generation bytes do not match native scalars')
            elif opcode == 12:
                if action not in {1, 2}:
                    _custody('native slot adoption action is invalid')
                expected_action = action
            elif opcode in {13, 14, 15, 16}:
                expected_action = {13: 1, 14: 2, 15: 3, 16: 1}[opcode]
                expected_fields = 4
            if action != expected_action or count != expected_fields:
                _custody('native slot success has an invalid operation shape')
            if opcode not in {1, 2, 9} and (a or b):
                _custody('native slot success contains unclaimed scalars')
        if opcode == 1 and status == 0:
            request_count = struct.unpack_from('<Q', request, 16)[0]
            if request_count == 1 and b:
                _custody('single native u64 result contains a second value')
        if opcode in {7, 8, 9} and (not status or status in {6, 7}):
            words = struct.unpack('<16Q', bytes(workspace))
            tokens = struct.unpack_from('<4Q', request, 64)
            phase = 2 if opcode == 9 else 1
            kind = words[2]
            checksum = 1469598103934665603
            for index, word in enumerate(words):
                if index != 12:
                    checksum = (((checksum << 7) & MAX_U64) | (checksum >> 57)) ^ word
            if (words[0] != STATE_MAGIC or words[1] != phase or kind not in {1, 2}
                    or tuple(words[8:12]) != tokens or words[12] != checksum
                    or words[5] > 1 or any(words[i] for i in (7, 13, 14, 15))):
                _custody('native slot receipt lost its private fold state')
            if ((opcode == 7 and kind != struct.unpack_from('<Q', request, 24)[0])
                    or (opcode == 8 and kind != 1)
                    or (status == 6 and kind != 1) or (status == 7 and kind != 2)):
                _custody('native slot receipt has the wrong fold operation')
            if opcode == 9 and status == 0 and (a, b) != (words[6], words[3]):
                _custody('native slot result differs from its frozen final state')
        return SlotLedgerReceipt(status, action, (a, b), tuple(fields), raw)


def selected_slot_ledger():
    if SELECTOR not in os.environ:
        return None
    selected = os.environ[SELECTOR]
    if not selected:
        raise ValueError('slot ledger selector must not be empty')
    return _installed_json_image(selected, SOURCE, SCHEMA, NativeSlotLedger)


def _text(value):
    # A type tag preserves comparison against non-string local API inputs.
    # Strings are not put through the bounded JSON bridge: the original local
    # slot observation/acquire API imposes no new string or history-row cap.
    if type(value) is str:
        try:
            return b'S' + value.encode('utf-8')
        except UnicodeError:
            return b'X'
    return b'X'


def _untext(value):
    if not value.startswith(b'S'):
        _custody('native slot row returned a non-text SQLite field')
    try:
        return value[1:].decode('utf-8')
    except UnicodeError:
        _custody('native slot row returned invalid UTF-8')


def _decimal(value):
    if type(value) is str:
        try:
            return value.encode('ascii')
        except UnicodeError:
            pass
    return b''


def _raise(receipt, labels=()):
    from .hia_agent_store import AgentRejected
    status = receipt.status
    if not status:
        return receipt
    if status == 2:
        index = receipt.values[0] - 1
        if not 0 <= index < len(labels):
            _custody('native range refusal lacks its field label')
        raise AgentRejected('E_HIA_RANGE', labels[index] + ' must be a canonical u64 decimal string')
    messages = {
        3: ('E_HIA_GENERATION_STALE', 'slot changed; read the retained current snapshot and choose a fresh conditional request', 'adoption'),
        4: ('E_HIA_ABI', 'candidate changes the live slot ABI', 'adoption'),
        5: ('E_HIA_BASELINE', 'evaluation baseline is not the currently active image', 'adoption'),
        6: ('E_HIA_GENERATION_EXHAUSTED', 'u64 generation or epoch space is exhausted', 'adoption'),
        7: ('E_HIA_GENERATION_EXHAUSTED', 'u64 epoch space is exhausted', 'adoption'),
        8: ('E_HIA_SLOT', 'slot has no active generation', 'admission'),
        9: ('E_HIA_SLOT', 'slot has no retained generation', 'adoption'),
        10: ('E_HIA_GENERATION', 'requested generation is not retained', 'adoption'),
        11: ('E_HIA_LEASE', 'lease is released, unknown or modified', 'admission'),
        13: ('E_HIA_ABI', 'retained generation is not ABI compatible', 'adoption'),
    }
    if status not in messages:
        _custody('native slot state or frame custody failed')
    code, message, phase = messages[status]
    if status == 3:
        raise AgentRejected(code, message, phase, retry_action='refresh_context')
    raise AgentRejected(code, message, phase)



class _SelectedRendererFailure(RuntimeError):
    """Preserve a selected native tool failure across the JSON input gate."""
    def __init__(self, error):
        super().__init__('selected native JSON renderer failed')
        self.error = error
        self.original_traceback = error.__traceback__


def _claimed_artifact_wire(value):
    # Same mechanical JSON bridge and limits as AgentStore.wire. The native
    # callback is wrapped solely to distinguish its failures from malformed
    # caller values; the bounded encoder otherwise wraps both as edit errors.
    from .hia_agent_store import MAX_INPUT_BYTES
    from .hia_program_tools import bounded_json_wire, HIAEditRejected
    selected = os.environ.get('HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST')
    renderer = None
    if selected:
        from .hia_agent_binary64_format_native import installed_agent_binary64_format
        image = installed_agent_binary64_format(selected)
        def renderer(number):
            try:
                return image.render(number).decode('ascii')
            except Exception as error:
                raise _SelectedRendererFailure(error) from error
    try:
        return bounded_json_wire(value, MAX_INPUT_BYTES, ensure_ascii=False,
                                 sort_keys=True, float_renderer=renderer), True
    except _SelectedRendererFailure as failure:
        raise failure.error.with_traceback(failure.original_traceback) from None
    except HIAEditRejected:
        return b'', False

class NativeSlotLedgerStore:
    """Mechanical effects on the caller's original active connection.

    No independent connection, transaction or commit is introduced. The same
    service may be used by serialized threads under AgentStore.transaction.
    A fold's workspace and random anti-mixup tokens exist only for that call.
    """
    def __init__(self, store, image):
        self.store, self.image = store, image

    def _execute(self, connection, statement, parameters=()):
        if self.store.db is not connection:
            _custody('slot operation lost its original SQLite connection')
        return connection.execute(statement, parameters)

    def _call(self, opcode, fields=(), *, labels=(), state=None, **values):
        receipt = self.image.transition(request_packet(opcode, fields, **values), state)
        return _raise(receipt, labels)

    def snapshot(self, slot):
        from .hia_agent_store import decode_data, wire
        db = self.store.db
        row = self._execute(db, 'SELECT * FROM slots WHERE name=?', (slot,)).fetchone()
        if row is None:
            receipt = self._call(2)
        else:
            version = self._execute(db, 'SELECT artifact FROM versions WHERE slot=? AND generation=?',
                (slot, row['generation'])).fetchone()
            count = self._execute(db, 'SELECT COUNT(*) FROM leases WHERE slot=? AND active=1',
                (slot,)).fetchone()[0]
            artifact = decode_data(version['artifact'])
            receipt = self._call(2, (_text(row['generation']), _text(row['epoch']),
                _text(row['context_id']), wire(artifact)), flags=1, a=count)
        if receipt.action == 0:
            return {'target_slot': slot, 'current': {'generation': '0', 'epoch': '0'},
                'active_artifact': None, 'context': None, 'in_flight_leases': 0,
                'snapshot_is_adoption_authority': False}
        generation, epoch, context, artifact = receipt.fields
        return {'target_slot': slot, 'current': {'generation': _untext(generation), 'epoch': _untext(epoch)},
            'active_artifact': decode_data(artifact), 'context': _untext(context),
            'in_flight_leases': receipt.values[0], 'snapshot_is_adoption_authority': False}

    def validate_u64(self, value, label):
        flag = {'generation': 1, 'epoch': 2, 'retained_generation': 3}.get(label, 1)
        return self._call(1, (_decimal(value),), flags=flag, labels=(label,)).values[0]

    def conditional(self, args, snapshot_reader):
        from .hia_agent_store import AgentRejected
        expected = args['expected_current']
        # Fetch and validate in the original order, before any slot read.
        self.validate_u64(expected['generation'], 'generation')
        self.validate_u64(expected['epoch'], 'epoch')
        snapshot = snapshot_reader(args['target_slot'])
        fields = (_text(snapshot['current']['generation']), _text(snapshot['current']['epoch']),
                  _text(expected['generation']), _text(expected['epoch']))
        exact = isinstance(expected, dict) and set(expected) == {'generation', 'epoch'}
        try:
            self._call(3, fields, flags=int(exact))
        except AgentRejected as error:
            if error.code == 'E_HIA_GENERATION_STALE':
                error.pending_slot_snapshot = snapshot
            raise
        return snapshot

    def _begin(self, epoch, target=None):
        workspace = ctypes.create_string_buffer(STATE_BYTES)
        token = struct.unpack('<4Q', os.urandom(32))
        fields = (_decimal(epoch),) if target is None else (_decimal(epoch), _decimal(target))
        self._call(7, fields, flags=1 if target is None else 2, token=token,
            state=workspace, labels=('epoch',) if target is None else ('epoch', 'retained_generation'))
        return workspace, token

    def adopt(self, args, snapshot, evaluation, abi, native):
        from .hia_agent_store import wire
        db = self.store.db
        active = snapshot['active_artifact'] is not None
        plan = self._call(12, flags=int(active))
        if plan.action == 1:
            self._execute(db, 'INSERT INTO slots VALUES (?,?,?,?,?)',
                (args['target_slot'], args['context']['id'], '0', '0', abi))
            self._execute(db, 'INSERT INTO versions VALUES (?,?,?)',
                (args['target_slot'], '0', wire(evaluation['baseline_artifact']).decode()))
        else:
            current = self._execute(db, 'SELECT * FROM slots WHERE name=?',
                (args['target_slot'],)).fetchone()
            self._call(4, (_text(current['abi_sha256']), _text(abi)))
            data, _metadata, _program = native(snapshot['active_artifact'])
            self._call(5, (_text(sha256(data).hexdigest()), _text(evaluation['baseline_artifact']['sha256'])))
        workspace, token = self._begin(snapshot['current']['epoch'])
        # Consume the original cursor row by row. SQL cannot truncate the stream
        # or cast u64 TEXT through SQLite's signed integer range.
        cursor = self._execute(db, 'SELECT generation FROM versions WHERE slot=?', (args['target_slot'],))
        for row in cursor:
            self._call(8, (_decimal(row['generation']),), token=token, state=workspace,
                labels=('generation',))
        final = self._call(9, token=token, state=workspace)
        current = {'generation': final.fields[0].decode('ascii'), 'epoch': final.fields[1].decode('ascii')}
        self._execute(db, 'INSERT INTO versions VALUES (?,?,?)',
            (args['target_slot'], current['generation'], wire(args['candidate_artifact']).decode()))
        self._execute(db, 'UPDATE slots SET generation=?,epoch=?,context_id=? WHERE name=?',
            (current['generation'], current['epoch'], args['context']['id'], args['target_slot']))
        return current

    def rollback(self, args, snapshot, native):
        from .hia_agent_store import decode_data, digest
        db = self.store.db
        self._call(6, flags=int(snapshot['active_artifact'] is not None), a=1)
        row = self._execute(db, 'SELECT artifact FROM versions WHERE slot=? AND generation=?',
            (args['target_slot'], args['retained_generation'])).fetchone()
        self._call(10, flags=int(row is not None))
        artifact = decode_data(row['artifact'])
        _data, metadata, _program = native(artifact)
        current_row = self._execute(db, 'SELECT * FROM slots WHERE name=?',
            (args['target_slot'],)).fetchone()
        self._call(11, (_text(digest(metadata['signatures'])), _text(current_row['abi_sha256'])))
        workspace, token = self._begin(snapshot['current']['epoch'], args['retained_generation'])
        final = self._call(9, token=token, state=workspace)
        current = {'generation': final.fields[0].decode('ascii'), 'epoch': final.fields[1].decode('ascii')}
        self._execute(db, 'UPDATE slots SET generation=?,epoch=?,context_id=? WHERE name=?',
            (current['generation'], current['epoch'], args['context']['id'], args['target_slot']))
        return current, artifact

    @staticmethod
    def _lease_value(fields):
        from .hia_agent_store import decode_data
        identity, slot, generation, artifact = fields
        return {'id': _untext(identity), 'slot': _untext(slot), 'generation': _untext(generation),
                'artifact': decode_data(artifact)}

    def acquire(self, target_slot, snapshot_reader, native):
        from .hia_agent_store import wire
        db = self.store.db
        snapshot = snapshot_reader(target_slot)
        self._call(6, flags=int(snapshot['active_artifact'] is not None))
        native(snapshot['active_artifact'])
        fields = (_text('lease-' + uuid.uuid4().hex), _text(target_slot),
                  _text(snapshot['current']['generation']), wire(snapshot['active_artifact']))
        result = self._call(15, fields, flags=1)
        lease = self._lease_value(result.fields)
        self._execute(db, 'INSERT INTO leases VALUES (?,?,?,?,1)',
            (lease['id'], lease['slot'], lease['generation'], result.fields[3].decode()))
        return lease

    def lease(self, lease, *, release=False, connection=None):
        from .hia_agent_store import decode_data, keys, wire
        keys(lease, ('id', 'slot', 'generation', 'artifact'), label='generation lease')
        db = self.store.db if connection is None else connection
        row = self._execute(db, 'SELECT * FROM leases WHERE id=?', (lease['id'],)).fetchone()
        # HIA first preserves the original OR short-circuit: unknown, inactive
        # or mismatched keys must refuse before decoding the row's artifact.
        raw_fields = ((b'', b'', b'', b'') if row is None else
            (_text(row['id']), _text(row['slot']), _text(row['generation']), b''))
        active = (b'I' + str(row['active']).encode('ascii')
                  if row is not None and type(row['active']) is int else b'X')
        checked = self._call(16, (*raw_fields, _text(lease['slot']), _text(lease['generation']), active),
            flags=int(row is not None))
        identity, slot, generation, _placeholder = checked.fields
        # SQLite TEXT affinity can still hold BLOBs or corrupt non-text data.
        # Do not access or coerce this field until HIA accepts the earlier keys.
        # This is the same captured immutable Row, never a second SQL read.
        artifact = wire(decode_data(row['artifact']))
        claimed_artifact, valid = _claimed_artifact_wire(lease['artifact'])
        result = self._call(14 if release else 13,
            (identity, slot, generation, artifact, _text(lease['slot']),
             _text(lease['generation']), claimed_artifact), flags=1, a=1, b=int(valid))
        return self._lease_value(result.fields)

    def release(self, lease):
        db = self.store.db
        frozen = self.lease(lease, release=True, connection=db)
        self._execute(db, 'UPDATE leases SET active=0 WHERE id=?', (frozen['id'],))
        return {'released': True, 'generation': frozen['generation'], 'artifact_retained': True}
