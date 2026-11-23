"""HIA control for all fifteen ``NativeSlotLedgerStore`` methods.

The image owns all fifteen Slot method control graphs, original SQL order,
loops and ordinary exception continuations. Foreign SQL and decision providers
remain explicit. This module is a static candidate until its complete original
and actual-resource gates have run; it claims no SQLite-native implementation.
"""
from __future__ import annotations

import builtins
import ctypes
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import struct
import types

from .hia_emission_native import _global_value
from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path, _unique_manifest_pairs
from .hia_native_delivery import DeliveryRecord
from .hia_slot_operation_series import OperationSeries

# The original for-loop uses implicit iterator protocol, not global iter/next.
# These private mechanical primitives are independent of the original module's
# explicitly replaceable namespace values.
_PROTOCOL_ITER, _PROTOCOL_NEXT, _PROTOCOL_STOP = iter, next, StopIteration
from .hia_store_lifecycle_native import _regular_bytes
from .hia_slot_operations_protocol import (
    SELECTOR, SCHEMA, SOURCE_NAME, REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC,
    REQUEST_BYTES, OUTPUT_BYTES, STATE_BYTES, INITIALIZE, CLAIM, SUCCEEDED,
    RAISED, FINALIZE, ISSUED, CLAIMED, RETURNED, PROPAGATE,
    READY_RETURN, READY_PROPAGATE, PORT, PORTS, MODES, MODE_RANGES, ERROR_PORTS,
)

SOURCE = _source_resource_path(SOURCE_NAME)
_REQUEST_REJECTIONS = (ValueError, TypeError, OSError, OverflowError, RecursionError, sqlite3.Error)

LOCAL_SLOTS = {1:["self","store","image"],2:["self","connection","statement","parameters"],3:["self","opcode","fields","labels","state","values","receipt"],4:["self","slot","decode_data","wire","db","row","receipt","version","count","artifact","generation","epoch","context"],5:["self","value","label","flag"],6:["self","args","snapshot_reader","AgentRejected","expected","snapshot","fields","exact","error"],7:["self","epoch","target","workspace","token","fields"],8:["self","evaluation","objective","wire","name","outcome","allow_unchanged","receipt"],9:["self","objective","wire"],10:["self","args","snapshot","evaluation","abi","native","wire","db","active","plan","current","data","_metadata","_program","workspace","token","cursor","row","final"],11:["self","args","snapshot","native","decode_data","digest","db","row","artifact","_data","metadata","_program","current_row","workspace","token","final","current"],12:["fields","decode_data","identity","slot","generation","artifact"],13:["self","target_slot","snapshot_reader","native","wire","db","snapshot","fields","result","lease"],14:["self","lease","release","connection","decode_data","keys","wire","db","row","raw_fields","active","checked","identity","slot","generation","_placeholder","artifact","claimed_artifact","valid","result"],15:["self","lease","db","frozen"]}

# ctypes keeps its dynamically constructed array types in a weak cache. These
# three fixed ABI classes belong to the adapter, not to an invocation; retain
# them so destroying private buffers does not leave new type cycles for a
# caller's later GC. The buffers, user objects and per-call checks are unchanged.
_REQUEST_BUFFER_TYPE = ctypes.c_char * (REQUEST_BYTES + 16)
_OUTPUT_BUFFER_TYPE = ctypes.c_char * (OUTPUT_BYTES + 16)
_STATE_BUFFER_TYPE = ctypes.c_char * (STATE_BYTES + 16)


class _LocalReleaseProbe:
    """One fixed private type; no user object participates in the probe."""
    __slots__ = ('events', 'name')

    def __init__(self, events, name):
        self.events, self.name = events, name

    def __del__(self):
        self.events.append(self.name)


def _probe_frame_release(events):
    first = _LocalReleaseProbe(events, 'first')
    last = _LocalReleaseProbe(events, 'last')


def _probe_dict_release(events):
    values = {'first': _LocalReleaseProbe(events, 'first'),
              'last': _LocalReleaseProbe(events, 'last')}


@lru_cache(maxsize=15)
def _local_storage_order(mode):
    """Make an ordinary dict release the original frame's locals in order.

CPython 3.13 and 3.14 clear frame slots in opposite directions. Observe both
the running frame and dict mechanics instead of choosing a version threshold.
The fixed probe type stays alive, its two instances have no cycles, and the
cache contains only fixed local-slot names. No exceptional-path cleanup is inserted:
the caller still controls the lifetime of its actual traceback.
    """
    frame_events, dict_events = [], []
    _probe_frame_release(frame_events)
    _probe_dict_release(dict_events)
    forward, reverse = ['first', 'last'], ['last', 'first']
    if frame_events not in (forward, reverse) or dict_events not in (forward, reverse):
        raise RuntimeError('runtime does not provide immediate ordered local custody')
    names = LOCAL_SLOTS[mode]
    return names if frame_events == dict_events else names[::-1]



class SlotOperationsUnknown(RuntimeError):
    """An actual handler observation is unconfirmed; no terminal or replay."""


class NativeSlotOperations(NativeHiaJsonImage):
    pass


@lru_cache(maxsize=3)
def _mapped_slot_operations(raw, digest, source_digest):
    image = NativeSlotOperations(raw, digest)
    image.admitted_source_sha256 = source_digest
    return image


def installed_slot_operations(manifest_path):
    if not manifest_path:
        raise ValueError('native slot operations selector must not be empty')
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeSlotOperations)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_unique_manifest_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid native slot operations manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or Path(name).name != name or any(ord(char) < 32 for char in name)):
        raise ValueError('native slot operations image must be a sibling basename')
    source = _regular_bytes(SOURCE, 8 << 20)
    image_path = path.parent / name
    image = _regular_bytes(image_path, 1 << 20)
    if sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('native slot operations source identity mismatch')
    if sha256(image).hexdigest() != value['image_sha256']:
        raise ValueError('native slot operations image identity mismatch')
    if selected is None:
        selected = _mapped_slot_operations(image, value['image_sha256'], value['source_sha256'])
    elif type(selected) is not NativeSlotOperations or selected.image_sha256 != value['image_sha256']:
        raise ValueError('native slot operations differs from pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source
            or _regular_bytes(image_path, 1 << 20) != image):
        raise ValueError('native slot operations selection changed during admission')
    # A worker-pinned mapping has the same fully rechecked source authority.
    selected.admitted_source_sha256 = value['source_sha256']
    return selected


def _checksum(words):
    value = 1469598103934665603
    for index, word in enumerate(words):
        if index != 10:
            value = (((value << 7) | (value >> 57)) & ((1 << 64) - 1)) ^ word
    return value



class _Globals:
    __slots__ = ('namespace', 'builtins')
    def __init__(self, namespace):
        self.namespace = namespace
        values = namespace.get('__builtins__', vars(builtins))
        self.builtins = vars(values) if type(values) is types.ModuleType else values
    def __getitem__(self, name):
        return _global_value(self.namespace, self.builtins, name)


def _conditional_exact_expression(d, namespace, outcome):
    # Preserve the original AND operand on the interpreter value stack.
    # This capsule observes the original global call/truth and holds no policy
    # table. Only HIA can request/evaluate/send the RHS. A false LHS is assigned
    # unchanged; it is not replaced by False or passed through int().
    try:
        d['exact'] = namespace['isinstance'](d['expected'], namespace['dict']) and (yield 0)
    except BaseException as error:
        outcome[0] = error


def _open_conditional_exact(frame):
    frame._call_capsule = _conditional_exact_expression(
        frame.data, frame.namespace, frame._call_outcome)
    stopped = False
    try:
        _PROTOCOL_NEXT(frame._call_capsule)
    except _PROTOCOL_STOP:
        stopped = True
    if not stopped:
        return 1
    error, frame._call_outcome[0] = frame._call_outcome[0], None
    frame._call_capsule = None
    if error is not None:
        try:
            raise error
        finally:
            # The active exception owns itself; this forwarding local must not.
            error = None
    return 0


def _complete_conditional_exact(frame, value):
    stopped = False
    try:
        frame._call_capsule.send(value)
    except _PROTOCOL_STOP:
        stopped = True
    if not stopped:
        raise SlotOperationsUnknown('literal AND yielded an extra continuation')
    frame._call_capsule = None
    error, frame._call_outcome[0] = frame._call_outcome[0], None
    if error is not None:
        try:
            raise error
        finally:
            # The active exception owns itself; this forwarding local must not.
            error = None


def _lease_call_expression(d, namespace, outcome):
    # This is an expression capsule, not a policy generator. Its only yield
    # preserves the original callable/receiver on CPython's value stack while
    # HIA chooses opcode 13/14 after the original release truth observation.
    # Catch inside this private generator so a provider StopIteration keeps
    # its original identity instead of acquiring synthetic PEP 479 semantics.
    try:
        d['result'] = d['self']._call(
            (yield 0),
            (d['identity'], d['slot'], d['generation'], d['artifact'],
             namespace['_text'](d['lease']['slot']),
             namespace['_text'](d['lease']['generation']), d['claimed_artifact']),
            flags=1, a=1, b=namespace['int'](d['valid']))
    except BaseException as error:
        outcome[0] = error


def _open_lease_call(frame):
    frame._call_capsule = _lease_call_expression(frame.data, frame.namespace, frame._call_outcome)
    stopped = False
    try:
        next(frame._call_capsule)
    except StopIteration:
        stopped = True
    if stopped:
        error, frame._call_outcome[0] = frame._call_outcome[0], None
        frame._call_capsule = None
        if error is not None:
            # Outside the private StopIteration handler, the original active
            # exception context is restored before the same object is raised.
            try:
                raise error
            finally:
                # The active exception owns itself; this forwarding local must not.
                error = None
        raise SlotOperationsUnknown('literal call ended before its choice observation')


def _complete_lease_call(frame, opcode):
    stopped = False
    try:
        frame._call_capsule.send(opcode)
    except StopIteration:
        stopped = True
    if not stopped:
        raise SlotOperationsUnknown('literal call yielded an extra continuation')
    frame._call_capsule = None
    error, frame._call_outcome[0] = frame._call_outcome[0], None
    if error is not None:
        try:
            raise error
        finally:
            # The active exception owns itself; this forwarding local must not.
            error = None


def _unwind_call_expression(frame):
    capsule, frame._call_capsule = frame._call_capsule, None
    if capsule is not None:
        try:
            capsule.throw(frame._current_exception)
        except StopIteration:
            pass
        except BaseException as error:
            if error is not frame._current_exception:
                raise
    error, frame._call_outcome[0] = frame._call_outcome[0], None
    if error is not None and error is not frame._current_exception:
        try:
            raise error
        finally:
            # The active exception owns itself; this forwarding local must not.
            error = None


def _handoff_extent(record, extent):
    record.enter_native()
    return extent


@dataclass(frozen=True)
class SlotOperationsReceipt:
    port: int
    sequence: int
    phase: int
    failed: int


class SlotOperationsFrame:
    """Private ABI state; the data dictionary has the original local slots."""
    def __init__(self, image, mode, initial, *, namespace=None, mechanical=False):
        if type(image) is not NativeSlotOperations:
            raise TypeError('Slot operations require the admitted controller image')
        if type(mode) is not int or mode not in LOCAL_SLOTS:
            raise ValueError('unknown Slot operation mode')
        if namespace is None:
            from . import hia_slot_ledger_native
            namespace = vars(hia_slot_ledger_native)
        self.image, self.mode = image, mode
        self.namespace = _Globals(namespace)
        if type(mechanical) is not bool:
            raise TypeError('Slot mechanical option must be an exact bool')
        # Public C continuations own the real business fast locals.
        self.data = {} if mechanical else dict.fromkeys(_local_storage_order(mode))
        self._mechanical_session = None
        self._mechanical_rejections = _REQUEST_REJECTIONS
        # Normal completion drops this owner's storage reference. A real
        # handled provider traceback may still own an effect's original d.
        self._retired_data = {}
        for name, value in initial.items():
            if name not in self.data:
                raise ValueError('unknown Slot operation argument')
            self.data[name] = value
        self.result = None
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.buffer = ctypes.create_string_buffer(STATE_BYTES + 16)
        ctypes.memmove(ctypes.addressof(self.buffer) + STATE_BYTES, b'\xb7' * 16, 16)
        self.receipt = None
        self.fenced = self.finished = self.native_failed = False
        self._pending_foreign = None
        self._iterator = self._call_capsule = self._sql_attempt = None
        self._current_exception = None
        self._call_outcome = [None]
        self._delivery = DeliveryRecord(self)
        try:
            self.series = OperationSeries(self._delivery)
        except BaseException:
            self._delivery.retire()
            raise

    def call(self, event, observation=0):
        record = self._delivery
        if self.fenced or self.finished or not record.current():
            raise SlotOperationsUnknown('Slot operation has no current invocation')
        record.check(SlotOperationsUnknown)
        self.series.check()
        native_confirmed = False
        try:
            previous = self.receipt
            port, sequence = (0, 0) if previous is None else (previous.port, previous.sequence)
            old_failed = 0 if previous is None else previous.failed
            raw = struct.pack('<16Q', REQUEST_MAGIC, event, sequence, port,
                              observation, self.mode, *self.identity, *([0] * 8))
            source = ctypes.create_string_buffer(raw + b'\xc9' * 16, REQUEST_BYTES + 16)
            output = ctypes.create_string_buffer(OUTPUT_BYTES + 16)
            ctypes.memmove(ctypes.addressof(output) + OUTPUT_BYTES, b'\xa5' * 16, 16)
            code = self.image._entry(source, REQUEST_BYTES, output, OUTPUT_BYTES,
                                     self.buffer, _handoff_extent(record, STATE_BYTES))
            if (code != OUTPUT_BYTES or source.raw != raw + b'\xc9' * 16
                    or output.raw[OUTPUT_BYTES:] != b'\xa5' * 16
                    or self.buffer.raw[STATE_BYTES:] != b'\xb7' * 16):
                raise SlotOperationsUnknown('Slot controller return is unconfirmed')
            words = struct.unpack('<12Q', output.raw[:OUTPUT_BYTES])
            state = struct.unpack('<24Q', self.buffer.raw[:STATE_BYTES])
            expected_sequence = 1 if event == INITIALIZE else sequence if event == CLAIM else sequence + 1
            expected_phases = {
                INITIALIZE: (ISSUED,), CLAIM: (CLAIMED,),
                SUCCEEDED: (ISSUED, READY_RETURN, READY_PROPAGATE),
                RAISED: (ISSUED, READY_PROPAGATE),
                FINALIZE: (RETURNED, PROPAGATE),
            }[event]
            failed = 1 if event == RAISED else old_failed
            low, high = MODE_RANGES[self.mode]
            active = words[4] in (ISSUED, CLAIMED)
            if (words[0] != RESULT_MAGIC or words[1] != 0
                    or words[2:7] != (state[3], state[4], state[5], state[2], state[12])
                    or state[:3] != (STATE_MAGIC, 1, self.mode)
                    or words[8:10] != self.identity or state[6:8] != self.identity
                    or words[7] != 0 or words[10:12] != (0, 0)
                    or state[8] > 1 or state[9] > 1 or state[11] != 0
                    or state[13:24] != (0,) * 11 or state[10] != _checksum(state)
                    or (self.mode != 10 and state[8] != 0)
                    or (self.mode not in (6, 14) and state[9] != 0)
                    or words[3] != expected_sequence or words[4] not in expected_phases
                    or words[6] != failed
                    or (active and not low <= words[2] <= high)
                    or (active and int(words[2] in ERROR_PORTS) != failed)
                    or (not active and words[2] != 0)
                    or (words[4] in (RETURNED, READY_RETURN) and failed != 0)
                    or (words[4] in (PROPAGATE, READY_PROPAGATE) and failed != 1)
                    or (event == CLAIM and words[2] != port)
                    or (event == FINALIZE and (
                        previous.phase not in (READY_RETURN, READY_PROPAGATE)
                        or words[4] != (RETURNED if previous.phase == READY_RETURN else PROPAGATE)))):
                raise SlotOperationsUnknown('Slot controller receipt differs from its complete state')
            receipt = SlotOperationsReceipt(words[2], words[3], words[4], words[6])
            pending = None
            if event in (SUCCEEDED, RAISED):
                pending = self._pending_foreign
                if pending is None:
                    raise SlotOperationsUnknown('Slot controller has no matching foreign activation')
                pending.prepare_acknowledgement()
            record.check(SlotOperationsUnknown)
            record.confirmed()
            native_confirmed = True
            self.receipt = receipt
            if pending is not None:
                pending.acknowledged()
                self._pending_foreign = None
            if event == FINALIZE:
                self.series.confirmed()
            record.check(SlotOperationsUnknown)
            return receipt
        except BaseException as error:
            entered = record.native_pending
            lost = record.failed(error)
            pending = self._pending_foreign
            if pending is not None:
                pending.failed(error)
            self.series.failed(error)
            self.fenced = True
            self.native_failed = self.native_failed or lost or record.loss is not None
            if entered and not native_confirmed and isinstance(error, _REQUEST_REJECTIONS):
                raise SlotOperationsUnknown('Slot controller delivery failed') from error
            raise

    def finish(self):
        # A rejected re-entry is not a new owner of this invocation's cleanup.
        # Keep it outside the try/finally so a provider which catches this
        # refusal cannot retire the outer pending foreign/SQL obligations.
        if self.series.entered:
            raise SlotOperationsUnknown('Slot controller invocation cannot be reused or re-entered')
        try:
            if (not self._delivery.current() or self._delivery.loss is not None
                    or self._delivery.terminal or self._delivery.retired):
                self._delivery.check(SlotOperationsUnknown)
                raise SlotOperationsUnknown('Slot controller is no longer live')
            with self._delivery.foreign(observation=False):
                with self.series:
                    self.call(INITIALIZE)
                    return self._finish()
        except BaseException as error:
            self._delivery.failed(error)
            pending = self._pending_foreign
            if pending is not None:
                pending.failed(error)
            self.series.failed(error)
            if self._delivery.loss is not None:
                self.fenced = self.native_failed = True
                self._delivery.propagate(error, SlotOperationsUnknown, _REQUEST_REJECTIONS)
            raise
        finally:
            self._delivery.retire()

    def _mechanical_abandon_foreign(self, activation, error):
        """Reset only an entered private activation whose outcome is not ACKed.

        This is not ForeignCall.__exit__: a safe preparation failure must not
        manufacture record.observed(). Actual child/SQL loss remains sticky.
        """
        from .hia_native_delivery import _ACTIVE, _PENDING_RESOURCE_CAPTURE
        if activation is not self._pending_foreign:
            raise SlotOperationsUnknown('Slot cleanup has no exact foreign activation')
        try:
            activation.failed(error)
        finally:
            activation.active = False
            try:
                try:
                    if activation.capture_token is not None:
                        _PENDING_RESOURCE_CAPTURE.reset(activation.capture_token)
                finally:
                    _ACTIVE.reset(activation.token)
            except BaseException as reset_error:
                self._delivery.publish(reset_error)
                raise

    def _effect_once(self):
        if self.receipt.phase != ISSUED:
            raise SlotOperationsUnknown('Slot effect is not newly issued')
        self.call(CLAIM)
        activation = self._delivery.foreign(capture_resources=True, weak_registered_resources=True)
        self._pending_foreign = activation
        with activation:
            return self.effect(self.receipt.port)

    def _complete(self):
        expected = self.receipt.phase
        if expected not in (READY_RETURN, READY_PROPAGATE):
            raise SlotOperationsUnknown('Slot operation has no HIA completion directive')
        # Reserve/classify BEFORE the final native handoff. FINALIZE is a
        # distinct explicit protocol event; no intermediate ACK retires SQL.
        self.series.prepare_completion()
        self.call(FINALIZE)
        terminal = RETURNED if expected == READY_RETURN else PROPAGATE
        if self.receipt.phase != terminal:
            raise SlotOperationsUnknown('Slot final operation receipt is unconfirmed')
        self.finished = True
        if terminal == RETURNED:
            # HIA has confirmed the operation and its SQL holder. Drop only
            # this owner's local-storage reference; never mutate the storage
            # still owned by an actual handled provider traceback.
            self.data = self._retired_data
            self._retired_data = None
        # Real selected work in a finalizer still has the ambient activation.
        self._delivery.check(SlotOperationsUnknown)
        self._delivery.confirmed(terminal=True)

    def _exception_continuation(self):
        while self.receipt.phase == ISSUED:
            try:
                observed = self._effect_once()
            except BaseException as replacement:
                if self.native_failed or self._delivery.loss is not None:
                    self._delivery.propagate(replacement, SlotOperationsUnknown, _REQUEST_REJECTIONS)
                    raise
                previous = self._current_exception
                self._current_exception = replacement
                try:
                    self.call(RAISED)
                    self._exception_continuation()
                finally:
                    self._current_exception = previous
                raise
            self.call(SUCCEEDED, observed)
        if self.receipt.phase != READY_PROPAGATE:
            raise SlotOperationsUnknown('Slot exception has no HIA propagation directive')
        self._complete()

    def _finish(self):
        while True:
            try:
                observed = self._effect_once()
            except BaseException as error:
                if self.native_failed or self._delivery.loss is not None:
                    self._delivery.propagate(error, SlotOperationsUnknown, _REQUEST_REJECTIONS)
                    raise
                self._current_exception = error
                try:
                    self.call(RAISED)
                    self._exception_continuation()
                finally:
                    self._current_exception = None
                # No host blanket clear: the actual traceback retains the
                # original locals on the ordinary exceptional path.
                raise
            self.call(SUCCEEDED, observed)
            if self.receipt.phase == READY_RETURN:
                self._complete()
                # Transfer the confirmed result without a second Frame owner.
                return self.__dict__.pop('result')
            if self.receipt.phase != ISSUED:
                raise SlotOperationsUnknown('Slot control left its normal continuation')

    def effect(self, port):
        if (self.receipt is None or self.receipt.phase != CLAIMED
                or self.receipt.port != port or not 1 <= port <= len(PORTS)):
            raise SlotOperationsUnknown('Slot effect has no matching native claim')
        return getattr(self, '_port_' + PORTS[port - 1])()

    def _port_init_assign(self):
        d, ns = self.data, self.namespace
        d['self'].store, d['self'].image = d['store'], d['image']
        return 0

    def _port_execute_connection_same(self):
        d, ns = self.data, self.namespace
        self._sql_attempt = self.series.prepare_sql()
        if self._sql_attempt.borrow_store(d['self'].store).db is d['connection']:
            return 1
        return 0

    def _port_execute_refuse(self):
        d, ns = self.data, self.namespace
        ns['_custody']('slot operation lost its original SQLite connection')
        return 0

    def _port_execute_call(self):
        d, ns = self.data, self.namespace
        self.result = d['connection'].execute(d['statement'], self._sql_attempt.arguments(d['parameters']))
        self._sql_attempt = None
        return 0

    def _port_call_transition(self):
        d, ns = self.data, self.namespace
        d['receipt'] = d['self'].image.transition(ns['request_packet'](d['opcode'], d['fields'], **d['values']), d['state'])
        return 0

    def _port_call_raise(self):
        d, ns = self.data, self.namespace
        self.result = ns['_raise'](d['receipt'], d['labels'])
        return 0

    def _port_snapshot_import(self):
        d, ns = self.data, self.namespace
        from .hia_agent_store import decode_data, wire
        d['decode_data'], d['wire'] = decode_data, wire
        return 0

    def _port_snapshot_db(self):
        d, ns = self.data, self.namespace
        d['db'] = d['self'].store.db
        return 0

    def _port_snapshot_row(self):
        d, ns = self.data, self.namespace
        d['row'] = d['self']._execute(d['db'], 'SELECT * FROM slots WHERE name=?', (d['slot'],)).fetchone()
        return 0

    def _port_snapshot_row_none(self):
        d, ns = self.data, self.namespace
        if d['row'] is None:
            return 1
        return 0

    def _port_snapshot_absent_call(self):
        d, ns = self.data, self.namespace
        d['receipt'] = d['self']._call(2)
        return 0

    def _port_snapshot_version(self):
        d, ns = self.data, self.namespace
        d['version'] = d['self']._execute(d['db'], 'SELECT artifact FROM versions WHERE slot=? AND generation=?', (d['slot'], d['row']['generation'])).fetchone()
        return 0

    def _port_snapshot_count(self):
        d, ns = self.data, self.namespace
        d['count'] = d['self']._execute(d['db'], 'SELECT COUNT(*) FROM leases WHERE slot=? AND active=1', (d['slot'],)).fetchone()[0]
        return 0

    def _port_snapshot_artifact(self):
        d, ns = self.data, self.namespace
        d['artifact'] = d['decode_data'](d['version']['artifact'])
        return 0

    def _port_snapshot_present_call(self):
        d, ns = self.data, self.namespace
        d['receipt'] = d['self']._call(2, (ns['_text'](d['row']['generation']), ns['_text'](d['row']['epoch']), ns['_text'](d['row']['context_id']), d['wire'](d['artifact'])), flags=1, a=d['count'])
        return 0

    def _port_snapshot_action_zero(self):
        d, ns = self.data, self.namespace
        if d['receipt'].action == 0:
            return 1
        return 0

    def _port_snapshot_absent_result(self):
        d, ns = self.data, self.namespace
        self.result = {'target_slot': d['slot'], 'current': {'generation': '0', 'epoch': '0'}, 'active_artifact': None, 'context': None, 'in_flight_leases': 0, 'snapshot_is_adoption_authority': False}
        return 0

    def _port_snapshot_fields(self):
        d, ns = self.data, self.namespace
        d['generation'], d['epoch'], d['context'], d['artifact'] = d['receipt'].fields
        return 0

    def _port_snapshot_present_result(self):
        d, ns = self.data, self.namespace
        self.result = {'target_slot': d['slot'], 'current': {'generation': ns['_untext'](d['generation']), 'epoch': ns['_untext'](d['epoch'])}, 'active_artifact': d['decode_data'](d['artifact']), 'context': ns['_untext'](d['context']), 'in_flight_leases': d['receipt'].values[0], 'snapshot_is_adoption_authority': False}
        return 0

    def _port_validate_flag(self):
        d, ns = self.data, self.namespace
        d['flag'] = {'generation': 1, 'epoch': 2, 'retained_generation': 3}.get(d['label'], 1)
        return 0

    def _port_validate_result(self):
        d, ns = self.data, self.namespace
        self.result = d['self']._call(1, (ns['_decimal'](d['value']),), flags=d['flag'], labels=(d['label'],)).values[0]
        return 0

    def _port_conditional_import(self):
        d, ns = self.data, self.namespace
        from .hia_agent_store import AgentRejected
        d['AgentRejected'] = AgentRejected
        return 0

    def _port_conditional_expected(self):
        d, ns = self.data, self.namespace
        d['expected'] = d['args']['expected_current']
        return 0

    def _port_conditional_generation(self):
        d, ns = self.data, self.namespace
        d['self'].validate_u64(d['expected']['generation'], 'generation')
        return 0

    def _port_conditional_epoch(self):
        d, ns = self.data, self.namespace
        d['self'].validate_u64(d['expected']['epoch'], 'epoch')
        return 0

    def _port_conditional_snapshot(self):
        d, ns = self.data, self.namespace
        d['snapshot'] = d['snapshot_reader'](d['args']['target_slot'])
        return 0

    def _port_conditional_fields(self):
        d, ns = self.data, self.namespace
        d['fields'] = (ns['_text'](d['snapshot']['current']['generation']), ns['_text'](d['snapshot']['current']['epoch']), ns['_text'](d['expected']['generation']), ns['_text'](d['expected']['epoch']))
        return 0

    def _port_conditional_is_dict(self):
        d, ns = self.data, self.namespace
        return _open_conditional_exact(self)

    def _port_conditional_exact_keys(self):
        d, ns = self.data, self.namespace
        _complete_conditional_exact(self, ns['set'](d['expected']) == {'generation', 'epoch'})
        return 0

    def _port_conditional_exact_false(self):
        d, ns = self.data, self.namespace
        # The literal AND already stored its original false operand.
        return 0

    def _port_conditional_call(self):
        d, ns = self.data, self.namespace
        d['self']._call(3, d['fields'], flags=ns['int'](d['exact']))
        return 0

    def _port_conditional_result(self):
        d, ns = self.data, self.namespace
        self.result = d['snapshot']
        return 0

    def _port_conditional_error_matches(self):
        d, ns = self.data, self.namespace
        try:
            raise
        except d['AgentRejected'] as error:
            d['error'] = error
            return 1
        except BaseException:
            return 0

    def _port_conditional_error_stale(self):
        d, ns = self.data, self.namespace
        if d['error'].code == 'E_HIA_GENERATION_STALE':
            return 1
        return 0

    def _port_conditional_error_attach(self):
        d, ns = self.data, self.namespace
        d['error'].pending_slot_snapshot = d['snapshot']
        return 0

    def _port_conditional_error_forget(self):
        d, ns = self.data, self.namespace
        d['error'] = None
        return 0

    def _port_conditional_expression_unwind(self):
        _unwind_call_expression(self)
        return 0

    def _port_begin_workspace(self):
        d, ns = self.data, self.namespace
        d['workspace'] = ns['ctypes'].create_string_buffer(ns['STATE_BYTES'])
        return 0

    def _port_begin_token(self):
        d, ns = self.data, self.namespace
        d['token'] = ns['struct'].unpack('<4Q', ns['os'].urandom(32))
        return 0

    def _port_begin_target_none(self):
        d, ns = self.data, self.namespace
        if d['target'] is None:
            return 1
        return 0

    def _port_begin_fields_one(self):
        d, ns = self.data, self.namespace
        d['fields'] = (ns['_decimal'](d['epoch']),)
        return 0

    def _port_begin_fields_two(self):
        d, ns = self.data, self.namespace
        d['fields'] = (ns['_decimal'](d['epoch']), ns['_decimal'](d['target']))
        return 0

    # Both HIA ports reach the same method lookup in the original _begin.
    # Keep that one lookup site so CPython's adaptive attribute errors, including
    # their name and receiver, follow the same sequence across both branches.
    def _begin_call(self):
        d = self.data
        rollback = self.receipt.port == PORT['begin_call_two']
        d['self']._call(7, d['fields'], flags=2 if rollback else 1, token=d['token'],
                        state=d['workspace'], labels=('epoch', 'retained_generation') if rollback else ('epoch',))
        return 0

    _port_begin_call_one = _port_begin_call_two = _begin_call

    def _port_begin_result(self):
        d, ns = self.data, self.namespace
        self.result = d['workspace'], d['token']
        return 0

    def _port_evaluation_import(self):
        d, ns = self.data, self.namespace
        from .hia_agent_store import wire
        d['wire'] = wire
        return 0

    _evaluation_fields = {
        PORT['evaluation_first']: 'report_complete',
        PORT['evaluation_second']: 'planned_workload_complete',
        PORT['evaluation_third']: 'termination_confirmed',
    }

    def _evaluation_field(self):
        d = self.data
        d['name'] = self._evaluation_fields[self.receipt.port]
        d['self']._call(17, (d['wire'](d['evaluation'][d['name']]),))
        return 0

    _port_evaluation_first = _port_evaluation_second = _port_evaluation_third = _evaluation_field

    def _port_evaluation_outcome(self):
        d, ns = self.data, self.namespace
        d['outcome'] = d['evaluation']['outcome']
        return 0

    def _port_evaluation_allow(self):
        d, ns = self.data, self.namespace
        d['allow_unchanged'] = d['objective']['allow_unchanged']
        return 0

    def _port_evaluation_transition(self):
        d, ns = self.data, self.namespace
        d['receipt'] = d['self'].image.transition(ns['request_packet'](18, (d['wire'](d['outcome']), d['wire'](d['allow_unchanged']))))
        return 0

    def _port_evaluation_unhashable(self):
        d, ns = self.data, self.namespace
        if d['receipt'].status in {16, 17}:
            return 1
        return 0

    def _port_evaluation_allow_truth(self):
        d, ns = self.data, self.namespace
        if d['allow_unchanged']:
            return 1
        return 0

    def _port_evaluation_membership_allow(self):
        d, ns = self.data, self.namespace
        d['outcome'] not in {'improved', 'unchanged'}
        return 0

    def _port_evaluation_membership_improved(self):
        d, ns = self.data, self.namespace
        d['outcome'] not in {'improved'}
        return 0

    def _port_evaluation_refuse(self):
        d, ns = self.data, self.namespace
        ns['_custody']('native unhashable outcome refusal did not raise a Python error')
        return 0

    def _port_evaluation_raise(self):
        d, ns = self.data, self.namespace
        ns['_raise'](d['receipt'])
        return 0

    def _port_benefit_import(self):
        d, ns = self.data, self.namespace
        from .hia_agent_store import wire
        d['wire'] = wire
        return 0

    def _port_benefit_call(self):
        d, ns = self.data, self.namespace
        d['self']._call(19, (d['wire'](d['objective'].get('require_net_benefit', False)),))
        return 0

    def _port_adopt_import(self):
        d, ns = self.data, self.namespace
        from .hia_agent_store import wire
        d['wire'] = wire
        return 0

    def _port_adopt_db(self):
        d, ns = self.data, self.namespace
        d['db'] = d['self'].store.db
        return 0

    def _port_adopt_active(self):
        d, ns = self.data, self.namespace
        d['active'] = d['snapshot']['active_artifact'] is not None
        return 0

    def _port_adopt_plan(self):
        d, ns = self.data, self.namespace
        d['plan'] = d['self']._call(12, flags=ns['int'](d['active']))
        return 0

    def _port_adopt_initial(self):
        d, ns = self.data, self.namespace
        if d['plan'].action == 1:
            return 1
        return 0

    def _port_adopt_insert_slot(self):
        d, ns = self.data, self.namespace
        d['self']._execute(d['db'], 'INSERT INTO slots VALUES (?,?,?,?,?)', (d['args']['target_slot'], d['args']['context']['id'], '0', '0', d['abi']))
        return 0

    def _port_adopt_insert_baseline(self):
        d, ns = self.data, self.namespace
        d['self']._execute(d['db'], 'INSERT INTO versions VALUES (?,?,?)', (d['args']['target_slot'], '0', d['wire'](d['evaluation']['baseline_artifact']).decode()))
        return 0

    def _port_adopt_current(self):
        d, ns = self.data, self.namespace
        d['current'] = d['self']._execute(d['db'], 'SELECT * FROM slots WHERE name=?', (d['args']['target_slot'],)).fetchone()
        return 0

    def _port_adopt_abi(self):
        d, ns = self.data, self.namespace
        d['self']._call(4, (ns['_text'](d['current']['abi_sha256']), ns['_text'](d['abi'])))
        return 0

    def _port_adopt_native(self):
        d, ns = self.data, self.namespace
        d['data'], d['_metadata'], d['_program'] = d['native'](d['snapshot']['active_artifact'])
        return 0

    def _port_adopt_baseline(self):
        d, ns = self.data, self.namespace
        d['self']._call(5, (ns['_text'](ns['sha256'](d['data']).hexdigest()), ns['_text'](d['evaluation']['baseline_artifact']['sha256'])))
        return 0

    def _port_adopt_begin(self):
        d, ns = self.data, self.namespace
        d['workspace'], d['token'] = d['self']._begin(d['snapshot']['current']['epoch'])
        return 0

    def _port_adopt_cursor(self):
        d, ns = self.data, self.namespace
        d['cursor'] = d['self']._execute(d['db'], 'SELECT generation FROM versions WHERE slot=?', (d['args']['target_slot'],))
        return 0

    def _port_adopt_iterator(self):
        d, ns = self.data, self.namespace
        self._iterator = _PROTOCOL_ITER(d['cursor'])
        return 0

    def _port_adopt_next(self):
        d, ns = self.data, self.namespace
        try:
            row = _PROTOCOL_NEXT(self._iterator)
        except _PROTOCOL_STOP:
            return 1
        d['row'] = row
        return 0

    def _port_adopt_fold(self):
        d, ns = self.data, self.namespace
        d['self']._call(8, (ns['_decimal'](d['row']['generation']),), token=d['token'], state=d['workspace'], labels=('generation',))
        return 0

    def _port_adopt_iterator_done(self):
        d, ns = self.data, self.namespace
        self._iterator = None
        return 0

    def _port_adopt_final(self):
        d, ns = self.data, self.namespace
        d['final'] = d['self']._call(9, token=d['token'], state=d['workspace'])
        return 0

    def _port_adopt_result_fields(self):
        d, ns = self.data, self.namespace
        d['current'] = {'generation': d['final'].fields[0].decode('ascii'), 'epoch': d['final'].fields[1].decode('ascii')}
        return 0

    def _port_adopt_insert_candidate(self):
        d, ns = self.data, self.namespace
        d['self']._execute(d['db'], 'INSERT INTO versions VALUES (?,?,?)', (d['args']['target_slot'], d['current']['generation'], d['wire'](d['args']['candidate_artifact']).decode()))
        return 0

    def _port_adopt_update(self):
        d, ns = self.data, self.namespace
        d['self']._execute(d['db'], 'UPDATE slots SET generation=?,epoch=?,context_id=? WHERE name=?', (d['current']['generation'], d['current']['epoch'], d['args']['context']['id'], d['args']['target_slot']))
        return 0

    def _port_adopt_result(self):
        d, ns = self.data, self.namespace
        self.result = d['current']
        return 0

    def _port_adopt_iterator_error_release(self):
        d, ns = self.data, self.namespace
        self._iterator = None
        return 0

    def _port_rollback_import(self):
        d, ns = self.data, self.namespace
        from .hia_agent_store import decode_data, digest
        d['decode_data'], d['digest'] = decode_data, digest
        return 0

    def _port_rollback_db(self):
        d, ns = self.data, self.namespace
        d['db'] = d['self'].store.db
        return 0

    def _port_rollback_active(self):
        d, ns = self.data, self.namespace
        d['self']._call(6, flags=ns['int'](d['snapshot']['active_artifact'] is not None), a=1)
        return 0

    def _port_rollback_retained(self):
        d, ns = self.data, self.namespace
        d['row'] = d['self']._execute(d['db'], 'SELECT artifact FROM versions WHERE slot=? AND generation=?', (d['args']['target_slot'], d['args']['retained_generation'])).fetchone()
        return 0

    def _port_rollback_row_check(self):
        d, ns = self.data, self.namespace
        d['self']._call(10, flags=ns['int'](d['row'] is not None))
        return 0

    def _port_rollback_artifact(self):
        d, ns = self.data, self.namespace
        d['artifact'] = d['decode_data'](d['row']['artifact'])
        return 0

    def _port_rollback_native(self):
        d, ns = self.data, self.namespace
        d['_data'], d['metadata'], d['_program'] = d['native'](d['artifact'])
        return 0

    def _port_rollback_current(self):
        d, ns = self.data, self.namespace
        d['current_row'] = d['self']._execute(d['db'], 'SELECT * FROM slots WHERE name=?', (d['args']['target_slot'],)).fetchone()
        return 0

    def _port_rollback_abi(self):
        d, ns = self.data, self.namespace
        d['self']._call(11, (ns['_text'](d['digest'](d['metadata']['signatures'])), ns['_text'](d['current_row']['abi_sha256'])))
        return 0

    def _port_rollback_begin(self):
        d, ns = self.data, self.namespace
        d['workspace'], d['token'] = d['self']._begin(d['snapshot']['current']['epoch'], d['args']['retained_generation'])
        return 0

    def _port_rollback_final(self):
        d, ns = self.data, self.namespace
        d['final'] = d['self']._call(9, token=d['token'], state=d['workspace'])
        return 0

    def _port_rollback_result_fields(self):
        d, ns = self.data, self.namespace
        d['current'] = {'generation': d['final'].fields[0].decode('ascii'), 'epoch': d['final'].fields[1].decode('ascii')}
        return 0

    def _port_rollback_update(self):
        d, ns = self.data, self.namespace
        d['self']._execute(d['db'], 'UPDATE slots SET generation=?,epoch=?,context_id=? WHERE name=?', (d['current']['generation'], d['current']['epoch'], d['args']['context']['id'], d['args']['target_slot']))
        return 0

    def _port_rollback_result(self):
        d, ns = self.data, self.namespace
        self.result = d['current'], d['artifact']
        return 0

    def _port_lease_value_import(self):
        d, ns = self.data, self.namespace
        from .hia_agent_store import decode_data
        d['decode_data'] = decode_data
        return 0

    def _port_lease_value_fields(self):
        d, ns = self.data, self.namespace
        d['identity'], d['slot'], d['generation'], d['artifact'] = d['fields']
        return 0

    def _port_lease_value_result(self):
        d, ns = self.data, self.namespace
        self.result = {'id': ns['_untext'](d['identity']), 'slot': ns['_untext'](d['slot']), 'generation': ns['_untext'](d['generation']), 'artifact': d['decode_data'](d['artifact'])}
        return 0

    def _port_acquire_import(self):
        d, ns = self.data, self.namespace
        from .hia_agent_store import wire
        d['wire'] = wire
        return 0

    def _port_acquire_db(self):
        d, ns = self.data, self.namespace
        d['db'] = d['self'].store.db
        return 0

    def _port_acquire_snapshot(self):
        d, ns = self.data, self.namespace
        d['snapshot'] = d['snapshot_reader'](d['target_slot'])
        return 0

    def _port_acquire_active(self):
        d, ns = self.data, self.namespace
        d['self']._call(6, flags=ns['int'](d['snapshot']['active_artifact'] is not None))
        return 0

    def _port_acquire_native(self):
        d, ns = self.data, self.namespace
        d['native'](d['snapshot']['active_artifact'])
        return 0

    def _port_acquire_fields(self):
        d, ns = self.data, self.namespace
        d['fields'] = (ns['_text']('lease-' + ns['uuid'].uuid4().hex), ns['_text'](d['target_slot']), ns['_text'](d['snapshot']['current']['generation']), d['wire'](d['snapshot']['active_artifact']))
        return 0

    def _port_acquire_call(self):
        d, ns = self.data, self.namespace
        d['result'] = d['self']._call(15, d['fields'], flags=1)
        return 0

    def _port_acquire_lease(self):
        d, ns = self.data, self.namespace
        d['lease'] = d['self']._lease_value(d['result'].fields)
        return 0

    def _port_acquire_insert(self):
        d, ns = self.data, self.namespace
        d['self']._execute(d['db'], 'INSERT INTO leases VALUES (?,?,?,?,1)', (d['lease']['id'], d['lease']['slot'], d['lease']['generation'], d['result'].fields[3].decode()))
        return 0

    def _port_acquire_result(self):
        d, ns = self.data, self.namespace
        self.result = d['lease']
        return 0

    def _port_lease_import(self):
        d, ns = self.data, self.namespace
        from .hia_agent_store import decode_data, keys, wire
        d['decode_data'], d['keys'], d['wire'] = decode_data, keys, wire
        return 0

    def _port_lease_keys(self):
        d, ns = self.data, self.namespace
        d['keys'](d['lease'], ('id', 'slot', 'generation', 'artifact'), label='generation lease')
        return 0

    def _port_lease_connection_none(self):
        d, ns = self.data, self.namespace
        if d['connection'] is None:
            return 1
        return 0

    def _port_lease_db_store(self):
        d, ns = self.data, self.namespace
        d['db'] = d['self'].store.db
        return 0

    def _port_lease_db_connection(self):
        d, ns = self.data, self.namespace
        d['db'] = d['connection']
        return 0

    def _port_lease_row(self):
        d, ns = self.data, self.namespace
        d['row'] = d['self']._execute(d['db'], 'SELECT * FROM leases WHERE id=?', (d['lease']['id'],)).fetchone()
        return 0

    def _port_lease_row_none(self):
        d, ns = self.data, self.namespace
        if d['row'] is None:
            return 1
        return 0

    def _port_lease_raw_empty(self):
        d, ns = self.data, self.namespace
        d['raw_fields'] = (b'', b'', b'', b'')
        return 0

    def _port_lease_raw_fields(self):
        d, ns = self.data, self.namespace
        d['raw_fields'] = (ns['_text'](d['row']['id']), ns['_text'](d['row']['slot']), ns['_text'](d['row']['generation']), b'')
        return 0

    def _port_lease_active_type(self):
        d, ns = self.data, self.namespace
        if ns['type'](d['row']['active']) is ns['int']:
            return 1
        return 0

    def _port_lease_active_int(self):
        d, ns = self.data, self.namespace
        d['active'] = b'I' + ns['str'](d['row']['active']).encode('ascii')
        return 0

    def _port_lease_active_other(self):
        d, ns = self.data, self.namespace
        d['active'] = b'X'
        return 0

    def _port_lease_keys_call(self):
        d, ns = self.data, self.namespace
        d['checked'] = d['self']._call(16, (*d['raw_fields'], ns['_text'](d['lease']['slot']), ns['_text'](d['lease']['generation']), d['active']), flags=ns['int'](d['row'] is not None))
        return 0

    def _port_lease_checked_fields(self):
        d, ns = self.data, self.namespace
        d['identity'], d['slot'], d['generation'], d['_placeholder'] = d['checked'].fields
        return 0

    def _port_lease_artifact(self):
        d, ns = self.data, self.namespace
        d['artifact'] = d['wire'](d['decode_data'](d['row']['artifact']))
        return 0

    def _port_lease_claimed(self):
        d, ns = self.data, self.namespace
        d['claimed_artifact'], d['valid'] = ns['_claimed_artifact_wire'](d['lease']['artifact'])
        return 0

    def _port_lease_call_open(self):
        d, ns = self.data, self.namespace
        _open_lease_call(self)
        return 0

    def _port_lease_release_truth(self):
        d, ns = self.data, self.namespace
        if d['release']:
            return 1
        return 0

    def _port_lease_call_release(self):
        d, ns = self.data, self.namespace
        _complete_lease_call(self, 14)
        return 0

    def _port_lease_call_check(self):
        d, ns = self.data, self.namespace
        _complete_lease_call(self, 13)
        return 0

    def _port_lease_result(self):
        d, ns = self.data, self.namespace
        self.result = d['self']._lease_value(d['result'].fields)
        return 0

    def _port_lease_call_unwind(self):
        _unwind_call_expression(self)
        return 0

    def _port_release_db(self):
        d, ns = self.data, self.namespace
        d['db'] = d['self'].store.db
        return 0

    def _port_release_lease(self):
        d, ns = self.data, self.namespace
        d['frozen'] = d['self'].lease(d['lease'], release=True, connection=d['db'])
        return 0

    def _port_release_update(self):
        d, ns = self.data, self.namespace
        d['self']._execute(d['db'], 'UPDATE leases SET active=0 WHERE id=?', (d['frozen']['id'],))
        return 0

    def _port_release_result(self):
        d, ns = self.data, self.namespace
        self.result = {'released': True, 'generation': d['frozen']['generation'], 'artifact_retained': True}
        return 0
