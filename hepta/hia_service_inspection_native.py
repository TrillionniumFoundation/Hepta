"""Complete HIA control for service inspect and candidate handlers.

The two retained business bodies are never called by a selected frame. HIA
chooses all method branches, all(genexpr) short-circuiting, dictionary-loop
continuation, ephemeral unwind, and whole-method final acknowledgement.
Original graph/Core/patch/compiler/Store functions remain explicit providers.
No SQLite implementation, independent proof or whole-stack closure is claimed.
"""
from __future__ import annotations

import builtins
# Use one dynamic attribute lookup at the foreign receiver boundary.
# Exception fields are never constructed, rewritten or cleared here.
from builtins import getattr as _attribute
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
from .hia_store_lifecycle_native import _regular_bytes
from .hia_service_inspection_protocol import (
    SELECTOR, SCHEMA, SOURCE_NAME, REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC,
    REQUEST_BYTES, OUTPUT_BYTES, STATE_BYTES, INITIALIZE, CLAIM, SUCCEEDED,
    RAISED, FINALIZE, ISSUED, CLAIMED, RETURNED, PROPAGATE,
    READY_RETURN, READY_PROPAGATE, INSPECT, CANDIDATE, PORT, PORTS,
    MODE_RANGES, ERROR_PORTS,
)

SOURCE = _source_resource_path(SOURCE_NAME)
_REQUEST_REJECTIONS = (ValueError, TypeError, OSError, OverflowError,
                       RecursionError, sqlite3.Error)
_UNBOUND = object()


def _unbound_program():
    if False:
        program = None
    return program


def _unbound_diagnostics():
    if False:
        diagnostics = None
    return diagnostics


class _ReleaseProbe:
    __slots__ = ('events', 'name')
    def __init__(self, events, name):
        self.events, self.name = events, name
    def __del__(self):
        self.events.append(self.name)


def _frame_release_probe(events):
    first = _ReleaseProbe(events, 'first')
    last = _ReleaseProbe(events, 'last')


def _dict_release_probe(events):
    values = {'first': _ReleaseProbe(events, 'first'),
              'last': _ReleaseProbe(events, 'last')}


@lru_cache(maxsize=1)
def _storage_is_reversed():
    frame_events, dict_events = [], []
    _frame_release_probe(frame_events)
    _dict_release_probe(dict_events)
    admissible = (['first', 'last'], ['last', 'first'])
    if frame_events not in admissible or dict_events not in admissible:
        raise RuntimeError('runtime does not provide immediate local storage release')
    return frame_events != dict_events


class _ComprehensionProbe:
    """Fixed private iterator type; no user input or version threshold."""
    __slots__ = ('count',)
    def __init__(self):
        self.count = 0
    def __iter__(self):
        self.count += 1
        return self
    def __next__(self):
        raise StopIteration


@lru_cache(maxsize=1)
def _dict_reiterations():
    iterator = _ComprehensionProbe()
    value = {item: item for item in iterator}
    if iterator.count < 1:
        raise RuntimeError('runtime dictionary iteration protocol is unsupported')
    return iterator.count - 1


def _selector_memberships(selector):
    # This is an opaque one-next-at-a-time iterator. HIA chooses whether to
    # request another value and when to stop; no all()/policy loop runs here.
    # The real interpreter supplies genexpr-entry and PEP479 semantics.
    return (key in selector for key in ('function', 'block', 'output'))


def _is_builtin_all(value):
    # Arbitrary callables are not probed. These are fixed descriptors on the
    # exact immutable builtin-function type, not user __getattribute__.
    # The name/self combination identifies the runtime's actual builtins.all;
    # rebinding a globals or builtins dictionary to another callable is foreign.
    return (type(value) is types.BuiltinFunctionType
            and value.__self__ is builtins and value.__name__ == 'all')


class ServiceInspectionUnknown(RuntimeError):
    """The actual selected invocation has an unconfirmed delivery."""


class NativeServiceInspection(NativeHiaJsonImage):
    pass


@lru_cache(maxsize=3)
def _mapped_inspection(raw, digest, source_digest):
    image = NativeServiceInspection(raw, digest)
    image.admitted_source_sha256 = source_digest
    return image


def installed_service_inspection(manifest_path):
    if not manifest_path:
        raise ValueError('native service inspection selector must not be empty')
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeServiceInspection)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_unique_manifest_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid native service inspection manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or Path(name).name != name or any(ord(char) < 32 for char in name)):
        raise ValueError('native inspection image must be a sibling basename')
    source = _regular_bytes(SOURCE, 8 << 20)
    image_path = path.parent / name
    image_bytes = _regular_bytes(image_path, 1 << 20)
    if sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('native service inspection source identity mismatch')
    if sha256(image_bytes).hexdigest() != value['image_sha256']:
        raise ValueError('native service inspection image identity mismatch')
    if selected is None:
        selected = _mapped_inspection(image_bytes, value['image_sha256'], value['source_sha256'])
    elif type(selected) is not NativeServiceInspection or selected.image_sha256 != value['image_sha256']:
        raise ValueError('native inspection differs from the pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source
            or _regular_bytes(image_path, 1 << 20) != image_bytes):
        raise ValueError('native service inspection selection changed during admission')
    selected.admitted_source_sha256 = value['source_sha256']
    return selected


def _checksum(words):
    value = 1469598103934665603
    for index, word in enumerate(words):
        if index != 10:
            value = (((value << 7) | (value >> 57)) & ((1 << 64) - 1)) ^ word
    return value


def _handoff(record, extent):
    record.enter_native()
    return extent


def _candidate_put_expression(frame, outcome):
    # LOAD_METHOD and the receiver are on the interpreter's real value stack
    # before the yield. The yielded boolean is exclusively HIA's selected arm,
    # not a re-evaluation of native_payloads or any original business predicate.
    # Both operand expressions remain in the original CALL so ephemeral
    # arguments are not kept in a separate host local across result assignment.
    d = frame.data
    try:
        d['candidate'] = _attribute(d['self'], 'store').put(
            d['native_payloads'][0] if (yield 0) else _attribute(frame._local('program'), 'canonical_bytes'),
            'core', {'context': d['args']['context']})
    except BaseException as error:
        outcome[0] = error


def _open_put_expression(frame):
    frame._capsule = _candidate_put_expression(frame, frame._capsule_error)
    stopped = False
    try:
        next(frame._capsule)
    except StopIteration:
        stopped = True
    if stopped:
        error, frame._capsule_error[0] = frame._capsule_error[0], None
        frame._capsule = None
        if error is not None:
            raise error
        raise ServiceInspectionUnknown('candidate literal ended before HIA selection')


def _resume_put_expression(frame, native_arm):
    stopped = False
    try:
        frame._capsule.send(native_arm)
    except StopIteration:
        stopped = True
    if not stopped:
        raise ServiceInspectionUnknown('candidate literal yielded a second selection')
    frame._capsule = None
    error, frame._capsule_error[0] = frame._capsule_error[0], None
    if error is not None:
        raise error


def _unwind_put_expression(frame):
    capsule, frame._capsule = frame._capsule, None
    if capsule is not None:
        try:
            capsule.throw(frame._current_exception)
        except StopIteration:
            pass
        except BaseException as error:
            if error is not frame._current_exception:
                raise
    error, frame._capsule_error[0] = frame._capsule_error[0], None
    if error is not None and error is not frame._current_exception:
        raise error


@dataclass(frozen=True)
class ServiceInspectionReceipt:
    port: int
    sequence: int
    phase: int
    failed: int


class ServiceInspectionFrame:
    def __init__(self, image, mode, service, arguments, *, namespace=None,
                 local_names=None, global_builtins=None):
        if type(image) is not NativeServiceInspection:
            raise TypeError('service inspection requires its admitted image')
        if type(mode) is not int or mode not in (INSPECT, CANDIDATE):
            raise ValueError('unknown service inspection mode')
        from . import hia_agent_service
        if namespace is None:
            namespace = vars(hia_agent_service)
            global_builtins = hia_agent_service._SERVICE_INSPECTION_GLOBAL_BUILTINS[mode]
        elif global_builtins is None:
            global_builtins = namespace.get('__builtins__', vars(builtins))
        if type(global_builtins) is types.ModuleType:
            global_builtins = vars(global_builtins)
        if local_names is None:
            local_names = hia_agent_service._SERVICE_INSPECTION_LOCAL_NAMES[mode]
        names = tuple(local_names)
        if len(set(names)) != len(names) or 'self' not in names or 'args' not in names:
            raise ValueError('original inspection local layout is not unique')
        self.image, self.mode = image, mode
        self.namespace, self.global_builtins = namespace, global_builtins
        self._retired_data = {}
        self.data = dict.fromkeys(names[::-1] if _storage_is_reversed() else names, _UNBOUND)
        self.data['self'], self.data['args'] = service, arguments
        self.result = None
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.buffer = ctypes.create_string_buffer(STATE_BYTES + 16)
        ctypes.memmove(ctypes.addressof(self.buffer) + STATE_BYTES, b'\xb7' * 16, 16)
        self.receipt = None
        self.fenced = self.finished = self.native_failed = self._entered = False
        self._pending_foreign = self._whole = None
        self._foreign_started = False
        self._effect_started = False
        self._ephemeral = {}
        self._iterator = self._item = self._mapping = self._capsule = None
        self._capsule_error = [None]
        self._current_exception = None
        self._native_source = self._native_output = None
        self._reiterations = _dict_reiterations() if mode == INSPECT else 0
        self._delivery = DeliveryRecord(self)
        try:
            # INIT is outside the whole observed-provider scope. A safe packet
            # preparation failure is not promoted to an observed method body.
            self.call(INITIALIZE)
        except BaseException:
            self._delivery.retire()
            raise

    def _local(self, name):
        # Loading an unbound original local is interpreter protocol, not a
        # business rejection. In particular an explicit native-patch override
        # may return None, leaving original program/diagnostics unbound.
        value = self.data[name]
        if value is _UNBOUND:
            if name == 'program':
                return _unbound_program()
            if name == 'diagnostics':
                return _unbound_diagnostics()
            raise ServiceInspectionUnknown('unbound internal local without original load site')
        return value

    def _global(self, name):
        return _global_value(self.namespace, self.global_builtins, name)

    def _check(self):
        record = self._delivery
        record.check(ServiceInspectionUnknown)
        whole = self._whole
        if whole is not None:
            whole.pending_resources.check_borrowed_resources()
        # The identity query/GC can itself run a real child.
        record.check(ServiceInspectionUnknown)

    def call(self, event, observation=0):
        record = self._delivery
        if self.fenced or self.finished or not record.current():
            raise ServiceInspectionUnknown('service inspection has no current invocation')
        self._check()
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
            self._native_source, self._native_output = source, output
            code = self.image._entry(source, REQUEST_BYTES, output, OUTPUT_BYTES,
                                     self.buffer, _handoff(record, STATE_BYTES))
            if (code != OUTPUT_BYTES or source.raw != raw + b'\xc9' * 16
                    or output.raw[OUTPUT_BYTES:] != b'\xa5' * 16
                    or self.buffer.raw[STATE_BYTES:] != b'\xb7' * 16):
                raise ServiceInspectionUnknown('service inspection return is unconfirmed')
            words = struct.unpack('<12Q', output.raw[:OUTPUT_BYTES])
            state = struct.unpack('<24Q', self.buffer.raw[:STATE_BYTES])
            expected_sequence = 1 if event == INITIALIZE else sequence if event == CLAIM else sequence + 1
            expected_phases = {
                INITIALIZE:(ISSUED,), CLAIM:(CLAIMED,),
                SUCCEEDED:(ISSUED, READY_RETURN, READY_PROPAGATE),
                RAISED:(ISSUED, READY_PROPAGATE),
                FINALIZE:(RETURNED, PROPAGATE),
            }[event]
            failed = 1 if event == RAISED else old_failed
            low, high = MODE_RANGES[self.mode]
            active = words[4] in (ISSUED, CLAIMED)
            if (words[0] != RESULT_MAGIC or words[1] != 0
                    or words[2:7] != (state[3], state[4], state[5], state[2], state[12])
                    or state[:3] != (STATE_MAGIC, 1, self.mode)
                    or words[8:10] != self.identity or state[6:8] != self.identity
                    or words[7] != 0 or words[10:12] != (0, 0)
                    or state[8] > 4 or state[11] != 0
                    or state[13:] != (0,) * 11 or state[10] != _checksum(state)
                    or (self.mode == INSPECT and state[8] == 4)
                    or (self.mode == CANDIDATE and state[8] not in (0, 4))
                    or (state[8] not in (2, 3) and state[9] != 0)
                    or words[3] != expected_sequence or words[4] not in expected_phases
                    or words[6] != failed
                    or (active and not low <= words[2] <= high)
                    or (active and int(words[2] in ERROR_PORTS) != failed)
                    or (not active and words[2] != 0)
                    or (words[4] in (RETURNED, READY_RETURN) and
                        (failed != 0 or state[8] != 0 or state[9] != 0))
                    or (words[4] in (PROPAGATE, READY_PROPAGATE) and failed != 1)
                    or (event == CLAIM and words[2] != port)
                    or (event == FINALIZE and (
                        previous.phase not in (READY_RETURN, READY_PROPAGATE)
                        or words[4] != (RETURNED if previous.phase == READY_RETURN else PROPAGATE)))):
                raise ServiceInspectionUnknown('service inspection receipt differs from complete state')
            receipt = ServiceInspectionReceipt(words[2], words[3], words[4], words[6])
            pending = None
            if event in (SUCCEEDED, RAISED):
                pending = self._pending_foreign
            elif event == FINALIZE:
                pending = self._whole
            if event in (SUCCEEDED, RAISED, FINALIZE):
                if pending is None:
                    raise ServiceInspectionUnknown('inspection has no matching foreign activation')
                pending.prepare_acknowledgement()
            self._check()
            record.confirmed()
            native_confirmed = True
            self.receipt = receipt
            self._native_source = self._native_output = None
            if pending is not None:
                pending.acknowledged()
                if event != FINALIZE:
                    self._pending_foreign = None
            self._check()
            if event == FINALIZE:
                record.confirmed(terminal=True)
            return receipt
        except BaseException as error:
            entered = record.native_pending
            lost = record.failed(error)
            pending = self._pending_foreign
            if pending is not None:
                pending.failed(error)
            if self._whole is not None:
                self._whole.failed(error)
            self.fenced = True
            self.native_failed = self.native_failed or lost or record.loss is not None
            if entered and not native_confirmed and isinstance(error, _REQUEST_REJECTIONS):
                raise ServiceInspectionUnknown('service inspection native delivery failed') from error
            raise

    def finish(self):
        # A denied same-Frame reentry must never execute the active owner's
        # cleanup/retire finally. Normal public recursion creates a new Frame.
        if self._entered:
            raise ServiceInspectionUnknown('service inspection frame cannot be reused')
        if not self._delivery.current():
            raise ServiceInspectionUnknown('service inspection frame cannot be transferred')
        self._entered = True
        try:
            self._check()
            whole = self._delivery.foreign(capture_resources=True, weak_registered_resources=True)
            self._whole = whole
            with self._delivery.foreign(observation=False):
                try:
                    with whole:
                        release_observation = self._drive()
                        # The original-local owner has now really returned.
                        # Its ordinary finalizers (or retained traceback frame)
                        # determine lifetime before the release is acknowledged.
                        if (self.receipt.phase != CLAIMED
                                or self.receipt.port not in (PORT['inspect_release'],
                                                            PORT['candidate_release'])):
                            raise ServiceInspectionUnknown('inspection release is not awaiting acknowledgement')
                        self.call(SUCCEEDED, release_observation)
                        if self.receipt.phase != READY_RETURN:
                            raise ServiceInspectionUnknown('inspection release has no return directive')
                except BaseException as error:
                    if (not self._foreign_started and self._delivery.loss is None
                            and not self._delivery.native_pending):
                        # This is a proven refusal before the first original
                        # foreign handoff, not a completed body outcome.
                        self._delivery.foreign_refused()
                    if (not self.native_failed and self._delivery.loss is None
                            and self.receipt.phase == READY_PROPAGATE):
                        self._finalize()
                        raise
                    whole.failed(error)
                    raise
                self._finalize()
                return self.__dict__.pop('result')
        except BaseException as error:
            self._delivery.failed(error)
            if self._pending_foreign is not None:
                self._pending_foreign.failed(error)
            if self._whole is not None:
                self._whole.failed(error)
            if self._delivery.loss is not None:
                self.fenced = self.native_failed = True
                self._delivery.propagate(error, ServiceInspectionUnknown, _REQUEST_REJECTIONS)
            raise
        finally:
            self._delivery.retire()

    def _effect_once(self):
        self._effect_started = False
        if self.receipt.phase != ISSUED:
            raise ServiceInspectionUnknown('inspection effect is not newly issued')
        self.call(CLAIM)
        activation = self._delivery.foreign(capture_resources=True, weak_registered_resources=True)
        self._pending_foreign = activation
        with activation:
            self._check()
            # Exact one-way handoff marker. No original lookup has run between
            # this point and effect(); a failure of the call itself is uncertain.
            self._foreign_started = self._effect_started = True
            return self.effect(self.receipt.port)

    def _finalize(self):
        previous = self.receipt.phase
        if previous not in (READY_RETURN, READY_PROPAGATE):
            raise ServiceInspectionUnknown('inspection has no HIA completion directive')
        self.call(FINALIZE)
        wanted = RETURNED if previous == READY_RETURN else PROPAGATE
        if self.receipt.phase != wanted:
            raise ServiceInspectionUnknown('inspection final receipt is unconfirmed')
        self.finished = True
        if wanted == PROPAGATE:
            # HIA has confirmed the method's exceptional terminal outcome.
            # The actual drive frame owns the original local storage; keeping
            # a second owner here would outlive that frame's consumer clearing.
            # Detach only: neither the dictionary nor any traceback is cleared.
            self.data = self._retired_data

    def _error_continuation(self):
        while self.receipt.phase == ISSUED:
            try:
                observation = self._effect_once()
            except BaseException as replacement:
                if not self._effect_started:
                    raise
                if self.fenced or self.native_failed or self._delivery.loss is not None:
                    self._delivery.propagate(replacement, ServiceInspectionUnknown, _REQUEST_REJECTIONS)
                    raise
                previous = self._current_exception
                self._current_exception = replacement
                try:
                    self.call(RAISED)
                    self._error_continuation()
                finally:
                    self._current_exception = previous
                raise
            self.call(SUCCEEDED, observation)
        if self.receipt.phase != READY_PROPAGATE:
            raise ServiceInspectionUnknown('inspection error has no propagation directive')

    def _drive(self):
        # This is the one active frame spanning all ports of the original
        # method. A provider traceback can retain it indirectly through f_back
        # even when an iterator's StopIteration is handled inside its next port.
        # Keep the original local storage in this real frame, so its ordinary
        # return or the consumer's existing frame clearing owns that lifetime.
        original_locals = self.data
        while True:
            try:
                observed = self._effect_once()
            except BaseException as error:
                if not self._effect_started:
                    raise
                if self.fenced or self.native_failed or self._delivery.loss is not None:
                    self._delivery.propagate(error, ServiceInspectionUnknown, _REQUEST_REJECTIONS)
                    raise
                self._current_exception = error
                try:
                    self.call(RAISED)
                    self._error_continuation()
                finally:
                    self._current_exception = None
                raise
            if self.receipt.port in (PORT['inspect_release'], PORT['candidate_release']):
                # Return the owning frame before finish sends this port's ACK.
                # Do not clear its locals: a real provider traceback may hold it.
                return observed
            self.call(SUCCEEDED, observed)
            if self.receipt.phase == READY_RETURN:
                return
            if self.receipt.phase != ISSUED:
                raise ServiceInspectionUnknown('inspection left its normal continuation')

    def effect(self, port):
        if (self.receipt is None or self.receipt.phase != CLAIMED
                or self.receipt.port != port or not 1 <= port <= len(PORTS)):
            raise ServiceInspectionUnknown('inspection has no matching effect claim')
        return getattr(self, '_port_' + PORTS[port - 1])()


    def _port_inspect_import(self):
        from .hia_program_tools import inspect_program
        self.data['inspect_program'] = inspect_program
        return 0

    def _port_inspect_prepare_import(self):
        from .hia_edit_query import prepare_edit
        self.data['prepare_edit'] = prepare_edit
        return 0

    def _port_inspect_emit_import(self):
        from .hia_program_native import emit_program_machine
        self.data['emit_program_machine'] = emit_program_machine
        return 0

    def _port_inspect_program(self):
        d = self.data
        d['program'] = d['self']._program(d['args']['program'])
        return 0

    def _port_inspect_selector(self):
        d = self.data
        d['selector'] = d['args'].get('selector', {})
        return 0

    def _port_inspect_has_cursor(self):
        if 'cursor' in self.data['args']:
            return 1
        return 0

    def _port_inspect_reject_cursor(self):
        self._global('reject')('E_HIA_CURSOR',
            'inspection returns an immutable artifact; paginate it through hia_read')
        return 0

    def _port_inspect_view_query(self):
        d = self.data
        d['view'], d['query'] = d['args']['view'], None
        return 0

    def _port_inspect_is_summary(self):
        if self.data['view'] == 'summary':
            return 1
        return 0

    def _port_inspect_summary(self):
        d = self.data
        d['result'] = d['inspect_program'](d['program'])
        return 0

    def _port_inspect_is_lowering(self):
        if self.data['view'] == 'lowering':
            return 1
        return 0

    def _port_inspect_context(self):
        d = self.data
        d['context'] = d['self']._context(d['args']['context'])
        return 0

    def _port_inspect_emit(self):
        d = self.data
        d['image'] = d['emit_program_machine'](d['program'],
            foreign_buffer_exports=self._global('tuple')(self._global('map')(
                self._global('tuple'), d['context'].get('foreign_buffer_exports', []))))
        return 0

    def _port_inspect_lowering_result(self):
        d = self.data
        d['result'] = {'schema': 'hepta.hia.agent.lowering-view.v1',
            'core_sha256': _attribute(d['program'], 'sha256'),
            'text_sha256': self._global('sha256')(_attribute(d['image'], 'text_bytes')).hexdigest(),
            'object_sha256': _attribute(d['image'], 'sha256'),
            'text_bytes': self._global('str')(self._global('len')(_attribute(d['image'], 'text_bytes'))),
            'frames': self._global('dict')(_attribute(d['image'], 'function_frames')),
            'lowering_profile': _attribute(d['self'], 'profiles')['lowering'],
            'optimizer_used': False,
            'object': _attribute(d['self'], 'store').put(_attribute(d['image'], 'object_bytes'), 'lowering-object')}
        return 0

    def _port_inspect_is_dependencies(self):
        if self.data['view'] == 'dependencies':
            return 1
        return 0

    def _port_inspect_all_prepare(self):
        self._ephemeral['all'] = self._global('all')
        self._ephemeral['generator'] = _selector_memberships(self.data['selector'])
        if _is_builtin_all(self._ephemeral['all']):
            return 1
        return 0

    def _port_inspect_all_next(self):
        try:
            value = next(self._ephemeral['generator'])
        except StopIteration:
            return 2
        if value:
            return 1
        return 0

    def _port_inspect_all_foreign(self):
        # The original foreign all callable receives the real generator.
        # No user callable attributes are probed, and the callee/argument are
        # removed from private storage before CALL, preserving escaping aliases.
        if self._ephemeral.pop('all')(self._ephemeral.pop('generator')):
            return 1
        return 0

    def _port_inspect_all_false_done(self):
        self._ephemeral.clear()
        return 0

    def _port_inspect_all_true_done(self):
        self._ephemeral.clear()
        return 0

    def _port_inspect_reject_dependencies(self):
        self._global('reject')('E_HIA_SELECTOR',
                              'dependencies require function, block and output')
        return 0

    def _port_inspect_prepare_edit(self):
        d = self.data
        d['prepared'] = d['prepare_edit'](d['program'],
            function=d['selector']['function'], block=d['selector']['block'],
            output=d['selector']['output'], fields=['op', 'args', 'attrs'])
        return 0

    def _port_inspect_prepared_result(self):
        self.data['result'] = self.data['prepared']
        return 0

    def _port_inspect_query(self):
        d = self.data
        d['query'] = _attribute(d['self'], 'store').json(d['prepared'], 'edit-query')
        return 0

    def _port_inspect_has_function(self):
        if 'function' in self.data['selector']:
            return 1
        return 0

    def _port_inspect_reject_function_required(self):
        self._global('reject')('E_HIA_SELECTOR', 'function view requires an exact function')
        return 0

    def _port_inspect_functions_open(self):
        # The first iter belongs outside the comprehension loop. It must not
        # share the iterator-next EOF handler or generator PEP479 conversion.
        self._iterator = iter(self.data['program'].as_dict()['functions'])
        self._mapping = {}
        return self._reiterations

    def _port_inspect_functions_reiterate(self):
        # A runtime-specific comprehension entry may call iter again. The HIA
        # counter, sourced from a private fixed probe, owns how many repetitions.
        self._iterator = iter(self._iterator)
        return 0

    def _port_inspect_functions_next(self):
        try:
            self._item = next(self._iterator)
            return 0
        except StopIteration:
            return 1

    def _port_inspect_functions_put(self):
        self._mapping[self._item['name']] = self._item
        return 0

    def _port_inspect_functions_done(self):
        self._iterator = None
        self._item = None
        self.data['functions'], self._mapping = self._mapping, None
        return 0

    def _port_inspect_function_present(self):
        d = self.data
        if d['selector']['function'] in d['functions']:
            return 1
        return 0

    def _port_inspect_reject_function_missing(self):
        self._global('reject')('E_HIA_SELECTOR', 'function is not in this program')
        return 0

    def _port_inspect_function_result(self):
        d = self.data
        d['result'] = d['functions'][d['selector']['function']]
        return 0

    def _port_inspect_is_block(self):
        if self.data['view'] == 'block':
            return 1
        return 0

    def _port_inspect_blocks_open(self):
        self._iterator = iter(self.data['result']['blocks'])
        self._mapping = {}
        return self._reiterations

    def _port_inspect_blocks_reiterate(self):
        self._iterator = iter(self._iterator)
        return 0

    def _port_inspect_blocks_next(self):
        try:
            self._item = next(self._iterator)
            return 0
        except StopIteration:
            return 1

    def _port_inspect_blocks_put(self):
        self._mapping[self._item['id']] = self._item
        return 0

    def _port_inspect_blocks_done(self):
        self._iterator = None
        self._item = None
        self.data['blocks'], self._mapping = self._mapping, None
        return 0

    def _port_inspect_block_present(self):
        d = self.data
        if d['selector'].get('block') in d['blocks']:
            return 1
        return 0

    def _port_inspect_reject_block_missing(self):
        self._global('reject')('E_HIA_SELECTOR', 'block is not in this function')
        return 0

    def _port_inspect_block_result(self):
        d = self.data
        d['result'] = d['blocks'][d['selector']['block']]
        return 0

    def _port_inspect_result(self):
        d = self.data
        self.result = {'program': d['args']['program'],
            'view_artifact': _attribute(d['self'], 'store').json(d['result'], 'inspection'),
            'query_artifact': d['query'], 'next_cursor': None}
        return 0

    def _port_inspect_release(self):
        d = self.data
        self.data = self._retired_data
        return 0

    def _port_inspect_comprehension_unwind(self):
        self._iterator = None
        self._item = None
        self._mapping = None
        return 0

    def _port_inspect_all_unwind(self):
        self._ephemeral.clear()
        return 0

    def _port_candidate_assemble_import(self):
        from .hia_agent_assembly import assemble_program
        self.data['assemble_program'] = assemble_program
        return 0

    def _port_candidate_patch_import(self):
        from .hia_program_tools import apply_program_patch
        self.data['apply_program_patch'] = apply_program_patch
        return 0

    def _port_candidate_change_base_payloads(self):
        d = self.data
        d['change'], d['base'], d['native_payloads'] = d['args']['change'], None, None
        return 0

    def _port_candidate_is_import(self):
        if self.data['change']['kind'] == 'import':
            return 1
        return 0

    def _port_candidate_import_data(self):
        d = self.data
        d['data'], d['_'] = _attribute(d['self'], 'store').get(d['change']['source'])
        return 0

    def _port_candidate_is_assembly(self):
        if self.data['change']['format'] == 'hia-asm.v1':
            return 1
        return 0

    def _port_candidate_assemble(self):
        d = self.data
        d['program'] = d['assemble_program'](d['data'])
        return 0

    def _port_candidate_verify(self):
        d = self.data
        d['program'] = self._global('verify_program')(self._global('decode_json')(d['data']))
        return 0

    def _port_candidate_import_diagnostics(self):
        d = self.data
        d['diagnostics'] = {'schema': 'hepta.hia.agent.candidate-diagnostics.v1',
            'whole_program_checked': True, 'input_sha256': _attribute(d['program'], 'input_sha256'),
            'core_sha256': _attribute(d['program'], 'sha256')}
        return 0

    def _port_candidate_base(self):
        d = self.data
        d['base'] = d['change']['base_program']
        return 0

    def _port_candidate_patch_selector(self):
        self.data['selected'] = self._global('os').environ.get('HEPTA_HIA_CORE_PATCH_MANIFEST')
        return 0

    def _port_candidate_patch_selected(self):
        if self.data['selected']:
            return 1
        return 0

    def _port_candidate_native_patch_import(self):
        from .hia_agent_candidate_native import apply_candidate_patch
        self.data['apply_candidate_patch'] = apply_candidate_patch
        return 0

    def _port_candidate_original_bytes(self):
        d = self.data
        d['original_bytes'], d['_'] = _attribute(d['self'], 'store').get(d['base'])
        return 0

    def _port_candidate_patch_bytes(self):
        d = self.data
        d['patch_bytes'], d['_'] = _attribute(d['self'], 'store').get(d['change']['patch'])
        return 0

    def _port_candidate_apply_native(self):
        d = self.data
        d['native_payloads'] = d['apply_candidate_patch'](
            d['selected'], d['original_bytes'], d['patch_bytes'], d['change']['patch_schema'])
        return 0

    def _port_candidate_original_program(self):
        d = self.data
        d['original'] = d['self']._program(d['base'])
        return 0

    def _port_candidate_patch_document(self):
        d = self.data
        d['patch'], d['_'] = _attribute(d['self'], 'store').get_json(d['change']['patch'])
        return 0

    def _port_candidate_schema_differs(self):
        d = self.data
        if d['patch'].get('schema') != d['change']['patch_schema']:
            return 1
        return 0

    def _port_candidate_reject_schema(self):
        self._global('reject')('E_HIA_PATCH_SCHEMA',
                              'patch artifact differs from declared patch schema')
        return 0

    def _port_candidate_apply_program(self):
        d = self.data
        d['program'], d['diagnostics'] = d['apply_program_patch'](d['original'], d['patch'])
        return 0

    def _port_candidate_put_open(self):
        _open_put_expression(self)
        return 0

    def _port_candidate_payload_selected(self):
        if self.data['native_payloads'] is not None:
            return 1
        return 0

    def _port_candidate_put_native(self):
        _resume_put_expression(self, True)
        return 0

    def _port_candidate_put_program(self):
        _resume_put_expression(self, False)
        return 0

    def _port_candidate_diagnostics_selected(self):
        if self.data['native_payloads'] is not None:
            return 1
        return 0

    def _port_candidate_diagnostics_native(self):
        d = self.data
        d['diagnostic_artifact'] = _attribute(d['self'], 'store').put(
            d['native_payloads'][1], 'candidate-diagnostics')
        return 0

    def _port_candidate_diagnostics_json(self):
        d = self.data
        d['diagnostic_artifact'] = _attribute(d['self'], 'store').json(
            self._local('diagnostics'), 'candidate-diagnostics')
        return 0

    def _port_candidate_result(self):
        d = self.data
        self.result = {'candidate': d['candidate'], 'base_program': d['base'],
            'diagnostics': d['diagnostic_artifact'], 'core_admitted': True,
            'behavior_equivalence_proved': False, 'adopted': False}
        return 0

    def _port_candidate_release(self):
        d = self.data
        self.data = self._retired_data
        return 0

    def _port_candidate_put_unwind(self):
        _unwind_put_expression(self)
        return 0
