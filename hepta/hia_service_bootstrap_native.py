"""Unqualified complete service bootstrap/lifecycle/profile control candidate.

All original method choices, loops, constructor cleanup decisions and terminal
receipts belong to the HIA graph. OS/SQL/catalog/schema/Store/budget/ledger
operations remain explicit providers. The two real generator-expression
arguments use segmented HIA advances; no retained whole method is invoked.
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
import sys
import types
from .hia_emission_native import _global_value
from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path, _unique_manifest_pairs
from .hia_native_delivery import DeliveryRecord
from .hia_store_lifecycle_native import _regular_bytes
from .hia_service_bootstrap_protocol import (
    SELECTOR, SCHEMA, SOURCE_NAME, REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC,
    REQUEST_BYTES, OUTPUT_BYTES, STATE_BYTES, INITIALIZE, CLAIM, SUCCEEDED,
    RAISED, FINALIZE, RESUME_GENERATOR, THROW_GENERATOR, LEAVE_EXCEPTION,
    ISSUED, CLAIMED, RETURNED, PROPAGATE, READY_RETURN, READY_PROPAGATE,
    READY_YIELD, PAUSED, LEAVE_HANDLER, INIT, CLOSE, PROFILES, PROFILE, PROGRAM,
    GENERATOR_ROOTS, GENERATOR_DIRECTORIES, PORT, PORTS, MODE_RANGES)
SOURCE = _source_resource_path(SOURCE_NAME)
_BaseException, _StopIteration = BaseException, StopIteration
_ITER, _NEXT, _TYPE, _TUPLE = iter, next, type, tuple
_TYPE_MRO = type.__dict__['__mro__']
_HANDLED = sys.exception
_UNBOUND = object()
_REQUEST_REJECTIONS = (ValueError, TypeError, OSError, OverflowError, RecursionError, sqlite3.Error)
_REQUEST_BUFFER_TYPE = ctypes.c_char * (REQUEST_BYTES + 16)
_OUTPUT_BUFFER_TYPE = ctypes.c_char * (OUTPUT_BYTES + 16)
_STATE_BUFFER_TYPE = ctypes.c_char * (STATE_BYTES + 16)
RELEASE_PORTS = frozenset(PORT[name] for name in (
    'init_release', 'close_release', 'profiles_release', 'profile_release',
    'program_release', 'generator_release'))
YIELD_PORT = PORT['generator_yield']

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
    values = {'first': _ReleaseProbe(events, 'first'), 'last': _ReleaseProbe(events, 'last')}

@lru_cache(maxsize=1)
def _storage_is_reversed():
    frames, dictionaries = [], []
    _frame_release_probe(frames)
    _dict_release_probe(dictionaries)
    allowed = (['first', 'last'], ['last', 'first'])
    if frames not in allowed or dictionaries not in allowed:
        raise RuntimeError('service bootstrap local release order is unavailable')
    return frames != dictionaries

@lru_cache(maxsize=1)
def _handled_setter():
    if sys.implementation.name != 'cpython':
        raise RuntimeError('bootstrap cleanup requires the CPython handled-state ABI')
    setter = ctypes.pythonapi['PyErr_SetHandledException']
    setter.argtypes = (ctypes.c_void_p,)
    setter.restype = None
    return setter

def _actual_instance_of(value, expected):
    for base in _TYPE_MRO.__get__(_TYPE(value)):
        if base is expected:
            return True
    return False

def _exception_matches(error_type, candidate):
    targets = tuple.__iter__(candidate) if _actual_instance_of(candidate, _TUPLE) else (candidate,)
    for target in targets:
        if not _actual_instance_of(target, _TYPE):
            raise TypeError('catching classes that do not inherit from BaseException is not allowed')
        for base in _TYPE_MRO.__get__(target):
            if base is _BaseException:
                break
        else:
            raise TypeError('catching classes that do not inherit from BaseException is not allowed')
    targets = tuple.__iter__(candidate) if _actual_instance_of(candidate, _TUPLE) else (candidate,)
    actual = _TYPE_MRO.__get__(error_type)
    for target in targets:
        for base in actual:
            if base is target:
                return 1
    return 0

class ServiceBootstrapUnknown(RuntimeError):
    """An actually entered selected bootstrap delivery has no complete ACK."""

class NativeServiceBootstrap(NativeHiaJsonImage):
    pass

@lru_cache(maxsize=3)
def _mapped_bootstrap(raw, digest, source_digest):
    image = NativeServiceBootstrap(raw, digest)
    image.admitted_source_sha256 = source_digest
    return image

def installed_service_bootstrap(manifest_path):
    if not manifest_path:
        raise ValueError('native service bootstrap selector must not be empty')
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeServiceBootstrap)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_unique_manifest_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[k]) is not str or len(value[k]) != 64
                   or any(c not in '0123456789abcdef' for c in value[k])
                   for k in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid service bootstrap manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or Path(name).name != name or any(ord(c) < 32 for c in name)):
        raise ValueError('bootstrap image must be a sibling basename')
    source = _regular_bytes(SOURCE, 8 << 20)
    image_path = path.parent / name
    image_raw = _regular_bytes(image_path, 1 << 20)
    if sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('service bootstrap source differs')
    if sha256(image_raw).hexdigest() != value['image_sha256']:
        raise ValueError('service bootstrap image differs')
    if selected is None:
        selected = _mapped_bootstrap(image_raw, value['image_sha256'], value['source_sha256'])
    elif type(selected) is not NativeServiceBootstrap or selected.image_sha256 != value['image_sha256']:
        raise ValueError('service bootstrap differs from its pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source
            or _regular_bytes(image_path, 1 << 20) != image_raw):
        raise ValueError('service bootstrap selection changed during admission')
    selected.admitted_source_sha256 = value['source_sha256']
    return selected

def _checksum(words):
    value = 1469598103934665603
    for i, word in enumerate(words):
        if i != 10:
            value = (((value << 7) | (value >> 57)) & ((1 << 64) - 1)) ^ word
    return value

def _handoff(record, extent):
    record.enter_native()
    return extent

@dataclass(frozen=True)
class ServiceBootstrapReceipt:
    port: int
    sequence: int
    phase: int
    failed: int

def _capsule_start(capsule):
    outcome = None
    stopped = False
    try:
        try:
            yielded = _NEXT(capsule)
        except _StopIteration as end:
            outcome = end.value
            stopped = True
        if stopped:
            if type(outcome) is not tuple or len(outcome) != 2 or outcome[0] != 0:
                raise ServiceBootstrapUnknown('profile expression returned before its list-comprehension suspension')
            raise outcome[1]
        return yielded
    finally:
        outcome = None

def _capsule_finish(capsule, value):
    outcome = None
    stopped = False
    try:
        try:
            capsule.send(value)
        except _StopIteration as end:
            outcome = end.value
            stopped = True
        if not stopped or type(outcome) is not tuple or len(outcome) != 2:
            raise ServiceBootstrapUnknown('profile expression has no complete outcome')
        if outcome[0] == 0:
            raise outcome[1]
        if outcome[0] != 1:
            raise ServiceBootstrapUnknown('profile expression outcome tag differs')
        return outcome[1]
    finally:
        outcome = value = capsule = None

def _capsule_abort(capsule, error):
    outcome = None
    stopped = False
    try:
        if capsule.gi_frame is None:
            return
        try:
            capsule.throw(error)
        except _StopIteration as end:
            outcome = end.value
            stopped = True
        if (not stopped or type(outcome) is not tuple or len(outcome) != 2
                or outcome[0] != 0 or outcome[1] is not error):
            raise ServiceBootstrapUnknown('profile expression unwind changed the actual pending exception')
    finally:
        outcome = capsule = error = None


def _bootstrap_generator(image, mode, iterator, namespace, global_builtins, import_ports, local_layouts):
    # This is a real Python generator. Frame construction is lazy, as are the
    # original genexpr bodies. send values are discarded at the yield; throw
    # and close enter the real generator exception path and PEP 479 remains the
    # interpreter's rule. A fresh DeliveryRecord belongs to every actual advance.
    frame = ServiceBootstrapFrame(image, mode, {'iterator': iterator},
        namespace=namespace, global_builtins=global_builtins,
        import_ports=import_ports, local_layouts=local_layouts)
    del iterator
    while frame.advance_generator():
        # A thrown exception can retain this real generator frame. Its original
        # local storage must remain there until Python releases that frame.
        original_locals = frame.data
        try:
            yield frame.__dict__.pop('result')
        except _BaseException:
            frame.throw_generator()
            raise
        else:
            # Normal resume still releases in the existing HIA segment before
            # its final ACK; this alias belongs only to the suspended yield.
            del original_locals

class ServiceBootstrapFrame:
    def __init__(self, image, mode, initial, *, namespace=None, global_builtins=None,
                 import_ports=None, local_layouts=None, service_options=None):
        if type(image) is not NativeServiceBootstrap:
            raise TypeError('service bootstrap requires its admitted image')
        if type(mode) is not int or mode not in MODE_RANGES:
            raise ValueError('unknown bootstrap mode')
        from . import hia_agent_service
        canonical_imports = hia_agent_service._SERVICE_BOOTSTRAP_IMPORT_PORTS
        if namespace is None:
            namespace = vars(hia_agent_service)
            global_builtins = hia_agent_service._SERVICE_BOOTSTRAP_GLOBAL_BUILTINS
            import_ports = canonical_imports if import_ports is None else import_ports
            local_layouts = hia_agent_service._SERVICE_BOOTSTRAP_LOCAL_LAYOUTS if local_layouts is None else local_layouts
        if type(global_builtins) is types.ModuleType:
            global_builtins = vars(global_builtins)
        if type(namespace) is not dict or type(global_builtins) is not dict:
            raise TypeError('bootstrap needs actual global and captured builtin dictionaries')
        if import_ports is None or local_layouts is None:
            raise ValueError('explicit bootstrap namespace must carry captured import ports and original layouts')
        if set(import_ports) != set(canonical_imports):
            raise ValueError('bootstrap import port set differs')
        for name, function in import_ports.items():
            if (type(function) is not types.FunctionType
                    or function.__globals__ is not namespace
                    or function.__builtins__ is not global_builtins
                    or function.__code__ is not canonical_imports[name].__code__):
                raise ValueError('bootstrap import port code or captured namespace differs')
        names = local_layouts[mode] if mode <= PROGRAM else ('.0', 'root')
        if type(names) is not tuple or any(type(n) is not str for n in names):
            raise TypeError('bootstrap local layout must be the original code tuple')
        self.image, self.mode = image, mode
        self.namespace, self.global_builtins = namespace, global_builtins
        self.import_ports, self.local_layouts = import_ports, local_layouts
        self._retired_data = {}
        self.data = dict.fromkeys(names[::-1] if _storage_is_reversed() else names, _UNBOUND)
        self.stack = {}
        if mode <= PROGRAM:
            for name, value in initial.items():
                if name not in self.data:
                    raise ValueError('bootstrap initial local differs from its original signature')
                self.data[name] = value
        else:
            self.data['.0'] = initial['iterator']
        self.result = None
        self.service_options = service_options
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.buffer = ctypes.create_string_buffer(STATE_BYTES + 16)
        ctypes.memmove(ctypes.addressof(self.buffer) + STATE_BYTES, b'\xb7' * 16, 16)
        self.receipt = None
        self.fenced = self.finished = self.native_failed = self._entered = False
        self._pending_foreign = self._whole = None
        self._effect_started = self._foreign_started = False
        self._native_source = self._native_output = None
        self._caller_handled = _HANDLED()
        self._set_handled = _handled_setter()
        self._delivery = DeliveryRecord(self)
        try:
            self.call(INITIALIZE)
        except _BaseException:
            self._delivery.retire()
            raise

    def _global(self, name):
        return _global_value(self.namespace, self.global_builtins, name)

    def _check(self):
        record = self._delivery
        record.check(ServiceBootstrapUnknown)
        if self._whole is not None:
            self._whole.pending_resources.check_borrowed_resources()
        record.check(ServiceBootstrapUnknown)

    def call(self, event, observation=0):
        record = self._delivery
        if self.fenced or self.finished or record is None or not record.current():
            raise ServiceBootstrapUnknown('bootstrap has no current invocation')
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
                raise ServiceBootstrapUnknown('bootstrap return is unconfirmed')
            words = struct.unpack('<12Q', output.raw[:OUTPUT_BYTES])
            state = struct.unpack('<24Q', self.buffer.raw[:STATE_BYTES])
            expected_sequence = 1 if event == INITIALIZE else sequence if event == CLAIM else sequence + 1
            phases = {
                INITIALIZE:(ISSUED,), CLAIM:(CLAIMED,),
                SUCCEEDED:(ISSUED, READY_RETURN, READY_PROPAGATE, READY_YIELD, LEAVE_HANDLER),
                RAISED:(ISSUED, READY_PROPAGATE),
                FINALIZE:(RETURNED, PROPAGATE, PAUSED),
                RESUME_GENERATOR:(ISSUED,), THROW_GENERATOR:(ISSUED,),
                LEAVE_EXCEPTION:(ISSUED,),
            }[event]
            failed = 1 if event in (RAISED, THROW_GENERATOR) else old_failed
            low, high = MODE_RANGES[self.mode]
            active = words[4] in (ISSUED, CLAIMED, LEAVE_HANDLER)
            if (words[0] != RESULT_MAGIC or words[1] != 0
                    or words[2:7] != (state[3], state[4], state[5], state[2], state[12])
                    or state[:3] != (STATE_MAGIC, 1, self.mode)
                    or words[8:10] != self.identity or state[6:8] != self.identity
                    or words[7] != 0 or words[10:12] != (0, 0)
                    or state[8:10] != (0, 0) or state[11] != 0
                    or state[13:] != (0,) * 11 or state[10] != _checksum(state)
                    or words[3] != expected_sequence or words[4] not in phases or words[6] != failed
                    or (active and not low <= words[2] <= high)
                    or (active and self.mode == GENERATOR_ROOTS and words[2] == PORT['generator_dir_value'])
                    or (active and self.mode == GENERATOR_DIRECTORIES and words[2] == PORT['generator_root_value'])
                    or (not active and words[2] != 0)
                    or (words[4] in (READY_RETURN, RETURNED, READY_YIELD, PAUSED) and failed != 0)
                    or (words[4] in (READY_PROPAGATE, PROPAGATE, LEAVE_HANDLER) and failed != 1)
                    or (words[4] in (READY_YIELD, PAUSED) and self.mode < GENERATOR_ROOTS)
                    or (event == CLAIM and words[2] != port)
                    or (event == FINALIZE and (
                        previous.phase not in (READY_RETURN, READY_PROPAGATE, READY_YIELD)
                        or words[4] != {READY_RETURN:RETURNED, READY_PROPAGATE:PROPAGATE,
                                        READY_YIELD:PAUSED}[previous.phase]))):
                raise ServiceBootstrapUnknown('bootstrap receipt differs from its complete state')
            receipt = ServiceBootstrapReceipt(words[2], words[3], words[4], words[6])
            pending = self._pending_foreign if event in (SUCCEEDED, RAISED) else self._whole if event == FINALIZE else None
            if event in (SUCCEEDED, RAISED, FINALIZE):
                if pending is None:
                    raise ServiceBootstrapUnknown('bootstrap has no corresponding foreign activation')
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
        except _BaseException as error:
            entered = record.native_pending
            lost = record.failed(error)
            if self._pending_foreign is not None:
                self._pending_foreign.failed(error)
            if self._whole is not None:
                self._whole.failed(error)
            self.fenced = True
            self.native_failed = self.native_failed or lost or record.loss is not None
            if entered and not native_confirmed and isinstance(error, _REQUEST_REJECTIONS):
                raise ServiceBootstrapUnknown('bootstrap native delivery failed') from error
            raise

    def _finalize(self):
        previous = self.receipt.phase
        if previous not in (READY_RETURN, READY_PROPAGATE, READY_YIELD):
            raise ServiceBootstrapUnknown('bootstrap has no finalization directive')
        self.call(FINALIZE)
        expected = {READY_RETURN:RETURNED, READY_PROPAGATE:PROPAGATE, READY_YIELD:PAUSED}[previous]
        if self.receipt.phase != expected:
            raise ServiceBootstrapUnknown('bootstrap finalization differs')
        self.finished = expected != PAUSED
        if expected == PROPAGATE:
            self.data = self._retired_data

    def _effect_once(self):
        self._effect_started = False
        if self.receipt.phase != ISSUED:
            raise ServiceBootstrapUnknown('bootstrap effect is not newly issued')
        self.call(CLAIM)
        activation = self._delivery.foreign(capture_resources=True, weak_registered_resources=True)
        self._pending_foreign = activation
        with activation:
            self._check()
            self._foreign_started = self._effect_started = True
            return self.effect(self.receipt.port)

    def _foreign_raised(self, error):
        if not self._effect_started:
            raise
        if self.fenced or self.native_failed or self._delivery.loss is not None:
            self._delivery.propagate(error, ServiceBootstrapUnknown, _REQUEST_REJECTIONS)
            raise
        self.call(RAISED)

    def _exception_continuation(self):
        while self.receipt.phase == ISSUED:
            nested = False
            try:
                observed = self._effect_once()
            except _BaseException as error:
                self._foreign_raised(error)
                if self.receipt.phase == READY_PROPAGATE:
                    raise
                self._exception_continuation()
                nested = True
            else:
                self.call(SUCCEEDED, observed)
            # A successful inner cleanup handler has really left its except
            # block before HIA is asked to issue failure-alias retirement.
            if nested and self.receipt.phase == LEAVE_HANDLER:
                self.call(LEAVE_EXCEPTION)
        if self.receipt.phase == LEAVE_HANDLER:
            return
        if self.receipt.phase == READY_PROPAGATE:
            raise
        raise ServiceBootstrapUnknown('bootstrap exceptional continuation differs')

    def _drive(self, *, generator_throw=False):
        original_locals = self.data
        while True:
            try:
                observed = self._effect_once()
            except _BaseException as error:
                self._foreign_raised(error)
                if self.receipt.phase == READY_PROPAGATE:
                    raise
                self._exception_continuation()
            else:
                if self.receipt.port in RELEASE_PORTS or self.receipt.port == YIELD_PORT:
                    return observed
                if generator_throw and self.receipt.port == PORT['generator_propagate']:
                    # The real generator already owns this pending throw. Only
                    # a successful propagate-port ACK may relay it without
                    # adding these mechanical frames to its user traceback.
                    self.call(SUCCEEDED, observed)
                    if self.receipt.phase != READY_PROPAGATE:
                        raise ServiceBootstrapUnknown('bootstrap throw relay has no propagate directive')
                    return observed
                self.call(SUCCEEDED, observed)
            if self.receipt.phase == LEAVE_HANDLER:
                self.call(LEAVE_EXCEPTION)
            if self.receipt.phase == READY_PROPAGATE:
                raise
            if self.receipt.phase != ISSUED:
                raise ServiceBootstrapUnknown('bootstrap has no issued continuation')

    def _owned_segment(self, *, generator_throw=False):
        self._check()
        if generator_throw and (
                self.mode not in (GENERATOR_ROOTS, GENERATOR_DIRECTORIES)
                or self.receipt.phase != ISSUED
                or self.receipt.port != PORT['generator_error_unwind']
                or self.receipt.failed != 1
                or self._caller_handled is None
                or _HANDLED() is not self._caller_handled):
            raise ServiceBootstrapUnknown('bootstrap throw relay has no actual pending generator throw')
        whole = self._delivery.foreign(capture_resources=True, weak_registered_resources=True)
        self._whole = whole
        with self._delivery.foreign(observation=False):
            try:
                with whole:
                    observed = self._drive(generator_throw=generator_throw)
                    if generator_throw:
                        if (self.receipt.phase != READY_PROPAGATE
                                or _HANDLED() is not self._caller_handled):
                            raise ServiceBootstrapUnknown('bootstrap throw relay changed its pending outcome')
                    else:
                        if (self.receipt.phase != CLAIMED
                                or (self.receipt.port not in RELEASE_PORTS and self.receipt.port != YIELD_PORT)):
                            raise ServiceBootstrapUnknown('bootstrap drive did not stop at its exact release/yield')
                        self.call(SUCCEEDED, observed)
                        if self.receipt.phase not in (READY_RETURN, READY_YIELD):
                            raise ServiceBootstrapUnknown('bootstrap has no normal completion directive')
            except _BaseException as error:
                if not self._foreign_started and self._delivery.loss is None and not self._delivery.native_pending:
                    self._delivery.foreign_refused()
                if not self.native_failed and self._delivery.loss is None and self.receipt.phase == READY_PROPAGATE:
                    self._finalize()
                    raise
                whole.failed(error)
                raise
            self._finalize()
            return self.receipt.phase

    def finish(self):
        if self.mode >= GENERATOR_ROOTS:
            raise ServiceBootstrapUnknown('generator expressions need segmented advances')
        if self._entered or not self._delivery.current():
            raise ServiceBootstrapUnknown('bootstrap frame cannot be reentered or transferred')
        self._entered = True
        try:
            self._owned_segment()
            return self.__dict__.pop('result')
        except _BaseException as error:
            self._delivery.failed(error)
            if self._pending_foreign is not None:
                self._pending_foreign.failed(error)
            if self._whole is not None:
                self._whole.failed(error)
            if self._delivery.loss is not None:
                self.fenced = self.native_failed = True
                self._delivery.propagate(error, ServiceBootstrapUnknown, _REQUEST_REJECTIONS)
            raise
        finally:
            self._delivery.retire()

    def _new_generator_segment(self, event):
        if self._entered or self.fenced or self.finished or self.mode < GENERATOR_ROOTS:
            raise ServiceBootstrapUnknown('bootstrap generator has no new advance')
        if self.receipt.phase != PAUSED or self._delivery is not None:
            raise ServiceBootstrapUnknown('bootstrap generator is not paused after an acknowledged yield')
        self._caller_handled = _HANDLED()
        self._whole = self._pending_foreign = None
        self._foreign_started = self._effect_started = False
        self._delivery = DeliveryRecord(self)
        try:
            self.call(event)
        except _BaseException:
            self._delivery.retire()
            raise

    def advance_generator(self):
        if self.mode < GENERATOR_ROOTS or self._entered or self.fenced or self.finished:
            raise ServiceBootstrapUnknown('bootstrap generator cannot advance')
        if self.receipt.phase == PAUSED:
            self._new_generator_segment(RESUME_GENERATOR)
        self._entered = True
        try:
            phase = self._owned_segment()
            return phase == PAUSED
        except _BaseException as error:
            self._delivery.failed(error)
            if self._delivery.loss is not None:
                self.fenced = self.native_failed = True
                self._delivery.propagate(error, ServiceBootstrapUnknown, _REQUEST_REJECTIONS)
            raise
        finally:
            self._delivery.retire()
            self._delivery = None
            self._entered = False

    def throw_generator(self):
        self._new_generator_segment(THROW_GENERATOR)
        self._entered = True
        try:
            self._owned_segment(generator_throw=True)
        finally:
            try:
                self._delivery.retire()
                self._delivery = None
                self._entered = False
            finally:
                # The pending throw is owned by Python's exception state. This
                # completed segment must not keep an extra path back to its TB.
                self._caller_handled = None

    def _new_genexpr(self, mode, iterator):
        return _bootstrap_generator(self.image, mode, iterator, self.namespace,
            self.global_builtins, self.import_ports, self.local_layouts)

    def _release_at(self, name, handled):
        if self.receipt.phase != CLAIMED or self.receipt.port != PORT[name]:
            raise ServiceBootstrapUnknown('bootstrap stack retirement is not HIA-issued')
        pending = _HANDLED()
        setter = self._set_handled
        pending_pointer = None if pending is None else id(pending)
        handled_pointer = None if handled is None else id(handled)
        try:
            setter(handled_pointer)
            if _HANDLED() is not handled:
                raise ServiceBootstrapUnknown('bootstrap handled state was not installed')
            self._release_stack(name, pending)
            return 0
        finally:
            try:
                setter(pending_pointer)
                if _HANDLED() is not pending:
                    raise ServiceBootstrapUnknown('bootstrap handled state was not restored')
            finally:
                pending = handled = None

    def _release_stack(self, name, pending):
        d, s = self.data, self.stack
        if name == 'init_abort_failure':
            d['failure'] = _UNBOUND
        elif name in ('init_abort_error', 'init_clear_error'):
            if name == 'init_abort_error':
                # The loop stack unwinds while the body handler is still
                # active, before that handler's named exception is cleared.
                s.pop('cleanup_iterator', None)
            d['error'] = _UNBOUND
        elif name == 'init_clear_failure':
            d['failure'] = _UNBOUND
        elif name == 'init_stack_unwind':
            s.pop('cleanup_iterator', None)
            s.pop('tools_iterator', None)
            d['t'] = _UNBOUND
            s.pop('tools_result', None)
        elif name == 'profiles_error_unwind':
            s.pop('docs_iterator', None)
            s.pop('items_iterator', None)
            s.pop('roots_iterator', None)
            d['root'] = _UNBOUND
            s.pop('roots_result', None)
            s.pop('roots_input', None)
            capsule = s.pop('bodies_capsule', None)
            if capsule is not None:
                _capsule_abort(capsule, pending)
        elif name in ('close_error_unwind', 'profile_error_unwind', 'program_error_unwind', 'generator_error_unwind'):
            pass
        else:
            raise ServiceBootstrapUnknown('bootstrap stack retirement port differs')

    def effect(self, port):
        if (self.receipt is None or self.receipt.phase != CLAIMED
                or self.receipt.port != port or not MODE_RANGES[self.mode][0] <= port <= MODE_RANGES[self.mode][1]):
            raise ServiceBootstrapUnknown('bootstrap effect has no matching claim')
        return getattr(self, '_port_' + PORTS[port - 1])()

    def _port_init_import_candidate(self):
        d=self.data
        d['selected_candidate_budget'], d['NativeCandidateBudgetStore'] = self.import_ports['init_import_candidate'](d['self'],d['state_root'],d['artifact_roots'])
        return 0

    def _port_init_import_slot(self):
        d=self.data
        d['selected_slot_ledger'],d['NativeSlotLedgerStore'] = self.import_ports['init_import_slot'](d['self'],d['state_root'],d['artifact_roots'],d['selected_candidate_budget'],d['NativeCandidateBudgetStore'])
        return 0

    def _port_init_candidate_select(self):
        self.data['candidate_budget_image'] = self.data['selected_candidate_budget']()
        return 0

    def _port_init_slot_select(self):
        self.data['slot_ledger_image'] = self.data['selected_slot_ledger']()
        return 0

    def _port_init_catalog(self):
        self.import_ports['init_catalog'](self.data['self'])
        return 0

    def _port_init_tools_begin(self):
        self.stack['tools_result']={}
        self.stack['tools_iterator']=self.import_ports['init_tools_iter'](self.data['self'])
        return 0

    def _port_init_tools_next(self):
        try:
            self.data['t']=_NEXT(self.stack['tools_iterator'])
        except _StopIteration:
            return 0
        return 1

    def _port_init_tools_put(self):
        self.import_ports['init_tools_put'](self.stack['tools_result'],self.data['t'])
        return 0

    def _port_init_tools_end(self):
        self.stack.pop('tools_iterator')
        self.data['t']=_UNBOUND
        return 0

    def _port_init_tools_store(self):
        service = self.data['self']
        service.tools = self.stack.pop('tools_result')
        if self.service_options is not None:
            service._tool_roles = {name: index for index, name in enumerate(service.tools, 1)}
        return 0

    def _port_init_identities(self):
        self.import_ports['init_identities'](self.data['self'])
        return 0

    def _port_init_store(self):
        d=self.data
        options = self.service_options
        service = d['self']
        if options is None or options['native_store'] is None:
            self.import_ports['init_store'](service, d['state_root'])
        else:
            service.store = self.namespace['AgentStore'](d['state_root'], native_store=options['native_store'])
        if options is not None:
            service._native_edit_query = options['native_edit_query']
            service._native_candidate_import = options['native_candidate_import']
        return 0

    def _port_init_budget_none(self):
        self.data['self']._candidate_budget=None
        return 0

    def _port_init_ledger_none(self):
        self.data['self']._slot_ledger=None
        return 0

    def _port_init_budget_present(self):
        return 1 if self.data['candidate_budget_image'] is not None else 0

    def _port_init_budget_construct(self):
        d=self.data
        self.import_ports['init_budget_construct'](d['self'],d['NativeCandidateBudgetStore'],d['candidate_budget_image'])
        return 0

    def _port_init_budget_store_none(self):
        self.data['self']._candidate_budget=None
        return 0

    def _port_init_ledger_present(self):
        return 1 if self.data['slot_ledger_image'] is not None else 0

    def _port_init_ledger_construct(self):
        d=self.data
        self.import_ports['init_ledger_construct'](d['self'],d['NativeSlotLedgerStore'],d['slot_ledger_image'])
        return 0

    def _port_init_ledger_store_none(self):
        self.data['self']._slot_ledger=None
        return 0

    def _port_init_roots(self):
        d=self.data
        self.import_ports['init_roots'](d['self'],d['artifact_roots'],self._new_genexpr,GENERATOR_ROOTS)
        return 0

    def _port_init_roots_invalid(self):
        return self.import_ports['init_roots_invalid'](self.data['self'],self._new_genexpr,GENERATOR_DIRECTORIES)

    def _port_init_reject_roots(self):
        self.import_ports['init_reject_roots']()
        return 0

    def _port_init_profiles(self):
        self.import_ports['init_profiles'](self.data['self'])
        return 0

    def _port_init_return_none(self):
        self.result=None
        return 0

    def _port_init_release(self):
        self.data=self._retired_data
        return 0

    def _port_init_exception_match(self):
        return _exception_matches(_TYPE(_HANDLED()),self._global('BaseException'))

    def _port_init_bind_error(self):
        self.data['error']=_HANDLED()
        return 0

    def _port_init_cleanup_budget_present(self):
        return 1 if self.data['self']._candidate_budget is not None else 0

    def _port_init_cleanup_budget_bound(self):
        self.data['cleanups']=self.import_ports['init_cleanup_budget_bound'](self.data['self'])
        return 0

    def _port_init_cleanup_empty(self):
        self.data['cleanups']=[]
        return 0

    def _port_init_cleanup_list(self):
        d=self.data
        self.stack['cleanup_iterator']=self.import_ports['init_cleanup_list'](d['self'],d['cleanups'])
        return 0

    def _port_init_cleanup_next(self):
        try:
            self.data['cleanup']=_NEXT(self.stack['cleanup_iterator'])
        except _StopIteration:
            return 0
        return 1

    def _port_init_cleanup_call(self):
        self.data['cleanup']()
        return 0

    def _port_init_cleanup_failure_match(self):
        return _exception_matches(_TYPE(_HANDLED()),self._global('BaseException'))

    def _port_init_bind_failure(self):
        self.data['failure']=_HANDLED()
        return 0

    def _port_init_cleanup_note(self):
        d=self.data
        self.import_ports['init_cleanup_note'](d['error'],d['failure'])
        return 0

    def _port_init_clear_failure(self):
        return self._release_at('init_clear_failure',self.data['error'])

    def _port_init_cleanup_end(self):
        self.stack.pop('cleanup_iterator')
        return 0

    def _port_init_clear_error(self):
        return self._release_at('init_clear_error',self.data['error'])

    def _port_init_propagate(self):
        return 0

    def _port_init_abort_failure(self):
        return self._release_at('init_abort_failure',self.data['failure'])

    def _port_init_abort_error(self):
        return self._release_at('init_abort_error',self.data['error'] if self.data['error'] is not _UNBOUND else self._caller_handled)

    def _port_init_stack_unwind(self):
        return self._release_at('init_stack_unwind',self._caller_handled)

    def _port_close_budget_present(self):
        return 1 if self.data['self']._candidate_budget is not None else 0

    def _port_close_budget_call(self):
        self.import_ports['close_budget_call'](self.data['self'])
        return 0

    def _port_close_store(self):
        self.import_ports['close_store'](self.data['self'])
        return 0

    def _port_close_return_none(self):
        self.result=None
        return 0

    def _port_close_release(self):
        self.data=self._retired_data
        return 0

    def _port_close_store_exception(self):
        self.import_ports['close_store'](self.data['self'])
        return 0

    def _port_close_error_unwind(self):
        return self._release_at('close_error_unwind',self._caller_handled)

    def _port_close_propagate(self):
        return 0

    def _port_profiles_import_program(self):
        d=self.data
        d['TARGET'],d['PROFILE'],d['SUPPORTED_OPCODES'],d['CORE_SCHEMAS'],d['IMPORTS']=self.import_ports['profiles_import_program'](d['self'])
        return 0

    def _port_profiles_import_schema(self):
        d=self.data
        d['schema_registry']=self.import_ports['profiles_import_schema'](d['self'],d['TARGET'],d['PROFILE'],d['SUPPORTED_OPCODES'],d['CORE_SCHEMAS'],d['IMPORTS'])
        return 0

    def _port_profiles_import_safe(self):
        d=self.data
        d['ARTIFACT_PROFILE'],d['LIMITS']=self.import_ports['profiles_import_safe'](d['self'],d['TARGET'],d['PROFILE'],d['SUPPORTED_OPCODES'],d['CORE_SCHEMAS'],d['IMPORTS'],d['schema_registry'])
        return 0

    def _port_profiles_common(self):
        self.data['common']=self.import_ports['profiles_common'](self.data['self'])
        return 0

    def _port_profiles_bodies_open(self):
        d=self.data
        capsule=self.import_ports['profiles_bodies_expression'](d['self'],d['common'],d['TARGET'],d['PROFILE'],d['CORE_SCHEMAS'],d['SUPPORTED_OPCODES'],d['IMPORTS'],d['ARTIFACT_PROFILE'],d['LIMITS'])
        self.stack['bodies_capsule']=capsule
        self.stack['roots_input']=_capsule_start(capsule)
        return 0

    def _port_profiles_roots_begin(self):
        self.stack['roots_result']=[]
        self.stack['roots_iterator']=_ITER(self.stack.pop('roots_input'))
        return 0

    def _port_profiles_roots_next(self):
        try:
            self.data['root']=_NEXT(self.stack['roots_iterator'])
        except _StopIteration:
            return 0
        return 1

    def _port_profiles_roots_append(self):
        self.stack['roots_result'].append(self.import_ports['profiles_root_string'](self.data['root']))
        return 0

    def _port_profiles_roots_end(self):
        self.stack.pop('roots_iterator')
        self.data['root']=_UNBOUND
        return 0

    def _port_profiles_bodies_resume(self):
        self.data['bodies']=_capsule_finish(self.stack.pop('bodies_capsule'),self.stack.pop('roots_result'))
        return 0

    def _port_profiles_dicts(self):
        self.import_ports['profiles_dicts'](self.data['self'])
        return 0

    def _port_profiles_items_begin(self):
        self.stack['items_iterator']=_ITER(self.data['bodies'].items())
        return 0

    def _port_profiles_items_next(self):
        try:
            item=_NEXT(self.stack['items_iterator'])
        except _StopIteration:
            return 0
        try:
            self.data['name'],self.data['body']=item
        finally:
            item=None
        return 1

    def _port_profiles_profile(self):
        d=self.data
        d['ref'],d['artifact']=self.import_ports['profiles_profile'](d['self'],d['name'],d['body'])
        return 0

    def _port_profiles_assign(self):
        d=self.data
        self.import_ports['profiles_assign'](d['self'],d['name'],d['ref'],d['artifact'])
        return 0

    def _port_profiles_items_end(self):
        self.stack.pop('items_iterator')
        return 0

    def _port_profiles_resources(self):
        d=self.data
        self.import_ports['profiles_resources'](d['self'],d['schema_registry'])
        return 0

    def _port_profiles_docs_begin(self):
        self.stack['docs_iterator']=self.import_ports['profiles_docs_iter']()
        return 0

    def _port_profiles_docs_next(self):
        try:
            item=_NEXT(self.stack['docs_iterator'])
        except _StopIteration:
            return 0
        try:
            self.data['name'],self.data['filename']=item
        finally:
            item=None
        return 1

    def _port_profiles_doc_store(self):
        d=self.data
        self.import_ports['profiles_doc_store'](d['self'],d['name'],d['filename'])
        return 0

    def _port_profiles_docs_end(self):
        self.stack.pop('docs_iterator')
        return 0

    def _port_profiles_import_macro(self):
        d=self.data
        d['macro_policy_guidance']=self.import_ports['profiles_import_macro'](d['self'],d['TARGET'],d['PROFILE'],d['SUPPORTED_OPCODES'],d['CORE_SCHEMAS'],d['IMPORTS'],d['schema_registry'],d['ARTIFACT_PROFILE'],d['LIMITS'],d['common'],d['bodies'],d['name'],d['body'],d['ref'],d['artifact'],d['filename'])
        return 0

    def _port_profiles_macro(self):
        d=self.data
        self.import_ports['profiles_macro'](d['self'],d['macro_policy_guidance'])
        return 0

    def _port_profiles_examples(self):
        self.import_ports['profiles_examples'](self.data['self'])
        return 0

    def _port_profiles_diagnostics(self):
        self.import_ports['profiles_diagnostics'](self.data['self'])
        return 0

    def _port_profiles_manifest(self):
        self.import_ports['profiles_manifest'](self.data['self'])
        return 0

    def _port_profiles_return_none(self):
        self.result=None
        return 0

    def _port_profiles_release(self):
        self.data=self._retired_data
        return 0

    def _port_profiles_error_unwind(self):
        return self._release_at('profiles_error_unwind',self._caller_handled)

    def _port_profiles_propagate(self):
        return 0

    def _port_profile_result(self):
        d=self.data
        self.result=self.import_ports['profile_result'](d['self'],d['ref'],d['name'])
        return 0

    def _port_profile_release(self):
        self.data=self._retired_data
        return 0

    def _port_profile_error_unwind(self):
        return self._release_at('profile_error_unwind',self._caller_handled)

    def _port_profile_propagate(self):
        return 0

    def _port_program_get(self):
        d=self.data
        d['data'],d['_']=self.import_ports['program_get'](d['self'],d['ref'])
        return 0

    def _port_program_verify(self):
        service, data = self.data['self'], self.data['data']
        from .hia_agent_service import HIAAgentService

        if issubclass(type(service), HIAAgentService) and service._native_candidate_import is not None:
            self.result = service._admit_retained_program(data)
        else:
            self.result = self.import_ports['program_verify'](data)
        return 0

    def _port_program_release(self):
        self.data=self._retired_data
        return 0

    def _port_program_error_unwind(self):
        return self._release_at('program_error_unwind',self._caller_handled)

    def _port_program_propagate(self):
        return 0

    def _port_generator_next(self):
        try:
            self.data['root']=_NEXT(self.data['.0'])
        except _StopIteration:
            return 0
        return 1

    def _port_generator_root_value(self):
        self.result=self.import_ports['generator_root_value'](self.data['root'])
        return 0

    def _port_generator_dir_value(self):
        self.result=self.import_ports['generator_dir_value'](self.data['root'])
        return 0

    def _port_generator_yield(self):
        return 0

    def _port_generator_release(self):
        self.data=self._retired_data
        return 0

    def _port_generator_error_unwind(self):
        return self._release_at('generator_error_unwind',self._caller_handled)

    def _port_generator_propagate(self):
        return 0
