"""Complete HIA control of nine service proof workflows.

The selected graph owns decisions and ordering. Core admission, machine
emission, solver, filesystem and Store providers remain explicit host effects.
No retained complete workflow is invoked by a selected route. This static
candidate has not established object lifetime or complete input equivalence.
"""
from __future__ import annotations
import builtins
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
import sys
import types
from .hia_emission_native import _global_value
from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path, _unique_manifest_pairs
from .hia_native_delivery import DeliveryRecord
from .hia_store_lifecycle_native import _regular_bytes
from .hia_service_verification_protocol import (
    SELECTOR, SCHEMA, SOURCE_NAME, REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC,
    REQUEST_BYTES, OUTPUT_BYTES, STATE_BYTES, INITIALIZE, CLAIM, SUCCEEDED,
    RAISED, FINALIZE, RESUME_GENERATOR, THROW_GENERATOR, ISSUED, CLAIMED, RETURNED, PROPAGATE,
    READY_RETURN, READY_PROPAGATE, LEAVE_HANDLER, READY_YIELD, PAUSED, PORT, PORTS,
    MODE_RANGES, ERROR_PORTS, RELEASE_PORTS, YIELD_PORTS, PUBLIC_MODES,
    GENERATOR_MODES, GENERATOR_RESUME_PORTS, PRIVATE_LAYOUTS, PRIVATE_ARGUMENTS,
    COMPOUND_ITERATION_LOCALS, PRIVATE_ORIGINS,
    BEHAVIOR, SUBJECT, VERIFY, VERIFICATION, REPLAY, BINDING,
    REFINEMENT, CHECK, CLAIMS, ACYCLIC, FINISH, BLOCKS_COMP, INTERFACE_FN,
    INTERFACE_FIELDS, DOMAINS_COMP, OBSERVABLES_FN, CLAIM_SET, ACTUAL_COMP,
    CLAIM_LIST, SYMBOLS_COMP, VIOLATION_SET, GEN_LENGTHS, GEN_OPERATIONS,
    GEN_BITS, GEN_CLAIMS, GEN_ACYCLIC)
from .hia_service_lease_native import (
    _context_lookup_order, _lease_context_special as _context_special,
    _handled_state_setter)

SOURCE = _source_resource_path(SOURCE_NAME)
_REQUEST_REJECTIONS = (ValueError, TypeError, OSError, OverflowError,
                       RecursionError, sqlite3.Error)
_UNBOUND = object()
# These three private ABI classes are module-owned, not per-frame collectable
# ctypes type cycles. The real allocation and all guards remain unchanged.
_REQUEST_BUFFER_TYPE = ctypes.c_char * (REQUEST_BYTES + 16)
_OUTPUT_BUFFER_TYPE = ctypes.c_char * (OUTPUT_BYTES + 16)
_STATE_BUFFER_TYPE = ctypes.c_char * (STATE_BYTES + 16)

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


class ServiceVerificationUnknown(RuntimeError):
    """The actual selected invocation has an unconfirmed delivery."""


class NativeServiceVerification(NativeHiaJsonImage):
    pass


@lru_cache(maxsize=3)
def _mapped_verification(raw, digest, source_digest):
    image = NativeServiceVerification(raw, digest)
    image.admitted_source_sha256 = source_digest
    return image


def installed_service_verification(manifest_path):
    if not manifest_path:
        raise ValueError('native service verification selector must not be empty')
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeServiceVerification)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_unique_manifest_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid native service verification manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or Path(name).name != name or any(ord(char) < 32 for char in name)):
        raise ValueError('native verification image must be a sibling basename')
    source = _regular_bytes(SOURCE, 8 << 20)
    image_path = path.parent / name
    image_bytes = _regular_bytes(image_path, 1 << 20)
    if sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('native service verification source identity mismatch')
    if sha256(image_bytes).hexdigest() != value['image_sha256']:
        raise ValueError('native service verification image identity mismatch')
    if selected is None:
        selected = _mapped_verification(image_bytes, value['image_sha256'], value['source_sha256'])
    elif type(selected) is not NativeServiceVerification or selected.image_sha256 != value['image_sha256']:
        raise ValueError('native verification differs from the pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source
            or _regular_bytes(image_path, 1 << 20) != image_bytes):
        raise ValueError('native service verification selection changed during admission')
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


@dataclass(frozen=True)
class ServiceVerificationReceipt:
    port: int
    sequence: int
    phase: int
    failed: int



_BaseException = BaseException
_StopIteration = StopIteration
_IMPLICIT_ITER = iter
_IMPLICIT_NEXT = next
_HANDLED_EXCEPTION = sys.exception
_EMPTY_SET = set
_CELL_TYPE = types.CellType

PUBLIC_ARGUMENTS = (("self","original","revised","timeout_ms"),("self","args","program"),("self","args"),("self","ref","context","candidate"),("self","response","arguments"),("subject","built","program","object_bytes","final_bytes"),("self","args","program","context"),("self","evidence","subject","context","program"),("self","context","candidate_artifact","refs","baseline_core_sha"))
_PRIVATE_NAMES = PRIVATE_LAYOUTS
_IMPORT_ARGUMENTS = {
    'behavior_optimization': PUBLIC_ARGUMENTS[0],
    'behavior_widths': PUBLIC_ARGUMENTS[0],
    'subject_layout': PUBLIC_ARGUMENTS[1],
    'verify_emitter': PUBLIC_ARGUMENTS[2],
    'verify_checks': PUBLIC_ARGUMENTS[2],
    'refinement_safe': PUBLIC_ARGUMENTS[6],
    'check_elf': PUBLIC_ARGUMENTS[7],
}



def _unbound_local_template():
    marker: object
    return marker


def _unbound_free_template():
    marker = None
    def read():
        return marker
    del marker
    return read


# These private code objects contain only the runtime's actual unbound load.
# Renaming one slot retains CPython's own exception class/message/name behavior,
# including its runtime-version wording. They never execute a business body.
_UNBOUND_LOCAL_CODE = _unbound_local_template.__code__
_UNBOUND_FREE_CODE = _unbound_free_template().__code__
_UNBOUND_GLOBALS = {'__builtins__': vars(builtins)}


def _read_unbound_local(name):
    code = _UNBOUND_LOCAL_CODE.replace(co_varnames=(name,))
    return types.FunctionType(code, _UNBOUND_GLOBALS)()


def _read_empty_free_cell(name, cell):
    code = _UNBOUND_FREE_CODE.replace(co_freevars=(name,))
    return types.FunctionType(code, _UNBOUND_GLOBALS, closure=(cell,))()


class _LocalStorage(dict):
    """Original local slots; escaped callbacks share only actual closure cells."""
    __slots__ = ('cell_names',)

    def __init__(self, names, cell_names):
        self.cell_names = cell_names
        for name in names:
            dict.__setitem__(self, name, _CELL_TYPE() if name in cell_names else _UNBOUND)

    def __getitem__(self, name):
        value = dict.__getitem__(self, name)
        if name in self.cell_names:
            try:
                return value.cell_contents
            except ValueError:
                pass
            # End the mechanical cell_contents handler before the original
            # local-load exception so its implicit context remains the caller.
            return _read_unbound_local(name)
        if value is _UNBOUND:
            return _read_unbound_local(name)
        return value

    def __setitem__(self, name, value):
        if name in self.cell_names:
            dict.__getitem__(self, name).cell_contents = value
        else:
            dict.__setitem__(self, name, value)

    def capture(self, names):
        cells = {}
        for name in names:
            if name in self.cell_names:
                cells[name] = dict.__getitem__(self, name)
            else:
                # Inline comprehensions use ordinary fast locals on supported
                # runtimes. Their immediate private invocation gets the value,
                # not a strong alias of the containing method's complete locals.
                value = dict.__getitem__(self, name)
                cells[name] = _CELL_TYPE() if value is _UNBOUND else _CELL_TYPE(value)
        return _CapturedCells(cells)


class _CapturedCells:
    __slots__ = ('cells',)
    def __init__(self, cells):
        self.cells = cells
    def __getitem__(self, name):
        cell = self.cells[name]
        try:
            return cell.cell_contents
        except ValueError:
            pass
        return _read_empty_free_cell(name, cell)
    def subset(self, *names):
        return _CapturedCells({name: self.cells[name] for name in names})


def _verification_generator(image, mode, iterator, cells, namespace, captured, imports):
    # Python supplies actual generator entry/send/throw/close/gi_running and
    # PEP479. Iteration, predicates, values and stopping are HIA-owned. The
    # outermost GET_ITER has already happened at the original expression site.
    bound = {'.0': iterator}
    if cells is not None:
        bound['cells'] = cells
    frame = ServiceVerificationFrame(image, mode, bound, namespace=namespace,
        global_builtins=captured, import_capsules=imports)
    del bound, iterator, cells, image, mode, namespace, captured, imports
    while frame.advance_generator():
        try:
            yield frame.__dict__.pop('result')
        except _BaseException:
            frame.throw_generator()
            raise


class ServiceVerificationFrame:
    def __init__(self, image, mode, bound, *, namespace=None, global_builtins=None,
                 local_names=None, import_capsules=None):
        if type(image) is not NativeServiceVerification:
            raise TypeError('verification requires its admitted image')
        if type(mode) is not int or mode not in MODE_RANGES or type(bound) is not dict:
            raise ValueError('verification mode or mechanical argument binding is invalid')
        from . import hia_agent_service
        canonical_imports = hia_agent_service._SERVICE_VERIFICATION_IMPORTS
        public_mode = PRIVATE_ORIGINS.get(mode, mode)
        if namespace is None:
            namespace = hia_agent_service._SERVICE_VERIFICATION_NAMESPACE
            global_builtins = hia_agent_service._SERVICE_VERIFICATION_GLOBAL_BUILTINS[public_mode]
            if import_capsules is None:
                import_capsules = canonical_imports
        elif global_builtins is None:
            global_builtins = namespace.get('__builtins__', vars(builtins))
        if type(namespace) is not dict:
            raise TypeError('verification namespace must be an actual globals dictionary')
        if type(global_builtins) is types.ModuleType:
            global_builtins = vars(global_builtins)
        if import_capsules is None:
            import_capsules = {name: types.FunctionType(function.__code__, namespace, function.__name__)
                               for name, function in canonical_imports.items()}
        for name, canonical in canonical_imports.items():
            capsule = import_capsules[name]
            if (type(capsule) is not types.FunctionType or capsule.__code__ is not canonical.__code__
                    or capsule.__globals__ is not namespace
                    or capsule.__builtins__ is not global_builtins):
                raise ValueError('verification import capsule differs from its actual namespace')
        if local_names is None:
            local_names = (_PRIVATE_NAMES[mode] if mode not in PUBLIC_MODES
                           else hia_agent_service._SERVICE_VERIFICATION_LOCAL_NAMES[mode])
        names = tuple(local_names)
        required = PRIVATE_ARGUMENTS[mode] if mode not in PUBLIC_MODES else PUBLIC_ARGUMENTS[mode - 1]
        if set(bound) != set(required) or any(name not in names for name in required):
            raise TypeError('verification arguments do not match the complete method')
        self.image, self.mode = image, mode
        self.namespace, self.global_builtins = namespace, global_builtins
        self.import_capsules = import_capsules
        self._retired_data = {}
        cell_names = (hia_agent_service._SERVICE_VERIFICATION_CELL_NAMES[mode]
                      if mode in PUBLIC_MODES else frozenset())
        self.data = _LocalStorage(names[::-1] if _storage_is_reversed() else names, cell_names)
        for name, value in bound.items():
            self.data[name] = value
        self.stack = {}
        self._set_handled = _handled_state_setter()
        self._caller_handled = None
        self.result = None
        self.exception = None
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.buffer = ctypes.create_string_buffer(STATE_BYTES + 16)
        ctypes.memmove(ctypes.addressof(self.buffer) + STATE_BYTES, b'\xb7' * 16, 16)
        self.receipt = None
        self.fenced = self.finished = self.native_failed = self._entered = False
        self._pending_foreign = self._whole = None
        self._foreign_started = self._effect_started = False
        self._native_source = self._native_output = None
        self._delivery = DeliveryRecord(self)
        try:
            self.call(INITIALIZE)
        except _BaseException:
            self._delivery.retire()
            raise

    def _global(self, name):
        return _global_value(self.namespace, self.global_builtins, name)

    def _import(self, name, values):
        # The capsule contains the original IMPORT_NAME/IMPORT_FROM opcodes,
        # runs in the captured original globals and uses that frame's builtins.
        return self.import_capsules[name](*(values[key] for key in _IMPORT_ARGUMENTS[name]))

    def _matches(self, error, target):
        if _HANDLED_EXCEPTION() is not error:
            raise ServiceVerificationUnknown('exception matching lost its active handler')
        # Bare raise preserves the actual active exception and does not fabricate
        # a new error or assign a traceback. CPython performs its own original
        # dynamic except-type validation, including an invalid target's TypeError.
        try:
            raise
        except target:
            return True
        except _BaseException:
            return False

    def _capture(self, *names):
        return self.data.capture(names)

    def _compound(self, mode, bound):
        frame = ServiceVerificationFrame(self.image, mode, bound,
            namespace=self.namespace, global_builtins=self.global_builtins,
            import_capsules=self.import_capsules)
        del bound
        return frame.finish()

    def _new_generator(self, mode, iterator, cells=None):
        return _verification_generator(self.image, mode, iterator, cells,
            self.namespace, self.global_builtins, self.import_capsules)

    def _make_acyclic(self):
        image, namespace, captured = self.image, self.namespace, self.global_builtins
        imports, cells = self.import_capsules, self._capture('blocks', 'visiting', 'done', 'acyclic')
        def acyclic(name):
            frame = ServiceVerificationFrame(image, ACYCLIC, {'name': name, 'cells': cells},
                namespace=namespace, global_builtins=captured, import_capsules=imports)
            del name
            return frame.finish()
        return acyclic

    def _make_finish(self, evidence):
        image, namespace, captured = self.image, self.namespace, self.global_builtins
        imports = self.import_capsules
        def finish(status, reason=None):
            frame = ServiceVerificationFrame(image, FINISH,
                {'status': status, 'reason': reason, 'evidence': evidence},
                namespace=namespace, global_builtins=captured, import_capsules=imports)
            del status, reason
            return frame.finish()
        return finish

    def _make_interface(self):
        image, namespace, captured, imports = (
            self.image, self.namespace, self.global_builtins, self.import_capsules)
        def interface(d):
            frame = ServiceVerificationFrame(image, INTERFACE_FN, {'d': d},
                namespace=namespace, global_builtins=captured, import_capsules=imports)
            del d
            return frame.finish()
        return interface

    def _make_observables(self):
        image, namespace, captured, imports = (
            self.image, self.namespace, self.global_builtins, self.import_capsules)
        def observables(row):
            frame = ServiceVerificationFrame(image, OBSERVABLES_FN, {'row': row},
                namespace=namespace, global_builtins=captured, import_capsules=imports)
            del row
            return frame.finish()
        return observables

    def _release_compound_iteration(self):
        for name in COMPOUND_ITERATION_LOCALS[self.mode]:
            self.data[name] = _UNBOUND

    def _release_compound_error(self):
        self._release_compound_iteration()
        self._release_exception_stack()

    def _release_handler_local(self, name):
        # The original DELETE_FAST/STORE_FAST-None after an except-as binding.
        # This port is explicitly issued by HIA, never selected from error type.
        if name in self.data:
            self.data[name] = _UNBOUND

    def _release_loop_stack_before_exit(self):
        if (self.mode != REFINEMENT or self.receipt is None
                or self.receipt.phase != CLAIMED
                or self.receipt.port != PORT['refinement_cm_error_prepare']):
            raise ServiceVerificationUnknown('loop stack release was not issued')
        handled_state, set_handled = _HANDLED_EXCEPTION, self._set_handled
        caller = self._caller_handled
        pending = handled_state()
        caller_pointer = None if caller is None else id(caller)
        pending_pointer = None if pending is None else id(pending)
        try:
            # The original for-stack is unwound before the with handler makes
            # the raised exception active. Retire only this issued iterator at
            # the caller's handled state; __exit__ and ACK remain outside here.
            set_handled(caller_pointer)
            if handled_state() is not caller:
                raise ServiceVerificationUnknown('caller handled-state installation failed')
            self.stack.pop('path_iterator', None)
        finally:
            try:
                set_handled(pending_pointer)
                if handled_state() is not pending:
                    raise ServiceVerificationUnknown('pending handled-state restoration failed')
            finally:
                caller = pending = None

    def _release_normal_stack(self):
        while self.stack:
            self.stack.popitem()

    def _release_exception_stack(self):
        if (self.receipt is None or self.receipt.phase != CLAIMED
                or self.receipt.port not in ERROR_PORTS):
            raise ServiceVerificationUnknown('exception stack release was not issued')
        handled_state, set_handled = _HANDLED_EXCEPTION, self._set_handled
        caller = self._caller_handled
        pending = handled_state()
        caller_pointer = None if caller is None else id(caller)
        pending_pointer = None if pending is None else id(pending)
        try:
            # Original frame/with stack unwinding runs at the caller's handled
            # state. Only already-issued mechanical decrefs occur in this ABI
            # window. No provider effect, branch or native ACK is hidden here.
            set_handled(caller_pointer)
            if handled_state() is not caller:
                raise ServiceVerificationUnknown('caller handled-state installation failed')
            self.stack.pop('manager', None)
            while self.stack:
                self.stack.popitem()
            self._release_handler_local('exc')
            self.result = None
        finally:
            try:
                set_handled(pending_pointer)
                if handled_state() is not pending:
                    raise ServiceVerificationUnknown('pending handled-state restoration failed')
            finally:
                caller = pending = None

    def _check(self):
        record = self._delivery
        record.check(ServiceVerificationUnknown)
        whole = self._whole
        if whole is not None:
            whole.pending_resources.check_borrowed_resources()
        # The identity query/GC can itself run a real child.
        record.check(ServiceVerificationUnknown)


    def call(self, event, observation=0):
        record = self._delivery
        if self.fenced or self.finished or not record.current():
            raise ServiceVerificationUnknown('service verification has no current invocation')
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
                raise ServiceVerificationUnknown('service verification return is unconfirmed')
            words = struct.unpack('<12Q', output.raw[:OUTPUT_BYTES])
            state = struct.unpack('<24Q', self.buffer.raw[:STATE_BYTES])
            expected_sequence = 1 if event == INITIALIZE else sequence if event == CLAIM else sequence + 1
            expected_phases = {
                INITIALIZE:(ISSUED,), CLAIM:(CLAIMED,),
                SUCCEEDED:(ISSUED, READY_RETURN, READY_PROPAGATE, LEAVE_HANDLER, READY_YIELD),
                RAISED:(ISSUED, READY_PROPAGATE),
                FINALIZE:(RETURNED, PROPAGATE, PAUSED),
                RESUME_GENERATOR:(ISSUED,), THROW_GENERATOR:(ISSUED,),
            }[event]
            failed = (int(words[2] in ERROR_PORTS) if words[4] in (ISSUED, CLAIMED, LEAVE_HANDLER)
                      else int(words[4] in (READY_PROPAGATE, PROPAGATE)))
            low, high = MODE_RANGES[self.mode]
            active = words[4] in (ISSUED, CLAIMED, LEAVE_HANDLER)
            if (words[0] != RESULT_MAGIC or words[1] != 0
                    or words[2:7] != (state[3], state[4], state[5], state[2], state[12])
                    or state[:3] != (STATE_MAGIC, 1, self.mode)
                    or words[8:10] != self.identity or state[6:8] != self.identity
                    or words[7] != 0 or words[10:12] != (0, 0)
                    or state[8:10] != (0, 0) or state[11] != 0
                    or state[13:] != (0,) * 11 or state[10] != _checksum(state)
                    or words[3] != expected_sequence or words[4] not in expected_phases
                    or words[6] != failed
                    or (active and not low <= words[2] <= high)
                    or (active and int(words[2] in ERROR_PORTS) != failed)
                    or (not active and words[2] != 0)
                    or (words[4] in (RETURNED, READY_RETURN, READY_YIELD, PAUSED) and
                        (failed != 0 or state[8] != 0 or state[9] != 0))
                    or (words[4] in (PROPAGATE, READY_PROPAGATE) and failed != 1)
                    or (words[4] == LEAVE_HANDLER and failed != 0)
                    or (event == INITIALIZE and words[2] != low)
                    or (event == CLAIM and (words[2] != port or words[6] != old_failed))
                    or (words[4] in (READY_YIELD, PAUSED) and self.mode not in GENERATOR_MODES)
                    or (event in (RESUME_GENERATOR, THROW_GENERATOR) and
                        (previous.phase != PAUSED or self.mode not in GENERATOR_MODES))
                    or (event == RESUME_GENERATOR and words[2] != GENERATOR_RESUME_PORTS[self.mode])
                    or (event == THROW_GENERATOR and words[2] != high)
                    or (event == FINALIZE and (
                        previous.phase not in (READY_RETURN, READY_PROPAGATE, READY_YIELD)
                        or words[4] != {READY_RETURN: RETURNED, READY_PROPAGATE: PROPAGATE, READY_YIELD: PAUSED}[previous.phase]))):
                raise ServiceVerificationUnknown('service verification receipt differs from complete state')
            receipt = ServiceVerificationReceipt(words[2], words[3], words[4], words[6])
            pending = None
            if event in (SUCCEEDED, RAISED):
                pending = self._pending_foreign
            elif event == FINALIZE:
                pending = self._whole
            if event in (SUCCEEDED, RAISED, FINALIZE):
                if pending is None:
                    raise ServiceVerificationUnknown('verification has no matching foreign activation')
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
                raise ServiceVerificationUnknown('service verification native delivery failed') from error
            raise



    def _owned_segment(self):
        self._caller_handled = _HANDLED_EXCEPTION()
        self._check()
        whole = self._delivery.foreign(capture_resources=True, weak_registered_resources=True)
        self._whole = whole
        with self._delivery.foreign(observation=False):
            try:
                with whole:
                    observed = self._drive()
                    if (self.receipt.phase != CLAIMED
                            or self.receipt.port not in RELEASE_PORTS | YIELD_PORTS):
                        raise ServiceVerificationUnknown('verification suspension has no live claim')
                    self.call(SUCCEEDED, observed)
                    if self.receipt.phase not in (READY_RETURN, READY_YIELD):
                        raise ServiceVerificationUnknown('verification has no return or yield directive')
            except _BaseException as error:
                if (not self._foreign_started and self._delivery.loss is None
                        and not self._delivery.native_pending):
                    self._delivery.foreign_refused()
                if (not self.native_failed and self._delivery.loss is None
                        and self.receipt.phase == READY_PROPAGATE):
                    self._finalize()
                    raise
                whole.failed(error)
                raise
            self._finalize()
            return self.receipt.phase

    def _segment_failed(self, error):
        record = self._delivery
        record.failed(error)
        if self._pending_foreign is not None:
            self._pending_foreign.failed(error)
        if self._whole is not None:
            self._whole.failed(error)
        if record.loss is not None:
            self.fenced = self.native_failed = True
            record.propagate(error, ServiceVerificationUnknown, _REQUEST_REJECTIONS)

    def finish(self):
        if self.mode in GENERATOR_MODES or self._entered or self.finished or self.fenced:
            raise ServiceVerificationUnknown('verification frame cannot be reused')
        if not self._delivery.current():
            raise ServiceVerificationUnknown('verification frame cannot be transferred')
        self._entered = True
        try:
            if self._owned_segment() != RETURNED:
                raise ServiceVerificationUnknown('ordinary verification did not return')
            return self.__dict__.pop('result')
        except _BaseException as error:
            self._segment_failed(error)
            raise
        finally:
            try:
                self._delivery.retire()
            finally:
                self._caller_handled = None

    def _begin_generator_segment(self, event):
        if (self.mode not in GENERATOR_MODES or self._entered
                or self.finished or self.fenced or self.native_failed):
            raise ServiceVerificationUnknown('verification generator is not resumable')
        # A suspended raw generator has no pending native record. A legitimate
        # new advance may occur on another thread/Context; it gets actual current
        # custody, not an inherited or fabricated ancestry from the old segment.
        if self._delivery is None:
            self._delivery = DeliveryRecord(self)
            self._whole = self._pending_foreign = None
            self._foreign_started = self._effect_started = False
            try:
                self.call(event)
            except _BaseException:
                self._delivery.retire()
                self._delivery = None
                raise
        elif event != RESUME_GENERATOR or self.receipt.phase != ISSUED:
            raise ServiceVerificationUnknown('verification generator segment is already active')
        self._entered = True

    def _retire_generator_segment(self):
        try:
            self._delivery.retire()
        finally:
            self._delivery = None
            self._whole = self._pending_foreign = None
            self._caller_handled = None
            self._entered = False

    def advance_generator(self):
        self._begin_generator_segment(RESUME_GENERATOR)
        try:
            return self._owned_segment() == PAUSED
        except _BaseException as error:
            self._segment_failed(error)
            raise
        finally:
            self._retire_generator_segment()

    def throw_generator(self):
        self._begin_generator_segment(THROW_GENERATOR)
        try:
            self._owned_segment()
            raise ServiceVerificationUnknown('generator throw unexpectedly returned')
        except _BaseException as error:
            self._segment_failed(error)
            raise
        finally:
            self._retire_generator_segment()

    def _effect_once(self):
        self._effect_started = False
        if self.receipt.phase not in (ISSUED, LEAVE_HANDLER):
            raise ServiceVerificationUnknown('verification effect is not newly issued')
        self.call(CLAIM)
        activation = self._delivery.foreign(capture_resources=True, weak_registered_resources=True)
        self._pending_foreign = activation
        with activation:
            self._check()
            self._foreign_started = self._effect_started = True
            return self.effect(self.receipt.port)

    def _finalize(self):
        previous = self.receipt.phase
        if previous not in (READY_RETURN, READY_PROPAGATE, READY_YIELD):
            raise ServiceVerificationUnknown('verification has no completion directive')
        self.call(FINALIZE)
        wanted = {READY_RETURN: RETURNED, READY_PROPAGATE: PROPAGATE, READY_YIELD: PAUSED}[previous]
        if self.receipt.phase != wanted:
            raise ServiceVerificationUnknown('verification final receipt is unconfirmed')
        self.finished = wanted != PAUSED
        if wanted == PROPAGATE:
            self.data = self._retired_data
            self.exception = None

    def _foreign_raised(self, error):
        if self.fenced or self.native_failed or self._delivery.loss is not None:
            self._delivery.propagate(error, ServiceVerificationUnknown, _REQUEST_REJECTIONS)
            raise
        if not self._effect_started:
            raise
        self.exception = sys.exc_info()
        self.call(RAISED)

    def _exception_continuation(self):
        while self.receipt.phase == ISSUED:
            try:
                observed = self._effect_once()
            except _BaseException as error:
                self._foreign_raised(error)
                if self.receipt.phase == READY_PROPAGATE:
                    raise
                self._exception_continuation()
                return
            self.call(SUCCEEDED, observed)
        if self.receipt.phase == LEAVE_HANDLER:
            return
        if self.receipt.phase == READY_PROPAGATE:
            raise
        raise ServiceVerificationUnknown('verification has no exception continuation')

    def _drive(self):
        original_locals = self.data
        if (self.receipt.phase == ISSUED and self.receipt.port in ERROR_PORTS
                and self.mode in GENERATOR_MODES):
            # THROW_GENERATOR is acknowledged under the actual raw generator's
            # except handler. No exception object is synthesized from wire data.
            self._exception_continuation()
            raise ServiceVerificationUnknown('generator throw was not propagated')
        while True:
            try:
                observed = self._effect_once()
            except _BaseException as error:
                self._foreign_raised(error)
                if self.receipt.phase == READY_PROPAGATE:
                    raise
                self._exception_continuation()
            else:
                if self.receipt.port in RELEASE_PORTS | YIELD_PORTS:
                    return observed
                self.call(SUCCEEDED, observed)
            if self.receipt.phase == LEAVE_HANDLER:
                # End the real handler before evaluating the next ordinary
                # expression. Its active exception is not approximated by bytes.
                self.exception = None
                continue
            if self.receipt.phase != ISSUED:
                raise ServiceVerificationUnknown('verification left its issued continuation')

    def effect(self, port):
        low, high = MODE_RANGES[self.mode]
        if (self.receipt is None or self.receipt.phase != CLAIMED
                or self.receipt.port != port or not low <= port <= high):
            raise ServiceVerificationUnknown('verification has no matching effect claim')
        return getattr(self, '_port_' + PORTS[port - 1])()

    def _port_behavior_import_optimization(self):
        d = self.data
        g = self._global
        d['PURE'], d['DEFAULT_POLICY'], d['verify_optimization'] = self._import('behavior_optimization', d)
        return 0

    def _port_behavior_import_widths(self):
        d = self.data
        g = self._global
        d['WIDTHS'], d['integer_range'] = self._import('behavior_widths', d)
        return 0

    def _port_behavior_deadline_empty(self):
        d = self.data
        g = self._global
        return 1 if (d['timeout_ms'] <= 0) else 0

    def _port_behavior_budget_result(self):
        d = self.data
        g = self._global
        self.result = ('unknown', 'Verification cannot exceed the frozen context deadline', {'method': 'context_budget_exhausted', 'reason': 'context wall budget exhausted'})
        return 0

    def _port_behavior_canonical(self):
        d = self.data
        g = self._global
        return 1 if (d['original'].canonical_bytes == d['revised'].canonical_bytes) else 0

    def _port_behavior_identity_result(self):
        d = self.data
        g = self._global
        self.result = ('proved', 'Reflexivity for the exact admitted canonical Core bytes, including resources and traps',
            {'method': 'canonical_core_identity', 'base_sha256': d['original'].sha256, 'candidate_sha256': d['revised'].sha256, 'all_inputs': True})
        return 0

    def _port_behavior_documents(self):
        d = self.data
        g = self._global
        d['left'], d['right'] = d['original'].as_dict(), d['revised'].as_dict()
        return 0

    def _port_behavior_signatures(self):
        d = self.data
        g = self._global
        d['signatures'] = g('_signatures')(d['original'])
        return 0

    def _port_behavior_initial_finite(self):
        d = self.data
        g = self._global
        d['finite'] = d['signatures'] == g('_signatures')(d['revised']) and g('bool')(d['signatures'])
        return 0

    def _port_behavior_documents_iter(self):
        d = self.data
        g = self._global
        self.stack['document_iterator'] = _IMPLICIT_ITER((d['left'], d['right']))
        return 0

    def _port_behavior_documents_next(self):
        d = self.data
        g = self._global
        try:
            d['document'] = _IMPLICIT_NEXT(self.stack["document_iterator"])
        except _StopIteration:
            return 0
        return 1

    def _port_behavior_functions_iter(self):
        d = self.data
        g = self._global
        self.stack['function_iterator'] = _IMPLICIT_ITER(d['document']['functions'])
        return 0

    def _port_behavior_functions_next(self):
        d = self.data
        g = self._global
        try:
            d['fn'] = _IMPLICIT_NEXT(self.stack["function_iterator"])
        except _StopIteration:
            return 0
        return 1

    def _port_behavior_size(self):
        d = self.data
        g = self._global
        return 1 if (g('len')(d['fn']['blocks']) > 128 or g('sum')(self._new_generator(GEN_LENGTHS, _IMPLICIT_ITER(d['fn']['blocks']))) > 4096) else 0

    def _port_behavior_size_false(self):
        d = self.data
        g = self._global
        d['finite'] = False
        return 0

    def _port_behavior_effects(self):
        d = self.data
        g = self._global
        return 1 if (g('set')(d['fn']['effects']) - {'trap'} or g('any')(self._new_generator(GEN_OPERATIONS, _IMPLICIT_ITER(d['fn']['blocks']), self._capture('PURE')))) else 0

    def _port_behavior_effects_false(self):
        d = self.data
        g = self._global
        d['finite'] = False
        return 0

    def _port_behavior_blocks(self):
        d = self.data
        g = self._global
        d['blocks'] = self._compound(BLOCKS_COMP, {'.0': _IMPLICIT_ITER(d['fn']['blocks'])})
        return 0

    def _port_behavior_sets(self):
        d = self.data
        g = self._global
        d['visiting'], d['done'] = g('set')(), g('set')()
        return 0

    def _port_behavior_acyclic_define(self):
        d = self.data
        g = self._global
        d['acyclic'] = self._make_acyclic()
        return 0

    def _port_behavior_acyclic(self):
        d = self.data
        g = self._global
        return 1 if (not d['acyclic'](d['fn']['entry'])) else 0

    def _port_behavior_cycle_false(self):
        d = self.data
        g = self._global
        d['finite'] = False
        return 0

    def _port_behavior_functions_release(self):
        d = self.data
        g = self._global
        self.stack.pop('function_iterator')
        return 0

    def _port_behavior_documents_release(self):
        d = self.data
        g = self._global
        self.stack.pop('document_iterator')
        return 0

    def _port_behavior_interface_define(self):
        d = self.data
        g = self._global
        d['interface'] = self._make_interface()
        return 0

    def _port_behavior_interface(self):
        d = self.data
        g = self._global
        return 1 if (d['interface'](d['left']) != d['interface'](d['right'])) else 0

    def _port_behavior_interface_false(self):
        d = self.data
        g = self._global
        d['finite'] = False
        return 0

    def _port_behavior_domains(self):
        d = self.data
        g = self._global
        d['domains'], d['total'] = {}, 0
        return 0

    def _port_behavior_domain_gate(self):
        d = self.data
        g = self._global
        return 1 if (d['finite']) else 0

    def _port_behavior_signature_iter(self):
        d = self.data
        g = self._global
        self.stack['signature_iterator'] = _IMPLICIT_ITER(d['signatures'].items())
        return 0

    def _port_behavior_signature_next(self):
        d = self.data
        g = self._global
        try:
            value = _IMPLICIT_NEXT(self.stack["signature_iterator"])
        except _StopIteration:
            return 0
        try:
            (d['name'], d['signature']) = value
        finally:
            value = None
        return 1

    def _port_behavior_bits(self):
        d = self.data
        g = self._global
        d['bits'] = g('sum')(self._new_generator(GEN_BITS, _IMPLICIT_ITER(d['signature']['params']), self._capture('WIDTHS')))
        return 0

    def _port_behavior_domain_too_large(self):
        d = self.data
        g = self._global
        return 1 if (d['bits'] > 12 or d['total'] + (1 << d['bits']) > 4096) else 0

    def _port_behavior_domains_false(self):
        d = self.data
        g = self._global
        d['finite'] = False
        return 0

    def _port_behavior_domain_values(self):
        d = self.data
        g = self._global
        d['domains'][d['name']] = self._compound(DOMAINS_COMP, {'.0': _IMPLICIT_ITER(d['signature']['params']), 'cells': self._capture('integer_range')})
        return 0

    def _port_behavior_domain_total(self):
        d = self.data
        g = self._global
        d['total'] += 1 << d['bits']
        return 0

    def _port_behavior_signature_release(self):
        d = self.data
        g = self._global
        self.stack.pop('signature_iterator')
        return 0

    def _port_behavior_enumeration_gate(self):
        d = self.data
        g = self._global
        return 1 if (d['finite']) else 0

    def _port_behavior_transcript(self):
        d = self.data
        g = self._global
        d['transcript'] = g('sha256')()
        return 0

    def _port_behavior_checked(self):
        d = self.data
        g = self._global
        d['checked'] = 0
        return 0

    def _port_behavior_deadline(self):
        d = self.data
        g = self._global
        d['deadline'] = g('time').monotonic_ns() + g('min')(10000, d['timeout_ms']) * 1_000_000
        return 0

    def _port_behavior_domain_iter(self):
        d = self.data
        g = self._global
        self.stack['domain_iterator'] = _IMPLICIT_ITER(d['domains'].items())
        return 0

    def _port_behavior_domain_next(self):
        d = self.data
        g = self._global
        try:
            value = _IMPLICIT_NEXT(self.stack["domain_iterator"])
        except _StopIteration:
            return 0
        try:
            (d['name'], d['input_domains']) = value
        finally:
            value = None
        return 1

    def _port_behavior_arguments_iter(self):
        d = self.data
        g = self._global
        self.stack['arguments_iterator'] = _IMPLICIT_ITER(g('itertools').product(*d['input_domains']))
        return 0

    def _port_behavior_arguments_next(self):
        d = self.data
        g = self._global
        try:
            d['arguments'] = _IMPLICIT_NEXT(self.stack["arguments_iterator"])
        except _StopIteration:
            return 0
        return 1

    def _port_behavior_iteration_deadline(self):
        d = self.data
        g = self._global
        return 1 if (g('time').monotonic_ns() > d['deadline']) else 0

    def _port_behavior_deadline_result(self):
        d = self.data
        g = self._global
        self.result = ('unknown', 'Pure acyclic scalar finite domain; exhaustive enumeration deadline expired', {'method': 'finite_domain', 'checked': d['checked'], 'required': d['total'], 'complete': False})
        return 0

    def _port_behavior_case(self):
        d = self.data
        g = self._global
        d['case'] = {'function': d['name'], 'arguments': g('list')(d['arguments'])}
        return 0

    def _port_behavior_before(self):
        d = self.data
        g = self._global
        d['before'] = g('_vm_observation')(d['original'], d['case'], steps=10000)
        return 0

    def _port_behavior_after(self):
        d = self.data
        g = self._global
        d['after'] = g('_vm_observation')(d['revised'], d['case'], steps=10000)
        return 0

    def _port_behavior_reference_budget(self):
        d = self.data
        g = self._global
        return 1 if ('budget_exceeded' in {d['before']['status'], d['after']['status']}) else 0

    def _port_behavior_budget_incomplete(self):
        d = self.data
        g = self._global
        self.result = ('unknown', 'Pure acyclic scalar finite domain; reference budget prevented completeness', {'method': 'finite_domain', 'checked': d['checked'], 'required': d['total'], 'complete': False})
        return 0

    def _port_behavior_observables_define(self):
        d = self.data
        g = self._global
        d['observables'] = self._make_observables()
        return 0

    def _port_behavior_observables(self):
        d = self.data
        g = self._global
        d['first'], d['second'] = d['observables'](d['before']), d['observables'](d['after'])
        return 0

    def _port_behavior_update(self):
        d = self.data
        g = self._global
        d['transcript'].update(g('wire')({'case': d['case'], 'before': d['first'], 'after': d['second']}))
        return 0

    def _port_behavior_increment(self):
        d = self.data
        g = self._global
        d['checked'] += 1
        return 0

    def _port_behavior_differs(self):
        d = self.data
        g = self._global
        return 1 if (d['first'] != d['second']) else 0

    def _port_behavior_refuted(self):
        d = self.data
        g = self._global
        self.result = ('refuted', 'All scalar inputs in a finite pure acyclic domain; return/first-trap/resource observations', {'method': 'finite_domain', 'counterexample': d['case'], 'before': d['first'], 'after': d['second'], 'checked': d['checked'], 'required': d['total'], 'complete': False})
        return 0

    def _port_behavior_early_iter_release(self):
        d = self.data
        g = self._global
        self.stack.pop('arguments_iterator')
        self.stack.pop('domain_iterator')
        return 0

    def _port_behavior_arguments_release(self):
        d = self.data
        g = self._global
        self.stack.pop('arguments_iterator')
        return 0

    def _port_behavior_domain_release(self):
        d = self.data
        g = self._global
        self.stack.pop('domain_iterator')
        return 0

    def _port_behavior_final_deadline(self):
        d = self.data
        g = self._global
        return 1 if (g('time').monotonic_ns() > d['deadline']) else 0

    def _port_behavior_late_result(self):
        d = self.data
        g = self._global
        self.result = ('unknown', 'Exhaustive scalar enumeration finished after its frozen verification deadline', {'method': 'finite_domain', 'checked': d['checked'], 'required': d['total'], 'complete': False, 'deadline_met': False})
        return 0

    def _port_behavior_proved(self):
        d = self.data
        g = self._global
        self.result = ('proved', 'Exhaustive complete pure acyclic scalar domain (at most 12 total input bits), including first trap and resource ledger',
            {'method': 'finite_domain', 'checked': d['checked'], 'required': d['total'], 'complete': True,
            'all_inputs_in_declared_widths': True, 'transcript_sha256': d['transcript'].hexdigest(),
            'base_sha256': d['original'].sha256, 'candidate_sha256': d['revised'].sha256})
        return 0

    def _port_behavior_solver(self):
        d = self.data
        g = self._global
        d['report'] = d['verify_optimization'](d['original'], d['revised'], {**d['DEFAULT_POLICY'], 'timeout_ms': g('min')(5000, d['timeout_ms'])})
        return 0

    def _port_behavior_solver_status(self):
        d = self.data
        g = self._global
        d['status'] = {'verified': 'proved', 'rejected': 'refuted', 'unknown': 'unknown', 'timeout': 'unknown'}[d['report']['status']]
        return 0

    def _port_behavior_solver_result(self):
        d = self.data
        g = self._global
        self.result = (d['status'], 'Existing compositional v1-v7 scalar/effect/trap verifier with identical CFG/interface/ordered effects', d['report'])
        return 0

    def _port_behavior_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_behavior_propagate(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_subject_load(self):
        d = self.data
        g = self._global
        d['subject'] = d['args']['subject']
        return 0

    def _port_subject_not_core(self):
        d = self.data
        g = self._global
        return 1 if (d['subject']['kind'] != 'core') else 0

    def _port_subject_backend(self):
        d = self.data
        g = self._global
        d['self']._profile(d['subject']['backend_profile'], 'backend')
        return 0

    def _port_subject_canonical(self):
        d = self.data
        g = self._global
        return 1 if (d['subject']['kind'] == 'canonical_lowering') else 0

    def _port_subject_lowering(self):
        d = self.data
        g = self._global
        d['self']._profile(d['subject']['lowering_profile'], 'lowering')
        return 0

    def _port_subject_machine(self):
        d = self.data
        g = self._global
        return 1 if (d['subject']['kind'] == 'agent_machine_plan') else 0

    def _port_subject_import(self):
        d = self.data
        g = self._global
        d['validate_block_layout_plan'] = self._import('subject_layout', d)
        return 0

    def _port_subject_plan_profile(self):
        d = self.data
        g = self._global
        d['self']._profile(d['subject']['plan_profile'], 'plan')
        return 0

    def _port_subject_plan(self):
        d = self.data
        g = self._global
        d['plan'], d['_'] = d['self'].store.get_json(d['subject']['plan'])
        return 0

    def _port_subject_validate(self):
        d = self.data
        g = self._global
        g('validate')(d['plan'], g('PLAN_SCHEMA'), 'machine_plan')
        return 0

    def _port_subject_return_plan(self):
        d = self.data
        g = self._global
        self.result = d['validate_block_layout_plan'](d['program'], d['plan'])
        return 0

    def _port_subject_native(self):
        d = self.data
        g = self._global
        return 1 if (d['subject']['kind'] == 'native_artifact') else 0

    def _port_subject_receipt(self):
        d = self.data
        g = self._global
        d['receipt'] = d['self']._build_receipt(d['subject']['build_receipt'], d['args']['context'], d['subject']['native_artifact'])
        return 0

    def _port_subject_differs(self):
        d = self.data
        g = self._global
        return 1 if (d['receipt']['candidate'] != d['args']['candidate']) else 0

    def _port_subject_reject(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_SUBJECT', 'native build receipt belongs to a different candidate', 'verification')
        return 0

    def _port_subject_none(self):
        d = self.data
        g = self._global
        self.result = None
        return 0

    def _port_subject_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_subject_propagate(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_verify_context(self):
        d = self.data
        g = self._global
        d['context'] = d['self']._context(d['args']['context'])
        return 0

    def _port_verify_profile(self):
        d = self.data
        g = self._global
        d['self']._profile(d['args']['validation_profile'], 'validation')
        return 0

    def _port_verify_program(self):
        d = self.data
        g = self._global
        d['program'] = d['self']._program(d['args']['candidate'])
        return 0

    def _port_verify_base_none(self):
        d = self.data
        g = self._global
        return 1 if (d['args']['base_program'] is None) else 0

    def _port_verify_set_none(self):
        d = self.data
        g = self._global
        d['original'] = None
        return 0

    def _port_verify_base(self):
        d = self.data
        g = self._global
        d['original'] = d['self']._program(d['args']['base_program'])
        return 0

    def _port_verify_subject(self):
        d = self.data
        g = self._global
        d['plan'] = d['self']._subject(d['args'], d['program'])
        return 0

    def _port_verify_binding(self):
        d = self.data
        g = self._global
        d['binding'] = {'context': d['args']['context'], 'candidate': d['args']['candidate'],
            'candidate_core_sha256': d['program'].sha256, 'base_program': d['args']['base_program'],
            'base_core_sha256': None if d['original'] is None else d['original'].sha256, 'subject': d['args']['subject']}
        return 0

    def _port_verify_scoped_subject(self):
        d = self.data
        g = self._global
        d['scoped_subject'] = g('proof_subject')(d['binding'], d['context']['target_profile'])
        return 0

    def _port_verify_checks(self):
        d = self.data
        g = self._global
        d['checks'] = []
        return 0

    def _port_verify_iter(self):
        d = self.data
        g = self._global
        self.stack['claim_iterator'] = _IMPLICIT_ITER(d['args']['claims'])
        return 0

    def _port_verify_next(self):
        d = self.data
        g = self._global
        try:
            d['claim'] = _IMPLICIT_NEXT(self.stack["claim_iterator"])
        except _StopIteration:
            return 0
        return 1

    def _port_verify_core_claim(self):
        d = self.data
        g = self._global
        return 1 if (d['claim'] == 'core_admission') else 0

    def _port_verify_core_result(self):
        d = self.data
        g = self._global
        d['status'], d['domain'], d['evidence'] = 'proved', 'Exact canonical Core accepted by the installed whole-program checker; no behavioral or native claim', {
            'checker': 'hepta.hia_program.verify_program', 'core_sha256': d['program'].sha256,
            'input_sha256': d['program'].input_sha256, 'canonical_bytes': g('str')(g('len')(d['program'].canonical_bytes))}
        return 0

    def _port_verify_behavior_claim(self):
        d = self.data
        g = self._global
        return 1 if (d['claim'] == 'behavior_equivalence') else 0

    def _port_verify_behavior_missing(self):
        d = self.data
        g = self._global
        return 1 if (d['original'] is None) else 0

    def _port_verify_reject_base(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_SUBJECT', 'behavior equivalence requires a base program', 'verification')
        return 0

    def _port_verify_behavior(self):
        d = self.data
        g = self._global
        d['status'], d['domain'], d['evidence'] = d['self']._behavior_equivalence(d['original'], d['program'], d['self']._remaining_ms(d['context']))
        return 0

    def _port_verify_lowering_claim(self):
        d = self.data
        g = self._global
        return 1 if (d['claim'] == 'lowering_refinement') else 0

    def _port_verify_lowering_native(self):
        d = self.data
        g = self._global
        return 1 if (d['args']['subject']['kind'] == 'native_artifact') else 0

    def _port_verify_refinement(self):
        d = self.data
        g = self._global
        d['status'], d['domain'], d['evidence'] = d['self']._independent_native_refinement(d['args'], d['program'], d['context'])
        return 0

    def _port_verify_plan_none(self):
        d = self.data
        g = self._global
        return 1 if (d['plan'] is None) else 0

    def _port_verify_lowering_unsupported(self):
        d = self.data
        g = self._global
        d['status'], d['domain'], d['evidence'] = 'unsupported', 'Whole Core-to-x86 refinement of canonical lowering is not proved by this profile', {
            'reason': 'native qualification and deterministic reemission are not a universal semantic refinement proof'}
        return 0

    def _port_verify_import_emitter(self):
        d = self.data
        g = self._global
        d['emit_program_machine'] = self._import('verify_emitter', d)
        return 0

    def _port_verify_exports_plan(self):
        d = self.data
        g = self._global
        d['exports'] = g('tuple')(g('map')(g('tuple'), d['context'].get('foreign_buffer_exports', [])))
        return 0

    def _port_verify_image(self):
        d = self.data
        g = self._global
        d['image'] = d['emit_program_machine'](d['program'], machine_plan=d['plan'], foreign_buffer_exports=d['exports'])
        return 0

    def _port_verify_canonical(self):
        d = self.data
        g = self._global
        d['canonical'] = d['emit_program_machine'](d['program'], foreign_buffer_exports=d['exports'])
        return 0

    def _port_verify_import_checks(self):
        d = self.data
        g = self._global
        d['preservation_checks'] = self._import('verify_checks', d)
        return 0

    def _port_verify_choice_checks(self):
        d = self.data
        g = self._global
        d['choice_checks'] = d['preservation_checks'](d['plan'], d['program'])
        return 0

    def _port_verify_lowering_status(self):
        d = self.data
        g = self._global
        d['status'], d['domain'] = 'proved', 'Checked explicit machine choices preserve canonical CFG, scalar value lifetimes and path effects, conditional on canonical lowering/encoder correctness'
        return 0

    def _port_verify_lowering_evidence(self):
        d = self.data
        g = self._global
        d['evidence'] = {'method': 'checked_explicit_machine_choices', 'choice_checks': d['choice_checks'], 'core_sha256': d['program'].sha256,
            'plan': d['plan'], 'canonical_object_sha256': d['canonical'].sha256, 'planned_object_sha256': d['image'].sha256,
            'same_slots': not g('any')(d['plan'].get('value_registers', {}).values()),
            'same_frame_sizes': g('dict')(d['canonical'].function_frames) == g('dict')(d['image'].function_frames),
            'canonical_frame_bytes': g('dict')(d['canonical'].function_frames), 'planned_frame_bytes': g('dict')(d['image'].function_frames),
            'implicit_optimizer_used': False}
        return 0

    def _port_verify_encoding_claim(self):
        d = self.data
        g = self._global
        return 1 if (d['claim'] == 'encoding_check') else 0

    def _port_verify_encoding_subject(self):
        d = self.data
        g = self._global
        d['subject'] = d['args']['subject']
        return 0

    def _port_verify_built(self):
        d = self.data
        g = self._global
        d['built'] = d['self']._build_receipt(d['subject']['build_receipt'], d['args']['context'], d['subject']['native_artifact'])
        return 0

    def _port_verify_actual(self):
        d = self.data
        g = self._global
        d['actual'], d['_'] = d['self'].store.get(d['subject']['native_artifact'], kind='native')
        return 0

    def _port_verify_exports_encoding(self):
        d = self.data
        g = self._global
        d['exports'] = g('tuple')(g('map')(g('tuple'), d['context'].get('foreign_buffer_exports', [])))
        return 0

    def _port_verify_compile(self):
        d = self.data
        g = self._global
        d['reemitted'], d['rebuilt'] = d['self']._compile(d['program'], d['built']['output_kind'], d['built']['machine_plan'], d['self']._remaining_ms(d['context']), **({'foreign_buffer_exports': d['exports']} if d['exports'] else {}))
        return 0

    def _port_verify_bytes_equal(self):
        d = self.data
        g = self._global
        d['bytes_equal'] = d['actual'] == d['reemitted']
        return 0

    def _port_verify_object_equal(self):
        d = self.data
        g = self._global
        d['object_equal'] = d['rebuilt']['object_sha256'] == d['built']['native_build']['object_sha256']
        return 0

    def _port_verify_matches(self):
        d = self.data
        g = self._global
        d['matches'] = d['bytes_equal'] and d['object_equal']
        return 0

    def _port_verify_match_truth(self):
        d = self.data
        g = self._global
        return 1 if (d['matches']) else 0

    def _port_verify_encoding_proved(self):
        d = self.data
        g = self._global
        d['status'] = 'proved'
        return 0

    def _port_verify_encoding_refuted(self):
        d = self.data
        g = self._global
        d['status'] = 'refuted'
        return 0

    def _port_verify_encoding_domain(self):
        d = self.data
        g = self._global
        d['domain'] = 'Exact actual artifact equals reverified Core/plan reemission and linkage by the same installed implementation, with checked closed symbol/ABI inventory; no independent semantic refinement claim'
        return 0

    def _port_verify_encoding_evidence(self):
        d = self.data
        g = self._global
        d['evidence'] = {'method': 'complete_native_rederivation', 'actual_sha256': g('sha256')(d['actual']).hexdigest(),
            'rederived_sha256': g('sha256')(d['reemitted']).hexdigest(), 'bytes_equal': d['bytes_equal'],
            'object_identity_equal': d['object_equal'], 'native_build': d['rebuilt'], 'no_llvm_or_external_assembler': True}
        return 0

    def _port_verify_reject_claim(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_CLAIM', 'unimplemented verification claim', 'verification')
        return 0

    def _port_verify_scoped(self):
        d = self.data
        g = self._global
        d['scoped'] = g('proof_result')(claim=d['claim'], status=d['status'], domain=d['domain'], subject=d['scoped_subject'], profile=d['args']['validation_profile'], installation=d['self'].identities, evidence=d['evidence'])
        return 0

    def _port_verify_deadline(self):
        d = self.data
        g = self._global
        return 1 if (d['evidence'].get('method') == g('SAFE_CORE_METHOD') and d['status'] == 'proved' and d['self']._remaining_ms(d['context']) <= 0) else 0

    def _port_verify_unknown(self):
        d = self.data
        g = self._global
        d['status'] = 'unknown'
        return 0

    def _port_verify_deadline_evidence(self):
        d = self.data
        g = self._global
        d['evidence'].update(outcome=d['status'], deadline_met=False, reason='the frozen context deadline expired before proof publication')
        return 0

    def _port_verify_rescope(self):
        d = self.data
        g = self._global
        d['scoped'] = g('proof_result')(claim=d['claim'], status=d['status'], domain=d['domain'], subject=d['scoped_subject'], profile=d['args']['validation_profile'], installation=d['self'].identities, evidence=d['evidence'])
        return 0

    def _port_verify_append(self):
        d = self.data
        g = self._global
        d['checks'].append({**d['scoped'],
            'assumptions_artifact': d['self'].store.json(g('assumptions_document')(d['scoped']), 'verification-assumptions'),
            'evidence_artifact': d['self'].store.json({**d['evidence'], 'proof_binding': d['scoped']}, 'verification-evidence')})
        return 0

    def _port_verify_iter_release(self):
        d = self.data
        g = self._global
        self.stack.pop('claim_iterator')
        return 0

    def _port_verify_receipt(self):
        d = self.data
        g = self._global
        d['receipt'] = d['self'].store.json({'schema': 'hepta.hia.agent.verification.v1', 'context': d['args']['context'],
            'candidate': d['args']['candidate'], 'candidate_core_sha256': d['program'].sha256,
            'base_program': d['args']['base_program'], 'base_core_sha256': None if d['original'] is None else d['original'].sha256,
            'validation_profile': d['args']['validation_profile'], 'subject': d['args']['subject'],
            'checks': d['checks'], 'installation': d['self'].identities}, 'verification-receipt')
        return 0

    def _port_verify_return(self):
        d = self.data
        g = self._global
        self.result = {'candidate': d['args']['candidate'], 'subject': d['args']['subject'], 'verification_receipt': d['receipt'], 'checks': d['checks'], 'adopted': False}
        return 0

    def _port_verify_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_verify_propagate(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_verification_load(self):
        d = self.data
        g = self._global
        d['record'], d['_'] = d['self'].store.get_json(d['ref'], kind='verification-receipt')
        return 0

    def _port_verification_binding(self):
        d = self.data
        g = self._global
        return 1 if (d['record']['context'] != d['context'] or d['record']['installation'] != d['self'].identities
            or d['candidate'] is not None and d['record']['candidate'] != d['candidate']) else 0

    def _port_verification_reject_binding(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_RECEIPT_BINDING', 'verification receipt belongs to a different context, candidate or implementation', 'verification')
        return 0

    def _port_verification_profile(self):
        d = self.data
        g = self._global
        d['self']._profile(d['record']['validation_profile'], 'validation')
        return 0

    def _port_verification_program(self):
        d = self.data
        g = self._global
        d['program'] = d['self']._program(d['record']['candidate'])
        return 0

    def _port_verification_core(self):
        d = self.data
        g = self._global
        return 1 if (d['program'].sha256 != d['record']['candidate_core_sha256']) else 0

    def _port_verification_reject_core(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_RECEIPT_BINDING', 'verification Core identity changed', 'verification')
        return 0

    def _port_verification_base_none(self):
        d = self.data
        g = self._global
        return 1 if (d['record']['base_program'] is None) else 0

    def _port_verification_set_none(self):
        d = self.data
        g = self._global
        d['original'] = None
        return 0

    def _port_verification_base(self):
        d = self.data
        g = self._global
        d['original'] = d['self']._program(d['record']['base_program'])
        return 0

    def _port_verification_base_binding(self):
        d = self.data
        g = self._global
        return 1 if (d['record']['base_core_sha256'] != (None if d['original'] is None else d['original'].sha256)) else 0

    def _port_verification_reject_base(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_RECEIPT_BINDING', 'verification base Core identity changed', 'verification')
        return 0

    def _port_verification_subject(self):
        d = self.data
        g = self._global
        d['self']._subject(d['record'], d['program'])
        return 0

    def _port_verification_context(self):
        d = self.data
        g = self._global
        d['context_record'] = d['self']._context(d['context'])
        return 0

    def _port_verification_proof_subject(self):
        d = self.data
        g = self._global
        d['subject'] = g('proof_subject')(d['record'], d['context_record']['target_profile'])
        return 0

    def _port_verification_schema(self):
        d = self.data
        g = self._global
        d['checks_schema'] = d['self'].tools['hia_verify']['outputSchema']['properties']['result']['properties']['checks']
        return 0

    def _port_verification_validate(self):
        d = self.data
        g = self._global
        g('validate')(d['record']['checks'], d['checks_schema'], 'verification.checks')
        return 0

    def _port_verification_match_rejection(self):
        d = self.data
        g = self._global
        return 1 if (self._matches(self.exception[1], g('AgentRejected'))) else 0

    def _port_verification_bind_exception(self):
        d = self.data
        g = self._global
        d['exc'] = self.exception[1]
        return 0

    def _port_verification_reject_schema(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_PROOF_SCOPE', 'missing or invalid proof scope; rerun verification with a fresh request key: ' + g('str')(d['exc']), 'verification')
        return 0

    def _port_verification_handler_release(self):
        d = self.data
        g = self._global
        self._release_handler_local('exc')
        return 0

    def _port_verification_duplicates(self):
        d = self.data
        g = self._global
        return 1 if (g('len')(self._compound(CLAIM_SET, {'.0': _IMPLICIT_ITER(d['record']['checks'])})) != g('len')(d['record']['checks'])) else 0

    def _port_verification_reject_duplicates(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_PROOF_SCOPE', 'verification repeats a proof property', 'verification')
        return 0

    def _port_verification_iter(self):
        d = self.data
        g = self._global
        self.stack['check_iterator'] = _IMPLICIT_ITER(d['record']['checks'])
        return 0

    def _port_verification_next(self):
        d = self.data
        g = self._global
        try:
            d['check'] = _IMPLICIT_NEXT(self.stack["check_iterator"])
        except _StopIteration:
            return 0
        return 1

    def _port_verification_evidence(self):
        d = self.data
        g = self._global
        d['evidence'], d['_'] = d['self'].store.get_json(d['check']['evidence_artifact'], kind='verification-evidence')
        return 0

    def _port_verification_assumptions(self):
        d = self.data
        g = self._global
        d['assumptions'], d['_'] = d['self'].store.get_json(d['check']['assumptions_artifact'], kind='verification-assumptions')
        return 0

    def _port_verification_safe(self):
        d = self.data
        g = self._global
        return 1 if (d['evidence'].get('method') == g('SAFE_CORE_METHOD')) else 0

    def _port_verification_safe_check(self):
        d = self.data
        g = self._global
        d['self']._check_native_refinement_evidence(d['evidence'], d['record']['subject'], d['context'], d['program'])
        return 0

    def _port_verification_expected(self):
        d = self.data
        g = self._global
        d['expected'] = g('proof_result')(claim=d['check']['claim'], status=d['check']['status'], domain=d['check']['domain'], subject=d['subject'], profile=d['record']['validation_profile'], installation=d['self'].identities, evidence=d['evidence'])
        return 0

    def _port_verification_actual(self):
        d = self.data
        g = self._global
        d['actual'] = self._compound(ACTUAL_COMP, {'.0': _IMPLICIT_ITER(d['check'].items())})
        return 0

    def _port_verification_scope(self):
        d = self.data
        g = self._global
        return 1 if (d['actual'] != d['expected'] or d['evidence'].get('proof_binding') != d['expected'] or d['assumptions'] != g('assumptions_document')(d['expected'])) else 0

    def _port_verification_reject_scope(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_PROOF_SCOPE', 'proof scope or retained checker conclusion differs; rerun verification with a fresh request key', 'verification')
        return 0

    def _port_verification_iter_release(self):
        d = self.data
        g = self._global
        self.stack.pop('check_iterator')
        return 0

    def _port_verification_return(self):
        d = self.data
        g = self._global
        self.result = d['record']
        return 0

    def _port_verification_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_verification_propagate(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_replay_validate(self):
        d = self.data
        g = self._global
        g('validate')(d['response'], d['self'].tools['hia_verify']['outputSchema'], 'replayed verification')
        return 0

    def _port_replay_match_rejection(self):
        d = self.data
        g = self._global
        return 1 if (self._matches(self.exception[1], g('AgentRejected'))) else 0

    def _port_replay_bind_exception(self):
        d = self.data
        g = self._global
        d['exc'] = self.exception[1]
        return 0

    def _port_replay_reject_schema(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_PROOF_SCOPE', 'cached proof lacks current scope; rerun verification with a fresh request key: ' + g('str')(d['exc']), 'verification')
        return 0

    def _port_replay_handler_release(self):
        d = self.data
        g = self._global
        self._release_handler_local('exc')
        return 0

    def _port_replay_installation(self):
        d = self.data
        g = self._global
        return 1 if (g('installation_manifest')() != d['self'].identities) else 0

    def _port_replay_reject_installation(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_IMPLEMENTATION_STALE', 'installed implementation changed during verification replay')
        return 0

    def _port_replay_result(self):
        d = self.data
        g = self._global
        d['result'] = d['response']['result']
        return 0

    def _port_replay_retained(self):
        d = self.data
        g = self._global
        d['retained'] = d['self']._verification(d['result']['verification_receipt'], d['arguments']['context'], d['arguments']['candidate'])
        return 0

    def _port_replay_differs(self):
        d = self.data
        g = self._global
        return 1 if (d['result']['candidate'] != d['retained']['candidate'] or d['result']['subject'] != d['retained']['subject']
            or d['result']['checks'] != d['retained']['checks'] or d['retained']['subject'] != d['arguments']['subject']
            or d['retained']['base_program'] != d['arguments']['base_program']
            or d['retained']['validation_profile'] != d['arguments']['validation_profile']
            or self._compound(CLAIM_LIST, {'.0': _IMPLICIT_ITER(d['retained']['checks'])}) != d['arguments']['claims']) else 0

    def _port_replay_reject_difference(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_PROOF_SCOPE', 'cached proof differs from the original subject or retained conclusion; rerun verification with a fresh request key', 'verification')
        return 0

    def _port_replay_none(self):
        d = self.data
        g = self._global
        self.result = None
        return 0

    def _port_replay_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_replay_propagate(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_binding_result(self):
        d = self.data
        g = self._global
        self.result = {'candidate_core_sha256': d['program'].sha256, 'input_sha256': d['program'].input_sha256,
            'native_artifact': d['subject']['native_artifact'], 'build_receipt': d['subject']['build_receipt'],
            'object_artifact': d['built']['object_artifact'], 'object_sha256': g('sha256')(d['object_bytes']).hexdigest(),
            'final_image_sha256': g('sha256')(d['final_bytes']).hexdigest(), 'output_kind': d['built']['output_kind'],
            'entry_symbols': self._compound(SYMBOLS_COMP, {'.0': _IMPLICIT_ITER(d['program'].as_dict()['functions'])}),
            'foreign_buffer_exports': d['built']['native_build'].get('foreign_buffer_exports')}
        return 0

    def _port_binding_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_binding_propagate(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_refinement_import(self):
        d = self.data
        g = self._global
        (d['ARTIFACT_PROFILE'], d['ARTIFACT_OBLIGATIONS'], d['SafeCoreRejected'], d['_profile'], d['_checker_source_identity'], d['validate_safe_core_artifact']) = self._import('refinement_safe', d)
        return 0

    def _port_refinement_subject(self):
        d = self.data
        g = self._global
        d['subject'] = d['args']['subject']
        return 0

    def _port_refinement_inputs(self):
        d = self.data
        g = self._global
        d['built'], d['final_bytes'], d['object_bytes'], d['retained'] = d['self']._build_inputs(d['subject']['build_receipt'], d['args']['context'], d['subject']['native_artifact'])
        return 0

    def _port_refinement_core(self):
        d = self.data
        g = self._global
        return 1 if (d['retained'].sha256 != d['program'].sha256) else 0

    def _port_refinement_reject_core(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_RECEIPT_BINDING', 'retained machine subject differs from the requested Core', 'verification')
        return 0

    def _port_refinement_identity(self):
        d = self.data
        g = self._global
        d['identity'] = d['_checker_source_identity']()
        return 0

    def _port_refinement_evidence(self):
        d = self.data
        g = self._global
        d['evidence'] = {'method': g('SAFE_CORE_METHOD'), 'profile': d['ARTIFACT_PROFILE'],
            'service_profile': g('SAFE_CORE_SERVICE_PROFILE'),
            'artifact_binding': d['self']._native_refinement_binding(d['subject'], d['built'], d['program'], d['object_bytes'], d['final_bytes']),
            'source_identity': d['identity'], 'checker_sha256': g('digest')(d['identity']), 'solver': None,
            'validation': None, 'queries': [], 'deadline_met': False}
        return 0

    def _port_refinement_finish_define(self):
        d = self.data
        g = self._global
        d['finish'] = self._make_finish(d['evidence'])
        return 0

    def _port_refinement_output_kind(self):
        d = self.data
        g = self._global
        return 1 if (d['built']['output_kind'] != 'shared' or d['built']['native_build'].get('foreign_buffer_exports') != []) else 0

    def _port_refinement_unsupported_output(self):
        d = self.data
        g = self._global
        self.result = d['finish']('unsupported', 'Agent machine validation admits final shared ELF with scalar entries only')
        return 0

    def _port_refinement_profile(self):
        d = self.data
        g = self._global
        d['_profile'](d['program'], foreign_buffer_exports=())
        return 0

    def _port_refinement_profile_match(self):
        d = self.data
        g = self._global
        return 1 if (self._matches(self.exception[1], d['SafeCoreRejected'])) else 0

    def _port_refinement_profile_bind(self):
        d = self.data
        g = self._global
        d['exc'] = self.exception[1]
        return 0

    def _port_refinement_profile_result(self):
        d = self.data
        g = self._global
        self.result = d['finish']('unsupported', g('str')(d['exc']))
        return 0

    def _port_refinement_profile_release(self):
        d = self.data
        g = self._global
        self._release_handler_local('exc')
        return 0

    def _port_refinement_profile_failed_release(self):
        d = self.data
        g = self._global
        self._release_handler_local('exc')
        return 0

    def _port_refinement_remaining(self):
        d = self.data
        g = self._global
        d['remaining'] = g('min')(60000, d['self']._remaining_ms(d['context']))
        return 0

    def _port_refinement_minimum(self):
        d = self.data
        g = self._global
        return 1 if (d['remaining'] < 100) else 0

    def _port_refinement_unknown_minimum(self):
        d = self.data
        g = self._global
        self.result = d['finish']('unknown', 'less than the minimum 100 ms remains in the frozen verification budget')
        return 0

    def _port_refinement_status(self):
        d = self.data
        g = self._global
        d['status'], d['reason'] = 'unknown', None
        return 0

    def _port_refinement_cm_create(self):
        d = self.data
        g = self._global
        self.stack['manager'] = g('tempfile').TemporaryDirectory(prefix='machine-proof-', dir=d['self'].store.root)
        self.stack['lookup'] = _IMPLICIT_ITER(_context_lookup_order())
        return 0

    def _port_refinement_cm_lookup_next(self):
        d = self.data
        g = self._global
        return _IMPLICIT_NEXT(self.stack['lookup'], 0)

    def _port_refinement_cm_lookup_enter(self):
        d = self.data
        g = self._global
        self.stack['enter'] = _context_special(self.stack['manager'], '__enter__')
        return 0

    def _port_refinement_cm_lookup_exit(self):
        d = self.data
        g = self._global
        self.stack['exit'] = _context_special(self.stack['manager'], '__exit__')
        return 0

    def _port_refinement_cm_enter(self):
        d = self.data
        g = self._global
        del self.stack['lookup'], self.stack['manager']
        d['directory'] = self.stack.pop('enter')()
        return 0

    def _port_refinement_cm_preentry_release(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_refinement_query_directory(self):
        d = self.data
        g = self._global
        d['query_directory'] = g('Path')(d['directory']) / 'queries'
        return 0

    def _port_refinement_validate(self):
        d = self.data
        g = self._global
        d['evidence']['validation'] = d['validate_safe_core_artifact'](d['program'], d['object_bytes'], d['final_bytes'], timeout_ms=d['remaining'], query_directory=d['query_directory'])
        return 0

    def _port_refinement_proved(self):
        d = self.data
        g = self._global
        d['status'] = 'proved'
        return 0

    def _port_refinement_validate_match_safe(self):
        d = self.data
        g = self._global
        return 1 if (self._matches(self.exception[1], d['SafeCoreRejected'])) else 0

    def _port_refinement_validate_bind_safe(self):
        d = self.data
        g = self._global
        d['exc'] = self.exception[1]
        return 0

    def _port_refinement_exc_validation(self):
        d = self.data
        g = self._global
        d['evidence']['validation'] = d['exc'].validation
        return 0

    def _port_refinement_counterexample(self):
        d = self.data
        g = self._global
        d['counterexample'] = d['exc'].counterexample
        return 0

    def _port_refinement_violation_names(self):
        d = self.data
        g = self._global
        d['violation_names'] = self._compound(VIOLATION_SET, {'.0': _IMPLICIT_ITER(d['ARTIFACT_OBLIGATIONS'])})
        return 0

    def _port_refinement_refuted_check(self):
        d = self.data
        g = self._global
        return 1 if (g('type')(d['counterexample']) is g('dict') and d['counterexample'].get('obligation') in d['violation_names'] and g('type')(d['exc'].validation) is g('dict') and d['exc'].validation.get('status') == 'refuted') else 0

    def _port_refinement_refuted_status(self):
        d = self.data
        g = self._global
        d['status'] = 'refuted'
        return 0

    def _port_refinement_refuted_evidence(self):
        d = self.data
        g = self._global
        d['evidence']['counterexample'] = d['counterexample']
        return 0

    def _port_refinement_safe_reason(self):
        d = self.data
        g = self._global
        d['reason'] = g('str')(d['exc'])
        return 0

    def _port_refinement_validate_match_value(self):
        d = self.data
        g = self._global
        return 1 if (self._matches(self.exception[1], g('ValueError'))) else 0

    def _port_refinement_validate_bind_value(self):
        d = self.data
        g = self._global
        d['exc'] = self.exception[1]
        return 0

    def _port_refinement_value_result(self):
        d = self.data
        g = self._global
        d['status'], d['reason'] = 'unsupported', g('str')(d['exc'])
        return 0

    def _port_refinement_handler_release(self):
        d = self.data
        g = self._global
        self._release_handler_local('exc')
        return 0

    def _port_refinement_handler_failed_release(self):
        d = self.data
        g = self._global
        self._release_handler_local('exc')
        return 0

    def _port_refinement_validation(self):
        d = self.data
        g = self._global
        d['validation'] = d['evidence']['validation']
        return 0

    def _port_refinement_has_validation(self):
        d = self.data
        g = self._global
        return 1 if (d['validation'] is not None) else 0

    def _port_refinement_solver(self):
        d = self.data
        g = self._global
        d['evidence']['solver'] = d['validation']['solver']
        return 0

    def _port_refinement_paths_iter(self):
        d = self.data
        g = self._global
        self.stack['path_iterator'] = _IMPLICIT_ITER(g('sorted')(d['query_directory'].glob('*.smt2')))
        return 0

    def _port_refinement_path_next(self):
        d = self.data
        g = self._global
        try:
            d['path'] = _IMPLICIT_NEXT(self.stack["path_iterator"])
        except _StopIteration:
            return 0
        return 1

    def _port_refinement_read_query(self):
        d = self.data
        g = self._global
        d['data'] = d['path'].read_bytes()
        return 0

    def _port_refinement_query_append(self):
        d = self.data
        g = self._global
        d['evidence']['queries'].append({'name': d['path'].name, 'sha256': g('sha256')(d['data']).hexdigest(), 'artifact': d['self'].store.put(d['data'], 'machine-validation-query')})
        return 0

    def _port_refinement_paths_release(self):
        d = self.data
        g = self._global
        self.stack.pop('path_iterator')
        return 0

    def _port_refinement_cm_normal_exit(self):
        d = self.data
        g = self._global
        self.stack.pop('exit')(None, None, None)
        return 0

    def _port_refinement_cm_normal_release(self):
        d = self.data
        g = self._global
        self._release_normal_stack()
        return 0

    def _port_refinement_cm_error_exit(self):
        d = self.data
        g = self._global
        self.stack['exit_outcome'] = self.stack['exit'](*self.exception)
        return 0

    def _port_refinement_cm_truth(self):
        d = self.data
        g = self._global
        return 1 if (self.stack.pop('exit_outcome')) else 0

    def _port_refinement_cm_suppressed_release(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_refinement_cm_terminal_error_release(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_refinement_deadline(self):
        d = self.data
        g = self._global
        d['evidence']['deadline_met'] = d['self']._remaining_ms(d['context']) > 0
        return 0

    def _port_refinement_deadline_missed(self):
        d = self.data
        g = self._global
        return 1 if (not d['evidence']['deadline_met']) else 0

    def _port_refinement_deadline_unknown(self):
        d = self.data
        g = self._global
        d['status'], d['reason'] = 'unknown', 'the frozen context deadline expired before proof publication'
        return 0

    def _port_refinement_result(self):
        d = self.data
        g = self._global
        self.result = d['finish'](d['status'], d['reason'])
        return 0

    def _port_refinement_cm_error_prepare(self):
        d = self.data
        g = self._global
        self._release_loop_stack_before_exit()
        return 0

    def _port_refinement_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_refinement_propagate(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_check_subject(self):
        d = self.data
        g = self._global
        return 1 if (d['subject'].get('kind') != 'native_artifact') else 0

    def _port_check_reject_subject(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_PROOF_SCOPE', 'independent machine evidence requires its exact native subject', 'verification')
        return 0

    def _port_check_inputs(self):
        d = self.data
        g = self._global
        d['built'], d['final_bytes'], d['object_bytes'], d['retained'] = d['self']._build_inputs(d['subject']['build_receipt'], d['context'], d['subject']['native_artifact'])
        return 0

    def _port_check_expected(self):
        d = self.data
        g = self._global
        d['expected'] = d['self']._native_refinement_binding(d['subject'], d['built'], d['retained'], d['object_bytes'], d['final_bytes'])
        return 0

    def _port_check_binding(self):
        d = self.data
        g = self._global
        return 1 if (d['program'].sha256 != d['retained'].sha256 or d['evidence'].get('artifact_binding') != d['expected']) else 0

    def _port_check_reject_binding(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_PROOF_SCOPE', 'machine evidence differs from retained Core/object/final build bytes', 'verification')
        return 0

    def _port_check_validation(self):
        d = self.data
        g = self._global
        d['validation'] = d['evidence'].get('validation')
        return 0

    def _port_check_validation_type(self):
        d = self.data
        g = self._global
        return 1 if (g('type')(d['validation']) is g('dict')) else 0

    def _port_check_import_elf(self):
        d = self.data
        g = self._global
        d['bind_final_artifact'] = self._import('check_elf', d)
        return 0

    def _port_check_bind_elf(self):
        d = self.data
        g = self._global
        d['binding'] = d['bind_final_artifact'](d['object_bytes'], d['final_bytes'], d['retained'].as_dict()['functions'][0]['name'])
        return 0

    def _port_check_image(self):
        d = self.data
        g = self._global
        return 1 if (d['validation'].get('image_binding') != d['binding']['binding']) else 0

    def _port_check_reject_image(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_PROOF_SCOPE', "machine proof's ELF binding differs from the actual retained bytes", 'verification')
        return 0

    def _port_check_queries(self):
        d = self.data
        g = self._global
        d['queries'] = d['evidence'].get('queries')
        return 0

    def _port_check_queries_type(self):
        d = self.data
        g = self._global
        return 1 if (g('type')(d['queries']) is not g('list')) else 0

    def _port_check_reject_queries(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_PROOF_SCOPE', 'machine proof lacks retained query identities', 'verification')
        return 0

    def _port_check_reports(self):
        d = self.data
        g = self._global
        d['reports'] = [] if d['validation'] is None else d['validation'].get('obligations', [])
        return 0

    def _port_check_count(self):
        d = self.data
        g = self._global
        return 1 if (d['validation'] is not None and g('len')(d['queries']) != g('len')(d['reports'])) else 0

    def _port_check_reject_count(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_PROOF_SCOPE', 'machine proof query inventory differs', 'verification')
        return 0

    def _port_check_iter(self):
        d = self.data
        g = self._global
        self.stack['query_iterator'] = _IMPLICIT_ITER(g('enumerate')(d['queries']))
        return 0

    def _port_check_next(self):
        d = self.data
        g = self._global
        try:
            value = _IMPLICIT_NEXT(self.stack["query_iterator"])
        except _StopIteration:
            return 0
        try:
            (d['index'], d['query']) = value
        finally:
            value = None
        return 1

    def _port_check_query_shape(self):
        d = self.data
        g = self._global
        return 1 if (g('type')(d['query']) is not g('dict') or g('set')(d['query']) != {'name', 'sha256', 'artifact'}) else 0

    def _port_check_reject_shape(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_PROOF_SCOPE', 'machine proof query reference is invalid', 'verification')
        return 0

    def _port_check_data(self):
        d = self.data
        g = self._global
        d['data'], d['_'] = d['self'].store.get(d['query']['artifact'], kind='machine-validation-query')
        return 0

    def _port_check_query_bytes(self):
        d = self.data
        g = self._global
        return 1 if (g('sha256')(d['data']).hexdigest() != d['query']['sha256']
            or d['validation'] is not None and (d['query']['sha256'] != d['reports'][d['index']].get('query_sha256')
                or d['query']['name'] != d['reports'][d['index']].get('query_file'))) else 0

    def _port_check_reject_bytes(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_PROOF_SCOPE', 'machine proof query bytes differ', 'verification')
        return 0

    def _port_check_iter_release(self):
        d = self.data
        g = self._global
        self.stack.pop('query_iterator')
        return 0

    def _port_check_none(self):
        d = self.data
        g = self._global
        self.result = None
        return 0

    def _port_check_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_check_propagate(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_claims_native(self):
        d = self.data
        g = self._global
        d['_data'], d['native'], d['_program'] = d['self']._native(d['candidate_artifact'], d['context']['ref'])
        return 0

    def _port_claims_objective(self):
        d = self.data
        g = self._global
        d['objective'], d['_'] = d['self'].store.get_json(d['context']['objective'])
        return 0

    def _port_claims_receipts_begin(self):
        d = self.data
        g = self._global
        self.stack['receipts_pending'] = []
        self.stack['refs_iterator'] = _IMPLICIT_ITER(d['refs'])
        return 0

    def _port_claims_refs_next(self):
        d = self.data
        g = self._global
        try:
            self.stack['ref'] = _IMPLICIT_NEXT(self.stack["refs_iterator"])
        except _StopIteration:
            return 0
        return 1

    def _port_claims_receipt_call(self):
        d = self.data
        g = self._global
        self.stack['receipts_pending'].append(d['self']._verification(self.stack['ref'], d['context']['ref'], d['native']['candidate']))
        return 0

    def _port_claims_receipts_commit(self):
        d = self.data
        g = self._global
        self.stack.pop('refs_iterator')
        self.stack.pop('ref', None)
        d['receipts'] = self.stack.pop('receipts_pending')
        return 0

    def _port_claims_iter(self):
        d = self.data
        g = self._global
        self.stack['claim_iterator'] = _IMPLICIT_ITER(d['objective']['required_claims'])
        return 0

    def _port_claims_next(self):
        d = self.data
        g = self._global
        try:
            d['claim'] = _IMPLICIT_NEXT(self.stack["claim_iterator"])
        except _StopIteration:
            return 0
        return 1

    def _port_claims_false(self):
        d = self.data
        g = self._global
        d['qualified'] = False
        return 0

    def _port_claims_receipt_iter(self):
        d = self.data
        g = self._global
        self.stack['receipt_iterator'] = _IMPLICIT_ITER(d['receipts'])
        return 0

    def _port_claims_receipt_next(self):
        d = self.data
        g = self._global
        try:
            d['receipt'] = _IMPLICIT_NEXT(self.stack["receipt_iterator"])
        except _StopIteration:
            return 0
        return 1

    def _port_claims_proved(self):
        d = self.data
        g = self._global
        return 1 if (not g('any')(self._new_generator(GEN_CLAIMS, _IMPLICIT_ITER(d['receipt']['checks']), self._capture('claim')))) else 0

    def _port_claims_subject(self):
        d = self.data
        g = self._global
        d['subject'] = d['receipt']['subject']
        return 0

    def _port_claims_encoding(self):
        d = self.data
        g = self._global
        return 1 if (d['claim'] == 'encoding_check') else 0

    def _port_claims_encoding_subject(self):
        d = self.data
        g = self._global
        return 1 if (d['subject']['kind'] != 'native_artifact' or d['subject']['native_artifact'] != d['candidate_artifact']) else 0

    def _port_claims_encoding_receipt(self):
        d = self.data
        g = self._global
        d['self']._build_receipt(d['subject']['build_receipt'], d['context']['ref'], d['candidate_artifact'])
        return 0

    def _port_claims_behavior(self):
        d = self.data
        g = self._global
        return 1 if (d['claim'] == 'behavior_equivalence') else 0

    def _port_claims_behavior_base(self):
        d = self.data
        g = self._global
        return 1 if (d['receipt']['base_core_sha256'] != d['baseline_core_sha']) else 0

    def _port_claims_lowering(self):
        d = self.data
        g = self._global
        return 1 if (d['claim'] == 'lowering_refinement') else 0

    def _port_claims_lowering_native(self):
        d = self.data
        g = self._global
        return 1 if (d['subject']['kind'] == 'native_artifact') else 0

    def _port_claims_lowering_artifact(self):
        d = self.data
        g = self._global
        return 1 if (d['subject']['native_artifact'] != d['candidate_artifact']) else 0

    def _port_claims_lowering_receipt(self):
        d = self.data
        g = self._global
        d['self']._build_receipt(d['subject']['build_receipt'], d['context']['ref'], d['candidate_artifact'])
        return 0

    def _port_claims_lowering_plan(self):
        d = self.data
        g = self._global
        return 1 if (d['native']['machine_plan'] is None or d['subject']['kind'] != 'agent_machine_plan' or d['subject']['plan'] != d['native']['codegen']['plan']) else 0

    def _port_claims_true(self):
        d = self.data
        g = self._global
        d['qualified'] = True
        return 0

    def _port_claims_receipt_release(self):
        d = self.data
        g = self._global
        self.stack.pop('receipt_iterator')
        return 0

    def _port_claims_unqualified(self):
        d = self.data
        g = self._global
        return 1 if (not d['qualified']) else 0

    def _port_claims_reject(self):
        d = self.data
        g = self._global
        g('reject')('E_HIA_CLAIM_REQUIRED', 'missing exact proved acceptance claim: ' + d['claim'], 'verification')
        return 0

    def _port_claims_iter_release(self):
        d = self.data
        g = self._global
        self.stack.pop('claim_iterator')
        return 0

    def _port_claims_return(self):
        d = self.data
        g = self._global
        self.result = d['objective']
        return 0

    def _port_claims_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_claims_propagate(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_acyclic_visiting(self):
        d = self.data
        g = self._global
        return 1 if (d['name'] in d['cells']['visiting']) else 0

    def _port_acyclic_done(self):
        d = self.data
        g = self._global
        return 1 if (d['name'] in d['cells']['done']) else 0

    def _port_acyclic_add(self):
        d = self.data
        g = self._global
        d['cells']['visiting'].add(d['name'])
        return 0

    def _port_acyclic_term(self):
        d = self.data
        g = self._global
        d['term'] = d['cells']['blocks'][d['name']]['term']
        return 0

    def _port_acyclic_jump(self):
        d = self.data
        g = self._global
        return 1 if (d['term']['op'] == 'jump') else 0

    def _port_acyclic_jump_targets(self):
        d = self.data
        g = self._global
        d['targets'] = [d['term']['target']]
        return 0

    def _port_acyclic_branch(self):
        d = self.data
        g = self._global
        return 1 if (d['term']['op'] == 'branch') else 0

    def _port_acyclic_branch_targets(self):
        d = self.data
        g = self._global
        d['targets'] = [d['term']['then']['target'], d['term']['else']['target']]
        return 0

    def _port_acyclic_no_targets(self):
        d = self.data
        g = self._global
        d['targets'] = []
        return 0

    def _port_acyclic_all(self):
        d = self.data
        g = self._global
        return 1 if (not g('all')(self._new_generator(GEN_ACYCLIC, _IMPLICIT_ITER(d['targets']), d['cells'].subset('acyclic')))) else 0

    def _port_acyclic_remove(self):
        d = self.data
        g = self._global
        d['cells']['visiting'].remove(d['name'])
        return 0

    def _port_acyclic_finish(self):
        d = self.data
        g = self._global
        d['cells']['done'].add(d['name'])
        return 0

    def _port_acyclic_false(self):
        d = self.data
        g = self._global
        self.result = False
        return 0

    def _port_acyclic_true(self):
        d = self.data
        g = self._global
        self.result = True
        return 0

    def _port_acyclic_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_acyclic_propagate(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_finish_outcome(self):
        d = self.data
        g = self._global
        d['evidence']['outcome'] = d['status']
        return 0

    def _port_finish_has_reason(self):
        d = self.data
        g = self._global
        return 1 if (d['reason'] is not None) else 0

    def _port_finish_reason(self):
        d = self.data
        g = self._global
        d['evidence']['reason'] = d['reason']
        return 0

    def _port_finish_result(self):
        d = self.data
        g = self._global
        self.result = (d['status'], g('SAFE_CORE_DOMAIN'), d['evidence'])
        return 0

    def _port_finish_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_finish_propagate(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_blocks_comp_allocate(self):
        d = self.data
        g = self._global
        self.result = {}
        return 0

    def _port_blocks_comp_next(self):
        d = self.data
        g = self._global
        try:
            value = _IMPLICIT_NEXT(d['.0'])
        except _StopIteration:
            return 0
        try:
            d['b'] = value
        finally:
            value = None
        return 1

    def _port_blocks_comp_put(self):
        d = self.data
        g = self._global
        self.result[d['b']['id']] = d['b']
        return 0

    def _port_blocks_comp_end(self):
        d = self.data
        g = self._global
        self._release_compound_iteration()
        return 0

    def _port_blocks_comp_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_blocks_comp_propagate(self):
        d = self.data
        g = self._global
        self._release_compound_error()
        return 0

    def _port_interface_fn_iterator(self):
        d = self.data
        g = self._global
        d['.0'] = _IMPLICIT_ITER(d['d']['functions'])
        return 0

    def _port_interface_fn_allocate(self):
        d = self.data
        g = self._global
        self.result = {}
        return 0

    def _port_interface_fn_next(self):
        d = self.data
        g = self._global
        try:
            value = _IMPLICIT_NEXT(d['.0'])
        except _StopIteration:
            return 0
        try:
            d['fn'] = value
        finally:
            value = None
        return 1

    def _port_interface_fn_key(self):
        d = self.data
        g = self._global
        self.stack['key'] = d['fn']['name']
        return 0

    def _port_interface_fn_put(self):
        d = self.data
        g = self._global
        self.result[self.stack.pop('key')] = self._compound(INTERFACE_FIELDS, {'.0': _IMPLICIT_ITER(('params', 'returns', 'effects')), 'fn': d['fn']})
        return 0

    def _port_interface_fn_end(self):
        d = self.data
        g = self._global
        self._release_compound_iteration()
        return 0

    def _port_interface_fn_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_interface_fn_propagate(self):
        d = self.data
        g = self._global
        self._release_compound_error()
        return 0

    def _port_interface_fields_allocate(self):
        d = self.data
        g = self._global
        self.result = {}
        return 0

    def _port_interface_fields_next(self):
        d = self.data
        g = self._global
        try:
            value = _IMPLICIT_NEXT(d['.0'])
        except _StopIteration:
            return 0
        try:
            d['k'] = value
        finally:
            value = None
        return 1

    def _port_interface_fields_put(self):
        d = self.data
        g = self._global
        self.result[d['k']] = d['fn'][d['k']]
        return 0

    def _port_interface_fields_end(self):
        d = self.data
        g = self._global
        self._release_compound_iteration()
        return 0

    def _port_interface_fields_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_interface_fields_propagate(self):
        d = self.data
        g = self._global
        self._release_compound_error()
        return 0

    def _port_domains_comp_allocate(self):
        d = self.data
        g = self._global
        self.result = []
        return 0

    def _port_domains_comp_next(self):
        d = self.data
        g = self._global
        try:
            value = _IMPLICIT_NEXT(d['.0'])
        except _StopIteration:
            return 0
        try:
            d['typ'] = value
        finally:
            value = None
        return 1

    def _port_domains_comp_bool(self):
        d = self.data
        g = self._global
        return 1 if d['typ'] == 'bool' else 0

    def _port_domains_comp_bool_value(self):
        d = self.data
        g = self._global
        self.result.append([False, True])
        return 0

    def _port_domains_comp_range(self):
        d = self.data
        g = self._global
        self.result.append(g('range')(d['cells']['integer_range'](d['typ'])[0], d['cells']['integer_range'](d['typ'])[1] + 1))
        return 0

    def _port_domains_comp_end(self):
        d = self.data
        g = self._global
        self._release_compound_iteration()
        return 0

    def _port_domains_comp_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_domains_comp_propagate(self):
        d = self.data
        g = self._global
        self._release_compound_error()
        return 0

    def _port_observables_fn_value(self):
        d = self.data
        g = self._global
        self.result = {'status': d['row']['status'], 'values': d['row'].get('values'), 'first_trap': d['row'].get('trap_code'), 'resources': d['row']['ledger']['resources']}
        return 0

    def _port_observables_fn_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_observables_fn_propagate(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_claim_set_allocate(self):
        d = self.data
        g = self._global
        self.result = _EMPTY_SET()
        return 0

    def _port_claim_set_next(self):
        d = self.data
        g = self._global
        try:
            value = _IMPLICIT_NEXT(d['.0'])
        except _StopIteration:
            return 0
        try:
            d['check'] = value
        finally:
            value = None
        return 1

    def _port_claim_set_put(self):
        d = self.data
        g = self._global
        self.result.add(d['check']['claim'])
        return 0

    def _port_claim_set_end(self):
        d = self.data
        g = self._global
        self._release_compound_iteration()
        return 0

    def _port_claim_set_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_claim_set_propagate(self):
        d = self.data
        g = self._global
        self._release_compound_error()
        return 0

    def _port_actual_comp_allocate(self):
        d = self.data
        g = self._global
        self.result = {}
        return 0

    def _port_actual_comp_next(self):
        d = self.data
        g = self._global
        try:
            value = _IMPLICIT_NEXT(d['.0'])
        except _StopIteration:
            return 0
        try:
            (d['key'], d['value']) = value
        finally:
            value = None
        return 1

    def _port_actual_comp_filter(self):
        d = self.data
        g = self._global
        return 1 if d['key'] not in {'assumptions_artifact', 'evidence_artifact'} else 0

    def _port_actual_comp_put(self):
        d = self.data
        g = self._global
        self.result[d['key']] = d['value']
        return 0

    def _port_actual_comp_end(self):
        d = self.data
        g = self._global
        self._release_compound_iteration()
        return 0

    def _port_actual_comp_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_actual_comp_propagate(self):
        d = self.data
        g = self._global
        self._release_compound_error()
        return 0

    def _port_claim_list_allocate(self):
        d = self.data
        g = self._global
        self.result = []
        return 0

    def _port_claim_list_next(self):
        d = self.data
        g = self._global
        try:
            value = _IMPLICIT_NEXT(d['.0'])
        except _StopIteration:
            return 0
        try:
            d['check'] = value
        finally:
            value = None
        return 1

    def _port_claim_list_put(self):
        d = self.data
        g = self._global
        self.result.append(d['check']['claim'])
        return 0

    def _port_claim_list_end(self):
        d = self.data
        g = self._global
        self._release_compound_iteration()
        return 0

    def _port_claim_list_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_claim_list_propagate(self):
        d = self.data
        g = self._global
        self._release_compound_error()
        return 0

    def _port_symbols_comp_allocate(self):
        d = self.data
        g = self._global
        self.result = []
        return 0

    def _port_symbols_comp_next(self):
        d = self.data
        g = self._global
        try:
            value = _IMPLICIT_NEXT(d['.0'])
        except _StopIteration:
            return 0
        try:
            d['fn'] = value
        finally:
            value = None
        return 1

    def _port_symbols_comp_put(self):
        d = self.data
        g = self._global
        self.result.append(d['fn']['name'])
        return 0

    def _port_symbols_comp_end(self):
        d = self.data
        g = self._global
        self._release_compound_iteration()
        return 0

    def _port_symbols_comp_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_symbols_comp_propagate(self):
        d = self.data
        g = self._global
        self._release_compound_error()
        return 0

    def _port_violation_set_allocate(self):
        d = self.data
        g = self._global
        self.result = _EMPTY_SET()
        return 0

    def _port_violation_set_next(self):
        d = self.data
        g = self._global
        try:
            value = _IMPLICIT_NEXT(d['.0'])
        except _StopIteration:
            return 0
        try:
            (d['name'], d['expected']) = value
        finally:
            value = None
        return 1

    def _port_violation_set_filter(self):
        d = self.data
        g = self._global
        return 1 if d['expected'] == 'unsat' else 0

    def _port_violation_set_put(self):
        d = self.data
        g = self._global
        self.result.add(d['name'])
        return 0

    def _port_violation_set_end(self):
        d = self.data
        g = self._global
        self._release_compound_iteration()
        return 0

    def _port_violation_set_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_violation_set_propagate(self):
        d = self.data
        g = self._global
        self._release_compound_error()
        return 0

    def _port_gen_lengths_next(self):
        d = self.data
        g = self._global
        try:
            value = _IMPLICIT_NEXT(d['.0'])
        except _StopIteration:
            return 0
        try:
            d['b'] = value
        finally:
            value = None
        return 1

    def _port_gen_lengths_value(self):
        d = self.data
        g = self._global
        self.result = g('len')(d['b']['ops'])
        return 0

    def _port_gen_lengths_yield(self):
        d = self.data
        g = self._global
        return 0

    def _port_gen_lengths_stop(self):
        d = self.data
        g = self._global
        self.result = None
        return 0

    def _port_gen_lengths_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_gen_lengths_propagate(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_gen_operations_next(self):
        d = self.data
        g = self._global
        try:
            value = _IMPLICIT_NEXT(d['.0'])
        except _StopIteration:
            return 0
        try:
            d['b'] = value
        finally:
            value = None
        return 1

    def _port_gen_operations_inner(self):
        d = self.data
        g = self._global
        self.stack['op_iterator'] = _IMPLICIT_ITER(d['b']['ops'])
        return 0

    def _port_gen_operations_op_next(self):
        d = self.data
        g = self._global
        try:
            value = _IMPLICIT_NEXT(self.stack['op_iterator'])
        except _StopIteration:
            return 0
        try:
            d['op'] = value
        finally:
            value = None
        return 1

    def _port_gen_operations_value(self):
        d = self.data
        g = self._global
        self.result = d['op']['op'] not in d['cells']['PURE']
        return 0

    def _port_gen_operations_inner_end(self):
        d = self.data
        g = self._global
        self.stack.pop('op_iterator')
        return 0

    def _port_gen_operations_yield(self):
        d = self.data
        g = self._global
        return 0

    def _port_gen_operations_stop(self):
        d = self.data
        g = self._global
        self.result = None
        return 0

    def _port_gen_operations_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_gen_operations_propagate(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_gen_bits_next(self):
        d = self.data
        g = self._global
        try:
            value = _IMPLICIT_NEXT(d['.0'])
        except _StopIteration:
            return 0
        try:
            d['typ'] = value
        finally:
            value = None
        return 1

    def _port_gen_bits_bool(self):
        d = self.data
        g = self._global
        return 1 if d['typ'] == 'bool' else 0

    def _port_gen_bits_one(self):
        d = self.data
        g = self._global
        self.result = 1
        return 0

    def _port_gen_bits_width(self):
        d = self.data
        g = self._global
        self.result = d['cells']['WIDTHS'].get(d['typ'], 1000000)
        return 0

    def _port_gen_bits_yield(self):
        d = self.data
        g = self._global
        return 0

    def _port_gen_bits_stop(self):
        d = self.data
        g = self._global
        self.result = None
        return 0

    def _port_gen_bits_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_gen_bits_propagate(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_gen_claims_next(self):
        d = self.data
        g = self._global
        try:
            value = _IMPLICIT_NEXT(d['.0'])
        except _StopIteration:
            return 0
        try:
            d['c'] = value
        finally:
            value = None
        return 1

    def _port_gen_claims_left(self):
        d = self.data
        g = self._global
        self.stack['left'] = d['c']['claim'] == d['cells']['claim']
        return 0

    def _port_gen_claims_truth(self):
        d = self.data
        g = self._global
        return 1 if self.stack['left'] else 0

    def _port_gen_claims_drop_left(self):
        d = self.data
        g = self._global
        self.stack.pop('left')
        return 0

    def _port_gen_claims_right(self):
        d = self.data
        g = self._global
        self.result = d['c']['status'] == 'proved'
        return 0

    def _port_gen_claims_false_value(self):
        d = self.data
        g = self._global
        self.result = self.stack.pop('left')
        return 0

    def _port_gen_claims_yield(self):
        d = self.data
        g = self._global
        return 0

    def _port_gen_claims_stop(self):
        d = self.data
        g = self._global
        self.result = None
        return 0

    def _port_gen_claims_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_gen_claims_propagate(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0

    def _port_gen_acyclic_next(self):
        d = self.data
        g = self._global
        try:
            value = _IMPLICIT_NEXT(d['.0'])
        except _StopIteration:
            return 0
        try:
            d['target'] = value
        finally:
            value = None
        return 1

    def _port_gen_acyclic_value(self):
        d = self.data
        g = self._global
        self.result = d['cells']['acyclic'](d['target'])
        return 0

    def _port_gen_acyclic_yield(self):
        d = self.data
        g = self._global
        return 0

    def _port_gen_acyclic_stop(self):
        d = self.data
        g = self._global
        self.result = None
        return 0

    def _port_gen_acyclic_release(self):
        d = self.data
        g = self._global
        self.data = self._retired_data
        return 0

    def _port_gen_acyclic_propagate(self):
        d = self.data
        g = self._global
        self._release_exception_stack()
        return 0
