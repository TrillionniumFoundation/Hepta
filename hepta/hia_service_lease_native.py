"""Complete HIA ownership of acquire_slot, _lease, invoke_lease and release_slot.

HIA owns every business branch, loop, transaction exit and terminal decision.
Foreign ports retain original literal expressions; ledger and disposable worker
providers keep their independently admitted interfaces. No SQL retry policy is
implemented here. This component does not establish whole-native execution.
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

from .hia_emission_native import (
    _global_value, _class_special, _MISSING_SPECIAL,
    _context_missing_message, _bind_special_descriptor,
)
from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path, _unique_manifest_pairs
from .hia_native_delivery import DeliveryRecord
from .hia_store_lifecycle_native import _regular_bytes
from .hia_service_lease_protocol import (
    SELECTOR, SCHEMA, SOURCE_NAME, REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC,
    REQUEST_BYTES, OUTPUT_BYTES, STATE_BYTES, INITIALIZE, CLAIM, SUCCEEDED,
    RAISED, FINALIZE, ISSUED, CLAIMED, READY_RETURN, READY_PROPAGATE,
    RETURNED, PROPAGATE, LEAVE_HANDLER, PORT, PORTS, ACQUIRE, LEASE, INVOKE, RELEASE,
)

SOURCE = _source_resource_path(SOURCE_NAME)
_REQUEST_REJECTIONS = (ValueError, TypeError, OSError, OverflowError, RecursionError, sqlite3.Error)

# ctypes keeps its dynamically constructed array types in a weak cache. These
# three fixed ABI classes belong to the adapter, not to an invocation; retain
# them so destroying private buffers does not leave new type cycles for a
# caller's later GC. The buffers, user objects and per-call checks are unchanged.
_REQUEST_BUFFER_TYPE = ctypes.c_char * (REQUEST_BYTES + 16)
_OUTPUT_BUFFER_TYPE = ctypes.c_char * (OUTPUT_BYTES + 16)
_STATE_BUFFER_TYPE = ctypes.c_char * (STATE_BYTES + 16)



_BaseException = BaseException
_StopIteration = StopIteration
_IMPLICIT_ITER = iter
_IMPLICIT_NEXT = next
_HANDLED_EXCEPTION = sys.exception

@lru_cache(maxsize=1)
def _handled_state_setter():
    """Bind CPython public handled-state save/restore with borrowed inputs."""
    if sys.implementation.name != 'cpython':
        raise RuntimeError('service lease cleanup requires CPython handled-state ABI')
    # Use a private function view, leaving ctypes.pythonapi attribute views alone.
    # The runtime acquires its own reference; the frame retains each input owner.
    setter = ctypes.pythonapi['PyErr_SetHandledException']
    setter.argtypes = (ctypes.c_void_p,)
    setter.restype = None
    return setter


def _lease_context_special(manager, name):
    kind = type(manager)
    descriptor = _class_special(kind, name)
    if descriptor is _MISSING_SPECIAL:
        try:
            raise TypeError(_context_missing_message(manager, name))
        finally:
            # The original evaluation stack, not a forwarding traceback frame,
            # owns this receiver until the HIA unwind directive retires it.
            del manager
    return _bind_special_descriptor(descriptor, manager, kind)


LOCAL_NAMES = {
    ACQUIRE: ('self', 'target_slot'),
    LEASE: ('self', 'lease'),
    INVOKE: ('self', 'lease', 'function', 'arguments', 'run_native_batch',
             'validate_arguments', 'data', 'metadata', '_program', 'signature',
             'context', 'result', 'buffers', 'captured', 'external', 'observation'),
    RELEASE: ('self', 'lease'),
}


class _LocalReleaseProbe:
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


@lru_cache(maxsize=4)
def _local_storage_order(mode):
    frame_events, dict_events = [], []
    _probe_frame_release(frame_events)
    _probe_dict_release(dict_events)
    orders = (['first', 'last'], ['last', 'first'])
    if frame_events not in orders or dict_events not in orders:
        raise RuntimeError('runtime does not provide immediate ordered local custody')
    names = LOCAL_NAMES[mode]
    return names if frame_events == dict_events else names[::-1]


def _probe_cm_enter():
    return None


def _probe_cm_exit(typ, value, traceback):
    return False


class _ContextSpecialProbe:
    __slots__ = ('tag', 'call')

    def __init__(self, tag, call):
        self.tag, self.call = tag, call

    def __get__(self, instance, owner):
        instance.events.append(self.tag)
        return self.call


class _ContextProbe:
    __slots__ = ('events',)
    __enter__ = _ContextSpecialProbe(1, _probe_cm_enter)
    __exit__ = _ContextSpecialProbe(2, _probe_cm_exit)

    def __init__(self, events):
        self.events = events


@lru_cache(maxsize=1)
def _context_lookup_order():
    events = []
    with _ContextProbe(events):
        pass
    result = tuple(events)
    if result not in ((1, 2), (2, 1)):
        raise RuntimeError('runtime context special lookup order is unsupported')
    return result


def _import_runner_template():
    from .hia_agent_runner import run_native_batch
    return run_native_batch


def _import_validator_template():
    from .hia_agent_buffers import validate_arguments
    return validate_arguments


def _valid_port(mode, port):
    if port in (PORT['normal_release'], PORT['exception_stack_release']):
        return True
    if mode == INVOKE:
        return PORT['import_runner'] <= port <= PORT['return_status']
    if port == PORT['ledger_present']:
        return True
    if mode == LEASE:
        return port in (PORT['lease_ledger'], PORT['lease_reference'])
    if (PORT['cm_create'] <= port <= PORT['cm_enter']
            or PORT['cm_exit_normal'] <= port <= PORT['implicit_none']):
        return True
    names = ('acquire_ledger', 'acquire_reference') if mode == ACQUIRE else ('release_ledger', 'release_reference')
    return port in tuple(PORT[name] for name in names)


class ServiceLeaseUnknown(RuntimeError):
    """An actual handler observation is unconfirmed; no terminal or replay."""


class NativeServiceLease(NativeHiaJsonImage):
    pass


@lru_cache(maxsize=3)
def _mapped_service_lease(raw, digest, source_digest):
    image = NativeServiceLease(raw, digest)
    image.admitted_source_sha256 = source_digest
    return image


def installed_service_lease(manifest_path):
    if not manifest_path:
        raise ValueError('native service lease selector must not be empty')
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeServiceLease)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_unique_manifest_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid native service lease manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or Path(name).name != name or any(ord(char) < 32 for char in name)):
        raise ValueError('native service lease image must be a sibling basename')
    source = _regular_bytes(SOURCE, 8 << 20)
    image_path = path.parent / name
    image = _regular_bytes(image_path, 1 << 20)
    if sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('native service lease source identity mismatch')
    if sha256(image).hexdigest() != value['image_sha256']:
        raise ValueError('native service lease image identity mismatch')
    if selected is None:
        selected = _mapped_service_lease(image, value['image_sha256'], value['source_sha256'])
    elif type(selected) is not NativeServiceLease or selected.image_sha256 != value['image_sha256']:
        raise ValueError('native service lease differs from pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source
            or _regular_bytes(image_path, 1 << 20) != image):
        raise ValueError('native service lease selection changed during admission')
    return selected


def _handoff(record, extent):
    record.enter_native()
    return extent


def _checksum(words):
    value = 1469598103934665603
    for index, word in enumerate(words):
        if index != 10:
            value = (((value << 7) | (value >> 57)) & ((1 << 64) - 1)) ^ word
    return value



# Literal method calls keep the original LOAD_METHOD/argument order. Each
# predicate returns only an observation; HIA selects the subsequent port.
def _literal_cm(service):
    return service.store.transaction()


def _literal_acquire(service, target):
    return service._slot_ledger.acquire(target, service._slot_snapshot, service._native)


def _literal_acquire_reference(service, target):
    return service._reference_slot_acquire(target)


def _literal_lease(service, lease):
    return service._slot_ledger.lease(lease)


def _literal_lease_reference(service, lease):
    return service._reference_slot_lease(lease)


def _literal_release(service, lease):
    return service._slot_ledger.release(lease)


def _literal_release_reference(service, lease):
    return service._reference_slot_release(lease)


def _literal_invoke_lease(service, lease):
    return service._lease(lease)


def _literal_native(service, lease):
    return service._native(lease['artifact'])


def _literal_context(service, metadata):
    return service._context(metadata['context'])


def _literal_run_native(run_native_batch, data, metadata, function, arguments, context, lookup):
    return run_native_batch(data, metadata['signatures'],
        [{'function': function, 'arguments': arguments}],
        timeout_ms=context['budget']['max_native_wall_ms'],
        memory_bytes=lookup('uint64')(context['budget']['max_memory_bytes'], 'max_memory_bytes'),
        capture_buffers=True)


def _literal_buffer_append(buffers, captured, service, data, lease, function):
    buffers.append({**captured, 'artifact': service.store.put(data, 'invocation-buffer', {
        'lease': lease['id'], 'generation': lease['generation'], 'artifact': lease['artifact'],
        'function': function, 'argument': captured['argument'], 'termination_confirmed': True})})


def _literal_return_values(observation, lease, external):
    return {'status': 'returned', 'values': observation['values'], 'generation': lease['generation'],
            'artifact': lease['artifact'], 'termination_confirmed': True, **external}


def _literal_return_observation(observation, lease, external):
    return {'status': observation['status'], 'generation': lease['generation'],
            'artifact': lease['artifact'], 'termination_confirmed': True, **external}


def _literal_return_status(result, lease, external):
    return {'status': result['status'], 'generation': lease['generation'], 'artifact': lease['artifact'],
            'termination_confirmed': result['termination_confirmed'], **external}


@dataclass(frozen=True)
class ServiceLeaseReceipt:
    port: int
    sequence: int
    phase: int
    mode: int
    failed: int



class ServiceLeaseFrame:
    def __init__(self, image, mode, service, arguments, *, namespace=None, import_ports=None):
        if type(image) is not NativeServiceLease:
            raise TypeError('native service lease requires an admitted image')
        if type(mode) is not int or mode not in (ACQUIRE, LEASE, INVOKE, RELEASE):
            raise ValueError('native service lease mode is invalid')
        names = ('target_slot',) if mode == ACQUIRE else ('lease', 'function', 'arguments') if mode == INVOKE else ('lease',)
        if type(arguments) is not tuple or len(arguments) != len(names):
            raise TypeError('native service lease arguments do not match its mode')
        from . import hia_agent_service
        if namespace is None:
            namespace = vars(hia_agent_service)
            global_builtins = hia_agent_service._SERVICE_LEASE_GLOBAL_BUILTINS[mode]
            if import_ports is None:
                import_ports = (hia_agent_service._SERVICE_LEASE_IMPORT_RUNNER,
                                hia_agent_service._SERVICE_LEASE_IMPORT_VALIDATOR)
        else:
            global_builtins = namespace.get('__builtins__', vars(builtins))
            if type(global_builtins) is types.ModuleType:
                global_builtins = vars(global_builtins)
            if import_ports is None:
                # Qualification supplies the same frozen original namespace.
                # The two tiny import code objects contain no business policy.
                import_ports = (
                    types.FunctionType(_import_runner_template.__code__, namespace),
                    types.FunctionType(_import_validator_template.__code__, namespace))
        # Resolve the fixed ABI before INITIALIZE or any original foreign effect.
        self._set_handled = _handled_state_setter()
        self._caller_handled = None
        self.image, self.mode = image, mode
        self.namespace, self.global_builtins = namespace, global_builtins
        self.import_ports = import_ports
        self.data = dict.fromkeys(_local_storage_order(mode))
        self._retired_data = {}
        self.stack = {}
        self.data['self'] = service
        for name, value in zip(names, arguments):
            self.data[name] = value
        self.result = None
        self.exception = None
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.buffer = ctypes.create_string_buffer(STATE_BYTES + 16)
        ctypes.memmove(ctypes.addressof(self.buffer) + STATE_BYTES, b'\xb7' * 16, 16)
        self.receipt = None
        self.fenced = self.finished = self.native_failed = self._entered = False
        self._pending_foreign = self._whole = None
        self._foreign_started = self._effect_started = False
        self._delivery = DeliveryRecord(self)
        try:
            self.call(INITIALIZE)
        except _BaseException:
            self._delivery.retire()
            raise

    @property
    def service(self):
        return self.data.get('self')


    def _check(self):
        record = self._delivery
        record.check(ServiceLeaseUnknown)
        whole = self._whole
        if whole is not None:
            whole.pending_resources.check_borrowed_resources()
        # The identity query or GC may itself perform a real child call.
        record.check(ServiceLeaseUnknown)

    def call(self, event, observation=0):
        record = self._delivery
        if self.fenced or self.finished or not record.current():
            raise ServiceLeaseUnknown('native service lease has no current invocation')
        self._check()
        native_confirmed = False
        try:
            previous = self.receipt
            port, sequence = (0, 0) if previous is None else (previous.port, previous.sequence)
            old_failed = 0 if previous is None else previous.failed
            raw = struct.pack('<10Q', REQUEST_MAGIC, event, sequence, port, observation,
                              self.mode, *self.identity, 0, 0)
            source = ctypes.create_string_buffer(raw + b'\xc9' * 16, REQUEST_BYTES + 16)
            output = ctypes.create_string_buffer(OUTPUT_BYTES + 16)
            ctypes.memmove(ctypes.addressof(output) + OUTPUT_BYTES, b'\xa5' * 16, 16)
            # Resolve the actual entry callable and all buffer arguments before
            # marking native handoff, at the final argument of the literal call.
            code = self.image._entry(source, REQUEST_BYTES, output, OUTPUT_BYTES,
                                     self.buffer, _handoff(record, STATE_BYTES))
            if (code != OUTPUT_BYTES or source.raw != raw + b'\xc9' * 16
                    or output.raw[OUTPUT_BYTES:] != b'\xa5' * 16
                    or self.buffer.raw[STATE_BYTES:] != b'\xb7' * 16):
                raise ServiceLeaseUnknown('native service lease return is unconfirmed')
            words = struct.unpack('<12Q', output.raw[:OUTPUT_BYTES])
            state = struct.unpack('<16Q', self.buffer.raw[:STATE_BYTES])
            expected_sequence = 1 if event == INITIALIZE else sequence if event == CLAIM else sequence + 1
            expected_phases = {
                INITIALIZE: (ISSUED,), CLAIM: (CLAIMED,),
                SUCCEEDED: (ISSUED, READY_RETURN, READY_PROPAGATE, LEAVE_HANDLER),
                RAISED: (ISSUED, READY_PROPAGATE),
                FINALIZE: (RETURNED, PROPAGATE),
            }[event]
            failed = (1 if event == RAISED else 0 if event == SUCCEEDED
                      and port == PORT['cm_exit_truth'] and observation == 1 else old_failed)
            active = words[4] in (ISSUED, CLAIMED, LEAVE_HANDLER)
            if (words[0] != RESULT_MAGIC or words[1] != 0
                    or words[2:7] != (state[3], state[4], state[5], state[2], state[12])
                    or state[:3] != (STATE_MAGIC, 1, self.mode)
                    or words[8:10] != self.identity or state[6:8] != self.identity
                    or words[7] != 0 or words[10:12] != (0, 0)
                    or state[8] > 1 or state[9] != 0 or state[11] > 3
                    or state[13] != 0 or state[14] > 1 or state[15] != 0
                    or (self.mode in (LEASE, INVOKE) and (state[8] != 0 or state[11] != 0))
                    or (self.mode != INVOKE and state[14] != 0)
                    or state[10] != _checksum(state)
                    or words[3] != expected_sequence or words[4] not in expected_phases
                    or words[6] != failed
                    or (words[4] in (READY_RETURN, RETURNED) and failed != 0)
                    or (words[4] in (READY_PROPAGATE, PROPAGATE) and failed != 1)
                    or (not active and words[2] != 0)
                    or (words[4] == READY_RETURN and port != PORT['normal_release'])
                    or (words[4] == LEAVE_HANDLER and (words[2] != PORT['implicit_none'] or failed != 0))
                    or (active and not _valid_port(self.mode, words[2]))
                    or (event == CLAIM and words[2] != port)
                    or (event == FINALIZE and (
                        previous.phase not in (READY_RETURN, READY_PROPAGATE)
                        or words[4] != (RETURNED if previous.phase == READY_RETURN else PROPAGATE)))):
                raise ServiceLeaseUnknown('native service lease receipt differs from issued state')
            receipt = ServiceLeaseReceipt(words[2], words[3], words[4], words[5], words[6])
            pending = None
            if event in (SUCCEEDED, RAISED):
                pending = self._pending_foreign
            elif event == FINALIZE:
                pending = self._whole
            if event in (SUCCEEDED, RAISED, FINALIZE):
                if pending is None:
                    raise ServiceLeaseUnknown('native service lease has no matching foreign activation')
                pending.prepare_acknowledgement()
            self._check()
            record.confirmed()
            native_confirmed = True
            self.receipt = receipt
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
                raise ServiceLeaseUnknown('native service lease observation failed') from error
            raise


    def finish(self):
        # Same-Frame reentry is refused outside the active owner's cleanup
        # region. A recursive public handler creates its own fresh Frame.
        if self._entered:
            raise ServiceLeaseUnknown('native service lease frame cannot be reused')
        if not self._delivery.current():
            raise ServiceLeaseUnknown('native service lease frame cannot be transferred')
        self._entered = True
        try:
            # Capture the actual finish caller, not the Frame construction site.
            self._caller_handled = _HANDLED_EXCEPTION()
            self._check()
            whole = self._delivery.foreign(capture_resources=True,
                                          weak_registered_resources=True)
            self._whole = whole
            with self._delivery.foreign(observation=False):
                try:
                    with whole:
                        self._drive()
                except BaseException as error:
                    if (not self._foreign_started and self._delivery.loss is None
                            and not self._delivery.native_pending):
                        # Safe refusal before any original effect. INIT was
                        # also outside this observed whole-method scope.
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
                self._delivery.propagate(error, ServiceLeaseUnknown, _REQUEST_REJECTIONS)
            raise
        finally:
            try:
                self._delivery.retire()
            finally:
                # Do not leave the caller exception in a retained transport Frame.
                self._caller_handled = None

    def _effect_once(self):
        self._effect_started = False
        if self.receipt.phase not in (ISSUED, LEAVE_HANDLER):
            raise ServiceLeaseUnknown('native service lease effect is not newly issued')
        self.call(CLAIM)
        activation = self._delivery.foreign(capture_resources=True,
                                            weak_registered_resources=True)
        self._pending_foreign = activation
        with activation:
            self._check()
            self._foreign_started = self._effect_started = True
            return self.effect(self.receipt.port)

    def _finalize(self):
        previous = self.receipt.phase
        if previous not in (READY_RETURN, READY_PROPAGATE):
            raise ServiceLeaseUnknown('native service lease has no HIA completion directive')
        self.call(FINALIZE)
        if self.receipt.phase != (RETURNED if previous == READY_RETURN else PROPAGATE):
            raise ServiceLeaseUnknown('native service lease final receipt is unconfirmed')
        self.finished = True


    def _foreign_raised(self, error):
        if self.fenced or self.native_failed or self._delivery.loss is not None:
            self._delivery.propagate(error, ServiceLeaseUnknown, _REQUEST_REJECTIONS)
            raise
        if not self._effect_started:
            raise
        # This is the actual handled exception. HIA decides whether an
        # admitted context exit is required, and whether its result suppresses.
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
        raise ServiceLeaseUnknown('native service lease has no exception continuation')

    def _drive(self):
        while True:
            try:
                observed = self._effect_once()
            except _BaseException as error:
                self._foreign_raised(error)
                if self.receipt.phase == READY_PROPAGATE:
                    raise
                self._exception_continuation()
            else:
                self.call(SUCCEEDED, observed)
            # The active handler has now actually ended. The suppressed path
            # cannot evaluate its next ordinary port inside the old exception.
            if self.receipt.phase == LEAVE_HANDLER:
                self.exception = None
                continue
            if self.receipt.phase == READY_RETURN:
                return
            if self.receipt.phase != ISSUED:
                raise ServiceLeaseUnknown('native service lease left its continuation')

    def _global(self, name):
        return _global_value(self.namespace, self.global_builtins, name)


    def _release_stack_at_caller(self, name):
        if (name not in ('exception_stack_release', 'cm_suppressed_release')
                or self.receipt is None or self.receipt.phase != CLAIMED
                or self.receipt.port != PORT[name]):
            raise ServiceLeaseUnknown('service lease cleanup was not issued by HIA')
        # Pin restoration capabilities and pointer owners before callbacks run.
        handled_state = _HANDLED_EXCEPTION
        set_handled = self._set_handled
        caller = self._caller_handled
        caller_pointer = None if caller is None else id(caller)
        pending = handled_state()
        pending_pointer = None if pending is None else id(pending)
        s = self.stack
        try:
            # These are the already-issued original evaluation-stack decrefs.
            # No provider call or delivery acknowledgement is moved into this
            # handled-state window. Strong owners keep both raw pointers alive.
            set_handled(caller_pointer)
            if handled_state() is not caller:
                raise ServiceLeaseUnknown('service lease caller handled state was not installed')
            if name == 'exception_stack_release':
                # On failed with entry the manager is still above the previously
                # captured special callable on the original evaluation stack.
                s.pop('manager', None)
                s.pop('value', None)
                s.pop('wire', None)
                s.pop('decode', None)
                s.pop('iterator', None)
                s.pop('exit_outcome', None)
                s.pop('exit', None)
                s.pop('enter', None)
                s.pop('lookup', None)
                self.result = None
                self.exception = None
            else:
                s.pop('exit', None)
                s.pop('enter', None)
                s.pop('lookup', None)
                s.pop('manager', None)
                self.exception = None
            return 0
        finally:
            try:
                set_handled(pending_pointer)
                if handled_state() is not pending:
                    raise ServiceLeaseUnknown('service lease pending handled state was not restored')
            finally:
                # This forwarding alias must not become a new traceback owner.
                pending = caller = None

    def effect(self, port):
        if (self.receipt is None or self.receipt.phase != CLAIMED
                or self.receipt.port != port or not _valid_port(self.mode, port)):
            raise ServiceLeaseUnknown('native service lease effect was not claimed')
        name = PORTS[port - 1]
        d, s = self.data, self.stack
        if name == 'cm_create':
            s['manager'] = _literal_cm(self.service)
            s['lookup'] = _IMPLICIT_ITER(_context_lookup_order())
        elif name == 'cm_lookup_next':
            return _IMPLICIT_NEXT(s['lookup'], 0)
        elif name == 'cm_lookup_enter':
            s['enter'] = _lease_context_special(s['manager'], '__enter__')
        elif name == 'cm_lookup_exit':
            s['exit'] = _lease_context_special(s['manager'], '__exit__')
        elif name == 'cm_enter':
            del s['lookup'], s['manager']
            s.pop('enter')()
        elif name == 'ledger_present':
            return 1 if self.service._slot_ledger is not None else 0
        elif name == 'acquire_ledger':
            self.result = _literal_acquire(self.service, d['target_slot'])
        elif name == 'acquire_reference':
            self.result = _literal_acquire_reference(self.service, d['target_slot'])
        elif name == 'lease_ledger':
            self.result = _literal_lease(self.service, d['lease'])
        elif name == 'lease_reference':
            self.result = _literal_lease_reference(self.service, d['lease'])
        elif name == 'release_ledger':
            self.result = _literal_release(self.service, d['lease'])
        elif name == 'release_reference':
            self.result = _literal_release_reference(self.service, d['lease'])
        elif name == 'cm_exit_normal':
            s.pop('exit')(None, None, None)
        elif name == 'cm_exit_exception':
            s['exit_outcome'] = s['exit'](*self.exception)
        elif name == 'cm_exit_truth':
            return 1 if s.pop('exit_outcome') else 0
        elif name == 'cm_stack_release':
            s.pop('exit', None)
            s.pop('enter', None)
            s.pop('lookup', None)
            s.pop('manager', None)
        elif name == 'cm_suppressed_release':
            return self._release_stack_at_caller(name)
        elif name == 'implicit_none':
            self.result = None
        elif name == 'import_runner':
            d['run_native_batch'] = self.import_ports[0]()
        elif name == 'import_validator':
            d['validate_arguments'] = self.import_ports[1]()
        elif name == 'invoke_lease_lookup':
            d['lease'] = _literal_invoke_lease(self.service, d['lease'])
        elif name == 'invoke_native':
            d['data'], d['metadata'], d['_program'] = _literal_native(self.service, d['lease'])
        elif name == 'output_kind_differs':
            return 1 if d['metadata']['output_kind'] != 'shared' else 0
        elif name == 'reject_kind':
            self._global('reject')('E_HIA_ABI', 'slot generation is not an executable shared image')
        elif name == 'function_is_str':
            return 1 if self._global('type')(d['function']) is self._global('str') else 0
        elif name == 'signature_get':
            d['signature'] = d['metadata']['signatures'].get(d['function'])
        elif name == 'signature_none':
            d['signature'] = None
        elif name == 'signature_missing':
            return 1 if d['signature'] is None else 0
        elif name == 'reject_signature':
            self._global('reject')('E_HIA_ARGUMENTS', 'call does not match the retained public ABI')

        elif name == 'snapshot_prefix':
            # The two outer callees are loaded before the original conditional.
            # These are evaluation-stack values, not new original locals.
            s['decode'] = self._global('decode_data')
            s['wire'] = self._global('wire')
            return 1 if self._global('type')(d['arguments']) is self._global('tuple') else 0
        elif name == 'snapshot_list':
            s['value'] = self._global('list')(d['arguments'])
        elif name == 'snapshot_identity':
            s['value'] = d['arguments']
        elif name == 'snapshot_wire':
            s['value'] = s.pop('wire')(s.pop('value'))
        elif name == 'snapshot_decode':
            d['arguments'] = s.pop('decode')(s.pop('value'))
        elif name == 'validate_arguments':
            d['validate_arguments'](d['signature'], d['arguments'])
        elif name == 'context_lookup':
            d['context'] = _literal_context(self.service, d['metadata'])
        elif name == 'run_native':
            d['result'] = _literal_run_native(d['run_native_batch'], d['data'],
                d['metadata'], d['function'], d['arguments'], d['context'], self._global)
        elif name == 'buffers_init':
            d['buffers'] = []
        elif name == 'captured_iter':
            s['iterator'] = _IMPLICIT_ITER(d['result'].pop('captured_buffers', []))
        elif name == 'captured_next':
            try:
                d['captured'] = _IMPLICIT_NEXT(s['iterator'])
            except _StopIteration:
                return 0
            return 1
        elif name == 'captured_data':
            d['data'] = d['captured'].pop('data')
        elif name == 'captured_append':
            _literal_buffer_append(d['buffers'], d['captured'], self.service,
                d['data'], d['lease'], d['function'])
        elif name == 'captured_iter_release':
            s.pop('iterator')
        elif name == 'signature_abi':
            return 1 if d['signature'].get('abi') else 0
        elif name == 'external_buffers':
            d['external'] = {'buffers': d['buffers']}
        elif name == 'external_empty':
            d['external'] = {}
        elif name == 'result_returned':
            return 1 if d['result']['status'] == 'returned' else 0
        elif name == 'observation_lookup':
            d['observation'] = d['result']['report']['observations'][0]
        elif name == 'observation_returned':
            return 1 if d['observation']['status'] == 'returned' else 0
        elif name == 'return_values':
            self.result = _literal_return_values(d['observation'], d['lease'], d['external'])
        elif name == 'return_observation':
            self.result = _literal_return_observation(d['observation'], d['lease'], d['external'])
        elif name == 'return_status':
            self.result = _literal_return_status(d['result'], d['lease'], d['external'])
        elif name == 'normal_release':
            self.data = self._retired_data
        elif name == 'exception_stack_release':
            return self._release_stack_at_caller(name)
        return 0
