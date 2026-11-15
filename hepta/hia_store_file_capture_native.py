"""HIA control for complete stable_read and authorized capture_path.

HIA chooses every original branch, loop, exception and finally continuation.
OS, Path, stream and object expressions remain explicit hosted observations.
The separate raw Linux descriptor ABI is a candidate primitive, not a silently
substituted implementation of os.open/fdopen or a claim of full native I/O.
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
from .hia_native_admission_io import regular_bytes as _regular_bytes, resolve_path as _admission_resolve
from .hia_store_file_capture_protocol import (
    SELECTOR, SCHEMA, SOURCE_NAME, REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC,
    REQUEST_BYTES, OUTPUT_BYTES, STATE_BYTES, INITIALIZE, CLAIM, SUCCEEDED,
    RAISED, FINALIZE, RESUME, ISSUED, CLAIMED, READY_RETURN, READY_PROPAGATE,
    RETURNED, PROPAGATE, LEAVE_EXCEPTION, PORT, PORTS, LAST_STABLE_PORT,
    STABLE_READ, CAPTURE_PATH, STATE_VERSION, FD_NONE, FD_OWNED, FD_CLOSE_CLAIMED,
    STABLE_PORTS, CAPTURE_PORTS, STABLE_CLOSE_PORTS,
)
SOURCE = _source_resource_path(SOURCE_NAME)
_REQUEST_REJECTIONS = (ValueError, TypeError, OSError, OverflowError, RecursionError, sqlite3.Error)
_REQUEST_BUFFER_TYPE = ctypes.c_char * (REQUEST_BYTES + 16)
_OUTPUT_BUFFER_TYPE = ctypes.c_char * (OUTPUT_BYTES + 16)
_STATE_BUFFER_TYPE = ctypes.c_char * (STATE_BYTES + 16)
_ITER, _NEXT = iter, next
_TYPE_MRO = vars(type)['__mro__']
_BASE_EXCEPTION = BaseException
_TYPE, _TUPLE = type, tuple

_HANDLED_EXCEPTION = sys.exception

@lru_cache(maxsize=1)
def _capture_handled_state_setter():
    """Bind the public handled-state bridge for issued context-stack decrefs."""
    if sys.implementation.name != 'cpython':
        raise RuntimeError('file capture context cleanup requires CPython handled-state ABI')
    setter = ctypes.pythonapi['PyErr_SetHandledException']
    setter.argtypes = (ctypes.c_void_p,)
    setter.restype = None
    return setter


def _capture_context_special(manager, name):
    kind = type(manager)
    descriptor = _class_special(kind, name)
    if descriptor is _MISSING_SPECIAL:
        try:
            raise TypeError(_context_missing_message(manager, name))
        finally:
            # The original evaluation stack, not this forwarding traceback,
            # owns the receiver until its HIA-selected unwind port.
            del manager
    return _bind_special_descriptor(descriptor, manager, kind)


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

@lru_cache(maxsize=2)
def _local_storage_order(mode):
    frame_events, dict_events = [], []
    _probe_frame_release(frame_events)
    _probe_dict_release(dict_events)
    forward, reverse = ['first', 'last'], ['last', 'first']
    if frame_events not in (forward, reverse) or dict_events not in (forward, reverse):
        raise RuntimeError('runtime does not provide immediate ordered local custody')
    names = (('path', 'limit', 'dir_fd', 'flags', 'fd', 'stream', 'before', 'data',
              'after', 'identity', 'exc') if mode == STABLE_READ else
             ('path', 'roots', 'limit', 'parts', 'lexical', 'chosen', 'root',
              'relative', 'descriptors', 'fd', 'component', 'exc'))
    return names if frame_events == dict_events else names[::-1]

def _probe_enter():
    return None

def _probe_exit(*args):
    return False

class _LookupSpecial:
    __slots__ = ('name',)
    def __init__(self, name):
        self.name = name
    def __get__(self, instance, owner):
        instance.events.append(self.name)
        return _probe_enter if self.name == '__enter__' else _probe_exit

class _LookupManager:
    __slots__ = ('events',)
    __enter__ = _LookupSpecial('__enter__')
    __exit__ = _LookupSpecial('__exit__')
    def __init__(self, events):
        self.events = events

@lru_cache(maxsize=1)
def _context_lookup_order():
    events = []
    with _LookupManager(events):
        pass
    result = tuple(events)
    if result not in (('__enter__', '__exit__'), ('__exit__', '__enter__')):
        raise RuntimeError('unrecognized runtime context special lookup order')
    return result

def _actual_instance_of(value, expected):
    # Inspect the true runtime type through type's C descriptor. isinstance()
    # could consult an opaque value's __class__ property on its false path.
    for base in _TYPE_MRO.__get__(_TYPE(value)):
        if base is expected:
            return True
    return False

def _exception_matches(error_type, candidate):
    """Match a dynamic except target without user meta hooks or reraising."""
    if _actual_instance_of(candidate, _TUPLE):
        targets = tuple.__iter__(candidate)
    else:
        targets = (candidate,)
    for target in targets:
        if not _actual_instance_of(target, _TYPE):
            raise TypeError('catching classes that do not inherit from BaseException is not allowed')
        for base in _TYPE_MRO.__get__(target):
            if base is _BASE_EXCEPTION:
                break
        else:
            raise TypeError('catching classes that do not inherit from BaseException is not allowed')
    targets = tuple.__iter__(candidate) if _actual_instance_of(candidate, _TUPLE) else (candidate,)
    actual_mro = _TYPE_MRO.__get__(error_type)
    for target in targets:
        for base in actual_mro:
            if base is target:
                return 1
    return 0

class StoreFileCaptureUnknown(RuntimeError):
    """An actual handler observation is unconfirmed; no terminal or replay."""


class NativeStoreFileCapture(NativeHiaJsonImage):
    pass


@lru_cache(maxsize=3)
def _mapped_store_file_capture(raw, digest, source_digest):
    image = NativeStoreFileCapture(raw, digest)
    image.admitted_source_sha256 = source_digest
    return image


def installed_store_file_capture(manifest_path):
    if not manifest_path:
        raise ValueError('native store file capture selector must not be empty')
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeStoreFileCapture,
                            _admission_resolver=_admission_resolve)
    path = _admission_resolve(manifest_path, strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_unique_manifest_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid native store file capture manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or Path(name).name != name or any(ord(char) < 32 for char in name)):
        raise ValueError('native store file capture image must be a sibling basename')
    source = _regular_bytes(SOURCE, 8 << 20)
    image_path = path.parent / name
    image = _regular_bytes(image_path, 1 << 20)
    if sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('native store file capture source identity mismatch')
    if sha256(image).hexdigest() != value['image_sha256']:
        raise ValueError('native store file capture image identity mismatch')
    if selected is None:
        selected = _mapped_store_file_capture(image, value['image_sha256'], value['source_sha256'])
    elif type(selected) is not NativeStoreFileCapture or selected.image_sha256 != value['image_sha256']:
        raise ValueError('native store file capture differs from pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source
            or _regular_bytes(image_path, 1 << 20) != image):
        raise ValueError('native store file capture selection changed during admission')
    selected.admitted_source_sha256 = value['source_sha256']
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



# Each callable below preserves one original expression/linear call, including
# LOAD_METHOD before argument evaluation. No retained whole function is called.
def _literal_stable_flags(lookup):
    return lookup('os').O_RDONLY | lookup('os').O_CLOEXEC | lookup('os').O_NOFOLLOW | lookup('os').O_NONBLOCK

def _literal_stable_open(lookup, path, flags, dir_fd):
    return lookup('os').open(path, flags, dir_fd=dir_fd)

def _literal_stable_fdopen(lookup, fd):
    return lookup('os').fdopen(fd, "rb", closefd=False)

def _literal_stable_close(lookup, fd):
    lookup('os').close(fd)

def _literal_stable_before(lookup, stream):
    return lookup('os').fstat(stream.fileno())

def _literal_stable_not_regular(lookup, before):
    return 1 if not lookup('stat').S_ISREG(before.st_mode) else 0

def _literal_stable_too_large(before, limit):
    return 1 if before.st_size > limit else 0

def _literal_stable_reject_file(lookup):
    lookup('reject')("E_HIA_ARTIFACT_FILE", "artifact is not a bounded ordinary file")

def _literal_stable_read(stream, limit):
    return stream.read(limit + 1)

def _literal_stable_after(lookup, stream):
    return lookup('os').fstat(stream.fileno())

def _literal_stable_identity():
    return lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

def _literal_stable_size_differs(lookup, data, before):
    return 1 if lookup('len')(data) != before.st_size else 0

def _literal_stable_identity_differs(identity, before, after):
    return 1 if identity(before) != identity(after) else 0

def _literal_stable_reject_changed(lookup):
    lookup('reject')("E_HIA_ARTIFACT_CHANGED", "artifact changed while it was read")

def _literal_stable_wrap_oserror(lookup, error):
    try:
        raise lookup('AgentRejected')("E_HIA_ARTIFACT_FILE", "cannot read authorized ordinary artifact") from error
    finally:
        error = None

def _literal_capture_not_string(lookup, path):
    return 1 if lookup('type')(path) is not lookup('str') else 0

def _literal_capture_not_absolute(lookup, path):
    return 1 if not lookup('os').path.isabs(path) else 0

def _literal_capture_reject_absolute(lookup):
    lookup('reject')("E_HIA_PATH", "artifact paths must be absolute")

def _literal_capture_parts(lookup, path):
    return lookup('Path')(path).parts

def _literal_capture_parent_component(parts):
    return 1 if ".." in parts else 0

def _literal_capture_dot_component(parts):
    return 1 if "." in parts else 0

def _literal_capture_nul(path):
    return 1 if "\x00" in path else 0

def _literal_capture_reject_traversal(lookup):
    lookup('reject')("E_HIA_PATH", "artifact traversal is not permitted")

def _literal_capture_lexical(lookup, path):
    return lookup('Path')(path)

def _literal_capture_relative(lexical, root):
    return lexical.relative_to(root)

def _literal_capture_relative_truth(relative):
    return 1 if relative.parts else 0

def _literal_capture_choose(root, relative):
    return (root, relative.parts)

def _literal_capture_no_chosen(chosen):
    return 1 if chosen is None else 0

def _literal_capture_reject_authority(lookup):
    lookup('reject')("E_HIA_PATH_AUTHORITY", "artifact path is outside configured roots")

def _literal_capture_open_root(lookup, root):
    return lookup('os').open(root, lookup('os').O_RDONLY | lookup('os').O_DIRECTORY | lookup('os').O_CLOEXEC | lookup('os').O_NOFOLLOW)

def _literal_capture_append(descriptors, fd):
    descriptors.append(fd)

def _literal_capture_open_component(lookup, component, fd):
    return lookup('os').open(component, lookup('os').O_RDONLY | lookup('os').O_DIRECTORY | lookup('os').O_CLOEXEC | lookup('os').O_NOFOLLOW, dir_fd=fd)

def _literal_capture_read(lookup, relative, limit, fd):
    return lookup('stable_read')(relative[-1], limit, dir_fd=fd)

def _literal_capture_close(lookup, fd):
    lookup('os').close(fd)

def _literal_capture_wrap_oserror(lookup, error):
    try:
        raise lookup('AgentRejected')("E_HIA_PATH", "artifact path contains an unavailable or unsafe component") from error
    finally:
        error = None

@dataclass(frozen=True)
class StoreFileCaptureReceipt:
    port: int
    sequence: int
    phase: int
    mode: int
    failed: int
    resume_port: int
    fd_state: int

class StoreFileCaptureFrame:
    def __init__(self, image, mode, initial, *, namespace=None):
        if type(image) is not NativeStoreFileCapture:
            raise TypeError('native store file capture requires an admitted image')
        if type(mode) is not int or mode not in (STABLE_READ, CAPTURE_PATH):
            raise ValueError('native store file capture requires one original mode')
        expected = {'path', 'limit', 'dir_fd'} if mode == STABLE_READ else {'path', 'roots', 'limit'}
        if type(initial) is not dict or set(initial) != expected:
            raise TypeError('file capture initial slots differ')
        from . import hia_agent_store
        if namespace is None:
            namespace = vars(hia_agent_store)
            global_builtins = (hia_agent_store._STABLE_READ_GLOBAL_BUILTINS if mode == STABLE_READ
                               else hia_agent_store._CAPTURE_PATH_GLOBAL_BUILTINS)
        else:
            global_builtins = namespace.get('__builtins__', vars(builtins))
            if type(global_builtins) is types.ModuleType:
                global_builtins = vars(global_builtins)
        self.image, self.mode = image, mode
        self.namespace, self.global_builtins = namespace, global_builtins
        self.data = dict.fromkeys(_local_storage_order(mode))
        self.data.update(initial)
        self._retired_data = {}
        self._set_handled = _capture_handled_state_setter()
        self._caller_handled = None
        self.stack = {}
        self.context_lookup_order = _context_lookup_order()
        self.result = None
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
        except BaseException:
            self._delivery.retire()
            raise

    def _global(self, name):
        return _global_value(self.namespace, self.global_builtins, name)
    def _check(self):
        record = self._delivery
        record.check(StoreFileCaptureUnknown)
        whole = self._whole
        if whole is not None:
            whole.pending_resources.check_borrowed_resources()
        # The identity query or GC may itself perform a real child call.
        record.check(StoreFileCaptureUnknown)

    def call(self, event, observation=0):
        record = self._delivery
        if self.fenced or self.finished or not record.current():
            raise StoreFileCaptureUnknown('native store file capture has no current invocation')
        self._check()
        native_confirmed = False
        try:
            previous = self.receipt
            port, sequence = (0, 0) if previous is None else (previous.port, previous.sequence)
            old_failed = 0 if previous is None else previous.failed
            fd_state = FD_NONE if previous is None else previous.fd_state
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
                raise StoreFileCaptureUnknown('native store file capture return is unconfirmed')
            words = struct.unpack('<12Q', output.raw[:OUTPUT_BYTES])
            state = struct.unpack('<16Q', self.buffer.raw[:STATE_BYTES])
            expected_sequence = 1 if event == INITIALIZE else sequence if event == CLAIM else sequence + 1
            expected_phases = {
                INITIALIZE: (ISSUED,), CLAIM: (CLAIMED,),
                SUCCEEDED: (ISSUED, READY_RETURN, READY_PROPAGATE, LEAVE_EXCEPTION),
                RAISED: (ISSUED, READY_PROPAGATE),
                RESUME: (ISSUED,), FINALIZE: (RETURNED, PROPAGATE),
            }[event]
            failed = (1 if event == RAISED else 0 if event == RESUME else old_failed)
            if event == SUCCEEDED and port == PORT['stable_open']:
                if self.mode != STABLE_READ or fd_state != FD_NONE:
                    raise StoreFileCaptureUnknown('owned-fd open acknowledgement has no empty responsibility')
                fd_state = FD_OWNED
            if event == CLAIM and port in STABLE_CLOSE_PORTS:
                if self.mode != STABLE_READ or fd_state != FD_OWNED:
                    raise StoreFileCaptureUnknown('owned-fd close cannot be claimed twice')
                fd_state = FD_CLOSE_CLAIMED
            active = words[4] in (ISSUED, CLAIMED)
            if (words[0] != RESULT_MAGIC or words[1] != 0
                    or words[2:7] != (state[3], state[4], state[5], state[2], state[12])
                    or words[7] != state[8]
                    or state[:3] != (STATE_MAGIC, STATE_VERSION, self.mode)
                    or words[8:10] != self.identity or state[6:8] != self.identity
                    or words[10:12] != (0, 0)
                    or state[9] != fd_state or state[11] != 0 or state[13:16] != (0, 0, 0)
                    or state[10] != _checksum(state)
                    or words[3] != expected_sequence or words[4] not in expected_phases
                    or words[6] != failed
                    or (words[4] in (READY_RETURN, RETURNED) and failed != 0)
                    or (words[4] in (READY_PROPAGATE, PROPAGATE, LEAVE_EXCEPTION) and failed != 1)
                    or (not active and words[2] != 0)
                    or (active and not 1 <= words[2] <= len(PORTS))
                    or (active and ((self.mode == STABLE_READ and words[2] not in STABLE_PORTS)
                        or (self.mode == CAPTURE_PATH and words[2] not in CAPTURE_PORTS)))
                    or (self.mode == CAPTURE_PATH and state[9] != FD_NONE)
                    or (words[4] != LEAVE_EXCEPTION and words[7] != 0)
                    or (words[4] == LEAVE_EXCEPTION and words[7] != PORT[
                        'stable_suppressed_result' if self.mode == STABLE_READ else 'capture_roots_next'])
                    or (event == CLAIM and words[2] != port)
                    or (event == RESUME and (previous.phase != LEAVE_EXCEPTION
                                            or words[2] != previous.resume_port))
                    or (event == FINALIZE and (previous.phase not in (READY_RETURN, READY_PROPAGATE)
                        or words[4] != (RETURNED if previous.phase == READY_RETURN else PROPAGATE)))):
                raise StoreFileCaptureUnknown('native file capture receipt differs from issued state')
            receipt = StoreFileCaptureReceipt(words[2], words[3], words[4], words[5], words[6], words[7], state[9])
            pending = None
            if event in (SUCCEEDED, RAISED):
                pending = self._pending_foreign
            elif event == FINALIZE:
                pending = self._whole
            if event in (SUCCEEDED, RAISED, FINALIZE):
                if pending is None:
                    raise StoreFileCaptureUnknown('native store file capture has no matching foreign activation')
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
                raise StoreFileCaptureUnknown('native store file capture observation failed') from error
            raise

    def finish(self):
        # Same-Frame reentry is refused outside the active owner's cleanup
        # region. A recursive public handler creates its own fresh Frame.
        if self._entered:
            raise StoreFileCaptureUnknown('native store file capture frame cannot be reused')
        if not self._delivery.current():
            raise StoreFileCaptureUnknown('native store file capture frame cannot be transferred')
        self._entered = True
        try:
            # Capture the actual invocation caller, not construction history.
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
                self._delivery.propagate(error, StoreFileCaptureUnknown, _REQUEST_REJECTIONS)
            raise
        finally:
            try:
                self._delivery.retire()
            finally:
                self._caller_handled = None

    def _effect_once(self):
        self._effect_started = False
        if self.receipt.phase != ISSUED:
            raise StoreFileCaptureUnknown('native store file capture effect is not newly issued')
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
            raise StoreFileCaptureUnknown('native store file capture has no HIA completion directive')
        self.call(FINALIZE)
        if self.receipt.phase != (RETURNED if previous == READY_RETURN else PROPAGATE):
            raise StoreFileCaptureUnknown('native store file capture final receipt is unconfirmed')
        self.finished = True


    def _exception_continuation(self):
        # The caller remains in its actual except suite. HIA alone requests
        # special exit, dynamic matching, translation, finally, or suppression.
        while self.receipt.phase == ISSUED:
            try:
                observed = self._effect_once()
            except BaseException as error:
                if self.fenced or self.native_failed or self._delivery.loss is not None:
                    self._delivery.propagate(error, StoreFileCaptureUnknown, _REQUEST_REJECTIONS)
                    raise
                if not self._effect_started:
                    raise
                self.call(RAISED)
                self._exception_continuation()
                return
            self.call(SUCCEEDED, observed)
        if self.receipt.phase == LEAVE_EXCEPTION:
            return
        if self.receipt.phase == READY_PROPAGATE:
            raise
        raise StoreFileCaptureUnknown('native file capture left its exception continuation')

    def _drive(self):
        while True:
            # RESUME happens after leaving the actual except suite, so the
            # original outer exception is restored before loop/with continuation.
            if self.receipt.phase == LEAVE_EXCEPTION:
                self.call(RESUME)
            try:
                observed = self._effect_once()
            except BaseException as error:
                if self.fenced or self.native_failed or self._delivery.loss is not None:
                    self._delivery.propagate(error, StoreFileCaptureUnknown, _REQUEST_REJECTIONS)
                    raise
                if not self._effect_started:
                    raise
                self.call(RAISED)
                self._exception_continuation()
                continue
            self.call(SUCCEEDED, observed)
            if self.receipt.phase == READY_RETURN:
                return
            if self.receipt.phase != ISSUED:
                raise StoreFileCaptureUnknown('native file capture left its normal continuation')

    def _next(self, key, target):
        # FOR_ITER StopIteration is consumed outside the visible caller's
        # exception context. Release the iterator after leaving this handler.
        try:
            self.data[target] = _NEXT(self.stack[key])
        except StopIteration:
            pass
        else:
            return 1
        self.stack.pop(key)
        return 0


    def _release_context_stack_at_caller(self, name):
        if (name not in ('stable_cm_unwind', 'stable_enter_unwind', 'stable_cancel_return', 'capture_cancel_return',
                         'capture_search_unwind')
                or self.receipt is None or self.receipt.phase != CLAIMED
                or self.receipt.port != PORT[name]):
            raise StoreFileCaptureUnknown('file capture context cleanup was not issued by HIA')
        # Capture the restoration capability and both strong pointer owners
        # before an original stack decrement can call a destructor.
        handled_state = _HANDLED_EXCEPTION
        set_handled = self._set_handled
        caller = self._caller_handled
        caller_pointer = None if caller is None else id(caller)
        pending = handled_state()
        pending_pointer = None if pending is None else id(pending)
        s = self.stack
        try:
            set_handled(caller_pointer)
            if handled_state() is not caller:
                raise StoreFileCaptureUnknown('file capture caller handled state was not installed')
            if name == 'stable_cm_unwind':
                # The manager is above the captured special callable(s) on a
                # failed lookup's original evaluation stack.
                s.pop('manager', None)
                s.pop('enter', None)
                s.pop('exit', None)
                s.pop('lookup_index', None)
            elif name == 'stable_enter_unwind':
                s.pop('exit', None)
            elif name == 'capture_search_unwind':
                # The original for-loop value stack is unwound after leaving
                # its except matcher, in the invocation caller's handled state.
                s.pop('roots_iterator', None)
            else:
                # A pending return exists after stable_result or capture_read succeeded.
                # Its original finally ran in the invocation caller's handled
                # state; a new cleanup exception must not own this decref.
                self.result = None
            return 0
        finally:
            try:
                set_handled(pending_pointer)
                if handled_state() is not pending:
                    raise StoreFileCaptureUnknown('file capture pending handled state was not restored')
            finally:
                pending = caller = None

    def effect(self, port):
        if (self.receipt is None or self.receipt.phase != CLAIMED or self.receipt.port != port
                or not 1 <= port <= len(PORTS)):
            raise StoreFileCaptureUnknown('file capture effect has no matching claim')
        name = PORTS[port - 1]
        d = self.data
        if name == 'stable_flags':
            d['flags'] = _literal_stable_flags(self._global)
        elif name == 'stable_open':
            d['fd'] = _literal_stable_open(self._global, d['path'], d['flags'], d['dir_fd'])
        elif name == 'stable_fdopen':
            self.stack['manager'] = _literal_stable_fdopen(self._global, d['fd'])
        elif name == 'stable_cm_prepare':
            self.stack['lookup_index'] = 0
        elif name == 'stable_cm_next':
            index = self.stack['lookup_index']
            if index == 2:
                self.stack.pop('manager')
                self.stack.pop('lookup_index')
                return 0
            self.stack['lookup_index'] = index + 1
            return 1 if self.context_lookup_order[index] == '__enter__' else 2
        elif name == 'stable_lookup_enter':
            self.stack['enter'] = _capture_context_special(self.stack['manager'], '__enter__')
        elif name == 'stable_lookup_exit':
            self.stack['exit'] = _capture_context_special(self.stack['manager'], '__exit__')
        elif name == 'stable_enter':
            d['stream'] = self.stack.pop('enter')()
        elif name == 'stable_before':
            d['before'] = _literal_stable_before(self._global, d['stream'])
        elif name == 'stable_not_regular':
            return _literal_stable_not_regular(self._global, d['before'])
        elif name == 'stable_too_large':
            return _literal_stable_too_large(d['before'], d['limit'])
        elif name == 'stable_reject_file':
            _literal_stable_reject_file(self._global)
        elif name == 'stable_read':
            d['data'] = _literal_stable_read(d['stream'], d['limit'])
        elif name == 'stable_after':
            d['after'] = _literal_stable_after(self._global, d['stream'])
        elif name == 'stable_identity':
            d['identity'] = _literal_stable_identity()
        elif name == 'stable_size_differs':
            return _literal_stable_size_differs(self._global, d['data'], d['before'])
        elif name == 'stable_identity_differs':
            return _literal_stable_identity_differs(d['identity'], d['before'], d['after'])
        elif name == 'stable_reject_changed':
            _literal_stable_reject_changed(self._global)
        elif name == 'stable_result':
            self.result = d['data']
        elif name == 'stable_exit_normal':
            self.stack.pop('exit')(None, None, None)
        elif name == 'stable_exit_error':
            # WITH_EXCEPT_START keeps the exit callable on its value stack
            # through the result's truth observation and unwind/suppression.
            self.stack['exit_result'] = self.stack['exit'](*sys.exc_info())
        elif name == 'stable_exit_truth':
            return 1 if self.stack.pop('exit_result') else 0
        elif name == 'stable_suppressed_result':
            # HIA LEAVE_EXCEPTION/RESUME has already restored the original
            # caller handled state; now retire the retained exit callable.
            self.stack.pop('exit', None)
            self.result = None
        elif name == 'stable_cancel_return':
            return self._release_context_stack_at_caller(name)
        elif name in ('stable_close_normal', 'stable_close_error'):
            if self.receipt.fd_state != FD_CLOSE_CLAIMED:
                raise StoreFileCaptureUnknown('owned-fd close has no current HIA claim')
            _literal_stable_close(self._global, d['fd'])
        elif name in ('stable_cm_unwind', 'stable_enter_unwind'):
            return self._release_context_stack_at_caller(name)
        elif name in ('stable_match_oserror', 'capture_match_oserror'):
            return _exception_matches(type(sys.exception()), self._global('OSError'))
        elif name == 'capture_match_valueerror':
            return _exception_matches(type(sys.exception()), self._global('ValueError'))
        elif name in ('stable_bind_exception', 'capture_bind_exception'):
            d['exc'] = sys.exception()
        elif name == 'stable_wrap_oserror':
            _literal_stable_wrap_oserror(self._global, d['exc'])
        elif name == 'capture_wrap_oserror':
            _literal_capture_wrap_oserror(self._global, d['exc'])
        elif name in ('stable_clear_exception', 'capture_clear_exception'):
            # An except-as target is cleared before propagating into finally.
            d['exc'] = None
        elif name in ('stable_release_locals', 'capture_release_locals'):
            if self.stack:
                raise StoreFileCaptureUnknown('native release still has an interpreter value stack')
            # Detached old storage may still belong to a handled provider TB.
            self.data = self._retired_data
        elif name == 'capture_not_string':
            return _literal_capture_not_string(self._global, d['path'])
        elif name == 'capture_not_absolute':
            return _literal_capture_not_absolute(self._global, d['path'])
        elif name == 'capture_reject_absolute':
            _literal_capture_reject_absolute(self._global)
        elif name == 'capture_parts':
            d['parts'] = _literal_capture_parts(self._global, d['path'])
        elif name == 'capture_parent_component':
            return _literal_capture_parent_component(d['parts'])
        elif name == 'capture_dot_component':
            return _literal_capture_dot_component(d['parts'])
        elif name == 'capture_nul':
            return _literal_capture_nul(d['path'])
        elif name == 'capture_reject_traversal':
            _literal_capture_reject_traversal(self._global)
        elif name == 'capture_lexical':
            d['lexical'] = _literal_capture_lexical(self._global, d['path'])
        elif name == 'capture_chosen_none':
            d['chosen'] = None
        elif name == 'capture_roots_iter':
            self.stack['roots_iterator'] = _ITER(d['roots'])
        elif name == 'capture_roots_next':
            return self._next('roots_iterator', 'root')
        elif name == 'capture_relative':
            d['relative'] = _literal_capture_relative(d['lexical'], d['root'])
        elif name == 'capture_relative_truth':
            return _literal_capture_relative_truth(d['relative'])
        elif name == 'capture_choose':
            d['chosen'] = _literal_capture_choose(d['root'], d['relative'])
        elif name == 'capture_roots_release':
            self.stack.pop('roots_iterator', None)
        elif name == 'capture_search_unwind':
            return self._release_context_stack_at_caller(name)
        elif name == 'capture_no_chosen':
            return _literal_capture_no_chosen(d['chosen'])
        elif name == 'capture_reject_authority':
            _literal_capture_reject_authority(self._global)
        elif name == 'capture_unpack':
            d['root'], d['relative'] = d['chosen']
        elif name == 'capture_descriptors':
            d['descriptors'] = []
        elif name == 'capture_open_root':
            d['fd'] = _literal_capture_open_root(self._global, d['root'])
        elif name in ('capture_append_root', 'capture_append_component'):
            _literal_capture_append(d['descriptors'], d['fd'])
        elif name == 'capture_components_iter':
            self.stack['components_iterator'] = _ITER(d['relative'][:-1])
        elif name == 'capture_components_next':
            return self._next('components_iterator', 'component')
        elif name == 'capture_open_component':
            d['fd'] = _literal_capture_open_component(self._global, d['component'], d['fd'])
        elif name == 'capture_read':
            self.result = _literal_capture_read(self._global, d['relative'], d['limit'], d['fd'])
        elif name == 'capture_body_unwind':
            self.stack.pop('components_iterator', None)
        elif name == 'capture_cleanup_iter':
            self.stack['cleanup_iterator'] = _ITER(self._global('reversed')(d['descriptors']))
        elif name == 'capture_cleanup_next':
            return self._next('cleanup_iterator', 'fd')
        elif name == 'capture_close':
            _literal_capture_close(self._global, d['fd'])
        elif name == 'capture_cleanup_unwind':
            self.stack.pop('cleanup_iterator', None)
        elif name == 'capture_cancel_return':
            self.stack.pop('cleanup_iterator', None)
            return self._release_context_stack_at_caller(name)
        else:
            raise StoreFileCaptureUnknown('unknown native file capture port')
        return 0
