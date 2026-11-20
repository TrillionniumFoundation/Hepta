"""HIA control for the complete ``HIAAgentService._hia_read`` handler.

The image owns cursor short circuits, both UTF-8 trim loops, format choice,
repeated wire-budget control, cursor publication, exception continuations and
normal local retirement. Object/numeric protocols, codec, wire, digest and
SQLite expressions remain explicit foreign providers. Pending resources are
learned from actual downstream native/resource scopes or an exact registered
Store weak identity at the original SQL receiver, never from receiver guesses
or exception classes. The weak shared API is an explicit source dependency.
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
from .hia_agent_store import uses_native_store
import struct
import types

from .hia_emission_native import _global_value
from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path, _unique_manifest_pairs
from .hia_native_delivery import DeliveryRecord, guarded, request_rejections
from .hia_store_lifecycle_native import _regular_bytes
from .hia_service_read_protocol import (
    SELECTOR, SCHEMA, SOURCE_NAME, REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC,
    REQUEST_BYTES, OUTPUT_BYTES, STATE_BYTES, INITIALIZE, CLAIM, SUCCEEDED,
    RAISED, ISSUED, CLAIMED, RETURNED, PROPAGATE, UNWIND, PORT, PORTS,
)

SOURCE = _source_resource_path(SOURCE_NAME)

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


@lru_cache(maxsize=1)
def _local_storage_order():
    """Make an ordinary dict release the original frame's twelve local slots.

Observe the running frame and builtin dict instead of choosing a Python
version. The fixed private probe has no user references or cycles; only the
twelve fixed storage names are cached. The original names self, args and _
map to service, arguments and metadata. Exceptional cleanup is not inserted:
the caller still controls the lifetime of its actual traceback.
    """
    frame_events, dict_events = [], []
    _probe_frame_release(frame_events)
    _probe_dict_release(dict_events)
    forward, reverse = ['first', 'last'], ['last', 'first']
    if frame_events not in (forward, reverse) or dict_events not in (forward, reverse):
        raise RuntimeError('runtime does not provide immediate ordered local custody')
    names = ('service', 'arguments', 'ref', 'data', 'metadata', 'offset',
             'row', 'limit', 'chunk', 'encoding', 'content', 'next_cursor')
    return names if frame_events == dict_events else names[::-1]


class ServiceReadUnknown(RuntimeError):
    """An actual handler observation is unconfirmed; no terminal or replay."""


class NativeServiceRead(NativeHiaJsonImage):
    pass


@lru_cache(maxsize=3)
def _mapped_service_read(raw, digest, source_digest):
    image = NativeServiceRead(raw, digest)
    image.admitted_source_sha256 = source_digest
    return image


def installed_service_read(manifest_path):
    if not manifest_path:
        raise ValueError('native service read selector must not be empty')
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeServiceRead)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_unique_manifest_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid native service read manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or Path(name).name != name or any(ord(char) < 32 for char in name)):
        raise ValueError('native service read image must be a sibling basename')
    source = _regular_bytes(SOURCE, 8 << 20)
    image_path = path.parent / name
    image = _regular_bytes(image_path, 1 << 20)
    if sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('native service read source identity mismatch')
    if sha256(image).hexdigest() != value['image_sha256']:
        raise ValueError('native service read image identity mismatch')
    if selected is None:
        selected = _mapped_service_read(image, value['image_sha256'], value['source_sha256'])
    elif type(selected) is not NativeServiceRead or selected.image_sha256 != value['image_sha256']:
        raise ValueError('native service read differs from pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source
            or _regular_bytes(image_path, 1 << 20) != image):
        raise ValueError('native service read selection changed during admission')
    return selected


def _checksum(words):
    value = 1469598103934665603
    for index, word in enumerate(words):
        if index != 10:
            value = (((value << 7) | (value >> 57)) & ((1 << 64) - 1)) ^ word
    return value


# These complete linear expressions preserve LOAD_METHOD, callable capture,
# unpack/slice and temporary release. No expression selects a read branch or
# repeats a read loop; those continuations are issued by the HIA image.
def _literal_get(service, ref):
    return service.store.get(ref)


def _literal_cursor_select(service, arguments, activation):
    # Bind only instrumentation methods before the original expression. The
    # user receiver, LOAD_METHOD, tuple and fetchone chain remain in place.
    borrow = activation.borrow_registered_resource
    call_arguments = activation.resource_call_arguments
    store = borrow(service.store)
    try:
        native = uses_native_store(store)
        receiver = [store if native else store.db]
    finally:
        # Release the temporary Store before looking up a legacy DB method.
        del store
    if native:
        return receiver.pop().cursor_lookup(*call_arguments(guarded((arguments['cursor'],))))
    return receiver.pop().execute('SELECT * FROM cursors WHERE id=?',
        call_arguments(guarded((arguments['cursor'],)))).fetchone()


def _literal_cursor_id_test(row, ref):
    return int(bool(row['artifact_id'] != ref['id']))


def _literal_cursor_sha_test(row, ref):
    return int(bool(row['sha256'] != ref['sha256']))


def _literal_limit(arguments, lookup):
    return lookup('int')(arguments.get('max_bytes', 65536))


def _literal_initial_chunk(data, offset, limit):
    return data[offset:offset + limit]


def _literal_budget_test(content, lookup):
    # Keep the original complete linear expression on the interpreter stack.
    # Its temporary operands must also unwind at their original exception
    # cutpoints. HIA consumes only its truth observation and owns the loop.
    return int(bool(lookup('len')(lookup('wire')(content))
        + lookup('len')(lookup('wire')(lookup('wire')(content).decode('utf-8'))) > 230000))


def _literal_halve(chunk, lookup):
    return chunk[:lookup('max')(1, lookup('len')(chunk) // 2)]


def _literal_initial_base64(chunk, lookup):
    return 'base64', lookup('base64').b64encode(chunk).decode('ascii')


def _literal_later_base64(chunk, lookup):
    return lookup('base64').b64encode(chunk).decode('ascii')


def _literal_next_cursor(ref, offset, chunk, lookup):
    return 'page-' + lookup('digest')({'artifact': ref, 'offset': offset + lookup('len')(chunk)})


def _literal_end_test(offset, chunk, data, lookup):
    return int(bool(offset + lookup('len')(chunk) < lookup('len')(data)))


def _literal_cursor_insert(service, cursor, ref, offset, chunk, lookup, activation):
    borrow = activation.borrow_registered_resource
    call_arguments = activation.resource_call_arguments
    store = borrow(service.store)
    try:
        native = uses_native_store(store)
        receiver = [store if native else store.db]
    finally:
        del store
    if native:
        receiver.pop().cursor_retain(*call_arguments(guarded((cursor, ref['id'], ref['sha256'],
                                            offset + lookup('len')(chunk)))))
        return
    receiver.pop().execute('INSERT OR IGNORE INTO cursors VALUES (?,?,?,?)',
        call_arguments(guarded((cursor, ref['id'], ref['sha256'],
                                offset + lookup('len')(chunk)))))


def _literal_exception_match(lookup):
    # Execute this interpreter's actual except matching, including invalid
    # matchers and their first error. The caller keeps the original exception
    # active; isinstance() would not implement this protocol.
    try:
        raise
    except lookup('UnicodeDecodeError'):
        return 1
    except BaseException:
        return 0


@dataclass(frozen=True)
class ServiceReadReceipt:
    port: int
    sequence: int
    phase: int
    failed: int
    encoding: int


class ServiceReadFrame:
    def __init__(self, image, service, arguments, *, namespace=None):
        if type(image) is not NativeServiceRead:
            raise TypeError('native service read requires an admitted image')
        from . import hia_agent_service
        if namespace is None:
            namespace = vars(hia_agent_service)
            global_builtins = hia_agent_service._SERVICE_READ_GLOBAL_BUILTINS
        else:
            global_builtins = namespace.get('__builtins__', vars(builtins))
            if type(global_builtins) is types.ModuleType:
                global_builtins = vars(global_builtins)
        self.image = image
        self.namespace, self.global_builtins = namespace, global_builtins
        # Preallocate every original local slot before any provider. Subsequent
        # assignments replace values without moving slots. An unbound original
        # local occupies an inert None slot; it is never read by a new branch.
        # The builtin dict follows real frame ownership, including handled
        # exceptions whose traceback still retains an earlier effect frame.
        # There is no second service reference here. Reserve empty retired
        # storage before any provider so normal retirement need not allocate.
        self.data = dict.fromkeys(_local_storage_order())
        self._retired_data = {}
        self.data['service'], self.data['arguments'] = service, arguments
        self.result = None
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.buffer = ctypes.create_string_buffer(STATE_BYTES + 16)
        ctypes.memmove(ctypes.addressof(self.buffer) + STATE_BYTES, b'\xb7' * 16, 16)
        self.receipt = None
        self.fenced = self.finished = self.native_failed = False
        self._pending_foreign = None
        # DeliveryRecord already owns this full frame while unknown. A second
        # owner-specific lock/registry would add no custody guarantee.
        self._delivery = DeliveryRecord(self)
        try:
            self.call(INITIALIZE)
        except BaseException:
            self._delivery.retire()
            raise

    @property
    def service(self):
        return self.data.get('service')

    @service.setter
    def service(self, value):
        self.data['service'] = value

    def call(self, event, observation=0):
        record = self._delivery
        if self.fenced or self.finished or not record.current():
            raise ServiceReadUnknown('native service read has no current invocation')
        record.check(ServiceReadUnknown)
        handed_off = False
        native_confirmed = False
        try:
            port, sequence = (0, 0) if self.receipt is None else (self.receipt.port, self.receipt.sequence)
            raw = struct.pack('<10Q', REQUEST_MAGIC, event, sequence, port, observation, 1, *self.identity, 0, 0)
            source = ctypes.create_string_buffer(raw + b'\xc9' * 16, REQUEST_BYTES + 16)
            output = ctypes.create_string_buffer(OUTPUT_BYTES + 16)
            ctypes.memmove(ctypes.addressof(output) + OUTPUT_BYTES, b'\xa5' * 16, 16)
            record.enter_native()
            handed_off = True
            code = self.image._entry(source, REQUEST_BYTES, output, OUTPUT_BYTES, self.buffer, STATE_BYTES)
            if (code != OUTPUT_BYTES or source.raw != raw + b'\xc9' * 16
                    or output.raw[OUTPUT_BYTES:] != b'\xa5' * 16
                    or self.buffer.raw[STATE_BYTES:] != b'\xb7' * 16):
                raise ServiceReadUnknown('native service read return is unconfirmed')
            words = struct.unpack('<12Q', output.raw[:OUTPUT_BYTES])
            state = struct.unpack('<16Q', self.buffer.raw[:STATE_BYTES])
            expected_sequence = 1 if event == INITIALIZE else sequence if event == CLAIM else sequence + 1
            expected_phases = ((ISSUED, RETURNED, PROPAGATE, UNWIND) if event == SUCCEEDED
                               else (CLAIMED,) if event == CLAIM
                               else (ISSUED, PROPAGATE) if event == RAISED else (ISSUED,))
            if (words[0] != RESULT_MAGIC or words[1] != 0
                    or words[2:7] != (state[3], state[4], state[5], state[2], state[12])
                    or state[:3] != (STATE_MAGIC, 1, 1)
                    or words[8:10] != self.identity or state[6:8] != self.identity
                    or words[7] != state[8] or words[7] not in (0, 1) or words[10:12] != (0, 0)
                    or state[9] != 0 or state[11] != 0 or state[13:16] != (0, 0, 0)
                    or state[10] != _checksum(state)
                    or words[3] != expected_sequence or words[4] not in expected_phases
                    or words[6] != int(words[4] == PROPAGATE)
                    or (words[4] in (RETURNED, PROPAGATE) and words[2] != 0)
                    or (words[4] == RETURNED and port != PORT['return'])
                    or (words[4] in (ISSUED, CLAIMED, UNWIND) and not 1 <= words[2] <= len(PORTS))
                    or (words[4] == UNWIND and words[2] not in (PORT['first_chunk_decode'], PORT['later_chunk_decode'], PORT['budget_test']))
                    or (event == CLAIM and words[2] != port)):
                raise ServiceReadUnknown('native service read receipt differs from issued state')
            self.receipt = ServiceReadReceipt(words[2], words[3], words[4], words[6], words[7])
            # The full native receipt discharges this exact foreign result.
            # Healthy resource references are released before the next port.
            # A release that itself makes a real child call still has this
            # live ambient invocation until completion is recorded below.
            pending = None
            if event in (SUCCEEDED, RAISED):
                pending = self._pending_foreign
                if pending is None:
                    raise ServiceReadUnknown('native service read has no matching foreign activation')
                pending.prepare_acknowledgement()
            record.check(ServiceReadUnknown)
            record.confirmed()
            native_confirmed = True
            if pending is not None:
                pending.acknowledged()
                self._pending_foreign = None
            record.check(ServiceReadUnknown)
            record.confirmed(terminal=words[4] in (RETURNED, PROPAGATE))
            return self.receipt
        except BaseException as error:
            lost = record.failed(error)
            pending = self._pending_foreign
            if pending is not None:
                pending.failed(error)
            self.fenced = True
            self.native_failed = self.native_failed or lost or record.loss is not None
            # A safe INIT allocation/preparation refusal is not an uncertain
            # native call. Foreign MemoryError and process-control signals
            # retain their original identities; actual handoff failures use
            # the established continuation transport classification.
            if handed_off and not native_confirmed and isinstance(error, Exception) and (
                    not isinstance(error, RuntimeError) or isinstance(error, request_rejections())):
                raise ServiceReadUnknown('native service read observation failed') from error
            raise

    def finish(self):
        try:
            if (not self._delivery.current() or self._delivery.loss is not None
                    or self._delivery.terminal or self._delivery.retired):
                return self._finish()
            with self._delivery.foreign(observation=False):
                return self._finish()
        except BaseException as error:
            self._delivery.failed(error)
            pending = self._pending_foreign
            if pending is not None:
                pending.failed(error)
            if self._delivery.loss is not None:
                self.fenced = self.native_failed = True
                self._delivery.propagate(error, ServiceReadUnknown, request_rejections())
            raise
        finally:
            self._delivery.retire()

    def _confirmed_foreign_failure(self):
        if self.receipt.phase != PROPAGATE:
            self.fenced = True
            raise ServiceReadUnknown('native service read exception was not confirmed')
        self.finished = True

    def _exception_continuation(self):
        # Every call remains inside the original active except suite. HIA
        # alone chooses inner matching, outer matching, trim, propagation or
        # the point at which that exception context must be left.
        while self.receipt.phase == ISSUED:
            self.call(CLAIM)
            activation = self._delivery.foreign(capture_resources=True,
                                                weak_registered_resources=True)
            self._pending_foreign = activation
            try:
                with activation:
                    observed = self.effect(self.receipt.port)
            except BaseException as error:
                if self.native_failed or self._delivery.loss is not None:
                    activation.failed(error)
                    self.fenced = True
                    self._delivery.propagate(error, ServiceReadUnknown, request_rejections())
                    raise
                self.call(RAISED)
                if self.receipt.phase == PROPAGATE:
                    self._confirmed_foreign_failure()
                    raise
                # A new handler/trim error is matched while that NEW exception
                # is active, with the original error retained as its context.
                self._exception_continuation()
                return
            self.call(SUCCEEDED, observed)
        if self.receipt.phase == UNWIND:
            return
        self._confirmed_foreign_failure()
        raise

    def _finish(self):
        if self.finished:
            raise ServiceReadUnknown('native service read already completed')
        if self.fenced or self._delivery.loss is not None or not self._delivery.current():
            raise ServiceReadUnknown('native service read has no current invocation')
        while True:
            if self.receipt.phase not in (ISSUED, UNWIND):
                raise ServiceReadUnknown('native service read effect is not newly issued')
            self.call(CLAIM)
            activation = self._delivery.foreign(capture_resources=True,
                                                weak_registered_resources=True)
            self._pending_foreign = activation
            try:
                with activation:
                    observed = self.effect(self.receipt.port)
            except BaseException as error:
                if self.native_failed or self._delivery.loss is not None:
                    activation.failed(error)
                    self.fenced = True
                    self._delivery.propagate(error, ServiceReadUnknown, request_rejections())
                    raise
                self.call(RAISED)
                if self.receipt.phase == PROPAGATE:
                    self._confirmed_foreign_failure()
                    raise
                self._exception_continuation()
                # Leave the active handler before the next native-issued
                # decode/budget operation. No sys.exception normalization.
                continue
            self.call(SUCCEEDED, observed)
            if self.receipt.phase == RETURNED:
                self.finished = True
                # Transfer the result without leaving another owner in this
                # frame or a new local retained by an earlier handled traceback.
                # An unconfirmed return never reaches this terminal transfer.
                return self.__dict__.pop('result')

    def _global(self, name):
        return _global_value(self.namespace, self.global_builtins, name)

    def effect(self, port):
        if (self.receipt is None or self.receipt.phase != CLAIMED or self.receipt.port != port
                or not 1 <= port <= len(PORTS)):
            raise ServiceReadUnknown('native service read effect has no matching claim')
        name = PORTS[port - 1]
        d = self.data
        if name == 'artifact_argument':
            d['ref'] = d['arguments']['artifact']
        elif name == 'artifact_get':
            d['data'], d['metadata'] = _literal_get(self.service, d['ref'])
        elif name == 'offset_zero':
            d['offset'] = 0
        elif name == 'cursor_present':
            return int('cursor' in d['arguments'])
        elif name == 'cursor_select':
            d['row'] = _literal_cursor_select(self.service, d['arguments'], self._pending_foreign)
        elif name == 'cursor_missing':
            return int(d['row'] is None)
        elif name == 'cursor_id_test':
            return _literal_cursor_id_test(d['row'], d['ref'])
        elif name == 'cursor_sha_test':
            return _literal_cursor_sha_test(d['row'], d['ref'])
        elif name == 'cursor_reject':
            self._global('reject')('E_HIA_CURSOR', 'cursor is not bound to this exact artifact')
        elif name == 'cursor_offset':
            d['offset'] = d['row']['offset']
        elif name == 'limit':
            d['limit'] = _literal_limit(d['arguments'], self._global)
        elif name == 'initial_chunk':
            d['chunk'] = _literal_initial_chunk(d['data'], d['offset'], d['limit'])
        elif name == 'encoding_utf8':
            d['encoding'] = 'utf8'
        elif name == 'whole_data_decode':
            d['data'].decode('utf-8')
        elif name in ('first_chunk_decode', 'later_chunk_decode'):
            d['content'] = d['chunk'].decode('utf-8')
        elif name in ('first_exception_match', 'outer_exception_match', 'later_exception_match'):
            return _literal_exception_match(self._global)
        elif name in ('first_chunk_trim', 'later_chunk_trim'):
            d['chunk'] = d['chunk'][:-1]
        elif name == 'initial_base64':
            d['encoding'], d['content'] = _literal_initial_base64(d['chunk'], self._global)
        elif name == 'budget_test':
            return _literal_budget_test(d['content'], self._global)
        elif name == 'budget_chunk_halve':
            d['chunk'] = _literal_halve(d['chunk'], self._global)
        elif name == 'later_base64':
            d['content'] = _literal_later_base64(d['chunk'], self._global)
        elif name == 'next_cursor_none':
            d['next_cursor'] = None
        elif name == 'end_test':
            return _literal_end_test(d['offset'], d['chunk'], d['data'], self._global)
        elif name == 'next_cursor_digest':
            d['next_cursor'] = _literal_next_cursor(d['ref'], d['offset'], d['chunk'], self._global)
        elif name == 'cursor_insert':
            _literal_cursor_insert(self.service, d['next_cursor'], d['ref'], d['offset'],
                                   d['chunk'], self._global, self._pending_foreign)
        elif name == 'result':
            self.result = {'artifact': d['ref'], 'encoding': d['encoding'],
                           'content': d['content'], 'next_cursor': d['next_cursor']}
        elif name == 'release_locals':
            # Drop this owner's reference; do not mutate storage which an
            # actual handled exception frame may still own through its d local.
            # With no such owner the dict retires at this effect frame's exit,
            # inside the same foreign activation and in the probed slot order.
            self.data = self._retired_data
            self._retired_data = None
        return 0
