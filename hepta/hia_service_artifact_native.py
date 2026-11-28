"""HIA control for the complete ``HIAAgentService._hia_artifact`` handler.

The image owns sequencing, source selection, expected-digest rejection and
normal/error termination. Python supplies the original opaque object calls,
text encoding, path capture, hash and Store effects. A literal Store call does
not extract or retain a temporary receiver. Pending resource custody is learned
only at explicit downstream resource/native boundaries during that actual call.
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
import struct
import types

from .hia_service_artifact_bridge import _global_value, _regular_bytes
from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path, _unique_manifest_pairs
from .hia_native_delivery import DeliveryRecord, request_rejections
from .hia_service_artifact_protocol import (
    SELECTOR, SCHEMA, SOURCE_NAME, REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC,
    REQUEST_BYTES, OUTPUT_BYTES, STATE_BYTES, INITIALIZE, CLAIM, SUCCEEDED,
    RAISED, ISSUED, CLAIMED, RETURNED, PROPAGATE, PORT, PORTS,
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
    """Make an ordinary dict release the original frame's locals in order.

CPython 3.13 and 3.14 clear frame slots in opposite directions. Observe both
the running frame and dict mechanics instead of choosing a version threshold.
The fixed probe type stays alive, its two instances have no cycles, and the
cache contains only six fixed names. No exceptional-path cleanup is inserted:
the caller still controls the lifetime of its actual traceback.
    """
    frame_events, dict_events = [], []
    _probe_frame_release(frame_events)
    _probe_dict_release(dict_events)
    forward, reverse = ['first', 'last'], ['last', 'first']
    if frame_events not in (forward, reverse) or dict_events not in (forward, reverse):
        raise RuntimeError('runtime does not provide immediate ordered local custody')
    names = ('service', 'arguments', 'source', 'data', 'expected', 'ref')
    return names if frame_events == dict_events else names[::-1]


class ServiceArtifactUnknown(RuntimeError):
    """An actual handler observation is unconfirmed; no terminal or replay."""


class NativeServiceArtifact(NativeHiaJsonImage):
    def __init__(self, image, expected_sha256):
        import platform
        if (platform.system() != 'Linux' or platform.machine() != 'x86_64'
                or ctypes.sizeof(ctypes.c_void_p) != 8):
            raise ValueError('native HIA JSON image requires Linux x86-64 LP64')
        if (type(image) is not bytes or not 0 < len(image) <= 1 << 20
                or sha256(image).hexdigest() != expected_sha256):
            raise ValueError('native HIA JSON executable identity mismatch')
        from .hia_native_image import selected_extension
        carrier = selected_extension()
        self._native_image_carrier = carrier
        if carrier is None:
            super().__init__(image, expected_sha256)
        else:
            self.image_sha256 = expected_sha256
            self._mapping = carrier.Image(image)
            self._entry = self._mapping


def _frame_buffer(image, *arguments):
    carrier = getattr(image, '_native_image_carrier', None)
    return ctypes.create_string_buffer(*arguments) if carrier is None else carrier.Buffer(*arguments)


def _buffer_canary(image, buffer, offset, raw):
    if getattr(image, '_native_image_carrier', None) is None:
        ctypes.memmove(ctypes.addressof(buffer) + offset, raw, len(raw))
    else:
        memoryview(buffer)[offset:offset + len(raw)] = raw


@lru_cache(maxsize=3)
def _mapped_service_artifact(raw, digest, source_digest):
    image = NativeServiceArtifact(raw, digest)
    image.admitted_source_sha256 = source_digest
    return image


def installed_service_artifact(manifest_path):
    if not manifest_path:
        raise ValueError('native service artifact selector must not be empty')
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeServiceArtifact)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_unique_manifest_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid native service artifact manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or Path(name).name != name or any(ord(char) < 32 for char in name)):
        raise ValueError('native service artifact image must be a sibling basename')
    source = _regular_bytes(SOURCE, 8 << 20)
    image_path = path.parent / name
    image = _regular_bytes(image_path, 1 << 20)
    if sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('native service artifact source identity mismatch')
    if sha256(image).hexdigest() != value['image_sha256']:
        raise ValueError('native service artifact image identity mismatch')
    if selected is None:
        selected = _mapped_service_artifact(image, value['image_sha256'], value['source_sha256'])
    elif type(selected) is not NativeServiceArtifact or selected.image_sha256 != value['image_sha256']:
        raise ValueError('native service artifact differs from pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source
            or _regular_bytes(image_path, 1 << 20) != image):
        raise ValueError('native service artifact selection changed during admission')
    return selected


def _checksum(words):
    value = 1469598103934665603
    for index, word in enumerate(words):
        if index != 10:
            value = (((value << 7) | (value >> 57)) & ((1 << 64) - 1)) ^ word
    return value


# Complete expressions retain Python's method binding and temporary release
# points. ``lookup`` implements only the original global/builtins lookup; it
# does not pre-bind later providers or choose a handler continuation.
def _literal_profile(service, arguments):
    service._profile(arguments['artifact_profile'], 'artifact')


def _literal_kind_is_utf8(source):
    if source['kind'] == 'utf8':
        return 1
    return 0


def _literal_utf8(source):
    return source['text'].encode('utf-8')


def _literal_capture(service, source, lookup):
    return lookup('capture_path')(source['path'], service.artifact_roots, lookup('int')(source['max_bytes']))


def _literal_digest_differs(expected, data, lookup):
    if expected != lookup('sha256')(data).hexdigest():
        return 1
    return 0


def _literal_reject_changed(lookup):
    lookup('reject')('E_HIA_ARTIFACT_CHANGED', 'captured bytes differ from the expected digest')


def _literal_put(service, data):
    return service.store.put(data, 'input')


def _literal_result(ref, data, lookup):
    return {'artifact': ref, 'byte_length': lookup('str')(lookup('len')(data)),
            'content_admitted_as_program': False, 'execution_authority_granted': False}


@dataclass(frozen=True)
class ServiceArtifactReceipt:
    port: int
    sequence: int
    phase: int
    failed: int


class ServiceArtifactFrame:
    def __init__(self, image, service, arguments, *, namespace=None):
        if type(image) is not NativeServiceArtifact:
            raise TypeError('native service artifact requires an admitted image')
        if getattr(image, '_native_image_carrier', None) is not None:
            from .hia_native_image import admit_runtime
            admit_runtime()
        from . import hia_agent_service
        self.runtime_namespace = namespace is None
        if namespace is None:
            namespace = vars(hia_agent_service)
            global_builtins = hia_agent_service._SERVICE_ARTIFACT_GLOBAL_BUILTINS
        else:
            global_builtins = namespace.get('__builtins__', vars(builtins))
            if type(global_builtins) is types.ModuleType:
                global_builtins = vars(global_builtins)
        self.image = image
        self.namespace, self.global_builtins = namespace, global_builtins
        # These are the original handler's complete local slots. Preallocate
        # their storage order before any provider; later assignments replace
        # slots without moving them. A builtin dict supplies the destruction
        # mechanism, including when the caller releases an error traceback.
        self.data = dict.fromkeys(_local_storage_order())
        self.data['service'], self.data['arguments'] = service, arguments
        self.result = None
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.buffer = _frame_buffer(image, STATE_BYTES + 16)
        _buffer_canary(image, self.buffer, STATE_BYTES, b'\xb7' * 16)
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
            raise ServiceArtifactUnknown('native service artifact has no current invocation')
        record.check(ServiceArtifactUnknown)
        handed_off = False
        native_confirmed = False
        try:
            port, sequence = (0, 0) if self.receipt is None else (self.receipt.port, self.receipt.sequence)
            raw = struct.pack('<10Q', REQUEST_MAGIC, event, sequence, port, observation, 1, *self.identity, 0, 0)
            source = _frame_buffer(self.image, raw + b'\xc9' * 16, REQUEST_BYTES + 16)
            output = _frame_buffer(self.image, OUTPUT_BYTES + 16)
            _buffer_canary(self.image, output, OUTPUT_BYTES, b'\xa5' * 16)
            record.enter_native()
            handed_off = True
            code = self.image._entry(source, REQUEST_BYTES, output, OUTPUT_BYTES, self.buffer, STATE_BYTES)
            if (code != OUTPUT_BYTES or source.raw != raw + b'\xc9' * 16
                    or output.raw[OUTPUT_BYTES:] != b'\xa5' * 16
                    or self.buffer.raw[STATE_BYTES:] != b'\xb7' * 16):
                raise ServiceArtifactUnknown('native service artifact return is unconfirmed')
            words = struct.unpack('<12Q', output.raw[:OUTPUT_BYTES])
            state = struct.unpack('<16Q', self.buffer.raw[:STATE_BYTES])
            expected_sequence = 1 if event == INITIALIZE else sequence if event == CLAIM else sequence + 1
            expected_phases = ((ISSUED, RETURNED) if event == SUCCEEDED
                               else (CLAIMED,) if event == CLAIM
                               else (PROPAGATE,) if event == RAISED else (ISSUED,))
            if (words[0] != RESULT_MAGIC or words[1] != 0
                    or words[2:7] != (state[3], state[4], state[5], state[2], state[12])
                    or state[:3] != (STATE_MAGIC, 1, 1)
                    or words[8:10] != self.identity or state[6:8] != self.identity
                    or words[7] != 0 or words[10:12] != (0, 0)
                    or state[8:10] != (0, 0) or state[11] != 0 or state[13:16] != (0, 0, 0)
                    or state[10] != _checksum(state)
                    or words[3] != expected_sequence or words[4] not in expected_phases
                    or words[6] != int(words[4] == PROPAGATE)
                    or (words[4] in (RETURNED, PROPAGATE) and words[2] != 0)
                    or (words[4] == RETURNED and port != PORT['release_locals'])
                    or (words[4] in (ISSUED, CLAIMED) and not 1 <= words[2] <= len(PORTS))
                    or (event == CLAIM and words[2] != port)):
                raise ServiceArtifactUnknown('native service artifact receipt differs from issued state')
            self.receipt = ServiceArtifactReceipt(words[2], words[3], words[4], words[6])
            # The full native receipt discharges this exact foreign result.
            # Healthy resource references are released before the next port.
            # A release that itself makes a real child call still has this
            # live ambient invocation until completion is recorded below.
            pending = None
            if event in (SUCCEEDED, RAISED):
                pending = self._pending_foreign
                if pending is None:
                    raise ServiceArtifactUnknown('native service artifact has no matching foreign activation')
                pending.prepare_acknowledgement()
            record.check(ServiceArtifactUnknown)
            record.confirmed()
            native_confirmed = True
            if pending is not None:
                pending.acknowledged()
                self._pending_foreign = None
            record.check(ServiceArtifactUnknown)
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
                raise ServiceArtifactUnknown('native service artifact observation failed') from error
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
                self._delivery.propagate(error, ServiceArtifactUnknown, request_rejections())
            raise
        finally:
            self._delivery.retire()

    def _finish(self):
        if self.finished:
            raise ServiceArtifactUnknown('native service artifact already completed')
        while True:
            if self.receipt.phase != ISSUED:
                raise ServiceArtifactUnknown('native service artifact effect is not newly issued')
            self.call(CLAIM)
            activation = self._delivery.foreign(capture_resources=True)
            self._pending_foreign = activation
            try:
                with activation:
                    observed = self.effect(self.receipt.port)
            except BaseException as error:
                if self.native_failed or self._delivery.loss is not None:
                    activation.failed(error)
                    self.fenced = True
                    self._delivery.propagate(error, ServiceArtifactUnknown, request_rejections())
                    raise
                self.call(RAISED)
                if self.receipt.phase != PROPAGATE:
                    raise ServiceArtifactUnknown('native service artifact exception was not confirmed')
                self.finished = True
                # No handler cleanup existed on this path. The actual error
                # traceback retains the original locals until its caller lets
                # it go; no host finally clears them or substitutes an error.
                raise
            self.call(SUCCEEDED, observed)
            if self.receipt.phase == RETURNED:
                self.finished = True
                return self.result

    def _global(self, name):
        return _global_value(self.namespace, self.global_builtins, name)

    def effect(self, port):
        if (self.receipt is None or self.receipt.phase != CLAIMED or self.receipt.port != port
                or not 1 <= port <= len(PORTS)):
            raise ServiceArtifactUnknown('native service artifact effect has no matching claim')
        name = PORTS[port - 1]
        d = self.data
        if name == 'profile':
            _literal_profile(self.service, d['arguments'])
        elif name == 'source':
            d['source'] = d['arguments']['source']
        elif name == 'kind_is_utf8':
            return _literal_kind_is_utf8(d['source'])
        elif name == 'utf8_data':
            d['data'] = _literal_utf8(d['source'])
        elif name == 'capture_data':
            source = d['source']
            if self.runtime_namespace:
                d['data'] = self.service.store._capture_input(
                    source['path'], self.service.artifact_roots, self._global('int')(source['max_bytes']))
            else:
                d['data'] = _literal_capture(self.service, source, self._global)
        elif name == 'expected':
            d['expected'] = d['source']['expected_sha256']
        elif name == 'expected_is_not_none':
            return int(d['expected'] is not None)
        elif name == 'digest_differs':
            return _literal_digest_differs(d['expected'], d['data'], self._global)
        elif name == 'reject_changed':
            _literal_reject_changed(self._global)
        elif name == 'put':
            d['ref'] = _literal_put(self.service, d['data'])
        elif name == 'result':
            self.result = _literal_result(d['ref'], d['data'], self._global)
        elif name == 'release_locals':
            # HIA issues this only after constructing the returned dictionary.
            # The same preordered builtin storage also supplies normal frame
            # release. The returned dictionary independently keeps its ref.
            d.clear()
        return 0


from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
