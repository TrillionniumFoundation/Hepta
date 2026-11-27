"""Explicit HIA artifact-page policy with a mechanical Store/SQL boundary.

The public Agent catalog admits pages of 512..65536 bytes and retained artifacts
of at most 64 MiB. This owner also transports zero/small page limits and signed
SQLite offsets for differential controls. Larger private-method page requests
and arbitrary replacement Store objects
remain outside its declared product profile. Actual SQLite non-integer offset
values retain the original arithmetic/slice exceptions at their original point.
Selecting it never invokes the retained page policy.

Persistent SQL/file custody, metadata decoding and Python object operations
remain foreign effects, requested in the original order by the HIA executable.
The complete page classification, encoding, wire-budget and cursor decisions
are executable HIA. This module does not claim an entirely native AgentStore.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import weakref

from .hia_native_delivery import DeliveryRecord, guarded, request_rejections
from .hia_agent_store import AgentStore, uses_native_store
from .hia_store_lifecycle_native import _regular_bytes

from .hia_json_preflight_native import (
    NativeHiaJsonImage, _load_manifest, _source_resource_path, _unique_manifest_pairs,
)
from .hia_json_wire_native import (
    ForeignGraphObserver, NativeJsonWire, SelectedBinary64Renderer,
    SOURCE as WIRE_SOURCE, SCHEMA as WIRE_SCHEMA, installed_json_wire,
)

SOURCE = _source_resource_path('examples/hia_bootstrap/artifact_page.hepta')
POLICY_SCHEMA = 'hepta.hia.artifact-page-native.v2'
SCHEMA = 'hepta.hia.artifact-page-bundle.v2'
SELECTOR = 'HEPTA_HIA_ARTIFACT_PAGE_MANIFEST'
MAGIC = int.from_bytes(b'HIAAPG02', 'little')
HIGH = 1 << 63
NODE_BASE = 4096
NODES = 21
CURSOR_CODE, CURSOR_MESSAGE = HIGH + 13, HIGH + 14
RESULT_NODE = HIGH + 20



class ArtifactPageUnknown(RuntimeError):
    """The actual native/effect observation is not confirmed; never replay it."""


class _BoundCursor:
    """One HIA-requested callable lookup; SQL argument evaluation stays later."""
    __slots__ = ('callable', 'kind', 'native', 'resource')

    def __init__(self, service, kind, activation):
        if kind not in (4, 13):
            raise ArtifactPageUnknown('artifact-page cursor binding kind differs')
        store = activation.borrow_registered_resource(service.store)
        self.kind = kind
        self.native = uses_native_store(store)
        self.resource = weakref.ref(store) if issubclass(type(store), AgentStore) else None
        if self.native:
            self.callable = store.cursor_lookup if kind == 4 else store.cursor_retain
        else:
            self.callable = store.db.execute

    def invoke(self, activation, kind, values):
        if kind != self.kind:
            raise ArtifactPageUnknown('artifact-page cursor callable used for another effect')
        resource = None if self.resource is None else self.resource()
        if self.resource is not None and resource is None:
            raise ArtifactPageUnknown('artifact-page cursor resource was retired')
        activation.borrow_registered_resource(resource)
        del resource
        arguments = activation.resource_call_arguments(guarded(values))
        if self.native:
            return self.callable(*arguments)
        if kind == 4:
            return self.callable('SELECT * FROM cursors WHERE id=?', arguments).fetchone()
        return self.callable('INSERT OR IGNORE INTO cursors VALUES (?,?,?,?)', arguments)


class PageGraphObserver:
    """Read HIA-owned virtual nodes; retain original foreign object identity."""
    def __init__(self, session):
        self.session = session
        self.foreign = ForeignGraphObserver()
        self._text = {}

    def register(self, value):
        handle = self.foreign.register(value)
        if handle >= HIGH:
            raise RuntimeError('artifact-page foreign handle namespace exhausted')
        return handle

    def _node(self, handle):
        index = handle - HIGH
        if not 0 < index <= NODES:
            raise RuntimeError('invalid artifact-page virtual handle')
        return struct.unpack_from('<6Q', self.session.workspace, NODE_BASE + index * 48)

    def summary(self, handle):
        if handle < HIGH:
            value = self.foreign.value(handle)
            if type(value) is bytes:
                return 9, len(value), 0, 0
            return self.foreign.summary(handle)
        kind, size, subtype, a, b, c = self._node(handle)
        return kind, size, a if kind in (1, 2) else 0, 0

    def child(self, handle, index, part):
        if handle < HIGH:
            return self.foreign.child(handle, index, part)
        kind, size, subtype, a, b, c = self._node(handle)
        if kind != 7 or index >= size or part not in (0, 1):
            raise RuntimeError('invalid artifact-page virtual dictionary observation')
        return struct.unpack_from('<Q', self.session.workspace, a + index * 16 + part * 8)[0]

    def _string(self, handle):
        kind, size, subtype, a, b, c = self._node(handle)
        if kind != 4:
            raise RuntimeError('artifact-page virtual node is not a string')
        epoch, = struct.unpack_from('<Q', self.session.workspace, 288)
        key = (handle, epoch)
        if key not in self._text:
            if subtype == 0:
                points = struct.unpack_from('<' + 'I' * size, self.session.workspace, a)
                value = ''.join(map(chr, points))
            elif subtype == 1:
                if a > len(self.session.output) or b > len(self.session.output) - a:
                    raise RuntimeError('artifact-page output extent differs')
                # HIA has already chosen and validated this exact UTF-8/base64
                # representation. Decoding only materializes its chosen value.
                value = self.session.output.raw[a:a + b].decode('utf-8')
            else:
                raise RuntimeError('invalid artifact-page virtual string representation')
            if len(value) != size:
                raise RuntimeError('artifact-page Unicode extent differs')
            self._text[key] = value
        return self._text[key]

    def points(self, handle, start, count):
        if handle < HIGH:
            return self.foreign.points(handle, start, count)
        value = self._string(handle)
        if start > len(value) or count > len(value) - start:
            raise RuntimeError('invalid artifact-page Unicode observation extent')
        return tuple(ord(value[i]) for i in range(start, start + count))

    def limbs(self, handle, start, count):
        if handle < HIGH:
            return self.foreign.limbs(handle, start, count)
        kind, size, subtype, sign, magnitude, c = self._node(handle)
        if kind != 2 or start > (size + 31) // 32 or count > (size + 31) // 32 - start:
            raise RuntimeError('invalid artifact-page integer observation extent')
        return tuple((magnitude >> (index * 32)) & 0xffffffff for index in range(start, start + count))

    def value(self, handle):
        if handle < HIGH:
            return self.foreign.value(handle)
        kind, size, subtype, a, b, c = self._node(handle)
        if kind == 0:
            return None
        if kind == 2:
            return -b if a else b
        if kind == 4:
            return self._string(handle)
        if kind == 7:
            # Keys, order and child handles all come from the HIA virtual arena.
            # Original foreign children are returned without copying them.
            return {self.value(self.child(handle, i, 0)): self.value(self.child(handle, i, 1))
                    for i in range(size)}
        raise RuntimeError('invalid artifact-page result node')


class PageSession:
    def __init__(self, owner, service, arguments):
        self.owner, self.service = owner, service
        self.workspace = ctypes.create_string_buffer(131072 + 16)
        self.output = ctypes.create_string_buffer(131072 + 16)
        ctypes.memmove(ctypes.addressof(self.workspace) + 131072, b'\xb7' * 16, 16)
        ctypes.memmove(ctypes.addressof(self.output) + 131072, b'\xa5' * 16, 16)
        self.observer = PageGraphObserver(self)
        self.packet = struct.pack('<4Q', MAGIC, 0, 0, self.observer.register(arguments))
        self.finished = False
        self._observation_pending = False
        self._pending_foreign = None
        self._delivery = DeliveryRecord(self)

    def step(self, packet=None):
        record = self._delivery
        try:
            if self.finished:
                raise RuntimeError('native artifact-page continuation is terminal')
            record.check(ArtifactPageUnknown)
            raw = self.packet if packet is None else packet
            before_sequence, = struct.unpack_from('<Q', self.workspace, 16)
            source = ctypes.create_string_buffer(raw + b'\xc9' * 16, len(raw) + 16)
            record.enter_native()
            code = self.owner.policy._entry(source, len(raw), self.output, 131072,
                                            self.workspace, 131072)
            if (source.raw != raw + b'\xc9' * 16
                    or self.output.raw[131072:] != b'\xa5' * 16
                    or self.workspace.raw[131072:] != b'\xb7' * 16
                    or code not in (1, 2, 100, 101, 102, 103, 198, 199)):
                raise ArtifactPageUnknown('native artifact-page return is unconfirmed')
            magic, opcode, sequence, phase = struct.unpack_from('<4Q', self.workspace)
            if code == 1:
                if (magic != MAGIC or not 1 <= opcode <= 17
                        or sequence != before_sequence + 1 or phase == 4294967295):
                    raise ArtifactPageUnknown('native artifact-page issued state differs')
            elif code != 199:
                if magic != MAGIC or opcode != 0 or phase != 4294967295:
                    raise ArtifactPageUnknown('native artifact-page terminal state differs')
            if code == 198 and (len(raw) != 64 or struct.unpack_from('<Q', raw, 56)[0] != 1):
                raise ArtifactPageUnknown('native artifact-page failure ACK was not requested')
            pending = self._pending_foreign
            if pending is not None and code == 199:
                raise ArtifactPageUnknown('native artifact-page refused its foreign acknowledgement')
            if pending is not None:
                pending.prepare_acknowledgement()
            record.check(ArtifactPageUnknown)
            record.confirmed()
            if pending is not None:
                pending.acknowledged()
                self._pending_foreign = None
            record.check(ArtifactPageUnknown)
            record.confirmed(terminal=code != 1)
            self._observation_pending = code == 1
            if code != 1:
                self.finished = True
                record.retire()
            return code
        except BaseException as error:
            record.failed(error)
            pending = self._pending_foreign
            if pending is not None:
                pending.failed(error)
            self.finished = True
            self._observation_pending = False
            record.propagate(error, ArtifactPageUnknown, request_rejections())
            record.retire()
            raise

    def _wire(self, handle):
        # The retained wire() admits an explicitly selected binary64 renderer
        # on every invocation, even for a string. Preserve that lookup and
        # source-check order before independently selected wire admission.
        renderer = None
        selected = os.environ.get('HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST')
        if selected:
            renderer = SelectedBinary64Renderer(selected)
        selected_wire = os.environ.get('HEPTA_HIA_JSON_WIRE_MANIFEST')
        image = installed_json_wire(selected_wire) if selected_wire else self.owner.wire
        return image.encode_observed(self.observer, handle, 8 << 20,
                                     ensure_ascii=False, sort_keys=True, float_renderer=renderer)

    def observe(self):
        if self.finished:
            raise RuntimeError('native artifact-page continuation is terminal')
        if not self._observation_pending:
            raise RuntimeError('native artifact-page observation was already consumed')
        self._delivery.check(ArtifactPageUnknown)
        self._observation_pending = False
        activation = self._delivery.foreign(capture_resources=True, weak_registered_resources=True)
        self._pending_foreign = activation
        try:
            with activation:
                result = self._effect(activation)
        except BaseException as error:
            if self._delivery.loss is not None:
                activation.failed(error)
                self.finished = True
                self._delivery.propagate(error, ArtifactPageUnknown, request_rejections())
                raise
            opcode, sequence = struct.unpack_from('<2Q', self.workspace, 8)
            failure = struct.pack('<8Q', MAGIC, sequence, opcode, 0, 0, 0, 0, 1)
            if self.step(failure) != 198:
                raise ArtifactPageUnknown('native artifact-page did not confirm the foreign exception')
            raise
        try:
            opcode, sequence, x, y, z, t, payload = result
            self.packet = struct.pack('<8Q', MAGIC, sequence, opcode, x, y, z, t, 0) + payload
            return self.packet
        except BaseException as error:
            self._delivery.failed(error)
            activation.failed(error)
            self.finished = True
            self._delivery.propagate(error, ArtifactPageUnknown, request_rejections())
            raise

    def _effect(self, activation):
        opcode, sequence = struct.unpack_from('<2Q', self.workspace, 8)
        a, b, c, d = struct.unpack_from('<4Q', self.workspace, 200)
        reg, value = self.observer.register, self.observer.value
        x = y = z = t = 0
        payload = b''
        if opcode == 1:
            x = reg(value(a)[value(b)])
        elif opcode == 2:
            data, _ = self.service.store.get(value(a))
            x = reg(data)
        elif opcode == 3:
            x = int(value(b) in value(a))
        elif opcode == 4:
            x = reg(value(a).invoke(activation, 4, (value(b),)))
        elif opcode == 5:
            x = reg(value(a).get(value(b), c))
        elif opcode == 6:
            x = reg(int(value(a)))
        elif opcode == 7:
            x, y, z, t = self.observer.summary(a)
        elif opcode in (8, 15):
            method = self.observer.points if opcode == 8 else self.observer.limbs
            words = method(a, b, c)
            x = len(words)
            payload = struct.pack('<' + 'I' * x, *words)
        elif opcode == 9:
            x = int(bool(value(a) != value(b)))
        elif opcode == 10:
            payload = value(a)[b:b + c]
            x = len(payload)
        elif opcode == 11:
            raw = self._wire(a)
            x, y = reg(raw), len(raw)
        elif opcode == 12:
            x = reg(value(a).decode('utf-8'))
        elif opcode == 13:
            e, = struct.unpack_from('<Q', self.workspace, 328)
            value(a).invoke(activation, 13, (value(b), value(c), value(d), value(e)))
        elif opcode == 14:
            payload = self._wire(a)
            x = len(payload)
        elif opcode == 16:
            x = reg(_BoundCursor(self.service, a, activation))
        elif opcode == 17:
            # HIA selects this foreign operation only for a builtin
            # non-integer SQLite offset. Preserve the interpreter's real
            # arithmetic/slice exception, after max_bytes conversion and
            # before any UTF-8 observation. Do not replace it with a
            # native-profile diagnostic or run the retained page owner.
            x = reg(value(a)[value(b):value(b) + value(c)])
        else:
            raise RuntimeError('native artifact-page requested an unknown effect')
        return opcode, sequence, x, y, z, t, payload

    def run(self):
        try:
            with self._delivery.foreign(observation=False):
                while True:
                    code = self.step()
                    if code == 1:
                        self.observe()
                    elif code == 2:
                        return self.observer.value(RESULT_NODE)
                    elif code == 100:
                        from .hia_agent_store import reject
                        reject(self.observer.value(CURSOR_CODE), self.observer.value(CURSOR_MESSAGE))
                    elif code in (101, 102, 103):
                        raise ValueError('native artifact-page input is outside its declared public product profile')
                    else:
                        raise RuntimeError('native artifact-page continuation profile refused')
        finally:
            self.finished = True
            self._observation_pending = False
            self._delivery.retire()


class NativeArtifactPage:
    def __init__(self, policy, wire):
        self.policy, self.wire = policy, wire

    def read(self, service, arguments):
        return PageSession(self, service, arguments).run()


def installed_artifact_page(path):
    if not path:
        raise ValueError('native artifact-page selector must not be empty')
    path = Path(path).absolute()
    raw = _regular_bytes(path, 8192)
    bundle = json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(raw.decode('utf-8'))
    if (type(bundle) is not dict or set(bundle) != {'schema', 'policy_manifest', 'policy_manifest_sha256',
                                                 'wire_manifest', 'wire_manifest_sha256'}
            or bundle['schema'] != SCHEMA):
        raise ValueError('invalid native artifact-page bundle')
    captured = {path: raw}
    images = {}
    sources = {'policy': SOURCE, 'wire': WIRE_SOURCE}
    schemas = {'policy': POLICY_SCHEMA, 'wire': WIRE_SCHEMA}
    factories = {'policy': NativeHiaJsonImage, 'wire': NativeJsonWire}
    compiler = None
    from .hia_native_helpers import pinned_image
    for name in ('policy', 'wire'):
        target = bundle[name + '_manifest']
        expected = bundle[name + '_manifest_sha256']
        if (type(target) is not str or not target or Path(target).is_absolute()
                or any(p in ('', '.', '..') for p in target.split('/'))
                or '\\' in target
                or type(expected) is not str or len(expected) != 64
                or any(c not in '0123456789abcdef' for c in expected)):
            raise ValueError('invalid native artifact-page child identity')
        child = path.parent / target
        child_raw = _regular_bytes(child, 16384)
        if sha256(child_raw).hexdigest() != expected:
            raise ValueError('native artifact-page child manifest identity mismatch')
        value = json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(child_raw.decode('utf-8'))
        if (type(value) is not dict or set(value) != {'schema', 'source_sha256',
                'image_path', 'image_sha256', 'compiler_sha256'}
                or value['schema'] != schemas[name]
                or any(type(value[k]) is not str or len(value[k]) != 64
                       or any(c not in '0123456789abcdef' for c in value[k])
                       for k in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
            raise ValueError('invalid native artifact-page child manifest')
        image_name = value['image_path']
        if (type(image_name) is not str or not image_name or image_name in ('.', '..')
                or Path(image_name).name != image_name or '/' in image_name or '\\' in image_name
                or any(ord(c) < 32 for c in image_name)):
            raise ValueError('native artifact-page image must be a sibling basename')
        source_raw = _regular_bytes(sources[name], 8 << 20)
        image_path = child.parent / image_name
        image_raw = _regular_bytes(image_path, 1 << 20)
        if (sha256(source_raw).hexdigest() != value['source_sha256']
                or sha256(image_raw).hexdigest() != value['image_sha256']):
            raise ValueError('native artifact-page source/image identity mismatch')
        if compiler is not None and compiler != value['compiler_sha256']:
            raise ValueError('native artifact-page children use different compilers')
        compiler = value['compiler_sha256']
        selected = pinned_image(child, sources[name], schemas[name], factories[name])
        if selected is None:
            selected = _load_manifest(str(child), child_raw, value['source_sha256'],
                                      schemas[name], factories[name])
        if (type(selected) is not factories[name]
                or selected.image_sha256 != value['image_sha256']):
            raise ValueError('native artifact-page differs from pinned worker image')
        images[name] = selected
        captured.update({child: child_raw, sources[name]: source_raw, image_path: image_raw})
    if any(_regular_bytes(p, max(1, len(data))) != data for p, data in captured.items()):
        raise ValueError('native artifact-page selection changed while loading')
    return NativeArtifactPage(images['policy'], images['wire'])
