"""Explicit HIA artifact-page policy with a mechanical Store/SQL boundary.

The public Agent catalog admits pages of 512..65536 bytes and retained artifacts
of at most 64 MiB. This owner also transports zero/small page limits and signed
SQLite offsets for differential controls; arbitrary replacement Store objects,
non-integer cursor rows and larger private-method page requests are outside its
declared product profile. Selecting it never invokes the retained page policy.

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

from .hia_json_preflight_native import (
    NativeHiaJsonImage, _load_manifest, _source_resource_path, _unique_manifest_pairs,
)
from .hia_json_wire_native import (
    ForeignGraphObserver, NativeJsonWire, SelectedBinary64Renderer,
    SOURCE as WIRE_SOURCE, SCHEMA as WIRE_SCHEMA, installed_json_wire,
)

SOURCE = _source_resource_path('examples/hia_bootstrap/artifact_page.hiaasm')
POLICY_SCHEMA = 'hepta.hia.artifact-page-native.v1'
SCHEMA = 'hepta.hia.artifact-page-bundle.v1'
SELECTOR = 'HEPTA_HIA_ARTIFACT_PAGE_MANIFEST'
MAGIC = int.from_bytes(b'HIAAPG01', 'little')
HIGH = 1 << 63
NODE_BASE = 4096
NODES = 21
CURSOR_CODE, CURSOR_MESSAGE = HIGH + 13, HIGH + 14
RESULT_NODE = HIGH + 20


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
        self.workspace = ctypes.create_string_buffer(131072)
        self.output = ctypes.create_string_buffer(131072)
        self.observer = PageGraphObserver(self)
        self.packet = struct.pack('<4Q', MAGIC, 0, 0, self.observer.register(arguments))
        self.finished = False
        self._observation_pending = False

    def step(self, packet=None):
        if self.finished:
            raise RuntimeError('native artifact-page continuation is terminal')
        raw = self.packet if packet is None else packet
        source = ctypes.create_string_buffer(raw, max(1, len(raw)))
        code = self.owner.policy._entry(source, len(raw), self.output, len(self.output),
                                        self.workspace, len(self.workspace))
        self._observation_pending = code == 1
        if code != 1:
            self.finished = True
        return code

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
        # Consume permission before invoking the foreign effect. An exception
        # closes the continuation; it cannot authorize a second SQL operation.
        self._observation_pending = False
        try:
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
                x = reg(self.service.store.db.execute('SELECT * FROM cursors WHERE id=?', (value(a),)).fetchone())
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
                self.service.store.db.execute('INSERT OR IGNORE INTO cursors VALUES (?,?,?,?)',
                                              (value(a), value(b), value(c), value(d)))
            elif opcode == 14:
                payload = self._wire(a)
                x = len(payload)
            else:
                raise RuntimeError('native artifact-page requested an unknown effect')
            self.packet = struct.pack('<8Q', MAGIC, sequence, opcode, x, y, z, t, 0) + payload
            return self.packet

        except BaseException:
            self.finished = True
            raise

    def run(self):
        try:
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
            # Preserve the actual exception/handled-context chain. A failed
            # foreign effect closes this continuation without replay or ACK.
            self.finished = True
            self._observation_pending = False


class NativeArtifactPage:
    def __init__(self, policy, wire):
        self.policy, self.wire = policy, wire

    def read(self, service, arguments):
        return PageSession(self, service, arguments).run()


def installed_artifact_page(path):
    path = Path(path).resolve(strict=True)
    with path.open('rb') as handle:
        raw = handle.read(8193)
    if len(raw) > 8192:
        raise ValueError('native artifact-page bundle exceeds manifest extent')
    bundle = json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(raw.decode('utf-8'))
    if (type(bundle) is not dict or set(bundle) != {'schema', 'policy_manifest', 'policy_manifest_sha256',
                                                 'wire_manifest', 'wire_manifest_sha256'}
            or bundle['schema'] != SCHEMA):
        raise ValueError('invalid native artifact-page bundle')
    children = {}
    for name in ('policy', 'wire'):
        target = bundle[name + '_manifest']
        expected = bundle[name + '_manifest_sha256']
        if (type(target) is not str or not target or Path(target).is_absolute() or '..' in Path(target).parts
                or type(expected) is not str or len(expected) != 64
                or any(c not in '0123456789abcdef' for c in expected)):
            raise ValueError('invalid native artifact-page child identity')
        child = (path.parent / target).resolve(strict=True)
        with child.open('rb') as handle:
            child_raw = handle.read(16385)
        if len(child_raw) > 16384 or sha256(child_raw).hexdigest() != expected:
            raise ValueError('native artifact-page child manifest identity mismatch')
        children[name] = child, child_raw
    sources = {'policy': SOURCE, 'wire': WIRE_SOURCE}
    hashes = {name: sha256(source.read_bytes()).hexdigest() for name, source in sources.items()}
    policy = _load_manifest(str(children['policy'][0]), children['policy'][1],
                            hashes['policy'], POLICY_SCHEMA, NativeHiaJsonImage)
    wire = _load_manifest(str(children['wire'][0]), children['wire'][1],
                          hashes['wire'], WIRE_SCHEMA, NativeJsonWire)
    if (path.read_bytes() != raw
            or any(child.read_bytes() != child_raw for child, child_raw in children.values())
            or any(sha256(source.read_bytes()).hexdigest() != hashes[name] for name, source in sources.items())):
        raise ValueError('native artifact-page selection changed while loading')
    return NativeArtifactPage(policy, wire)
