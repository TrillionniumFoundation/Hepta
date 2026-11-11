"""HIA-owned bounded JSON wire with a lazy, mechanical object observer.

The executable owns both traversals and every admission/output decision. Python
transports exact builtin type, identity, child, Unicode and integer magnitude
observations. It never serializes or recursively expands the input graph.
"""
from __future__ import annotations

import ctypes
import struct
import sys
from typing import Protocol

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_program_tools import HIAEditRejected

SOURCE = _source_resource_path('examples/hia_bootstrap/json_wire.hiaasm')
SCHEMA = 'hepta.hia.json-wire-native.v1'
SELECTOR = 'HEPTA_HIA_JSON_WIRE_MANIFEST'
MAGIC = int.from_bytes(b'HIAWIR01', 'little')
MAXIMUM = 8 << 20
NONE, BOOL, INT, FLOAT, STRING, LIST, TUPLE, DICT, OPAQUE = range(9)
SUMMARY, CHILD, POINTS, LIMBS, DIGIT_LIMIT, FORMAT_FLOAT = range(1, 7)

REASONS = {
    100: 'invalid JSON output byte budget',
    101: 'JSON input exceeds nesting depth before encoding',
    102: 'JSON input exceeds node/byte budget',
    103: 'JSON container exceeds queued-node/byte budget',
    104: 'cyclic JSON container',
    105: 'JSON integer exceeds byte budget',
    106: 'non-JSON in-process value',
    107: 'JSON object key collision after JSON conversion',
    108: 'JSON string exceeds byte budget before encoding',
    109: 'JSON key exceeds numeric byte budget',
    110: 'nonfinite JSON object key',
    111: 'nonfinite JSON number',
    112: 'invalid bounded JSON',
    113: 'unsupported JSON object key',
    114: 'JSON key exceeds byte budget',
    115: 'unpaired Unicode surrogate in UTF-8 JSON',
    116: 'JSON encoding exceeds byte budget',
}


class GraphObserver(Protocol):
    """Foreign observations requested individually by the HIA continuation.

    summary returns (kind,size,a,b). INT uses size=bit_length,a=negative;
    FLOAT uses a=IEEE64 bits; BOOL uses a=0/1; strings/containers use size=len.
    child(sequence,index,0) is an element; child(dict,index,0/1) is key/value.
    Codepoints retain isolated surrogates. Limbs are absolute-value little
    endian 32-bit words. Handles preserve identity and strong references.
    """
    def summary(self, handle: int) -> tuple[int, int, int, int]: ...
    def child(self, handle: int, index: int, part: int) -> int: ...
    def points(self, handle: int, start: int, count: int) -> tuple[int, ...]: ...
    def limbs(self, handle: int, start: int, count: int) -> tuple[int, ...]: ...


class ForeignGraphObserver:
    """Exact builtin transport. Registration does not inspect descendants."""
    def __init__(self):
        self._objects = {}
        self._identities = {}
        self._dict_cursors = {}
        self._magnitudes = {}

    def register(self, value):
        identity = id(value)
        old = self._identities.get(identity)
        if old is not None:
            return old
        handle = len(self._objects) + 1
        self._objects[handle] = value
        self._identities[identity] = handle
        return handle

    def value(self, handle):
        return self._objects[handle]

    def summary(self, handle):
        value = self.value(handle)
        kind = type(value)
        if value is None:
            return NONE, 0, 0, 0
        if kind is bool:
            return BOOL, 0, int(value), 0
        if kind is int:
            return INT, int.bit_length(value), int(value < 0), 0
        if kind is float:
            return FLOAT, 0, struct.unpack('<Q', struct.pack('<d', value))[0], 0
        if kind is str:
            return STRING, len(value), 0, 0
        if kind is list:
            return LIST, len(value), 0, 0
        if kind is tuple:
            return TUPLE, len(value), 0, 0
        if kind is dict:
            # A fresh observation starts a new traversal. Only requested pairs
            # are retained; no list(items), sorting or recursive transport.
            self._dict_cursors[handle] = (iter(value.items()), [])
            return DICT, len(value), 0, 0
        return OPAQUE, 0, 0, 0

    def child(self, handle, index, part):
        value = self.value(handle)
        if type(value) is dict:
            iterator, observed = self._dict_cursors[handle]
            while len(observed) <= index:
                observed.append(next(iterator))
            return self.register(observed[index][part])
        return self.register(value[index])

    def points(self, handle, start, count):
        value = self.value(handle)
        return tuple(ord(value[index]) for index in range(start, start + count))

    def limbs(self, handle, start, count):
        value = self.value(handle)
        raw = self._magnitudes.get(handle)
        if raw is None:
            # Representation transport begins only after HIA asks for limbs.
            # No decimal conversion, numeric policy or graph preflight here.
            magnitude = abs(value)
            raw = int.to_bytes(magnitude, ((magnitude.bit_length() + 31) // 32) * 4, 'little')
            self._magnitudes[handle] = raw
        return struct.unpack_from('<' + 'I' * count, raw, start * 4)


def buffer_sizes(maximum):
    """Physical allocation mirrors the published ABI; HIA admits the budget."""
    physical = maximum if type(maximum) is int and 0 <= maximum <= MAXIMUM else 0
    budget = min(physical, 262144)
    slots = 2
    while slots < budget * 2:
        slots *= 2
    size = (32768 + (budget + 130) * 24 + budget * 64 + slots * 8
            + (physical + 64) * 2 + ((physical * 4 + 31) // 32) * 4 + 64 + 8192)
    return physical, size


class WireSession:
    """Opaque HIA continuation plus protocol transport, independently testable."""
    def __init__(self, image, observer, root, maximum, *, ensure_ascii, sort_keys, float_renderer=None):
        self.image, self.observer = image, observer
        self.float_renderer = float_renderer
        output_size, workspace_size = buffer_sizes(maximum)
        self.output_size = output_size
        self.output = ctypes.create_string_buffer(max(1, output_size))
        self.workspace = ctypes.create_string_buffer(workspace_size)
        if type(maximum) is int:
            kind, sign, bits = INT, int(maximum < 0), maximum.bit_length()
            low = abs(maximum) & ((1 << 64) - 1)
        else:
            kind, sign, bits, low = OPAQUE, 0, 0, 0
        self.packet = struct.pack('<11Q', MAGIC, 0, 0, root, kind, sign, bits, low,
                                  int(bool(ensure_ascii)), int(bool(sort_keys)), int(float_renderer is not None))
        self.finished = False

    def step(self, packet=None):
        if self.finished:
            raise RuntimeError('native JSON wire session is terminal')
        raw = self.packet if packet is None else packet
        source = ctypes.create_string_buffer(raw, max(1, len(raw)))
        status = self.image._entry(source, len(raw), self.output, self.output_size,
                                   self.workspace, len(self.workspace))
        if status != 1:
            self.finished = True
        return status

    def observe(self):
        opcode, sequence = struct.unpack_from('<2Q', self.workspace, 8)
        handle, index, count, part = struct.unpack_from('<4Q', self.workspace, 200)
        a = b = c = d = 0
        payload = b''
        if opcode == SUMMARY:
            a, b, c, d = self.observer.summary(handle)
        elif opcode == CHILD:
            a = self.observer.child(handle, index, part)
        elif opcode == POINTS or opcode == LIMBS:
            method = self.observer.points if opcode == POINTS else self.observer.limbs
            values = method(handle, index, count)
            a = len(values)
            payload = struct.pack('<' + 'I' * a, *values)
        elif opcode == DIGIT_LIMIT:
            a = sys.get_int_max_str_digits()
        elif opcode == FORMAT_FLOAT:
            # The only supported callback profile is the existing selected
            # finite HIA binary64 printer, not an arbitrary JSON encoder hook.
            number = struct.unpack('<d', struct.pack('<Q', index))[0]
            rendered = self.float_renderer(number)
            payload = rendered.encode('ascii') if type(rendered) is str else rendered
            a = len(payload)
        else:
            raise RuntimeError('native JSON wire requested an unknown observation')
        self.packet = struct.pack('<7Q', MAGIC, sequence, opcode, a, b, c, d) + payload
        return self.packet

    def run(self):
        try:
            while True:
                status = self.step()
                if status == 1:
                    self.observe()
                    continue
                if status == 2:
                    count, = struct.unpack_from('<Q', self.workspace, 112)
                    if count > self.output_size:
                        raise RuntimeError('native JSON wire returned an invalid extent')
                    return self.output.raw[:count]
                if status in REASONS:
                    raise HIAEditRejected('E_HIA_EDIT: ' + REASONS[status])
                raise RuntimeError('native JSON wire continuation profile refused')
        except HIAEditRejected:
            raise
        except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
            raise HIAEditRejected('E_HIA_EDIT: invalid bounded JSON') from exc


class NativeJsonWire(NativeHiaJsonImage):
    def encode_observed(self, observer, root_handle, maximum=MAXIMUM, *, ensure_ascii=False,
                        sort_keys=True, float_renderer=None):
        return WireSession(self, observer, root_handle, maximum, ensure_ascii=ensure_ascii,
                           sort_keys=sort_keys, float_renderer=float_renderer).run()

    def encode(self, value, maximum=MAXIMUM, *, ensure_ascii=False, sort_keys=True, float_renderer=None):
        observer = ForeignGraphObserver()
        return self.encode_observed(observer, observer.register(value), maximum,
                                    ensure_ascii=ensure_ascii, sort_keys=sort_keys,
                                    float_renderer=float_renderer)


def installed_json_wire(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeJsonWire)
